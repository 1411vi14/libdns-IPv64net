// Package ipv64net implements a libdns provider for IPv64.net.
// It allows listing, adding, updating and deleting DNS records using IPv64.net's dyndns_updater_api.php.
package ipv64net

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with IPv64.net.
type Provider struct {
	// API token for authentication with the IPv64.net API.
	APIToken string `json:"api_token,omitempty"`

	// Optional custom HTTP client timeout in seconds. If unset, defaults to 15s.
	HTTPTimeoutSeconds int `json:"http_timeout_seconds,omitempty"`
}

const apiURL = "https://ipv64.net/dyndns_updater_api.php"

type apiRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Prio    int    `json:"prio,omitempty"`
}

func (p *Provider) httpClient() *http.Client {
	timeout := 15 * time.Second
	if p.HTTPTimeoutSeconds > 0 {
		timeout = time.Duration(p.HTTPTimeoutSeconds) * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func (p *Provider) doAPI(ctx context.Context, params url.Values) ([]apiRecord, error) {
	// ensure token included
	if p.APIToken == "" {
		return nil, fmt.Errorf("IPv64.net: api token not set")
	}
	params.Set("token", p.APIToken)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bs := bytesTrimBOM(body)
	// Try JSON first
	var arr []apiRecord
	if json.Unmarshal(bs, &arr) == nil {
		return arr, nil
	}

	// Fallback: parse text lines. Accept formats like:
	// name type content ttl prio  (space separated) or CSV/semicolon
	lines := strings.Split(strings.TrimSpace(string(bs)), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// allow several separators
		var parts []string
		if strings.Contains(ln, ";") {
			parts = strings.Split(ln, ";")
		} else if strings.Contains(ln, ",") {
			parts = strings.Split(ln, ",")
		} else {
			parts = strings.Fields(ln)
		}
		if len(parts) < 3 {
			// skip unparseable lines
			continue
		}
		rec := apiRecord{
			Name:    strings.TrimSpace(parts[0]),
			Type:    strings.TrimSpace(parts[1]),
			Content: strings.TrimSpace(parts[2]),
		}
		if len(parts) >= 4 {
			if v, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil {
				rec.TTL = v
			}
		}
		if len(parts) >= 5 {
			if v, err := strconv.Atoi(strings.TrimSpace(parts[4])); err == nil {
				rec.Prio = v
			}
		}
		arr = append(arr, rec)
	}
	return arr, nil
}

func bytesTrimBOM(b []byte) []byte {
	// remove possible UTF-8 BOM
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// fqdnToRelative converts a fully-qualified or relative record name to the
// provider-expected relative form with respect to the zone. Returns empty string
// for the zone apex.
func fqdnToRelative(name, zone string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return ""
	}
	// If name already relative (no trailing dot and not ending with zone), return as-is
	zone = strings.TrimSuffix(zone, ".")
	// remove trailing dot from name
	name = strings.TrimSuffix(name, ".")
	if strings.HasSuffix(name, "."+zone) {
		return strings.TrimSuffix(name, "."+zone)
	}
	if name == zone {
		return ""
	}
	return name
}

// relativeToHost converts the relative name into the host value expected by the API.
// The IPv64.net API expects "@" for the zone apex.
func relativeToHost(name, zone string) string {
	// API expects host relative or @ for zone apex
	if name == "" {
		return "@"
	}
	return name
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	// call list action
	params := url.Values{}
	params.Set("action", "list")
	params.Set("zone", zone)

	apiRecs, err := p.doAPI(ctx, params)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, ar := range apiRecs {
		name := fqdnToRelative(ar.Name, zone)
		// libdns.RR uses "@" to represent the zone apex; ensure we follow that convention.
		if name == "" {
			name = "@"
		}
		rr := libdns.RR{
			Type: ar.Type,
			Name: name,
			Data: ar.Content,
			TTL:  time.Duration(ar.TTL) * time.Second,
		}
		out = append(out, rr)
	}
	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	for _, r := range records {
		rr := r.RR()
		params := url.Values{}
		params.Set("action", "add")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(rr.Name, zone))
		params.Set("type", rr.Type)
		params.Set("content", rr.Data)
		if rr.TTL > 0 {
			params.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
		}
		// priority if present in Value? libdns.Record has no Prio field; skip unless TTL used
		_, err := p.doAPI(ctx, params)
		if err != nil {
			return nil, err
		}
		added = append(added, r)
	}
	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updated []libdns.Record
	for _, r := range records {
		rr := r.RR()
		params := url.Values{}
		params.Set("action", "update")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(rr.Name, zone))
		params.Set("type", rr.Type)
		params.Set("content", rr.Data)
		if rr.TTL > 0 {
			params.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
		}
		_, err := p.doAPI(ctx, params)
		if err != nil {
			// fallback: try to add if update fails
			addParams := url.Values{}
			addParams.Set("action", "add")
			addParams.Set("zone", zone)
			addParams.Set("host", relativeToHost(rr.Name, zone))
			addParams.Set("type", rr.Type)
			addParams.Set("content", rr.Data)
			if rr.TTL > 0 {
				addParams.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
			}
			if _, err2 := p.doAPI(ctx, addParams); err2 != nil {
				return nil, fmt.Errorf("update error: %v; add fallback error: %v", err, err2)
			}
		}
		updated = append(updated, r)
	}
	return updated, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	for _, r := range records {
		rr := r.RR()
		params := url.Values{}
		params.Set("action", "delete")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(rr.Name, zone))
		params.Set("type", rr.Type)
		// Some APIs expect content to choose which record to delete if multiple exist
		if rr.Data != "" {
			params.Set("content", rr.Data)
		}
		_, err := p.doAPI(ctx, params)
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, r)
	}
	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
