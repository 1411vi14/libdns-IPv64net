// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for IPv64.net. TODO: This package is a
// template only. Customize all godocs for actual implementation.
package libdnstemplate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// TODO: Providers must not require additional provisioning steps by the callers; it
// should work simply by populating a struct and calling methods on it. If your DNS
// service requires long-lived state or some extra provisioning step, do it implicitly
// when methods are called; sync.Once can help with this, and/or you can use a
// sync.(RW)Mutex in your Provider struct to synchronize implicit provisioning.

// Provider facilitates DNS record manipulation with IPv64.net.
type Provider struct {
	// TODO: Put config fields here (with snake_case json struct tags on exported fields), for example:
	APIToken string `json:"api_token,omitempty"`

	// optional custom client timeout
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
		return nil, fmt.Errorf("ipv64: api token not set")
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

	body, _ := ioutil.ReadAll(resp.Body)
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
	for _, r := range apiRecs {
		name := fqdnToRelative(r.Name, zone)
		rec := libdns.Record{
			Type:  r.Type,
			Name:  name,
			Value: r.Content,
		}
		if r.TTL > 0 {
			rec.TTL = time.Duration(r.TTL) * time.Second
		}
		out = append(out, rec)
	}
	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	for _, r := range records {
		params := url.Values{}
		params.Set("action", "add")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(r.Name, zone))
		params.Set("type", r.Type)
		params.Set("content", r.Value)
		if r.TTL > 0 {
			params.Set("ttl", strconv.Itoa(int(r.TTL.Seconds())))
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
		params := url.Values{}
		params.Set("action", "update")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(r.Name, zone))
		params.Set("type", r.Type)
		params.Set("content", r.Value)
		if r.TTL > 0 {
			params.Set("ttl", strconv.Itoa(int(r.TTL.Seconds())))
		}
		_, err := p.doAPI(ctx, params)
		if err != nil {
			// fallback: try to add if update fails
			addParams := url.Values{}
			addParams.Set("action", "add")
			addParams.Set("zone", zone)
			addParams.Set("host", relativeToHost(r.Name, zone))
			addParams.Set("type", r.Type)
			addParams.Set("content", r.Value)
			if r.TTL > 0 {
				addParams.Set("ttl", strconv.Itoa(int(r.TTL.Seconds())))
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
		params := url.Values{}
		params.Set("action", "delete")
		params.Set("zone", zone)
		params.Set("host", relativeToHost(r.Name, zone))
		params.Set("type", r.Type)
		// Some APIs expect content to choose which record to delete if multiple exist
		if r.Value != "" {
			params.Set("content", r.Value)
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
