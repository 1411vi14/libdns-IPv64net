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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

var apiURL string = "https://ipv64.net/api"

// Provider facilitates DNS record manipulation with IPv64.net.
type Provider struct {
	// API token for authentication with the IPv64.net API.
	APIToken string `json:"api_token,omitempty"`

	// Optional custom HTTP client timeout in seconds. If unset, defaults to 15s.
	HTTPTimeoutSeconds int `json:"http_timeout_seconds,omitempty"`

	httpClient *http.Client
}

func (p *Provider) getHttpClient() *http.Client {
	timeout := 15 * time.Second
	if p.HTTPTimeoutSeconds > 0 {
		timeout = time.Duration(p.HTTPTimeoutSeconds) * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func (p *Provider) doRequest(ctx context.Context, params url.Values, method string) ([]byte, int, error) {
	if p.APIToken == "" {
		return nil, 0, fmt.Errorf("ipv64net: api token not set")
	}

	fmt.Printf("ipv64net: doRequest params: %s\n", params.Encode())

	var req *http.Request
	var err error
	if method == http.MethodGet {
		urlStr := apiURL + "?" + params.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			return nil, 0, err
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// set Authorization header as Bearer token
	req.Header.Set("Authorization", "Bearer "+p.APIToken)

	resp, err := p.getHttpClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bs := bytesTrimBOM(body)
	// log short status + message (message is returned as bytes)
	fmt.Printf("ipv64net: %s %s -> %d %q\n", method, apiURL, resp.StatusCode, string(bs))

	return bs, resp.StatusCode, nil
}

func isSuccessStatus(code int) bool {
	return code >= 200 && code <= 299
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

// add a small struct matching the get_domains JSON shape (only fields we need)
type getDomainsResp struct {
	Subdomains map[string]struct {
		Updates     int  `json:"updates,omitempty"`
		Deactivated bool `json:"deactivated,omitempty"`
		Records     []struct {
			Type        string `json:"type,omitempty"`
			TTL         int    `json:"ttl,omitempty"`
			Praefix     string `json:"praefix,omitempty"`
			Deactivated bool   `json:"deactivated,omitempty"`
		} `json:"records,omitempty"`
	} `json:"subdomains"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	fmt.Println("ipv64net: ListZones called")
	// request domain information using documented get_domains
	params := url.Values{}
	params.Set("get_domains", "")

	body, _, err := p.doRequest(ctx, params, http.MethodGet)
	if err != nil {
		return nil, err
	}

	// Directly unmarshal into the concrete structure we expect.
	var resp getDomainsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		// Return parse error: API doesn't provide expected JSON
		return nil, fmt.Errorf("ipv64net: unexpected get_domains response: %w", err)
	}

	var out []libdns.Zone
	for subdomain, info := range resp.Subdomains {
		if info.Deactivated {
			continue
		}

		zone := libdns.Zone{
			Name: subdomain,
		}

		out = append(out, zone)
	}

	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	fmt.Println("ipv64net: AppendRecords called")
	var added []libdns.Record
	for _, r := range records {
		rr := r.RR()

		subdomain, praefix, err := splitACMEName(zone, rr.Name)
		if err != nil {
			return nil, err
		}

		params := url.Values{}
		params.Set("add_record", subdomain) // Domainname
		params.Set("praefix", praefix)      // Domain prefix / host
		params.Set("type", rr.Type)
		params.Set("content", rr.Data)
		// TTL is optional and may not be supported; include if set
		if rr.TTL > 0 {
			params.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
		}
		body, status, err := p.doRequest(ctx, params, http.MethodPost)
		if err != nil {
			return nil, err
		}
		if !isSuccessStatus(status) {
			// Print params for debugging
			fmt.Printf("ipv64net: add_record params: %s\n", params.Encode())
			return nil, fmt.Errorf("ipv64net: add_record failed: %d %s", status, string(body))
		}
		added = append(added, r)
	}
	return added, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	fmt.Println("ipv64net: DeleteRecords called")

	var deleted []libdns.Record
	for _, r := range records {
		rr := r.RR()

		subdomain, praefix, err := splitACMEName(zone, rr.Name)
		if err != nil {
			return nil, err
		}

		params := url.Values{}
		params.Set("del_record", subdomain)
		params.Set("praefix", praefix)
		params.Set("type", rr.Type)
		// Some APIs expect content to choose which record to delete if multiple exist
		if rr.Data != "" {
			params.Set("content", rr.Data)
		}
		body, status, err := p.doRequest(ctx, params, http.MethodPost)
		if err != nil {
			return nil, err
		}
		if !isSuccessStatus(status) {
			return nil, fmt.Errorf("ipv64net: del_record failed: %d %s", status, string(body))
		}
		deleted = append(deleted, r)
	}
	return deleted, nil
}

func splitACMEName(zone string, rrName string) (subdomain string, praefix string, err error) {
	zone = strings.TrimSuffix(zone, ".")
	rrName = strings.TrimSuffix(rrName, ".")

	parts := strings.Split(rrName, ".")

	if len(parts) < 1 {
		return "", "", fmt.Errorf("invalid rr.Name: %q", rrName)
	} else if len(parts) == 1 {
		return zone, rrName, nil
	}

	// last label is the subdomain
	sub := parts[len(parts)-1]

	// everything before that is the prefix
	praefix = strings.Join(parts[:len(parts)-1], ".")

	subdomain = sub + "." + zone
	return subdomain, praefix, nil
}

// Module Interface für Caddy
func init() {
	// Caddy erkennt den Provider
	caddy.RegisterModule(Provider{})
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64net",
		New: func() caddy.Module { return &Provider{} },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler so the provider can be
// configured from a Caddyfile block like:
//
//	tls {
//	  dns ipv64net {
//	    api_token <token>
//	    http_timeout_seconds 10
//	  }
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_token", "token":
				if !d.NextArg() {
					return d.Err("missing api_token")
				}
				p.APIToken = d.Val()
			case "http_timeout_seconds", "http_timeout":
				if !d.NextArg() {
					return d.Err("missing http_timeout_seconds")
				}
				v := d.Val()
				i, err := strconv.Atoi(v)
				if err != nil {
					return d.Errf("invalid http_timeout_seconds: %v", err)
				}
				p.HTTPTimeoutSeconds = i
			default:
				return d.Errf("unknown option %q in ipv64net block", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ libdns.ZoneLister     = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ caddy.Module          = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
)
