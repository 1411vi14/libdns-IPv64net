package ipv64net

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestFqdnToRelative(t *testing.T) {
	table := []struct {
		name string
		zone string
		want string
	}{
		{"", "example.com", ""},
		{"@", "example.com", ""},
		{"www.example.com.", "example.com", "www"},
		{"www", "example.com", "www"},
		{"sub.www.example.com.", "www.example.com", "sub"},
		{"example.com.", "example.com", ""},
	}
	for _, tc := range table {
		got := fqdnToRelative(tc.name, tc.zone)
		if got != tc.want {
			t.Fatalf("fqdnToRelative(%q,%q) = %q; want %q", tc.name, tc.zone, got, tc.want)
		}
	}
}

func TestListZones_parsesGetDomains(t *testing.T) {
	// sample response similar to documented shape
	resp := getDomainsResp{
		Subdomains: map[string]struct {
			Updates     int  `json:"updates,omitempty"`
			Deactivated bool `json:"deactivated,omitempty"`
			Records     []struct {
				Type        string `json:"type,omitempty"`
				TTL         int    `json:"ttl,omitempty"`
				Praefix     string `json:"praefix,omitempty"`
				Deactivated bool   `json:"deactivated,omitempty"`
			} `json:"records,omitempty"`
		}{"test.ipv64.net": {
			Updates: 1,
			Records: []struct {
				Type        string `json:"type,omitempty"`
				TTL         int    `json:"ttl,omitempty"`
				Praefix     string `json:"praefix,omitempty"`
				Deactivated bool   `json:"deactivated,omitempty"`
			}{
				{Type: "A", TTL: 300, Praefix: "www"},
			},
		}},
	}
	js, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ensure get_domains param present
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		// basic response
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(js)
	}))
	defer srv.Close()
	apiURL = srv.URL

	p := &Provider{
		APIToken:   "token",
		httpClient: srv.Client(),
	}

	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("GetRecords error: %v", err)
	}
	if len(zones) == 0 {
		t.Fatalf("expected records, got none")
	}
	// expect an RR with Name "www", Type "A", TTL 300s
	found := false
	for _, zone := range zones {
		if zone.Name == "test.ipv64.net" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected record with Name=www Type=A TTL=300s; got %+v", zones)
	}
}

func TestAppendAndDelete_callsAPI(t *testing.T) {
	var lastForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read body for POST
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm error: %v", err)
			}
			lastForm = r.PostForm
			_, _ = io.WriteString(w, "ok")
			return
		}
		// otherwise empty OK
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	apiURL = srv.URL

	p := &Provider{
		APIToken:   "token",
		httpClient: srv.Client(),
	}

	// AppendRecords should POST add_record
	rec := libdns.RR{Type: "A", Name: "host", Data: "1.2.3.4", TTL: 60 * time.Second}
	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("AppendRecords error: %v", err)
	}
	if lastForm.Get("add_record") != "example.com" || lastForm.Get("praefix") != "host" ||
		lastForm.Get("type") != "A" || lastForm.Get("content") != "1.2.3.4" {
		t.Fatalf("unexpected add_record form: %v", lastForm)
	}

	// DeleteRecords should POST del_record
	lastForm = nil
	_, err = p.DeleteRecords(context.Background(), "example.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords error: %v", err)
	}
	if lastForm.Get("del_record") != "example.com" || lastForm.Get("praefix") != "host" ||
		lastForm.Get("type") != "A" {
		t.Fatalf("unexpected del_record form: %v", lastForm)
	}
}

func TestSplitACMEName(t *testing.T) {
	table := []struct {
		zone       string
		rrName     string
		wantSubdom string
		wantPraef  string
		wantErr    bool
	}{
		{"example.com.", "_acme-challenge", "example.com", "_acme-challenge", false},
		{"example.com.", "_acme-challenge.test", "test.example.com", "_acme-challenge", false},
		{"example.com.", "_acme-challenge.test.subdomain", "subdomain.example.com", "_acme-challenge.test", false},
		{"example.com.", "_acme-challenge.test.subsubdomain.subdomain", "subdomain.example.com", "_acme-challenge.test.subsubdomain", false},
		{"example.com.", "", "example.com", "", true},
	}

	for _, tc := range table {
		gotSubdom, gotPraef, err := splitACMEName(tc.zone, tc.rrName)
		if err != nil {
			t.Fatalf("splitACMEName(%q,%q) error: %v", tc.zone, tc.rrName, err)
		}
		if gotSubdom != tc.wantSubdom || gotPraef != tc.wantPraef {
			t.Fatalf("splitACMEName(%q,%q) = (%q,%q); want (%q,%q)", tc.zone, tc.rrName, gotSubdom, gotPraef, tc.wantSubdom, tc.wantPraef)
		}
	}
}
