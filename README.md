# ipv64net libdns provider

This module implements the libdns interfaces for IPv64.net and allows listing,
adding, updating and deleting DNS records via IPv64.net's dyndns_updater_api.php.

Installation:
1. Get the module:
   go get github.com/1411vi14/libdns-IPv64net

Example usage:
```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
	"github.com/1411vi14/libdns-IPv64net"
)

func main() {
	p := &ipv64net.Provider{APIToken: "your-token"}
	ctx := context.Background()
	zone := "example.com"

	// List records
	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		fmt.Println("list error:", err)
	}
	_ = recs

	// Add a record (use libdns.RR or a typed record when available)
	records := []libdns.Record{
		libdns.RR{
			Type: "A",
			Name: "test",
			Data: "1.2.3.4",
			TTL:  time.Minute * 5,
		},
	}
	_, _ = p.AppendRecords(ctx, zone, records)
}
```

Notes:
- Set your API token in the `APIToken` field of the Provider.
- Optionally set `HTTPTimeoutSeconds`; default is 15s.
- This package implements the libdns interfaces: RecordGetter, RecordAppender, RecordSetter, RecordDeleter.
