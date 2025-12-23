# ipv64net libdns provider

This module implements the libdns interfaces for IPv64.net and allows listing,
adding, updating and deleting DNS records via IPv64.net's API.

Build Caddy with IPv64net Plugin:
```bash
xcaddy build --with github.com/1411vi14/libdns-IPv64net -output .\caddy-ipv64net.exe
```

Example usage with Caddy (Caddyfile):
```caddy
https://test.example.com {
	tls {
		dns ipv64net {
			api_token {env.IPV64_API_TOKEN}
			http_timeout_seconds 15
		}
	}

	respond "Hello, secure world!"
}
```

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
	_, _ = p.DeleteRecords(ctx, zone, records)
}
```

Notes:
- Set your API token in the `APIToken` field of the Provider.
- Optionally set `HTTPTimeoutSeconds`; default is 15s.
- This package implements the libdns interfaces: ZoneLister, RecordAppender, RecordDeleter.

Usefull Commands for Windows:
- Find Caddy Binary with PowerShell: `(Get-Command caddy).Path`
- WinGet Caddy Binary Path: `%LOCALAPPDATA%\Microsoft\WinGet\Packages\CaddyServer.Caddy_Microsoft.Winget.Source_8wekyb3d8bbwe\caddy.exe`
- `Start-Service caddy -ErrorAction SilentlyContinue`
- `Stop-Service caddy -ErrorAction SilentlyContinue`
- `.\caddy-ipv64net.exe list-modules | Select-String ipv64net`