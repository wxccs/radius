# radius

[![CI](https://github.com/wxccs/radius/actions/workflows/ci.yml/badge.svg)](https://github.com/wxccs/radius/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-N/A-lightgrey.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/wxccs/radius.svg)](https://pkg.go.dev/github.com/wxccs/radius)

A commercial-grade RADIUS protocol library implemented in Go, with full support
for the core RADIUS RFCs plus a command-line tool supporting both client and
server modes.

## Supported RFCs

| RFC | Title |
|-----|-------|
| 2865 | Remote Authentication Dial In User Service (RADIUS) |
| 2866 | RADIUS Accounting |
| 2867 | RADIUS Accounting Modifications for Tunnel Protocol Support |
| 2868 | RADIUS Attributes for Tunnel Protocol Support |
| 2869 | RADIUS Extensions |
| 3162 | RADIUS and IPv6 |
| 5176 | Dynamic Authorization Extensions to RADIUS |
| 6613 | RADIUS over TCP |
| 6929 | RADIUS Protocol Extensions |
| 9445 | RADIUS Extensions for DHCP-Configured Services |

## Status

Stable v1.0.0. The core packet, crypto, transport, protocol, client, and
server layers are complete and tested against the RFCs listed above. The
public API follows semantic versioning; breaking changes will be reserved
for v2.

## Installation

```sh
go get github.com/wxccs/radius@v1.0.0
```

## Quick Start

### Client (UDP)

```go
package main

import (
    "context"
    "log"
    "net"
    "time"

    "github.com/wxccs/radius/client"
    "github.com/wxccs/radius/packet"
    "github.com/wxccs/radius/protocol"
    "github.com/wxccs/radius/types"
)

func main() {
    c, err := client.NewUDPClient(
        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812},
        []byte("shared-secret"),
        client.Config{Timeout: 5 * time.Second},
    )
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close()

    resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
        Attributes: []packet.Attribute{
            packet.NewString(types.AttrUserName, "alice"),
            packet.NewString(types.AttrUserPassword, "hunter2"),
        },
        Method: protocol.AuthPAP,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("reply: %s", resp.Code)
}
```

### Server (UDP)

```go
package main

import (
    "context"
    "log"
    "net"

    "github.com/wxccs/radius/packet"
    "github.com/wxccs/radius/server"
    "github.com/wxccs/radius/types"
)

func main() {
    handler := server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
        // Replace with real credential lookup.
        return &packet.Packet{
            Code:          types.AccessAccept,
            Identifier:    req.Identifier,
            Authenticator: req.Authenticator,
        }, nil
    })
    srv, err := server.NewUDPServer("udp4",
        &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 1812},
        handler, server.StaticSecret([]byte("shared-secret")))
    if err != nil {
        log.Fatal(err)
    }
    if err := srv.Serve(context.Background()); err != nil {
        log.Fatal(err)
    }
}
```

### Accounting, CoA, Disconnect

The `protocol.Client` exposes `Account`, `SendCoA`, and `SendDisconnect`
methods mirroring `Authenticate`; the server-side `Handler` receives the
raw `*server.Request` and can branch on `req.Code`. See the
[package docs](https://pkg.go.dev/github.com/wxccs/radius) for the full API.

## Command-Line Tool

The `radius-tool` binary supports client mode (auth/acct/coa/dm) and a
lightweight test server mode. Build it with:

```sh
go build -o radius-tool ./cmd/radius-tool
./radius-tool --help
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

Third-party dependencies are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
