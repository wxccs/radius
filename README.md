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
| 6614 | RADIUS over TLS |
| 6929 | RADIUS Protocol Extensions |
| 7360 | RADIUS over DTLS |
| 9445 | RADIUS Extensions for DHCP-Configured Services |

## Status

Stable v2.0.0. The core packet, crypto, transport (UDP/TCP/TLS/DTLS),
protocol, client, server, dictionary parser/generator, and vendor
sub-package layers are complete and tested against the RFCs listed above.
The public API follows semantic versioning. See [CHANGELOG.md](CHANGELOG.md)
for the full change history, including the v2.0.0 breaking fix to
Message-Authenticator (RFC 3579 §3.2) interoperability.

## Installation

```sh
go get github.com/wxccs/radius@v2.0.0
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

## Transports

The `transport/` package exposes four transports, all of which use the
existing 2-byte `Length` field at offset 2..3 of the RADIUS header for
framing (RFC 6613 §2.1):

| Transport | Listener / Dialer | RFC |
|-----------|-------------------|-----|
| UDP       | `ListenUDP`, `DialUDP`        | 2865, 3162 |
| TCP       | `ListenTCP`, `DialTCP`        | 6613 |
| TLS       | `ListenTLS`, `DialTLS`        | 6614 |
| DTLS      | `ListenDTLS`, `DialDTLS`      | 7360 |

```go
// TLS server
ln, err := transport.ListenTLS("tcp4", laddr, tlsConfig)
// TLS client
client, err := transport.DialTLS("tcp4", server, tlsConfig)

// DTLS server (pion options API)
ln, err := transport.ListenDTLS("udp4", laddr,
    piondtls.WithCertificates(cert), piondtls.WithFlightInterval(100*time.Millisecond))
// DTLS client
client, err := transport.DialDTLS("udp4", server,
    piondtls.WithInsecureSkipVerify(true))
```

## Vendor-Specific Attributes

The `vendors/` package provides typed constructors for common vendor
sub-attributes, each in its own sub-package keyed by SMI Private Enterprise
Code:

| Sub-package | Vendor | Code  |
|-------------|--------|-------|
| `vendors/cisco`     | Cisco     | 9    |
| `vendors/h3c`       | H3C       | 2011 |
| `vendors/juniper`   | Juniper   | 2636 |
| `vendors/alcatel`   | Alcatel   | 800  |
| `vendors/redback`   | Redback   | 2352 |
| `vendors/microsoft` | Microsoft | 311  |

```go
// Microsoft MS-CHAP2-Success VSA, computed from MS-CHAPv2 inputs.
attr := microsoft.NewMSCHAP2SuccessFromAuth(
    authChallenge, peerChallenge, ntResponse, "alice", "password")
```

Shared helpers `vendors.NewVSA`, `vendors.DecodeVSA`, and
`vendors.MatchVSA` implement the RFC 2865 §5.26 wire format for vendors
not covered by a dedicated sub-package.

## Dictionary Support

The `dictionary/parser/` package parses FreeRADIUS dictionary files
(`$INCLUDE`, `ATTRIBUTE`, `VALUE`, `VENDOR`, `BEGIN-VENDOR`/`END-VENDOR`,
`ALIAS`, `BEGIN-TLV`, `BEGIN-ENUM`) and returns a `*parser.Dict` that
can be registered at runtime via `(*Dictionary).RegisterFromDict`.

The `dictionary/gen/` package and the `cmd/dict-gen` CLI emit typed Go
source (constants + accessor pairs) from a parsed dictionary, so you can
reference attributes by name at compile time:

```sh
go install ./cmd/dict-gen
dict-gen --in dictionary.freeradius --out attrs.go --pkg attrs
```

```go
// In your application:
attrs.AddUserName(p, "alice")
if v, ok := attrs.GetNASPort(p); ok { /* ... */ }
```

## Command-Line Tool

The `radius-tool` binary supports client mode (`access`, `account`, `coa`,
`disconnect`) and a lightweight test server mode. Build it with:

```sh
go build -o radius-tool ./cmd/radius-tool
./radius-tool --help
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

Third-party dependencies are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
