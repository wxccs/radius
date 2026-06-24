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

This library is under active development. Implementation is phased; see the
project board for progress. The first usable release is targeted after the
core packet, crypto, transport, and protocol layers are complete and tested.

## Installation

```sh
go get github.com/wxccs/radius
```

## Quick Start

> TODO: code examples will be added as the public API stabilizes in later
> phases. For now, see the `cmd/radius-tool` CLI for end-to-end usage.

## Command-Line Tool

The `radius-tool` binary supports client mode (auth/acct/coa/dm) and a
lightweight test server mode. Build it with:

```sh
go build -o radius-tool ./cmd/radius-tool
```

Usage details will be documented once the CLI is implemented.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

Third-party dependencies are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
