# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes.

## [v1.1.0] — 2026-06-25

### Added
- `dictionary/parser` — FreeRADIUS dictionary file parser supporting
  `$INCLUDE`, `ATTRIBUTE`, `VALUE`, `VENDOR`, `BEGIN-VENDOR`/`END-VENDOR`,
  `ALIAS`, `BEGIN-TLV`, and `BEGIN-ENUM` directives, with cycle detection
  on includes and tolerant handling of unknown value types (normalized to
  `raw`).
- `dictionary.RegisterFromDict(*parser.Dict)` — bridges parsed dictionary
  data into the runtime `*Dictionary` registry, mapping FreeRADIUS
  type strings to `ValueType` enum values.
- `dictionary.TypeRaw` — a new `ValueType` for attributes whose wire
  codec is not implemented; treated as opaque bytes by `packet.NewByName`
  and `Attribute.Decode`.
- `dictionary/gen` — code generator that emits typed Go source (constants
  + accessor pairs) from a parsed dictionary. Supports string, integer,
  ipaddr, ipv6addr, octets, and raw value types; emits vendor
  sub-attributes as constants only.
- `cmd/dict-gen` — cobra CLI front-end for the generator with `--in`
  (repeatable), `--out`, `--pkg`, and `--header` flags.
- `vendors` — shared VSA helpers (`NewVSA`, `DecodeVSA`, `MatchVSA`)
  implementing RFC 2865 §5.26 wire format with Vendor-Length capped at
  255 and value at 253.
- `vendors/cisco`, `vendors/h3c`, `vendors/juniper`, `vendors/alcatel`,
  `vendors/redback`, `vendors/microsoft` — vendor-specific sub-packages
  with `VendorID` constants, `New`/`Decode` pairs, and convenience
  constructors (e.g. `cisco.NewAVPair`, `juniper.NewLocalUserGroup`,
  `microsoft.NewMSCHAP2SuccessFromAuth`).
- `transport.ListenTLS`/`DialTLS` — RADIUS/TLS transport (RFC 6614)
  with `TLSListener`/`TLSConn`/`TLSClient` types. Forces the TLS
  handshake inside `Accept` so handshake failures surface there.
- `transport.ListenDTLS`/`DialDTLS` — RADIUS/DTLS transport (RFC 7360)
  built on `github.com/pion/dtls/v3`. Uses pion's recommended
  options-based API (`piondtls.ServerOption` / `piondtls.ClientOption`).
  Forces the DTLS handshake inside `DialDTLS` via `HandshakeContext`.
- `transport.readFramedStream` and `transport.readFramedMessage` —
  shared Length-framed read helpers split by transport semantics:
  byte-stream (TCP/TLS, using `io.ReadFull`) vs message-oriented (DTLS,
  using a single large `Read` because pion returns `errBufferTooSmall`
  on partial reads).
- Shared `transport.writeFramedPacket` helper for all connection-oriented
  transports.
- `CHANGELOG.md` and design docs for the dictionary, vendors, and
  transport (TLS/DTLS) layers.

### Changed
- `transport.isClosed` now also recognizes `piondtls.ErrConnClosed`
  (DTLS connection closed) and the `"udp: listener closed"` string
  returned by pion/dtls v3's internal UDP listener after `Close`. The
  sentinel is in an internal package and cannot be imported, so the
  string match is the stable contract pion exposes.
- `dictionary.go` — `ValueType.String()` returns `"raw"` for `TypeRaw`.
- README expanded with sections for transports, vendor sub-packages,
  and dictionary support; supported-RFCs table now lists RFC 6614
  (TLS) and RFC 7360 (DTLS).

### Security
- Upgraded `github.com/pion/dtls` from v2.2.12 to v3.1.4 to fix
  [GO-2026-4479](https://pkg.go.dev/vuln/GO-2026-4479) / CVE-2026-26014:
  "Usage of random nonce generation with AES GCM ciphers risks leaking
  the authentication key." The fix is only available in pion/dtls v3
  (v3.0.11+ or v3.1.1+); v2 is permanently affected. The vulnerability
  only affects the new DTLS transport introduced in this release; v1.0.0
  did not ship DTLS and is not affected.

### Fixed
- `cmd/dict-gen/main.go` and `dictionary/parser/parser.go` —
  `defer f.Close()` now wraps the error with `defer func() { _ = f.Close() }()`
  to satisfy `errcheck`.
- `crypto/mschapv2.go` — replaced `strings.IndexByte` with `strings.Cut`
  for the `stripDomain` helper (simpler, avoids `stringscut` lint).

## [v1.0.0] — 2026-05-15

### Added
- Core RADIUS packet codec (`packet/`) — RFC 2865 §5 attribute encoders
  for string, integer, ipaddr, ipv6addr, octets, ifid, time, and
  Vendor-Specific.
- `crypto/` — PAP, CHAP, MS-CHAPv1, MS-CHAPv2, MPPE key derivation
  (RFC 2759, RFC 3079 §3.4, RFC 2868 §5.2), and Message-Authenticator
  HMAC-MD5.
- `transport/` — UDP (RFC 2865, RFC 3162) and TCP (RFC 6613) transports
  with `context.Context` deadline propagation.
- `protocol/` — request state machines for Access, Accounting, and
  Dynamic Authorization (CoA/Disconnect), with Identifier allocation,
  retransmission, and authenticator verification.
- `client/` — high-level RADIUS client with retry, failover, and
  Status-Server watchdog.
- `server/` — pluggable RADIUS server with shared-secret lookup,
  per-source-IP rate limiting, and graceful `Shutdown`.
- `cmd/radius-tool` — CLI supporting `access`, `account`, `coa`,
  `disconnect`, and `server` modes.
- CI workflow with `go vet`, `golangci-lint`, race-enabled coverage
  (threshold 70%), and `go-licenses` license compliance check.
