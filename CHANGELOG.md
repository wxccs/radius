# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes.

## [v2.2.0] - 2026-07-13

### Added

- `vendors/microsoft` - added NAP/NPAS VSAs per the Microsoft Open
  Specifications [MS-RNAP] (v19.0) and [MS-RNAS] (v7.0): 28 sub-types
  across Vendor-Type 0x22-0x3F and 0x41, with typed constructors for
  the string family (MS-RAS-Client-Name/Version, MS-Service-Class,
  MS-Machine-Name, MS-Quarantine-User-Class, HCAP-*, MS-Azure-Policy-ID),
  32-bit integer/enum family (MS-Quarantine-Session-Timeout/State/Grace-
  Time, MS-Identity-Type, MS-Network-Access-Server-Type, MS-AFW-Zone,
  MS-AFW-Protection-Level, Not-Quarantine-Capable, MS-Extended-Quarantine-
  State, MS-RDG-Device-Redirection), IP-address family (MS-User-IPv4/
  IPv6-Address), GUID (MS-RAS-Correlation-ID), and complex binary family
  (MS-Quarantine-IPFilter, MS-IPv6-Filter, MS-User-Security-Identity,
  MS-IPv4/IPv6-Remediation-Servers, MS-Quarantine-SoH), plus the MS-RNAS
  §2.2.2.1 SSTP vendor-specific value for the standard Tunnel-Type
  (Type 64) attribute (0x00013701). Enumerated values and the
  RDG-Device-Redirection bitmask are exposed as constants.

## [v2.1.0] — 2026-07-13

### Added

- `vendors/huawei` - new sub-package for Huawei RADIUS extension
  attributes (Vendor-Id 2011), implementing all 47 Huawei-defined VSA
  sub-types from the Huawei Sx700 V600R025C00 documentation: the
  rate/burst family (1-6), accounting/management attributes (18, 26,
  28-29, 31, 33, 59-62, 82, 138, 141-142, 146, 153, 156, 158, 160),
  IPv6 accounting (163-164, 166-171), ACL/redirect/policy (173, 178,
  180, 188, 202-203, 238-240, 244, 251, 254-255), and
  HW-Framed-IPv6-Address (253, 16-byte IPv6). Includes typed
  constructors for integer, string, and IPv6 value types.
- `vendors/juniper` - added constructors for Juniper-Interactive-Command
  (8), Juniper-Configuration-Change (9), Juniper-User-Permissions (10),
  Juniper-Authentication-Type (11), Juniper-Session-Port (12),
  Juniper-Allow-Configuration-Regexps (13), and
  Juniper-Deny-Configuration-Regexps (14), per the Junos OS user-access
  RADIUS authentication documentation.
- `vendors/cisco` - added constructors for Cisco-NAS-Port (sub-type 2),
  the store-and-forward Fax/Email family (sub-types 3-21), and the
  H.323/VoIP call-accounting family (sub-types 23-31, 33), per the
  Cisco IOS 12.2 RADIUS VSA appendix.
- `vendors/h3c` - added 20 H3C VSA sub-types per the H3C RADIUS
  extension attributes table: Remanent_Volume (15), Command (20),
  Control_Identifier (24), Result_Code (25), Connect_ID (26),
  Exec_Privilege (29), NAS_Startup_Timestamp (59), Ip_Host_Addr (60),
  User_Notify (61), User_HeartBeat (62), Security_Level (141), the
  realtime-accounting interval family (201-206), Backup-NAS-IP (207,
  IPv4), and Product_ID (255).

### Changed (breaking)

- **`vendors/h3c` Vendor-Id corrected from 2011 to 25506.** H3C
  Technologies Co., Limited registers its own SMI code 25506; code
  2011 belongs to Huawei (see the new `vendors/huawei` sub-package).
  `h3c.Decode` now matches Vendor-Id 25506, so VSAs encoded with the
  old 2011 value no longer decode through the `h3c` package.
- **`vendors/h3c` sub-type numbers corrected to match the H3C
  documentation.** The previous values were wrong: sub-types 3-6 were
  misnumbered (3 is Input-Basic-Rate, not Output-Peak-Rate; 5/6 are
  Output-Average/Basic-Rate, not User-Group/Access-Level). `User-Group`
  moved from sub-type 5 to 140, and the non-existent `Access-Level`
  constant (6) was removed. `NewUserGroup` now emits sub-type 140. The
  rate family is now six sub-types (1-6) rather than four.
- **`vendors/juniper` renamed `VendorTypeLocalUserGroup` to
  `VendorTypeLocalUserName` and `NewLocalUserGroup` to
  `NewLocalUserName`.** The official Juniper attribute is
  Juniper-Local-User-Name (a user template name, not a group).

### Fixed

- `vendors/h3c` sub-type numbers now match the H3C "RADIUS扩展属性"
  documentation table. The previous values were based on the Huawei/old
  3Com rate family and did not match H3C's actual attribute numbering.
- `vendors/juniper` sub-type 1 naming corrected: the attribute is
  Juniper-Local-User-Name (user template), not Local-User-Group, per
  the Junos OS documentation.

### Documentation

- README vendor table updated: H3C SMI code 2011 -> 25506; added the
  Huawei (2011) row.
- `docs/design/vendors.md` updated: corrected H3C SMI code, added the
  `huawei` row, removed references to non-existent
  `juniper.NewRouterRole` and `cisco.NewURLRedirect`, and rewrote the
  Vendor-Id 2011 note to reflect that Huawei now owns it exclusively.

## [v2.0.0] — 2026-06-29

### Changed (breaking)

- `packet.VerifyMessageAuthenticator` now takes the Request Authenticator
  of the corresponding request as a second argument:
  `VerifyMessageAuthenticator(rawPacket, requestAuth, secret)`. Reply
  packets (Access-Accept/Reject/Challenge, Accounting-Response, CoA/DM
  ACK/NAK) substitute `requestAuth` for the Response Authenticator in
  the HMAC input. Callers that passed only `(raw, secret)` must update.
- `packet.Packet.Marshal` now signs the Message-Authenticator over the
  Request Authenticator for **all** packet types, per RFC 3579 §3.2.
  Previously only Access-Request did so; reply packets signed over a
  zero Authenticator field, and Accounting-Request/CoA-Request/
  Disconnect-Request signed over a zero Authenticator field while
  computing the Request Authenticator afterwards over the filled MA
  Value. The wire format of the latter three request types has changed:
  the Request Authenticator is now computed over attributes with the MA
  Value zeroed, and the MA is computed over the resulting Request
  Authenticator.
- `packet.Packet.Unmarshal` now verifies the Request Authenticator of
  Accounting-Request/CoA-Request/Disconnect-Request with the MA Value
  zeroed in a copy of the attributes, mirroring Marshal. New unexported
  helper `zeroMessageAuthenticatorValueInPlace` scans for the Type 80 /
  Length 18 attribute and zeroes its 16-byte Value field.

### Fixed

- **RADIUS/EAP interoperability with compliant servers (RFC 3579 §3.2).**
  The previous Message-Authenticator signing/verification for reply
  packets zeroed the Authenticator field, so the library could not
  verify replies from servers that follow RFC 3579 §3.2 (e.g. FreeRADIUS
  3.2 default behavior). Symptoms: `message-authenticator verification
  failed`, retransmission exhaustion, and authentication timeout. The
  round-trip tests passed because Marshal and Verify shared the same
  incorrect input ("self-signed/self-verified" blind spot).
- **Message-Authenticator for Accounting-Request/CoA-Request/
  Disconnect-Request** is now signed and verified over the Request
  Authenticator, matching RFC 5176 §3.4. The historic zero-field signing
  was interoperable only with this library.

### Migration

- Update all `packet.VerifyMessageAuthenticator(raw, secret)` call sites
  to `packet.VerifyMessageAuthenticator(raw, requestAuth, secret)`. For
  reply verification the Request Authenticator is the same value already
  passed to `packet.VerifyResponseAuthenticator` and `protocol.VerifyResponse`.
  For request-packet verification the `requestAuth` argument is ignored;
  passing a zero value is fine.
- Upgrade both ends of a RADIUS conversation together. The wire format
  of Accounting-Request, CoA-Request, and Disconnect-Request has changed
  (Request Authenticator now computed over MA-Value-zeroed attributes;
  MA now computed over the Request Authenticator). Older library
  versions emit packets the new version rejects and vice versa. The new
  behavior matches FreeRADIUS and other RFC-compliant peers.

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
