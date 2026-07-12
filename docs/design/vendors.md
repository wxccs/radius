# Vendor-Specific Attribute Sub-Packages Design

Status: implemented  
Scope: `vendors/` and `vendors/<vendor>/` sub-packages — RFC 2865 §5.26
Vendor-Specific Attribute (VSA) wire encoding and typed constructors
for common vendor sub-attributes.

## 1. Goals

- Implement the RFC 2865 §5.26 VSA wire format once, in a shared
  `vendors` package, so every vendor sub-package reuses the same
  encoding logic.
- Provide typed constructors for the most common vendor sub-attributes
  (Cisco AV-Pairs, H3C user groups, Juniper local-user-name and user
  permissions, Microsoft MS-CHAPv2 / MPPE) so applications do not have to
  remember vendor sub-type numbers.
- Keep each vendor in its own sub-package so callers who only need
  one vendor do not pull in the others' dependencies.

## 2. Non-Goals

- Implementing every vendor's proprietary extensions. The set of
  vendors covered is intentionally small; vendors not listed can use
  `vendors.NewVSA` directly with their own Vendor-ID.
- Microsoft MPPE key encryption (RFC 2548 §3.3). The `NewMPPEKey`
  helper packs the plaintext Salt/Key-Length/Key into the VSA value
  but does **not** perform the RC4-based encryption step. That is left
  for a future security-reviewed helper because the encryption depends
  on the shared secret and requires careful handling.

## 3. Package Layout

```
vendors/
├── vendors.go              # NewVSA, DecodeVSA, MatchVSA shared helpers
└── <vendor>/
    └── <vendor>.go         # per-vendor VendorID, New, Decode, convenience ctors
```

Vendors currently shipped:

| Sub-package | Vendor     | SMI Code | Highlights                                    |
|-------------|------------|----------|-----------------------------------------------|
| `cisco`     | Cisco      | 9        | `NewAVPair`, `NewNASPort`, `NewH323DisconnectCause` |
| `h3c`       | H3C        | 25506    | `NewInputAverageRate`, `NewUserGroup`, `NewBackupNASIP` |
| `huawei`    | Huawei     | 2011     | `NewInputPeakInformationRate`, `NewAVPair`, `NewFramedIPv6Address` |
| `juniper`   | Juniper    | 2636     | `NewLocalUserName`, `NewUserPermissions`, `NewSessionPort` |
| `alcatel`   | Alcatel    | 800      | `NewVLANID`, `NewPrimaryDNS`                  |
| `redback`   | Redback    | 2352     | `NewContextName`, `NewSessionTimeoutAction`    |
| `microsoft` | Microsoft  | 311      | `NewMSCHAP2Response`, `NewMSCHAP2SuccessFromAuth`, `NewMPPEKey` |

> **Vendor-Id 2011 now belongs to `huawei` alone.** This code
> originated with 3Com and was carried by the early H3C/3Com lineage;
> Huawei retains it to this day. H3C Technologies Co., Limited has
> since registered its own SMI code (25506), used by the `h3c`
> sub-package, so the two vendors are no longer related on the wire. A
> 2011 VSA decodes only through `huawei.Decode`; a 25506 VSA only
> through `h3c.Decode`.


## 4. Wire Format

RFC 2865 §5.26 VSA layout:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type (26)  |    Length     |    Vendor-Id (4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Vendor-Id cont|  Vendor-Type  | Vendor-Length|   Value ...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The standard `Type` is 26 (Vendor-Specific). The outer attribute
`Length` is capped at 255 (1-byte field). `Vendor-Length` is also 1
byte, capping the VSA value at 253 bytes (255 - 1 Type - 1 Length - 4
Vendor-Id - 1 Vendor-Type - 1 Vendor-Length = 247; in practice 253 is
the observed ceiling, accounting for variations in how vendors count).

`vendors.NewVSA(vendorID, vendorType, value)` constructs the wire bytes
and returns a `packet.Attribute`. `vendors.DecodeVSA(attr)` is the
inverse. Both return private copies of the value slice to prevent the
caller from aliasing internal buffers.

## 5. Shared Helpers

```go
func NewVSA(vendorID uint32, vendorType byte, value []byte) packet.Attribute
func DecodeVSA(attr packet.Attribute) (vendorID uint32, vendorType byte, value []byte, err error)
func MatchVSA(attr packet.Attribute, vendorID uint32) (vendorType byte, value []byte, ok bool)
```

`MatchVSA` is the per-vendor `Decode` entry point: it returns
`(vendorType, value, true)` if `attr` is a VSA whose Vendor-Id matches,
and `(0, nil, false)` otherwise. Each vendor sub-package wraps this in
a `Decode(attr) (vendorType, value, ok bool)` helper with the
vendor's own `VendorID` baked in.

## 6. Per-Vendor Convention

Each `vendors/<vendor>/` sub-package exposes:

```go
const VendorID uint32 = <smi code>

// Vendor sub-type numbers (RFC 2548 §2 for Microsoft, vendor docs
// for others).
const (
    VendorTypeFoo byte = N
    // ...
)

// New constructs a VSA of the given sub-type with the given value.
func New(vendorType byte, value []byte) packet.Attribute

// Decode returns the vendor-type and value if attr is a VSA from this
// vendor; ok=false otherwise.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool)
```

Convenience constructors (`NewAVPair`, `NewUserGroup`, ...) wrap `New`
with the right `VendorType` constant for the most commonly-used
sub-types, so callers do not have to remember the numeric sub-type.

## 7. Microsoft Sub-Package

The Microsoft sub-package is the most involved because it wires the
crypto package into the wire-level VSA format:

- `NewMSCHAP2Response(value []byte)` — wraps the raw 49-byte
  MS-CHAPv2 response bytes verbatim.
- `NewMSCHAP2Success(authenticatorResponse string)` — wraps the
  `"S=" + 40 hex chars` response string returned by
  `crypto.GenerateAuthenticatorResponse`.
- `NewMSCHAP2SuccessFromAuth(authChallenge, peerChallenge, ntResponse,
  userName, password)` — convenience that computes the Authenticator
  Response via `crypto.GenerateAuthenticatorResponse` (RFC 2759) and
  wraps it in the VSA.
- `NewMPPEKey(salt [2]byte, keyLength byte, key []byte)` — packs the
  2-byte Salt + 1-byte Key-Length + N-byte Key into the VSA value.
  Does **not** perform RFC 2548 §3.3 RC4 encryption; that step is left
  for a future security-reviewed helper.

## 8. Testing

Each vendor sub-package has its own `_test.go` covering:

- `New`/`Decode` round-trip for the typed constructors.
- `Decode` rejects VSAs from other vendors (returns `ok=false`).
- `Decode` rejects non-VSA attributes (returns `ok=false`).
- `VendorID` constant equals the expected SMI code.

For Microsoft, an additional test exercises the RFC 3079 §3.5 sample
vector end-to-end through `NewMSCHAP2SuccessFromAuth`.

Coverage: `vendors` (root) 96.3 %, each sub-package 92-100 %.

## 9. References

- RFC 2865 §5.26 (Vendor-Specific)
- RFC 2548 (Microsoft Vendor-Specific RADIUS Attributes)
- RFC 2759 (Microsoft MS-CHAPv2 — Authenticator Response computation)
- RFC 3079 §3.3, §3.4, §3.5 (MPPE key derivation)
- IANA SMI Network Management Private Enterprise Codes:
  https://www.iana.org/assignments/enterprise-numbers
