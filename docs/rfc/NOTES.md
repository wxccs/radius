# RFC Study Notes

Internal reference distilled from the RFC documents in this directory. These
notes capture only the normative requirements needed for implementation; they
are not a substitute for the RFC text. Section numbers refer to the source RFC.

---

## RFC 2865 — RADIUS (Base)

### Packet layout (Section 3)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Authenticator                         |  (16 octets)
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
```

- Code: 1 octet
- Identifier: 1 octet
- Length: 2 octets (big-endian). Min 20, **max 4096**.
- Authenticator: 16 octets, most-significant octet first
- Attributes: sequence of TLVs (Type 1B, Length 1B, Value up to 253B; Length includes Type+Length+Value so min length 2, max 255)

### Codes

| Decimal | Name | Direction |
|---------|------|-----------|
| 1 | Access-Request | client → server |
| 2 | Access-Accept | server → client |
| 3 | Access-Reject | server → client |
| 4 | Accounting-Request | client → server (RFC 2866) |
| 5 | Accounting-Response | server → client (RFC 2866) |
| 11 | Access-Challenge | server → client |
| 12 | Status-Server (experimental) | — |
| 13 | Status-Client (experimental) | — |
| 255 | Reserved | — |

CoA/DM codes (40–45) are defined in RFC 5176, not here.

### Authenticators (Section 3)

- **Request Authenticator (Access-Request)**: 16-octet random, unpredictable & unique per secret lifetime. Used as MD5 salt for User-Password encryption. MUST change whenever Identifier changes.
- **Response Authenticator (Access-Accept/Reject/Challenge)**:
  `MD5(Code + ID + Length + RequestAuth + Attributes + Secret)`
- **Accounting-Request Authenticator (RFC 2866)**: different formula — see RFC 2866 notes below.

Shared secret: MUST NOT be empty, SHOULD be ≥ 16 octets. Server selects secret by source IP address of UDP packet.

### Packet type rules (Section 4)

**Access-Request (1)**:
- SHOULD contain User-Name
- MUST contain NAS-IP-Address or NAS-Identifier (or both)
- MUST contain User-Password **or** CHAP-Password **or** State
- MUST NOT contain both User-Password and CHAP-Password
- SHOULD contain NAS-Port / NAS-Port-Type unless portless
- Identifier MUST change when Attributes change or on valid reply; unchanged on retransmission
- Request Authenticator MUST change with new Identifier

**Access-Accept (2) / Reject (3)**:
- Identifier = copy of Access-Request
- Response Authenticator computed as above

**Access-Challenge (11)**:
- MAY contain: Reply-Message, State (0 or 1), Vendor-Specific, Idle-Timeout, Session-Timeout, Proxy-State. **No other attributes permitted.**
- Client sends new Access-Request with new ID + new Request Auth + user response in User-Password + State from challenge
- If NAS does not support challenge/response, treat as Access-Reject

### User-Password encryption (Section 5.2)

Type = 2, Length 18–130, String 16–128 octets.

Algorithm (S = secret, RA = Request Authenticator, p_i = 16-octet password chunks null-padded to 16-byte boundary, last chunk padded with NULs):

```
b1 = MD5(S + RA)         c(1) = p1 XOR b1
b2 = MD5(S + c(1))       c(2) = p2 XOR b2
...
bi = MD5(S + c(i-1))     c(i) = pi XOR bi
String = c(1) || c(2) || ... || c(i)
```

Password max 128 octets → max 8 chunks → max String length 128 → max attribute length 130. Decryption reverses by recomputing b_i from S + c(i-1).

### CHAP-Password (Section 5.3)

Type = 3, Length = 19. Layout: CHAP Ident (1B) + CHAP Response (16B). CHAP challenge comes from CHAP-Challenge attribute (60) if present, otherwise from Request Authenticator.

### Vendor-Specific (Section 5.26)

Type = 26, Length ≥ 7. Layout: Vendor-Id (4B, high octet 0, low 3 = SMI Private Enterprise Code, network byte order) + String. String SHOULD be encoded as sequence of (vendor-type 1B, vendor-length 1B, vendor-value) sub-attributes. Multiple sub-attributes MAY be packed in one VSA attribute.

### Standard attribute types (Section 5)

| Type | Name | Length | Value type |
|------|------|--------|------------|
| 1 | User-Name | ≥3 | string (UTF-8/NAI/DN), handle ≥63 octets |
| 2 | User-Password | 18–130 | encrypted (see above) |
| 3 | CHAP-Password | 19 | 1B ident + 16B response |
| 4 | NAS-IP-Address | 6 | IPv4 (4B) |
| 5 | NAS-Port | 6 | uint32 |
| 6 | Service-Type | 6 | uint32 enum |
| 7 | Framed-Protocol | 6 | uint32 enum |
| 8 | Framed-IP-Address | 6 | IPv4 |
| 9 | Framed-IP-Netmask | 6 | IPv4 |
| 10 | Framed-Routing | 6 | uint32 enum |
| 11 | Filter-Id | ≥3 | string |
| 12 | Framed-MTU | 6 | uint32 |
| 13 | Framed-Compression | 6 | uint32 enum |
| 14 | Login-IP-Host | 6 | IPv4 |
| 15 | Login-Service | 6 | uint32 enum |
| 16 | Login-TCP-Port | 6 | uint32 |
| 18 | Reply-Message | ≥3 | string |
| 19 | Callback-Number | ≥3 | string |
| 20 | Callback-Id | ≥3 | string |
| 22 | Framed-Route | ≥3 | string |
| 23 | Framed-IPX-Network | 6 | uint32 |
| 24 | State | ≥3 | string (opaque) |
| 25 | Class | ≥3 | string (opaque) |
| 26 | Vendor-Specific | ≥7 | vendor-defined |
| 27 | Session-Timeout | 6 | uint32 (seconds) |
| 28 | Idle-Timeout | 6 | uint32 (seconds) |
| 29 | Termination-Action | 6 | uint32 enum |
| 30 | Called-Station-Id | ≥3 | string |
| 31 | Calling-Station-Id | ≥3 | string |
| 32 | NAS-Identifier | ≥3 | string |
| 33 | Proxy-State | ≥3 | string (opaque, proxy adds/removes) |
| 34 | Login-LAT-Service | ≥3 | string |
| 35 | Login-LAT-Node | ≥3 | string |
| 36 | Login-LAT-Group | ≥3 | string |
| 37 | Framed-AppleTalk-Link | 6 | uint32 |
| 38 | Framed-AppleTalk-Network | 6 | uint32 |
| 39 | Framed-AppleTalk-Zone | ≥3 | string |
| 60 | CHAP-Challenge | ≥3 | string |
| 61 | NAS-Port-Type | 6 | uint32 enum |
| 62 | Port-Limit | 6 | uint32 |
| 63 | Login-LAT-Port | ≥3 | string |

Types 17, 21, 40–59 unassigned in RFC 2865 (40–51 reserved for RFC 2866 accounting attrs; 60+ defined here).

### UDP ports

- Authentication: **1812** (legacy 1645, conflict with datametrics — do not use by default)
- Accounting: **1813** (RFC 2866; legacy 1646)

### Retransmission (Section 2.5)

- Client tracks RTT, doubles timeout on each retransmission up to a max
- Server treats duplicate (same client IP/port/Identifier) within short window as duplicate
- No keep-alives (Section 2.6 — harmful)

---

## RFC 2866 — RADIUS Accounting

### Differences from RFC 2865

- UDP destination port **1813**
- Length field: min 20, **max 4095** (one less than RFC 2865's 4096)
- Codes: only 4 (Accounting-Request) and 5 (Accounting-Response)

### Accounting-Request Authenticator (Section 3)

**Critical difference**: not random, it is an MD5 digest:

```
RequestAuth = MD5(Code + Identifier + Length + 16 zero octets + Attributes + Secret)
```

(The 16 zero octets stand in for the Authenticator field position during hashing.)

### Accounting-Response Authenticator (Section 3)

```
ResponseAuth = MD5(Code + Identifier + Length + RequestAuth + Attributes + Secret)
```

(Same formula as Access-Accept/Reject/Challenge.)

### Accounting-Request rules (Section 4.1)

- MUST NOT contain: User-Password, CHAP-Password, Reply-Message, State
- MUST contain NAS-IP-Address or NAS-Identifier
- SHOULD contain NAS-Port / NAS-Port-Type
- Server MUST respond with Accounting-Response only if it successfully records the request; otherwise silent
- If Acct-Delay-Time is present, it updates on retransmission → Attributes change → Identifier MUST change → Request Authenticator MUST be recomputed

### Accounting attributes

| Type | Name | Length | Notes |
|------|------|--------|-------|
| 40 | Acct-Status-Type | 6 | uint32: 1=Start, 2=Stop, 3=Interim-Update, 7=Accounting-On, 8=Accounting-Off, 9–14=tunnel (RFC 2867), 15=Failed |
| 41 | Acct-Delay-Time | 6 | uint32 seconds |
| 42 | Acct-Input-Octets | 6 | uint32; only in Stop |
| 43 | Acct-Output-Octets | 6 | uint32; only in Stop |
| 44 | Acct-Session-Id | ≥3 | string, unique session ID |
| 45 | Acct-Authentic | 6 | uint32: 1=RADIUS, 2=Local, 3=Remote |
| 46 | Acct-Session-Time | 6 | uint32 seconds; only in Stop |
| 47 | Acct-Input-Packets | 6 | uint32; only in Stop |
| 48 | Acct-Output-Packets | 6 | uint32; only in Stop |
| 49 | Acct-Terminate-Cause | 6 | uint32 1–18; only in Stop |
| 50 | Acct-Multi-Session-Id | ≥3 | string |
| 51 | Acct-Link-Count | 6 | uint32 |

### Acct-Terminate-Cause values (Section 5.10)

1 User Request, 2 Lost Carrier, 3 Lost Service, 4 Idle Timeout, 5 Session Timeout,
6 Admin Reset, 7 Admin Reboot, 8 Port Error, 9 NAS Error, 10 NAS Request,
11 NAS Reboot, 12 Port Unneeded, 13 Port Preempted, 14 Port Suspended,
15 Service Unavailable, 16 Callback, 17 User Error, 18 Host Request.

### Attribute ordering (Section 3)

Multiple instances of same type: order SHOULD be preserved. Different types: order not required.

---

## RFC 2867 — Tunnel Accounting (deferred to Phase 6)

Extends Acct-Status-Type with: 9=Tunnel-Start, 10=Tunnel-Stop, 11=Tunnel-Reject,
12=Tunnel-Link-Start, 13=Tunnel-Link-Stop, 14=Tunnel-Link-Reject. Adds tunnel
accounting attributes that overlap with RFC 2868. Study in depth when implementing
Phase 6 (tunnel support).

## RFC 2868 — Tunnel Attributes (deferred to Phase 6)

Defines Type 64–67, 69, 81–83, 90, 91 tunnel attributes. All use the "tagged"
attribute layout (Type-Length-Tag-Value). Study the tagging scheme carefully in
Phase 6 — it affects RFC 2868, 2867, and some 2869 attributes.

## RFC 2869 — RADIUS Extensions (deferred to Phase 5/6)

- **EAP-Message (79)**: long attribute, fragments EAP packets across multiple
  attributes concatenated in order. Length includes the EAP data.
- **Message-Authenticator (80)**: HMAC-MD5 over (Code + ID + Length + Request
  Auth + Attributes) keyed with shared secret. **MUST** be present in EAP
  Access-Request and all CoA/DM packets (RFC 5176). Computed with the field
  zeroed, then stored.
- Arctext attributes (87 NAS-Port-Id, 95–100 IPv6 set) — study alongside RFC 3162.
- **Acct-Interim-Interval (85)**: hint from server for interim-update cadence.

## RFC 3162 — RADIUS and IPv6 (deferred to Phase 4)

- NAS-IPv6-Address (95), Framed-Interface-Id (96), Framed-IPv6-Prefix (97),
  Login-IPv6-Host (98), Framed-IPv6-Route (99), Framed-IPv6-Pool (100).
- Framed-IPv6-Prefix layout: Type(1) + Length(1) + Reserved(1) + Prefix-Length(1) + Prefix(N).
- Accounting: 64-bit Acct-Input-Octets/Output-Octets added in RFC 2869 as
  52 (Acct-Input-Gigawords) / 53 (Acct-Output-Gigawords) — high 32 bits.

## RFC 5176 — Dynamic Authorization (CoA/DM) (deferred to Phase 7)

- UDP port **3799**. Codes 40–45 (see below). **MUST** include Message-Authenticator.
- Codes: 40=Disconnect-Request, 41=Disconnect-ACK, 42=Disconnect-NAK, 43=CoA-Request, 44=CoA-ACK, 45=CoA-NAK.
- Error-Cause (101): uint32 enum (e.g. 201 Invalid-Attribute, 401 Missing-Attribute, 501 Session-Context-Not-Found).
- Request Authenticator: random 16 octets (like Access-Request).
- Response Authenticator: MD5(Code+ID+Length+RequestAuth+Attributes+Secret).

## RFC 6613 — RADIUS over TCP (deferred to Phase 4)

- Per RFC 6613 §2.2, RADIUS/TCP uses the same IANA-assigned ports as UDP:
  1812/tcp (auth), 1813/tcp (acct), 3799/tcp (CoA). The `PortTCP = 5080`
  constant in `types/` is kept as the project's default listening port for
  the test server, distinct from the IANA-registered production ports.
- No separate length prefix. RFC 6613 §2.1 states the RADIUS packet format
  is unchanged, so framing on the TCP byte stream uses the existing 2-byte
  `Length` field at offset 2..3 of the RADIUS header: read 4 bytes (Code +
  ID + Length), decode Length, then read `Length - 4` more bytes.
- Connection management: persistent, MAY multiplex multiple concurrent
  requests over one connection; server matches responses by (ID, source)
  per connection. Per §2.6.5 only 256 IDs may be in flight on one
  connection.
- Per §2.6.4, malformed framing (Length < 20 or > 4096, attribute length
  0 or 1, attributes do not fill the declared Length, authenticator
  verification fails, Message-Authenticator fails) MUST close the
  connection.
- Per §2.6.1, no retransmission on the same TCP connection; redialing and
  retrying on a new connection is permitted but the new source port may
  change the ID, which requires recomputing Message-Authenticator.
- TLS variant defined in RFC 6614 (out of scope unless requested).

## RFC 6929 — Protocol Extensions (deferred to Phase 6)

- Long Extended types (Type 241–246): extended attribute space beyond 255.
- Type 241 = "Extended-Type", carrying (More-type, Type, Length, Value). Read
  the layout carefully — it is non-trivial.
- Long attributes (>253B): split via "More" flag bit on extended attributes.
- Nested TLV support (long attributes composed of sub-TLVs).

## RFC 9445 — DHCP-Configured Services (deferred to Phase 6)

- Adds DHCP-related RADIUS attributes for BNG scenarios.
- Study specific attribute numbers and layout in Phase 6.

---

## Implementation priorities for Phase 2 (core packet/crypto)

1. `types/`: Code enum, Attribute type registry, error sentinel set.
2. `crypto/`: MD5 authenticator (request/response for both Access and Accounting),
   User-Password encrypt/decrypt, HMAC-MD5 for Message-Authenticator.
3. `packet/`: Packet struct with Marshal/Unmarshal, Attribute TLV encode/decode,
   attribute list operations (Get/GetOne/Add/Set/Del).
4. `dictionary/`: Attribute type registration interface; register RFC 2865 standard
   attrs first. VSA sub-attribute parsing as separate concern.
5. Tests for each above targeting ≥95% coverage on crypto/packet, ≥90% elsewhere.

RFCs 2867, 2868, 2869, 3162, 5176, 6613, 6929, 9445 are read only at the summary
level above until their owning phase starts, at which point the relevant section
of the source RFC must be re-read in full before implementing.
