# Transport Layer Design

Status: implemented (UDP/TCP/TLS/DTLS)  
Scope: `transport/` package — UDP (RFC 2865, RFC 3162), TCP (RFC 6613),
TLS (RFC 6614), and DTLS (RFC 7360) transports for RADIUS.

## 1. Goals

- Provide a transport-agnostic surface for sending and receiving RADIUS
  packets on top of UDP, TCP, TLS, and DTLS.
- Conform to RFC 2865 (RADIUS/UDP), RFC 3162 (IPv6 attributes and
  transport), RFC 6613 (RADIUS/TCP), RFC 6614 (RADIUS/TLS), and
  RFC 7360 (RADIUS/DTLS).
- Be safe for concurrent use, support `context.Context` deadlines, and
  never log secrets.
- Target ≥ 85 % unit-test coverage (current: 84.8 %).

## 2. Non-Goals (deferred to higher layers)

- Retransmission policy, RTT estimation, duplicate detection → `protocol/`.
- Identifier allocation and matching across multiple in-flight requests →
  `protocol/`.
- Status-Server watchdog (RFC 3539, RFC 5997) → `client/`.
- Connection pooling and failover → `client/`.

## 3. Package Layout

```
transport/
├── transport.go    # interfaces, sentinel errors, shared helpers (isClosed, etc.)
├── udp.go          # UDPTransport, UDPClient
├── tcp.go          # TCPListener, TCPConn, TCPClient
├── tls.go          # TLSListener, TLSConn, TLSClient
├── dtls.go         # DTLSListener, DTLSConn, DTLSClient
├── framed.go       # shared read/write helpers split by stream vs. message semantics
├── udp_test.go     # unit + loopback tests
├── tcp_test.go     # unit + loopback tests
├── tls_test.go     # loopback + lifecycle tests
├── dtls_test.go    # loopback + lifecycle tests
└── certs_test.go   # per-test self-signed cert generator (shared by tls/dtls tests)
```

## 4. Interface Design

### 4.1 Server-side surface

```go
// PacketListener receives RADIUS packets from a specific transport and
// sends replies back to the source.
type PacketListener interface {
    // ReadPacket reads one complete RADIUS packet from the wire.
    // The returned data is a private copy; callers may retain it without
    // copying. The context's deadline, if any, is propagated to the
    // underlying read.
    ReadPacket(ctx context.Context) (data []byte, src net.Addr, err error)

    // SendPacket writes one complete RADIUS packet to dst.
    SendPacket(data []byte, dst net.Addr) error

    // LocalAddr returns the local address the listener is bound to.
    LocalAddr() net.Addr

    // Close releases the underlying socket.
    Close() error
}
```

`UDPTransport` is the only `PacketListener` implementation. TCP server-side
listening is connection-oriented and uses a different shape:

```go
type TCPListener struct { /* ... */ }

func ListenTCP(network string, laddr *net.TCPAddr) (*TCPListener, error)
func (l *TCPListener) Accept(ctx context.Context) (*TCPConn, error)
func (l *TCPListener) Close() error
func (l *TCPListener) LocalAddr() net.Addr

type TCPConn struct { /* ... */ }

func (c *TCPConn) ReadPacket(ctx context.Context) ([]byte, error)
func (c *TCPConn) WritePacket(raw []byte) error
func (c *TCPConn) Close() error
func (c *TCPConn) RemoteAddr() net.Addr
```

### 4.2 Client-side surface

```go
type UDPClient struct { /* ... */ }

func DialUDP(network string, server *net.UDPAddr, laddr *net.UDPAddr) (*UDPClient, error)
func (c *UDPClient) Exchange(ctx context.Context, raw []byte) ([]byte, error)
func (c *UDPClient) Close() error
func (c *UDPClient) LocalAddr() net.Addr

type TCPClient struct { /* ... */ }

func DialTCP(network string, server *net.TCPAddr) (*TCPClient, error)
func (c *TCPClient) Exchange(ctx context.Context, raw []byte) ([]byte, error)
func (c *TCPClient) Close() error
func (c *TCPClient) LocalAddr() net.Addr

type TLSClient struct { /* ... */ }

func DialTLS(network string, server *net.TCPAddr, config *tls.Config) (*TLSClient, error)
func (c *TLSClient) Exchange(ctx context.Context, raw []byte) ([]byte, error)
func (c *TLSClient) Close() error
func (c *TLSClient) LocalAddr() net.Addr

type DTLSClient struct { /* ... */ }

func DialDTLS(network string, server *net.UDPAddr, opts ...piondtls.ClientOption) (*DTLSClient, error)
func (c *DTLSClient) Exchange(ctx context.Context, raw []byte) ([]byte, error)
func (c *DTLSClient) Close() error
func (c *DTLSClient) LocalAddr() net.Addr
```

`Exchange` is the simple synchronous API. The `protocol/` layer will use
`*Conn.ReadPacket`/`WritePacket` directly for multiplexed dispatch by
Identifier (see §7).

## 5. UDP Transport (RFC 2865, RFC 3162)

### 5.1 ListenUDP

```go
func ListenUDP(network string, laddr *net.UDPAddr) (*UDPTransport, error)
```

- `network` is one of `"udp"`, `"udp4"`, `"udp6"` and is forwarded to
  `net.ListenUDP`.
- `laddr == nil` lets the OS pick an ephemeral port.
- The returned `*UDPTransport` wraps a `*net.UDPConn` and is safe for
  concurrent `ReadPacket`/`SendPacket` calls.
- Read buffer is sized to `types.PacketMaxLengthRFC2865` (4096) — RADIUS
  packets cannot exceed this and IP fragmentation handles datagrams larger
  than MTU.

### 5.2 DialUDP

```go
func DialUDP(network string, server *net.UDPAddr, laddr *net.UDPAddr) (*UDPClient, error)
```

- Creates a UDP socket bound to `laddr` (or ephemeral) and remembers
  `server` as the default destination for `Exchange`.
- `Exchange(ctx, raw)`:
  1. Apply `ctx` deadline via `SetWriteDeadline` / `SetReadDeadline`.
  2. Write `raw` to `server`.
  3. Read one datagram from the socket.
  4. Verify the source address matches `server`; on mismatch log at Warn(3)
     and discard (RFC 2865 §3 "silently discard" guidance for stray packets).
  5. Return the datagram bytes (a copy).
- No retransmission here. The `protocol/` layer above calls `Exchange`
  multiple times with back-off if needed.

### 5.3 IPv6

Dual-stack behavior is controlled by `network`:
- `"udp"` lets the kernel choose based on the resolved `laddr`.
- `"udp4"`/`"udp6"` force a specific family.

No additional code is needed beyond passing `network` through; IPv6 attribute
encoding (RFC 3162) is a `packet/` concern, not a transport concern.

## 6. TCP Transport (RFC 6613)

### 6.1 Framing

RFC 6613 §2.1 states that "the RADIUS packet format is unchanged". The
existing 2-byte `Length` field at offset 2..3 of the RADIUS header is the
framing mechanism on the TCP byte stream:

```
1. io.ReadFull(conn, header[0:4])              # Code, ID, Length-hi, Length-lo
2. length = int(binary.BigEndian.Uint16(header[2:4]))
3. validate 20 <= length <= 4096  (or 4095 for accounting)
4. payload := make([]byte, length-4)
5. io.ReadFull(conn, payload)
6. return append(header, payload...)
```

There is **no separate 2-byte length prefix**. (Earlier `docs/rfc/NOTES.md`
claimed otherwise; that note is being corrected in the same commit that
introduces this design.)

### 6.2 Malformed Packet Handling

Per RFC 6613 §2.6.4, the following conditions cause the TCP connection to
be closed immediately:

- `Length` field less than 20 or greater than 4096 (4095 for accounting).
- Attribute `Length` field of 0 or 1 within the packet body.
- Attributes do not exactly fill the declared `Length`.
- Authenticator verification fails (when required).
- Message-Authenticator verification fails.

When the reader detects any of these, it returns the corresponding sentinel
error from `errors/` and the caller (typically `server/`) is responsible for
closing the connection. The transport does not auto-close, so that the
caller can decide whether to log the event and what to do with the half-read
stream.

Two cases permit the connection to remain open (RFC 6613 §2.6.4):

- Invalid Code field — packet silently discarded.
- Response that does not match any outstanding request — silently discarded.

### 6.3 ListenTCP / Accept

```go
func ListenTCP(network string, laddr *net.TCPAddr) (*TCPListener, error)
func (l *TCPListener) Accept(ctx context.Context) (*TCPConn, error)
```

- `Accept` blocks until a new connection arrives or `ctx` is canceled.
  Implementation: spawn a goroutine that calls `l.ln.Accept()` and writes
  the result to a channel; `select` against `ctx.Done()`.
- `TCPConn.RemoteAddr()` exposes the peer address for shared-secret lookup
  (RFC 6613 §2.6.3 keys secrets by `(IP, port, transport protocol)`).

### 6.4 DialTCP / Exchange

```go
func DialTCP(network string, server *net.TCPAddr) (*TCPClient, error)
func (c *TCPClient) Exchange(ctx context.Context, raw []byte) ([]byte, error)
```

- `DialTCP` opens one TCP connection to `server` and keeps it open across
  calls.
- `Exchange(ctx, raw)`:
  1. Acquire `writeMu` (mutex on writes).
  2. Apply `ctx` deadline to the connection.
  3. `WritePacket(raw)`.
  4. `ReadPacket(ctx)` and return.
- Synchronous: a single in-flight request per `Exchange` call. Concurrent
  in-flight requests on one TCP connection require the `protocol/` layer
  using `TCPConn` directly with ID-based demultiplexing (§7).
- Per RFC 6613 §2.6.1: no retransmission on the same connection; if the
  connection is closed, the caller may redial and retry, but the new source
  port may change the ID and **must** trigger recomputation of
  Message-Authenticator — this is the `protocol/` layer's responsibility.

### 6.5 Concurrency Model

- `TCPConn.WritePacket` is guarded by an internal `sync.Mutex` so multiple
  goroutines may write concurrently.
- `TCPConn.ReadPacket` is **not** guarded; one reader goroutine per
  connection. The `protocol/` layer owns the read loop and dispatches by
  Identifier.
- `UDPTransport.SendPacket` is guarded by an internal `sync.Mutex`.
- `UDPTransport.ReadPacket` may be called by only one goroutine at a time
  per socket; the server `Serve` loop is the canonical single reader.
- `TLSConn` and `DTLSConn` mirror `TCPConn`'s concurrency model: write
  mutex on the connection, single reader per connection.

## 7. TLS Transport (RFC 6614)

### 7.1 Framing

RFC 6614 §2.4 states that TLS wraps TCP and "the RADIUS packet format is
unchanged" — the same 2-byte `Length` field at offset 2..3 delimits each
packet on the TLS record stream. `TLSConn.ReadPacket` therefore reuses
the same `readFramedStream` helper as `TCPConn.ReadPacket`:
4-byte header → validate Length → `io.ReadFull` for the payload.

### 7.2 Handshake

`tls.Listener` defers the TLS handshake to the first `Read`/`Write` on
the underlying `*tls.Conn`. To surface handshake failures from `Accept`
rather than the first `ReadPacket`, `TLSListener.Accept` forces the
handshake via `(*tls.Conn).HandshakeContext(ctx)` before returning the
connection to the caller. A handshake failure closes the connection and
returns the error from `Accept`.

### 7.3 ListenTLS / DialTLS

```go
func ListenTLS(network string, laddr *net.TCPAddr, config *tls.Config) (*TLSListener, error)
func DialTLS(network string, server *net.TCPAddr, config *tls.Config) (*TLSClient, error)
```

- `ListenTLS` requires `config.Certificates` to be non-empty; otherwise
  returns `ErrInvalidAttribute`.
- `DialTLS` uses `tls.DialWithDialer` with a 30 s dial timeout, then
  forces the handshake before returning. The client `*tls.Config` should
  set `InsecureSkipVerify` only for testing — production deployments
  should pin a `RootCAs` pool.
- Per RFC 6614 §2.5: TLS 1.2 is the minimum supported version; TLS 1.3
  is preferred when both peers support it.

### 7.4 Concurrency and Lifecycle

Same as TCP: `TLSConn.WritePacket` is mutex-guarded; one reader per
connection. `Close` is safe for concurrent calls.

## 8. DTLS Transport (RFC 7360)

### 8.1 Framing

RFC 7360 §2.4 carries RADIUS over DTLS, with the same Length-framed
packet format as TCP/TLS. However, DTLS is **message-oriented**: one
`Read` call returns the full decrypted DTLS record. If the caller's
buffer is smaller than the record, pion returns `errBufferTooSmall` and
**does not** leave the remainder for the next read.

`DTLSConn.ReadPacket` therefore uses a separate `readFramedMessage`
helper that allocates a buffer of `types.PacketMaxLengthRFC2866` (4095)
bytes and calls `Read` once. The first 4 bytes are validated as the
RADIUS header; if the declared `Length` exceeds the number of bytes
returned, the packet is rejected as malformed.

### 8.2 Implementation: pion/dtls/v3

The DTLS transport uses `github.com/pion/dtls/v3`, which is the only
maintained Go DTLS implementation. v3 is required because v2 is
permanently affected by [GO-2026-4479](https://pkg.go.dev/vuln/GO-2026-4479)
/ CVE-2026-26014 (random nonce generation with AES-GCM ciphers risks
leaking the authentication key).

pion v3 deprecated the `*Config`-based API in favor of an options-based
API (`ListenWithOptions` / `DialWithOptions` with `ServerOption` /
`ClientOption` variadic args). Our `ListenDTLS` and `DialDTLS` mirror
this shape:

```go
func ListenDTLS(network string, laddr *net.UDPAddr, opts ...piondtls.ServerOption) (*DTLSListener, error)
func DialDTLS(network string, server *net.UDPAddr, opts ...piondtls.ClientOption) (*DTLSClient, error)
```

Callers pass options like `piondtls.WithCertificates(cert)` and
`piondtls.WithInsecureSkipVerify(true)` directly. Passing no options to
`ListenDTLS` returns `ErrInvalidAttribute`.

### 8.3 Handshake

pion v3 defers the DTLS handshake to the first `Read`/`Write`. To mirror
the TLS transport (where handshake failures surface from `Dial*` rather
than the first `Exchange`), `DialDTLS` calls `(*piondtls.Conn).HandshakeContext(ctx)`
with a 30 s timeout before returning. A handshake failure closes the
connection and returns the error from `DialDTLS`.

`DTLSListener.Accept` does not force the handshake explicitly — pion's
`listener.Accept` performs the handshake internally before returning the
connection. Handshake failures on the server side therefore surface from
`Accept` directly.

### 8.4 Closed-connection error mapping

pion's closed-connection errors do not unwrap to `net.ErrClosed`:

- `piondtls.ErrConnClosed` — surfaced by `(*Conn).Write`/`Read` after
  `Close`. Wrapped in `&FatalError{}`. Matched explicitly in `isClosed`.
- `"udp: listener closed"` — surfaced by `listener.Accept` after
  `listener.Close`. The sentinel is in pion's internal `udp` package
  and cannot be imported from outside, so `isClosed` matches by
  substring (`"listener closed"`). The string has been stable across
  pion releases.

### 8.5 Retransmission

Per RFC 7360 §2.4.3, retransmission on the same DTLS connection is not
performed — the DTLS layer handles retransmission of handshake flights
but not of RADIUS request/response pairs. Redialing and retrying on a
new connection is the caller's responsibility, mirroring TLS.

## 9. Protocol Layer Hook (forward reference)

The `protocol/` layer (next phase) will use the transport primitives as
follows. This is documented here to validate that the transport surface is
sufficient.

```text
UDP server:
  - transport.ListenUDP(network, laddr)
  - for { p.ReadPacket(ctx) → handler.Handle(p) → p.SendPacket(reply, src) }

UDP client:
  - transport.DialUDP(network, server, nil)
  - protocol.ExchangeWithRetry(ctx, raw, retries, backoff) calls UDPClient.Exchange

TCP server:
  - transport.ListenTCP(network, laddr)
  - for { listener.Accept(ctx) → spawn goroutine:
        for { conn.ReadPacket(ctx) → handler.Handle(p) → conn.WritePacket(reply) }
        on malformed framing → conn.Close()
    }

TCP client (simplex):
  - transport.DialTCP(network, server)
  - TCPClient.Exchange(ctx, raw)

TCP client (multiplexed):
  - transport.DialTCP(network, server)
  - internal read loop: conn.ReadPacket(ctx) → demux by Identifier
  - per-request goroutine: conn.WritePacket(raw) then wait on demux channel
```

## 10. Error Handling

### 8.1 New sentinel errors (added to `errors/errors.go`)

```go
var (
    ErrTimeout         = New("operation timed out")           // wraps ctx.DeadlineExceeded
    ErrConnClosed      = New("connection closed")
    ErrMalformedPacket = New("malformed RADIUS packet")        // TCP framing failures
    ErrUnknownPeer     = New("packet from unknown peer")
)
```

Existing `ErrShortBuffer` and `ErrInvalidLength` are reused for the framing
boundary checks.

### 8.2 Context propagation

- `ReadPacket` and `Exchange` honor `ctx` deadlines via `SetReadDeadline`.
- `SendPacket` and `WritePacket` honor `ctx` deadlines via `SetWriteDeadline`.
- When `ctx` is canceled mid-read, the partial read is discarded and
  `ctx.Err()` is returned wrapped by `ErrTimeout`.

### 8.3 Closed-connection semantics

- After `Close()`, all in-flight and future `ReadPacket` / `SendPacket`
  calls return `ErrConnClosed`.
- `Close()` is idempotent and safe for concurrent calls.

## 11. Logging

Per the project's global convention (see `~/.claude/CLAUDE.md`):

- Library uses `github.com/sirupsen/logrus`.
- Every log entry includes a `func` field with the project-root-relative
  path joined by `.`, e.g. `transport.UDPTransport.ReadPacket`,
  `transport.TCPConn.WritePacket`.
- Levels used:
  - Info(4): `Listen`/`Dial`/`Accept` lifecycle events.
  - Warn(3): stray UDP packet from unexpected source, malformed framing that
    closes a TCP connection.
  - Error(2): underlying `Read`/`Write` failures beyond EOF.
  - Debug(5): per-packet size, peer address, identifier.
  - Trace(6): full packet hex dump **with the Authenticator and
    User-Password fields zeroed** — never log raw authenticators or
    secrets.

A small helper `transport.logger()` returns a `*logrus.Entry` pre-populated
with the `func` field, reducing boilerplate at call sites.

## 12. Testing Strategy

### 10.1 Unit tests (in-process, no real network)

- `udp_test.go`:
  - `net.PacketConn` mock for `ReadPacket` / `SendPacket` paths.
  - `Exchange` happy path over an in-memory pipe (`net.Pipe` is not suitable
    for UDP; instead use real loopback `127.0.0.1:0`).
  - Coverage of: short buffer, oversized datagram, ctx cancellation, source
    address mismatch, concurrent `SendPacket`.
- `tcp_test.go`:
  - `ReadPacket` framing: 4-byte header with declared Length, exact body
    read.
  - Malformed cases: Length < 20, Length > 4096, body short read, body
    over-length, attribute length 0 inside body.
  - `WritePacket` mutex under concurrent writers.
  - `Exchange` over real loopback TCP.
  - `Close` idempotency and post-close error semantics.

### 10.2 Loopback integration tests

- UDP: `ListenUDP` + `DialUDP` exchange bytes; verify reply round-trips.
- TCP: `ListenTCP` + `DialTCP`; exchange a synthetic Access-Request and
  Access-Accept pair using `packet/` to ensure framing is wire-compatible
  with the existing codec.
- IPv6: repeat the above with `network="udp6"`/`"tcp6"` and `::1` loopback.

### 10.3 Coverage target

- ≥ 95 % line coverage of `transport/` (matching `crypto/` and `packet/`).
- CI gate currently set to 0 % (Phase 1-9 tolerance); will be raised to
  90 % in Phase 10 once `protocol/`, `client/`, and `server/` are present.

## 13. Open Questions

None currently. If during implementation we discover that the protocol
layer needs additional hooks (e.g., peek-at-header without consuming the
body), we will revisit §4 before adding to the interface.

## 14. References

- RFC 2865 §2.4 (Why UDP?), §2.5 (Retransmission Hints), §2.6 (Keep-Alives
  Considered Harmful), §3 (Packet Format)
- RFC 3162 (RADIUS and IPv6 — transport is unchanged; only attribute
  encoding differs)
- RFC 6613 §2.1 (Packet Format unchanged), §2.6.1 (Duplicates and
  Retransmissions), §2.6.4 (Malformed Packets and Unknown Clients),
  §2.6.5 (Limitations of the ID Field)
