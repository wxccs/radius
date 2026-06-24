# Protocol Layer Design

Status: draft  
Scope: `protocol/` package — RADIUS state machines, Identifier
allocation, Request Authenticator generation, retransmission, and
response verification for Access (RFC 2865), Accounting (RFC 2866),
and Dynamic Authorization (RFC 5176) flows.

## 1. Goals

- Provide a high-level Client API that hides wire marshaling and
  transport concerns behind method calls like `Authenticate`,
  `Account`, `SendCoA`, `SendDisconnect`.
- Conform to RFC 2865 §4.1–4.4 (Access state machine), RFC 2866 §4
  (Accounting state machine), and RFC 5176 §2.1–2.3 (CoA/DM state
  machine).
- Generate Request Authenticators per-RFC: random for Access-Request,
  MD5-derived for Accounting-Request / CoA-Request / Disconnect-Request.
- Match replies by Identifier and verify Response Authenticator and
  Message-Authenticator (when present).
- Retransmit UDP requests with exponential backoff; never retransmit
  on a TCP connection (RFC 6613 §2.6.1).
- Target ≥ 90 % unit-test coverage.

## 2. Dependency on a Packet-Layer Bug Fix

`packet.Packet.Marshal` currently groups `CoARequest` and
`DisconnectRequest` with `AccessRequest` in the "copy caller-supplied
random authenticator" branch. RFC 5176 §2.3 requires these to use the
**Accounting-Request** authenticator formula:

```
RequestAuth = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
```

The fix moves `CoARequest` / `DisconnectRequest` out of the random
branch and into the accounting-authenticator branch. This is a
behavioral change to `packet.Marshal` but is invisible to callers that
do not pre-populate `Authenticator` for CoA/DM requests (the
`protocol.Client` never does). The change is made in the same commit
that introduces `protocol/`.

## 3. Package Layout

```
protocol/
├── client.go       # Client: Authenticate, Account, SendCoA, SendDisconnect
├── authenticator.go # Request Authenticator generation (random / MD5)
├── identifier.go   # Identifier pool (0-255, per-client)
├── retransmit.go   # Exponential backoff policy
├── verify.go       # Response Authenticator + Message-Authenticator verification
├── client_test.go
├── authenticator_test.go
├── identifier_test.go
├── retransmit_test.go
└── verify_test.go
```

## 4. Client API

```go
type Client struct {
    transport   Transport       // UDP or TCP (see §5)
    secret      []byte
    idPool      *IdentifierPool
    retransmit  RetransmitPolicy
    log         log.Logger
}

type Transport interface {
    Exchange(ctx context.Context, raw []byte) ([]byte, error)
    Close() error
}

func NewClient(t Transport, secret []byte, opts ...Option) *Client

func (c *Client) Authenticate(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
func (c *Client) Account(ctx context.Context, req *AcctRequest) (*AcctResponse, error)
func (c *Client) SendCoA(ctx context.Context, req *CoARequest) (*CoAResponse, error)
func (c *Client) SendDisconnect(ctx context.Context, req *DMRequest) (*DMResponse, error)
func (c *Client) Close() error
```

`Transport` is satisfied by both `*transport.UDPClient` and
`*transport.TCPClient`. Callers inject the transport of their choice;
the protocol layer is transport-agnostic.

## 5. Request Authenticator Generation

| Request type            | Algorithm                              | Source           |
|-------------------------|----------------------------------------|------------------|
| Access-Request          | `crypto/rand` 16 random bytes          | RFC 2865 §3      |
| Accounting-Request      | MD5(Code+ID+Len+16 zeros+Attrs+Secret)| RFC 2866 §3      |
| CoA-Request             | Same as Accounting-Request              | RFC 5176 §2.3    |
| Disconnect-Request      | Same as Accounting-Request             | RFC 5176 §2.3    |

`packet.Marshal` already computes the Accounting-Request authenticator
in-place; after the §2 fix it will also compute CoA/DM authenticators.
The protocol layer therefore only needs to generate a random 16-byte
authenticator for Access-Request and leave the field zero for the
other three codes.

## 6. Identifier Pool

```go
type IdentifierPool struct { /* ... */ }

func NewIdentifierPool() *IdentifierPool
func (p *IdentifierPool) Acquire(ctx context.Context) (byte, error)
func (p *IdentifierPool) Release(id byte)
```

- A `sync.Map` of `byte -> chan struct{}` tracks in-use IDs.
- `Acquire` blocks until a free ID is available or ctx is canceled.
- `Release` marks an ID as free and wakes one blocked Acquire.
- Capacity is 256 IDs per pool (one pool per Client). For TCP, RFC 6613
  §2.6.5 reserves ID 0 for Status-Server; the pool does not reserve
  anything by default — Status-Server support is a future concern.

## 7. Retransmission Policy (UDP only)

```go
type RetransmitPolicy struct {
    MaxAttempts int           // default 3 (1 initial + 2 retries)
    Initial     time.Duration // default 2s
    Max         time.Duration // default 16s
    Jitter      float64       // default 0.1 (±10 %)
}

func (p RetransmitPolicy) NextDelay(attempt int) time.Duration
```

- Exponential backoff: `delay = min(Initial << attempt, Max)`.
- Jitter applied as `delay * (1 + rand[-Jitter, +Jitter])` to avoid
  synchronized retry storms.
- On TCP transports `MaxAttempts` is effectively 1 — the policy is
  consulted but never retried, because `Transport.Exchange` on TCP
  either succeeds or closes the connection.

Per RFC 2865 §2.5 and RFC 5176 §2.3: if attributes have not changed
between retries, the same Identifier and Request Authenticator MUST be
reused. The protocol layer therefore marshals the request **once** and
re-sends the identical bytes on each retry, releasing the Identifier
only when a response is received or all attempts are exhausted.

## 8. Response Verification

```go
func VerifyResponse(raw []byte, requestAuth [16]byte, secret []byte) error
```

1. Unmarshal the reply (length bounds, attribute walk).
2. Match Identifier against the outstanding request.
3. Verify Response Authenticator:
   `MD5(Code + ID + Length + RequestAuth + Attributes + Secret)`.
4. If the reply contains a Message-Authenticator attribute, verify it
   (HMAC-MD5 over the packet with the attribute's Value field zeroed).

A mismatch on (3) or (4) returns `ErrAuthenticatorMismatch` /
`ErrMessageAuthenticatorMismatch` (already defined in `errors/`).
The packet is silently discarded per RFC 2865 §3.

## 9. State Machines

### 9.1 Authentication (RFC 2865 §4.1–4.4)

```
Client                              Server
  |  Access-Request (ID, RA, User-Password)  |
  |---------------------------------------->|
  |                                         |
  |  Access-Accept / Access-Reject /        |
  |  Access-Challenge (same ID)             |
  |<----------------------------------------|
```

- `Authenticate` sends one Access-Request and waits for one of the
  three reply codes.
- Access-Challenge is returned to the caller as a distinct response
  type; the caller may issue a follow-up `Authenticate` with the
  `State` attribute to continue the challenge/response exchange.
- EAP: when `req.Method == EAP`, the protocol layer adds
  Message-Authenticator to the Access-Request (RFC 2869 §5.14) and
  validates it on every reply.

### 9.2 Accounting (RFC 2866 §4)

```
Client                              Server
  |  Accounting-Request (ID, MD5-auth)      |
  |---------------------------------------->|
  |                                         |
  |  Accounting-Response (same ID)          |
  |<----------------------------------------|
```

- `Account` sends one Accounting-Request and waits for
  Accounting-Response.
- `Acct-Status-Type` (Start / Interim-Update / Stop) is set by the
  caller via `AcctRequest`; the protocol layer does not sequence
  these automatically — Interim-Update cadence is the caller's
  responsibility (or a future `session/` package).

### 9.3 Dynamic Authorization (RFC 5176)

```
DA-Client                           NAS
  |  CoA-Request / DM-Request (ID, MD5-auth, Msg-Auth) |
  |--------------------------------------------------->|
  |                                                    |
  |  CoA-ACK / CoA-NAK / DM-ACK / DM-NAK (same ID)    |
  |<---------------------------------------------------|
```

- `SendCoA` and `SendDisconnect` always include
  Message-Authenticator (RFC 5176 §3.4 mandates it).
- `Error-Cause` (attribute 101) is surfaced on NAK replies via
  `CoAResponse.ErrorCause` / `DMResponse.ErrorCause`.

## 10. Concurrency

- `Client` is safe for concurrent use. Each call acquires an
  Identifier from the pool, performs the exchange, and releases it.
- Multiple in-flight requests on one UDP socket are demultiplexed by
  Identifier inside `Transport.Exchange` (the transport reads one
  datagram per call; the protocol layer does not need a read loop).
  This is acceptable for low-throughput CLI use; a future
  `protocol.Mux` may add a shared read loop for high-throughput
  scenarios.
- On TCP, `Transport.Exchange` is serialized by an internal mutex
  (see transport design §6.4); concurrent `Authenticate` calls on
  one TCP Client are effectively serial.

## 11. Error Handling

The protocol layer reuses existing sentinel errors and adds:

```go
var (
    ErrNoResponse       = errors.New("no response after all retries")
    ErrIdentifierExhausted = errors.New("no free identifier available")
)
```

- `ErrNoResponse` is returned when all retransmission attempts are
  exhausted without a reply.
- `ErrIdentifierExhausted` is returned when `Acquire` times out
  (256 in-flight requests on one Client).

## 12. Logging

Per the project-wide convention:

- The protocol layer obtains a `log.Logger` via `log.Default.With("func", ...)`.
- Every method logs its entry/exit at Debug(5), retransmission events
  at Info(4), and malformed replies at Warn(3).
- Request Authenticators and User-Password values are never logged.

## 13. Testing Strategy

### 13.1 Unit tests

- `authenticator_test.go`: random vs MD5 authenticator generation,
  RFC 2866 §7.1 test vector for Accounting-Request authenticator.
- `identifier_test.go`: Acquire/Release lifecycle, blocking behavior,
  context cancellation, exhaustion.
- `retransmit_test.go`: exponential growth, jitter bounds, max cap.
- `verify_test.go`: valid response, wrong Identifier, wrong Response
  Authenticator, missing/invalid Message-Authenticator.
- `client_test.go`: Authenticate / Account / SendCoA / SendDisconnect
  against a loopback UDP server backed by `packet.Marshal/Unmarshal`.

### 13.2 Coverage target

≥ 90 % line coverage of `protocol/`. CI gate remains at 0 % until
Phase 10; the gate will be raised to 90 % once `client/` and
`server/` are present.

## 14. References

- RFC 2865 §2.5 (Retransmission Hints), §3 (Authenticators), §4.1–4.4
  (packet types)
- RFC 2866 §3 (Accounting authenticator), §4 (Accounting rules)
- RFC 5176 §2.1 (DM), §2.2 (CoA), §2.3 (Packet Format & Authenticator),
  §3.4 (Message-Authenticator), §3.5 (Error-Cause)
- RFC 6613 §2.6.1 (no TCP retransmission)
