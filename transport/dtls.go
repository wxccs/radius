package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v3"

	radiuserrors "github.com/wxccs/radius/v2/errors"
)

// DTLSListener accepts incoming RADIUS/DTLS connections (RFC 7360). DTLS
// wraps UDP and reuses the RFC 6613 framing: the 2-byte Length field at
// offset 2..3 of the RADIUS header delimits each packet on the stream.
// The packet format itself is unchanged from RFC 2865.
//
// A DTLSListener is constructed via ListenDTLS with at least one
// certificate supplied through pion's options API
// (piondtls.WithCertificates). Callers are responsible for rotating
// certs and for enabling client authentication as required by their
// deployment.
//
// RFC 7360 §2.4 recommends idle timeouts; callers should Close idle
// connections on both sides.
type DTLSListener struct {
	ln net.Listener
}

// ListenDTLS binds a DTLS-wrapped UDP socket on laddr. network is one
// of "udp", "udp4", or "udp6". A nil laddr selects an ephemeral port
// on all interfaces. opts must supply at least one certificate via
// piondtls.WithCertificates; passing no options returns
// ErrInvalidAttribute.
//
// The returned *DTLSListener is ready to Accept; the caller is expected
// to Close it on shutdown to release the port.
//
// The opts variadic uses pion's recommended options-based API
// (piondtls.ServerOption) so callers do not have to construct a
// *piondtls.Config directly.
func ListenDTLS(network string, laddr *net.UDPAddr, opts ...piondtls.ServerOption) (*DTLSListener, error) {
	log := withFunc("transport.ListenDTLS")
	if len(opts) == 0 {
		return nil, fmt.Errorf("%w: ListenDTLS requires at least one option (e.g. WithCertificates)",
			radiuserrors.ErrInvalidAttribute)
	}
	ln, err := piondtls.ListenWithOptions(network, laddr, opts...)
	if err != nil {
		log.Error("listen DTLS failed", "error", err)
		return nil, err
	}
	log.Info("DTLS listener bound",
		"network", network,
		"local", ln.Addr().String())
	return &DTLSListener{ln: ln}, nil
}

// Accept blocks until a new DTLS connection arrives or ctx is canceled.
// The returned *DTLSConn owns the underlying net.Conn; the caller must
// Close it when finished.
//
// Accept returns ErrConnClosed after the listener is closed. A context
// cancellation does not interrupt the in-flight Accept on the listener;
// callers shutting down should also Close the listener. The pion/dtls
// listener completes the DTLS handshake inside Accept, so handshake
// failures surface here as errors.
func (l *DTLSListener) Accept(ctx context.Context) (*DTLSConn, error) {
	log := withFunc("transport.DTLSListener.Accept")
	type acceptResult struct {
		conn *DTLSConn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.ln.Accept()
		if err != nil {
			ch <- acceptResult{nil, err}
			return
		}
		ch <- acceptResult{&DTLSConn{c: c}, nil}
	}()
	select {
	case <-ctx.Done():
		log.Info("accept canceled")
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			if isClosed(r.err) {
				return nil, radiuserrors.ErrConnClosed
			}
			return nil, r.err
		}
		log.Info("connection accepted", "remote", r.conn.RemoteAddr().String())
		return r.conn, nil
	}
}

// LocalAddr returns the local address the listener is bound to.
func (l *DTLSListener) LocalAddr() net.Addr { return l.ln.Addr() }

// Close releases the underlying listener. Safe for concurrent calls.
func (l *DTLSListener) Close() error { return l.ln.Close() }

// DTLSConn is a single RADIUS/DTLS connection. It shares the RADIUS
// packet framing (4-byte header with a 2-byte Length at offset 2..3)
// and adds the DTLS record layer underneath.
type DTLSConn struct {
	c       net.Conn
	writeMu sync.Mutex
}

// ReadPacket reads one RADIUS packet from the DTLS connection. The
// packet is framed by the 2-byte RADIUS Length field, exactly as on
// a TCP connection (RFC 6613 §2.1, RFC 7360 §2.4).
//
// Returns ErrMalformedPacket if the declared Length is out of bounds or
// if the connection closes mid-packet (short read). Returns
// ErrConnClosed if the peer closed the connection cleanly, or
// ErrTimeout if the context deadline is exceeded.
func (c *DTLSConn) ReadPacket(ctx context.Context) ([]byte, error) {
	return readFramedMessage(c.c, ctx, withFunc("transport.DTLSConn.ReadPacket"))
}

// WritePacket writes one RADIUS packet to the connection. Safe for
// concurrent callers.
func (c *DTLSConn) WritePacket(raw []byte) error {
	return writeFramedPacket(c.c, raw, &c.writeMu, withFunc("transport.DTLSConn.WritePacket"))
}

// RemoteAddr returns the peer's network address.
func (c *DTLSConn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

// LocalAddr returns the local address of the connection.
func (c *DTLSConn) LocalAddr() net.Addr { return c.c.LocalAddr() }

// Close closes the underlying connection. Safe for concurrent calls.
func (c *DTLSConn) Close() error { return c.c.Close() }

// DTLSClient is the client-side RADIUS/DTLS transport. It maintains a
// persistent DTLS connection to a server for synchronous
// request/response exchanges. Per RFC 7360 §2.4.3 retransmission on
// the same connection is not performed; redialing and retrying on a
// new connection is the caller's responsibility.
//
// Concurrent calls to Exchange are serialized by an internal mutex.
type DTLSClient struct {
	conn   *DTLSConn
	exchMu sync.Mutex
}

// DialDTLS dials a RADIUS/DTLS server at server. network is one of
// "udp", "udp4", or "udp6". opts configures the client via pion's
// options API (piondtls.ClientOption) — typically
// piondtls.WithInsecureSkipVerify for loopback testing or
// piondtls.WithRootCAs for production.
//
// The DTLS handshake is performed before DialDTLS returns, so a
// handshake failure surfaces as an error from DialDTLS rather than
// the first Exchange call. The handshake is bounded by a 30-second
// context deadline.
func DialDTLS(network string, server *net.UDPAddr, opts ...piondtls.ClientOption) (*DTLSClient, error) {
	log := withFunc("transport.DialDTLS")
	c, err := piondtls.DialWithOptions(network, server, opts...)
	if err != nil {
		log.Error("dial DTLS failed", "error", err)
		return nil, err
	}
	// pion/dtls v3 defers the handshake to the first Read/Write. Force
	// it here so handshake failures surface from DialDTLS rather than
	// the first Exchange call, mirroring the TLS transport's behavior.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		log.Error("DTLS handshake failed", "error", err)
		return nil, err
	}
	log.Info("DTLS connection established",
		"remote", c.RemoteAddr().String(),
		"local", c.LocalAddr().String())
	return &DTLSClient{conn: &DTLSConn{c: c}}, nil
}

// Exchange sends raw to the server and reads back one reply. The
// request/response pair is serialized with respect to other Exchange
// calls on the same client; concurrent calls block each other.
//
// The context deadline, if any, applies to both the write and the read.
// A timeout during the read returns ErrTimeout.
func (c *DTLSClient) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()
	if err := c.conn.WritePacket(raw); err != nil {
		return nil, err
	}
	return c.conn.ReadPacket(ctx)
}

// LocalAddr returns the local address of the client's connection.
func (c *DTLSClient) LocalAddr() net.Addr { return c.conn.c.LocalAddr() }

// Close closes the underlying connection.
func (c *DTLSClient) Close() error { return c.conn.Close() }
