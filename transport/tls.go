package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	radiuserrors "github.com/wxccs/radius/errors"
)

// TLSListener accepts incoming RADIUS/TLS connections (RFC 6614). TLS
// wraps the TCP framing defined by RFC 6613: a 2-byte Length field at
// offset 2..3 of the RADIUS header delimits each packet on the stream.
// The packet format itself is unchanged from RFC 2865.
//
// A TLSListener is constructed with a *tls.Config that supplies the
// server certificate. Callers are responsible for rotating certs and
// for enabling client authentication (VerifyClientCertificate) as
// required by their deployment.
type TLSListener struct {
	ln net.Listener
}

// ListenTLS binds a TLS-wrapped TCP socket on laddr. network is one of
// "tcp", "tcp4", or "tcp6". A nil laddr selects an ephemeral port on
// all interfaces. config must supply at least one certificate.
//
// The returned *TLSListener is ready to Accept; the caller is expected
// to Close it on shutdown to release the port.
func ListenTLS(network string, laddr *net.TCPAddr, config *tls.Config) (*TLSListener, error) {
	log := withFunc("transport.ListenTLS")
	if config == nil || len(config.Certificates) == 0 {
		return nil, fmt.Errorf("%w: tls.Config must supply at least one certificate",
			radiuserrors.ErrInvalidAttribute)
	}
	ln, err := tls.Listen(network, laddr.String(), config)
	if err != nil {
		log.Error("listen TLS failed", "error", err)
		return nil, err
	}
	log.Info("TLS listener bound",
		"network", network,
		"local", ln.Addr().String())
	return &TLSListener{ln: ln}, nil
}

// Accept blocks until a new TLS connection arrives or ctx is canceled.
// The returned *TLSConn owns the underlying *tls.Conn; the caller must
// Close it when finished.
//
// Accept returns ErrConnClosed after the listener is closed. A context
// cancellation does not interrupt the in-flight Accept on the listener;
// callers shutting down should also Close the listener.
func (l *TLSListener) Accept(ctx context.Context) (*TLSConn, error) {
	log := withFunc("transport.TLSListener.Accept")
	type acceptResult struct {
		conn *TLSConn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.ln.Accept()
		if err != nil {
			ch <- acceptResult{nil, err}
			return
		}
		// RFC 6614 §2.4: the TLS handshake must complete before the
		// connection is considered established. tls.Listener defers
		// the handshake to the first Read/Write, so we force it here
		// so that handshake failures are surfaced to Accept callers
		// rather than the first ReadPacket.
		if tc, ok := c.(*tls.Conn); ok {
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = c.Close()
				ch <- acceptResult{nil, err}
				return
			}
		}
		ch <- acceptResult{&TLSConn{c: c}, nil}
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
func (l *TLSListener) LocalAddr() net.Addr { return l.ln.Addr() }

// Close releases the underlying listener. Safe for concurrent calls.
func (l *TLSListener) Close() error { return l.ln.Close() }

// TLSConn is a single RADIUS/TLS connection. It shares the TCP packet
// framing (4-byte header with a 2-byte Length at offset 2..3) and adds
// the TLS record layer underneath.
type TLSConn struct {
	c       net.Conn
	writeMu sync.Mutex
}

// ReadPacket reads one RADIUS packet from the TLS connection. The
// packet is framed by the 2-byte RADIUS Length field, exactly as on a
// TCP connection (RFC 6613 §2.1, RFC 6614 §2.4).
//
// Returns ErrMalformedPacket if the declared Length is out of bounds or
// if the connection closes mid-packet (short read). Returns
// ErrConnClosed if the peer closed the connection cleanly, or
// ErrTimeout if the context deadline is exceeded.
func (c *TLSConn) ReadPacket(ctx context.Context) ([]byte, error) {
	return readFramedStream(c.c, ctx, withFunc("transport.TLSConn.ReadPacket"))
}

// WritePacket writes one RADIUS packet to the connection. Safe for
// concurrent callers.
func (c *TLSConn) WritePacket(raw []byte) error {
	return writeFramedPacket(c.c, raw, &c.writeMu, withFunc("transport.TLSConn.WritePacket"))
}

// RemoteAddr returns the peer's network address.
func (c *TLSConn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

// LocalAddr returns the local address of the connection.
func (c *TLSConn) LocalAddr() net.Addr { return c.c.LocalAddr() }

// Close closes the underlying connection. Safe for concurrent calls.
func (c *TLSConn) Close() error { return c.c.Close() }

// TLSClient is the client-side RADIUS/TLS transport. It maintains a
// persistent TLS connection to a server for synchronous request/response
// exchanges. Per RFC 6613 §2.6.1 (which RFC 6614 inherits) no
// retransmission is performed on the same connection; redialing and
// retrying on a new connection is the caller's responsibility.
//
// Concurrent calls to Exchange are serialized by an internal mutex.
type TLSClient struct {
	conn   *TLSConn
	exchMu sync.Mutex
}

// DialTLS dials a RADIUS/TLS server at server. network is one of "tcp",
// "tcp4", or "tcp6". config supplies the trusted CA pool and any
// client certificate required for mutual TLS.
//
// The TLS handshake is performed before DialTLS returns, so a handshake
// failure surfaces as an error from DialTLS rather than the first
// Exchange call.
func DialTLS(network string, server *net.TCPAddr, config *tls.Config) (*TLSClient, error) {
	log := withFunc("transport.DialTLS")
	d := &net.Dialer{Timeout: 30 * time.Second}
	c, err := tls.DialWithDialer(d, network, server.String(), config)
	if err != nil {
		log.Error("dial TLS failed", "error", err)
		return nil, err
	}
	if err := c.HandshakeContext(context.Background()); err != nil {
		_ = c.Close()
		return nil, err
	}
	log.Info("TLS connection established",
		"remote", c.RemoteAddr().String(),
		"local", c.LocalAddr().String())
	return &TLSClient{conn: &TLSConn{c: c}}, nil
}

// Exchange sends raw to the server and reads back one reply. The
// request/response pair is serialized with respect to other Exchange
// calls on the same client; concurrent calls block each other.
//
// The context deadline, if any, applies to both the write and the read.
// A timeout during the read returns ErrTimeout.
func (c *TLSClient) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()
	if err := c.conn.WritePacket(raw); err != nil {
		return nil, err
	}
	return c.conn.ReadPacket(ctx)
}

// LocalAddr returns the local address of the client's connection.
func (c *TLSClient) LocalAddr() net.Addr { return c.conn.c.LocalAddr() }

// Close closes the underlying connection.
func (c *TLSClient) Close() error { return c.conn.Close() }
