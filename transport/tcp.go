// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Daniel Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// TCPListener accepts incoming RADIUS/TCP connections (RFC 6613). Each
// accepted connection is returned as a *TCPConn which frames RADIUS
// packets using the existing 2-byte Length field at offset 2..3 of the
// header (RFC 6613 §2.1 — packet format unchanged from RFC 2865).
type TCPListener struct {
	ln *net.TCPListener
}

// ListenTCP binds a TCP socket on laddr. network is one of "tcp", "tcp4",
// or "tcp6". A nil laddr selects an ephemeral port on all interfaces.
func ListenTCP(network string, laddr *net.TCPAddr) (*TCPListener, error) {
	log := withFunc("transport.ListenTCP")
	ln, err := net.ListenTCP(network, laddr)
	if err != nil {
		log.Error("listen TCP failed", "error", err)
		return nil, err
	}
	log.Info("TCP listener bound",
		"network", network,
		"local", ln.Addr().String())
	return &TCPListener{ln: ln}, nil
}

// Accept blocks until a new connection arrives or ctx is canceled. The
// returned *TCPConn owns the underlying net.Conn; the caller must Close
// it when finished.
//
// If ctx is canceled while Accept is blocked, the in-flight Accept on the
// underlying listener is not interrupted; the goroutine running it will
// complete (or block indefinitely if no peer connects). Callers shutting
// down should also Close the listener to release any pending Accept.
func (l *TCPListener) Accept(ctx context.Context) (*TCPConn, error) {
	log := withFunc("transport.TCPListener.Accept")
	type acceptResult struct {
		conn *TCPConn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.ln.Accept()
		if err != nil {
			ch <- acceptResult{nil, err}
			return
		}
		ch <- acceptResult{&TCPConn{c: c}, nil}
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
func (l *TCPListener) LocalAddr() net.Addr { return l.ln.Addr() }

// Close releases the underlying listener. Safe for concurrent calls.
func (l *TCPListener) Close() error { return l.ln.Close() }

// TCPConn is a single RADIUS/TCP connection. It reads Length-framed packets
// and writes them back. WritePacket is safe for concurrent callers; only
// one goroutine may call ReadPacket at a time per connection.
type TCPConn struct {
	c       net.Conn
	writeMu sync.Mutex
}

// ReadPacket reads one RADIUS packet from the connection. The packet is
// framed by the 2-byte RADIUS Length field: a 4-byte header is read first,
// then Length-4 more bytes.
//
// Returns ErrMalformedPacket if the declared Length is out of bounds, or
// if the connection closes mid-packet (short read). Per RFC 6613 §2.6.4
// the caller should Close the connection on this error.
//
// Returns ErrConnClosed if the peer closed the connection cleanly, or
// ErrTimeout if the context deadline is exceeded.
func (c *TCPConn) ReadPacket(ctx context.Context) ([]byte, error) {
	log := withFunc("transport.TCPConn.ReadPacket")
	if err := c.applyReadDeadline(ctx); err != nil {
		if isClosed(err) {
			return nil, radiuserrors.ErrConnClosed
		}
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(c.c, header[:]); err != nil {
		return nil, mapReadErr(err, ctx)
	}
	length := binary.BigEndian.Uint16(header[2:4])
	if int(length) < types.PacketMinLength {
		log.Warn("malformed: length below minimum", "length", int(length))
		return nil, radiuserrors.ErrMalformedPacket
	}
	maxLen := types.PacketMaxLengthRFC2865
	if isAccountingCode(types.Code(header[0])) {
		maxLen = types.PacketMaxLengthRFC2866
	}
	if int(length) > maxLen {
		log.Warn("malformed: length above maximum",
			"length", int(length),
			"max", maxLen)
		return nil, radiuserrors.ErrMalformedPacket
	}
	payload := make([]byte, int(length)-4)
	if _, err := io.ReadFull(c.c, payload); err != nil {
		log.Warn("short read on payload", "error", err)
		return nil, mapReadErr(err, ctx)
	}
	out := make([]byte, int(length))
	copy(out[0:4], header[:])
	copy(out[4:], payload)
	log.Debug("read packet",
		"remote", c.c.RemoteAddr().String(),
		"length", int(length),
		"code", int(header[0]))
	return out, nil
}

// WritePacket writes one RADIUS packet to the connection. Safe for
// concurrent callers.
func (c *TCPConn) WritePacket(raw []byte) error {
	log := withFunc("transport.TCPConn.WritePacket")
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.c.Write(raw)
	if err != nil {
		if isClosed(err) {
			return radiuserrors.ErrConnClosed
		}
		return err
	}
	if n != len(raw) {
		log.Warn("short write",
			"written", n,
			"expected", len(raw))
		return radiuserrors.ErrShortBuffer
	}
	log.Debug("sent packet",
		"remote", c.c.RemoteAddr().String(),
		"length", n)
	return nil
}

// RemoteAddr returns the peer's network address.
func (c *TCPConn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

// LocalAddr returns the local address of the connection.
func (c *TCPConn) LocalAddr() net.Addr { return c.c.LocalAddr() }

// Close closes the underlying connection. Safe for concurrent calls.
func (c *TCPConn) Close() error { return c.c.Close() }

// applyReadDeadline translates the context deadline into a SetReadDeadline
// call. A context without a deadline clears any prior deadline.
func (c *TCPConn) applyReadDeadline(ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		return c.c.SetReadDeadline(dl)
	}
	return c.c.SetReadDeadline(time.Time{})
}

// TCPClient is the client-side TCP transport: maintains a persistent
// connection to a server for synchronous request/response exchanges.
// Per RFC 6613 §2.6.1 no retransmission is performed on the same
// connection; redialing and retrying on a new connection is the caller's
// responsibility.
//
// Concurrent calls to Exchange are serialized by an internal mutex. For
// multiplexed concurrent in-flight requests, the protocol layer should
// use DialTCP followed by direct TCPConn.WritePacket / ReadPacket calls
// with Identifier-based demultiplexing.
type TCPClient struct {
	conn   *TCPConn
	server *net.TCPAddr
	exMu   sync.Mutex
}

// DialTCP opens a TCP connection to server.
func DialTCP(network string, server *net.TCPAddr) (*TCPClient, error) {
	log := withFunc("transport.DialTCP")
	c, err := net.DialTCP(network, nil, server)
	if err != nil {
		log.Error("dial TCP failed", "error", err)
		return nil, err
	}
	log.Info("TCP client dialed",
		"network", network,
		"server", server.String(),
		"local", c.LocalAddr().String())
	return &TCPClient{conn: &TCPConn{c: c}, server: server}, nil
}

// Exchange sends raw to the server and returns the reply. The context
// deadline bounds both the write and the read.
func (c *TCPClient) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	log := withFunc("transport.TCPClient.Exchange")
	c.exMu.Lock()
	defer c.exMu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		if err := c.conn.c.SetDeadline(dl); err != nil {
			return nil, err
		}
	}
	if err := c.conn.WritePacket(raw); err != nil {
		return nil, err
	}
	reply, err := c.conn.ReadPacket(ctx)
	if err != nil {
		return nil, err
	}
	log.Debug("exchange complete",
		"server", c.server.String(),
		"req_len", len(raw),
		"resp_len", len(reply))
	return reply, nil
}

// LocalAddr returns the local address of the client's underlying connection.
func (c *TCPClient) LocalAddr() net.Addr { return c.conn.c.LocalAddr() }

// Close closes the underlying connection. Safe for concurrent calls.
func (c *TCPClient) Close() error { return c.conn.Close() }

// mapReadErr converts errors returned by io.ReadFull into the package's
// sentinel errors. A clean EOF or unexpected EOF (mid-packet close) is
// treated as a closed connection. Timeouts and closed-socket errors map
// to their respective sentinels.
func mapReadErr(err error, ctx context.Context) error {
	if err == nil {
		return nil
	}
	if isClosed(err) {
		return radiuserrors.ErrConnClosed
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return radiuserrors.ErrConnClosed
	}
	if isTimeout(err, ctx) {
		return radiuserrors.ErrTimeout
	}
	return err
}

// isAccountingCode reports whether code is an accounting-family code
// (RFC 2866), used to select the tighter 4095-octet maximum packet
// length on TCP framing.
func isAccountingCode(code types.Code) bool {
	return code.IsAccounting()
}
