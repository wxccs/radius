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
	"net"
	"sync"
	"time"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/types"
)

// udpReadBufferSize is the upper bound on a single datagram read. RADIUS
// packets cannot exceed 4096 octets on the wire (RFC 2865 §3), so this
// buffer always contains exactly one packet.
const udpReadBufferSize = types.PacketMaxLengthRFC2865

// UDPTransport implements PacketListener over a UDP socket (RFC 2865,
// RFC 3162). Safe for concurrent SendPacket calls; ReadPacket is
// intended for a single reader goroutine per socket.
type UDPTransport struct {
	conn    *net.UDPConn
	writeMu sync.Mutex
}

// ListenUDP binds a UDP socket on laddr. network is one of "udp", "udp4",
// or "udp6" and is forwarded to net.ListenUDP. A nil laddr selects an
// ephemeral port on all interfaces.
func ListenUDP(network string, laddr *net.UDPAddr) (*UDPTransport, error) {
	log := withFunc("transport.ListenUDP")
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		log.Error("listen UDP failed", "error", err)
		return nil, err
	}
	log.Info("UDP listener bound",
		"network", network,
		"local", conn.LocalAddr().String())
	return &UDPTransport{conn: conn}, nil
}

// ReadPacket reads one UDP datagram containing a RADIUS packet. The
// context deadline, if any, is applied to the underlying read.
//
// Returns ErrTimeout if the context deadline is exceeded, ErrConnClosed
// if the socket has been closed, or the underlying I/O error otherwise.
func (t *UDPTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	log := withFunc("transport.UDPTransport.ReadPacket")
	if err := t.applyReadDeadline(ctx); err != nil {
		if isClosed(err) {
			return nil, nil, radiuserrors.ErrConnClosed
		}
		return nil, nil, err
	}
	buf := make([]byte, udpReadBufferSize)
	n, src, err := t.conn.ReadFrom(buf)
	if err != nil {
		if isClosed(err) {
			log.Info("socket closed")
			return nil, nil, radiuserrors.ErrConnClosed
		}
		if isTimeout(err, ctx) {
			log.Debug("read timeout")
			return nil, nil, radiuserrors.ErrTimeout
		}
		// Surface the underlying error to the caller; the caller decides
		// whether to log it as Error. Transport stays silent to avoid
		// double-logging the same failure on both layers.
		return nil, nil, err
	}
	data := make([]byte, n)
	copy(data, buf[:n])
	log.Debug("read packet",
		"src", src.String(),
		"length", n)
	return data, src, nil
}

// SendPacket writes data to dst as a single UDP datagram. Safe for
// concurrent callers.
func (t *UDPTransport) SendPacket(data []byte, dst net.Addr) error {
	log := withFunc("transport.UDPTransport.SendPacket")
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	n, err := t.conn.WriteTo(data, dst)
	if err != nil {
		if isClosed(err) {
			return radiuserrors.ErrConnClosed
		}
		return err
	}
	if n != len(data) {
		log.Warn("short write",
			"written", n,
			"expected", len(data))
		return radiuserrors.ErrShortBuffer
	}
	log.Debug("sent packet",
		"dst", dst.String(),
		"length", n)
	return nil
}

// LocalAddr returns the local address the transport is bound to.
func (t *UDPTransport) LocalAddr() net.Addr { return t.conn.LocalAddr() }

// Close releases the underlying socket. Safe for concurrent calls.
func (t *UDPTransport) Close() error { return t.conn.Close() }

// applyReadDeadline translates the context deadline into a SetReadDeadline
// call. A context without a deadline clears any prior deadline so that
// the read blocks indefinitely.
func (t *UDPTransport) applyReadDeadline(ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		return t.conn.SetReadDeadline(dl)
	}
	return t.conn.SetReadDeadline(time.Time{})
}

// UDPClient is the client-side UDP transport: sends requests to a fixed
// server and reads replies. Each Exchange call performs one write and
// one read; retransmission is the caller's responsibility.
type UDPClient struct {
	conn    *net.UDPConn
	server  *net.UDPAddr
	writeMu sync.Mutex
}

// DialUDP opens a UDP socket bound to laddr (or ephemeral if nil) and
// configures it to exchange packets with server.
func DialUDP(network string, server *net.UDPAddr, laddr *net.UDPAddr) (*UDPClient, error) {
	log := withFunc("transport.DialUDP")
	conn, err := net.DialUDP(network, laddr, server)
	if err != nil {
		log.Error("dial UDP failed", "error", err)
		return nil, err
	}
	log.Info("UDP client dialed",
		"network", network,
		"server", server.String(),
		"local", conn.LocalAddr().String())
	return &UDPClient{conn: conn, server: server}, nil
}

// Exchange sends raw to the configured server and returns the reply.
// The context deadline bounds both the write and the read. Replies
// from a source address other than the server are silently discarded
// (per RFC 2865 §3 guidance for stray packets) and Exchange continues
// to wait until the deadline.
func (c *UDPClient) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	log := withFunc("transport.UDPClient.Exchange")
	if err := c.applyDeadline(ctx); err != nil {
		if isClosed(err) {
			return nil, radiuserrors.ErrConnClosed
		}
		return nil, err
	}
	c.writeMu.Lock()
	n, err := c.conn.Write(raw)
	c.writeMu.Unlock()
	if err != nil {
		if isClosed(err) {
			return nil, radiuserrors.ErrConnClosed
		}
		if isTimeout(err, ctx) {
			return nil, radiuserrors.ErrTimeout
		}
		return nil, err
	}
	if n != len(raw) {
		log.Warn("short write",
			"written", n,
			"expected", len(raw))
		return nil, radiuserrors.ErrShortBuffer
	}
	buf := make([]byte, udpReadBufferSize)
	for {
		n, src, err := c.conn.ReadFrom(buf)
		if err != nil {
			if isClosed(err) {
				return nil, radiuserrors.ErrConnClosed
			}
			if isTimeout(err, ctx) {
				return nil, radiuserrors.ErrTimeout
			}
			return nil, err
		}
		if !udpAddrEqual(src, c.server) {
			log.Warn("stray packet from unknown peer",
				"src", src.String(),
				"server", c.server.String())
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		log.Debug("exchange complete",
			"server", c.server.String(),
			"req_len", len(raw),
			"resp_len", n)
		return data, nil
	}
}

// LocalAddr returns the local address the client socket is bound to.
func (c *UDPClient) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Close releases the underlying socket. Safe for concurrent calls.
func (c *UDPClient) Close() error { return c.conn.Close() }

// applyDeadline sets both read and write deadlines from ctx. A context
// without a deadline clears any prior deadline.
func (c *UDPClient) applyDeadline(ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := c.conn.SetReadDeadline(dl); err != nil {
			return err
		}
		return c.conn.SetWriteDeadline(dl)
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	_ = c.conn.SetWriteDeadline(time.Time{})
	return nil
}

// udpAddrEqual reports whether a and b refer to the same UDP endpoint
// (IP, port, zone). Used to discard stray UDP replies.
func udpAddrEqual(a, b net.Addr) bool {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	ub, ok := b.(*net.UDPAddr)
	if !ok {
		return false
	}
	return ua.IP.Equal(ub.IP) && ua.Port == ub.Port && ua.Zone == ub.Zone
}
