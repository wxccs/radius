// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 wxccs
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

// Package server implements a RADIUS server framework over the transport
// and packet layers.
//
// A Server listens for incoming RADIUS packets and dispatches them to a
// user-supplied Handler. The Handler receives the parsed request packet
// along with the shared secret and the source network address, and returns
// the reply packet to send back. The Server takes care of:
//
//   - Reading and framing packets (UDP datagrams or TCP Length-framed
//     messages, per RFC 6613 §2.1).
//   - Verifying the Request Authenticator for Accounting-Request,
//     CoA-Request, and Disconnect-Request (RFC 2866 §3, RFC 5176 §2.3).
//   - Marshaling the reply, including computing the Response Authenticator
//     and (when present) the Message-Authenticator HMAC.
//
// The Server does NOT enforce request-rate limiting, duplicate detection,
// or per-client state. Those concerns belong to a higher-level session
// package that may be layered on top.
package server

import (
	"context"
	"net"

	radiuslog "github.com/wxccs/radius/log"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/transport"
	"github.com/wxccs/radius/types"
)

// Request bundles the parsed packet, the shared secret used to verify it,
// and the source network address. Handlers may inspect Attributes directly
// on the embedded Packet.
type Request struct {
	// Packet is the parsed incoming RADIUS packet. Its Authenticator
	// field holds the Request Authenticator; for Access-Request this is
	// the caller-supplied random value, for Accounting-Request / CoA /
	// DM-Request it is the MD5-derived value already verified by
	// packet.Unmarshal.
	*packet.Packet

	// Secret is the shared secret agreed with the client. Handlers MUST
	// pass this to packet.Marshal when building the reply so that the
	// Response Authenticator is computed correctly.
	Secret []byte

	// RemoteAddr is the source network address of the request.
	RemoteAddr net.Addr
}

// Handler processes a single RADIUS request and returns the reply to send
// back to the client. Returning a nil Packet signals "no response"; the
// Server silently drops the request (per RFC 2865 §3 guidance for
// malformed or unwanted packets).
//
// Handlers must be safe for concurrent use: the Server invokes Handle from
// multiple goroutines (one per in-flight request on UDP, one per TCP
// connection).
type Handler interface {
	Handle(ctx context.Context, req *Request) (*packet.Packet, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*packet.Packet, error)

// Handle calls f(ctx, req).
func (f HandlerFunc) Handle(ctx context.Context, req *Request) (*packet.Packet, error) {
	return f(ctx, req)
}

// SecretLookup returns the shared secret to use for a given client. The
// key is the client's source IP (without port). Returning ok=false tells
// the Server to silently drop the packet (RFC 2865 §3 allows servers to
// ignore packets from unknown clients).
//
// Callers that use a single shared secret for all clients can pass the
// StaticSecret helper.
type SecretLookup func(remoteIP net.IP) (secret []byte, ok bool)

// StaticSecret returns a SecretLookup that always returns the same secret
// regardless of the client address. Suitable for single-client deployments
// and for tests.
func StaticSecret(secret []byte) SecretLookup {
	return func(net.IP) ([]byte, bool) {
		return secret, true
	}
}

// UDPServer listens for RADIUS-over-UDP packets and dispatches them to a
// Handler. A single socket serves all clients; each request is handled in
// its own goroutine so a slow handler does not block other clients.
type UDPServer struct {
	listener *transport.UDPTransport
	handler  Handler
	lookup   SecretLookup
	log      radiuslog.Logger
}

// UDPOption configures a UDPServer at construction time.
type UDPOption func(*UDPServer)

// WithUDPLogger injects a logger into the server. nil falls back to
// log.Default.
func WithUDPLogger(l radiuslog.Logger) UDPOption {
	return func(s *UDPServer) {
		if l == nil {
			s.log = radiuslog.NopLogger{}
			return
		}
		s.log = l
	}
}

// NewUDPServer binds a UDP socket on laddr and returns a Server ready to
// serve requests via Serve. The Server does not start reading until Serve
// is called.
func NewUDPServer(network string, laddr *net.UDPAddr, handler Handler, lookup SecretLookup, opts ...UDPOption) (*UDPServer, error) {
	ln, err := transport.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	s := &UDPServer{
		listener: ln,
		handler:  handler,
		lookup:   lookup,
		log:      radiuslog.Default,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// LocalAddr returns the address the server is bound to.
func (s *UDPServer) LocalAddr() net.Addr { return s.listener.LocalAddr() }

// Serve reads packets from the socket and dispatches them to the handler
// until ctx is canceled or the listener is closed. Each packet is handled
// in its own goroutine so a slow handler does not block other clients.
//
// Canceling ctx does not interrupt an in-flight ReadPacket on the
// underlying UDP socket; callers shutting down should also call Close to
// release the reader.
func (s *UDPServer) Serve(ctx context.Context) error {
	log := s.log.With("func", "server.UDPServer.Serve")
	for {
		raw, src, err := s.listener.ReadPacket(ctx)
		if err != nil {
			return s.mapReadErr(ctx, err)
		}
		remoteIP := ipFromAddr(src)
		secret, ok := s.lookup(remoteIP)
		if !ok {
			log.Warn("dropping packet from unknown client", "src", src.String())
			continue
		}
		go s.handleOne(ctx, raw, src, secret)
	}
}

// handleOne parses, dispatches, and replies to a single request. Errors
// here are logged but never returned to the caller: a single bad packet
// must not bring down the server.
func (s *UDPServer) handleOne(ctx context.Context, raw []byte, src net.Addr, secret []byte) {
	log := s.log.With("func", "server.UDPServer.handleOne")
	pkt := &packet.Packet{}
	if err := pkt.Unmarshal(raw, secret); err != nil {
		log.Warn("dropping malformed packet",
			"src", src.String(),
			"error", err)
		return
	}
	log.Debug("request received",
		"src", src.String(),
		"code", pkt.Code.String(),
		"id", int(pkt.Identifier))

	req := &Request{
		Packet:     pkt,
		Secret:     secret,
		RemoteAddr: src,
	}
	reply, err := s.handler.Handle(ctx, req)
	if err != nil {
		log.Warn("handler error",
			"src", src.String(),
			"id", int(pkt.Identifier),
			"error", err)
		return
	}
	if reply == nil {
		// Handler chose to remain silent.
		return
	}
	out, err := reply.Marshal(secret)
	if err != nil {
		log.Error("marshal reply failed",
			"src", src.String(),
			"id", int(pkt.Identifier),
			"error", err)
		return
	}
	if err := s.listener.SendPacket(out, src); err != nil {
		log.Warn("send reply failed",
			"src", src.String(),
			"id", int(pkt.Identifier),
			"error", err)
	}
}

// mapReadErr translates a transport-layer read error into either nil
// (graceful shutdown) or the underlying error.
func (s *UDPServer) mapReadErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// If the context was canceled or the listener closed, treat as shutdown.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// Close releases the underlying socket. Safe to call concurrently with
// Serve; the in-flight ReadPacket will return an error and Serve will exit.
func (s *UDPServer) Close() error { return s.listener.Close() }

// TCPServer listens for RADIUS-over-TCP connections (RFC 6613). Each
// accepted connection is handled in its own goroutine; requests on a
// single connection are processed sequentially (the connection's
// ReadPacket is not safe for concurrent callers).
type TCPServer struct {
	listener *transport.TCPListener
	handler  Handler
	lookup   SecretLookup
	log      radiuslog.Logger
}

// TCPOption configures a TCPServer at construction time.
type TCPOption func(*TCPServer)

// WithTCPLogger injects a logger into the server.
func WithTCPLogger(l radiuslog.Logger) TCPOption {
	return func(s *TCPServer) {
		if l == nil {
			s.log = radiuslog.NopLogger{}
			return
		}
		s.log = l
	}
}

// NewTCPServer binds a TCP socket on laddr.
func NewTCPServer(network string, laddr *net.TCPAddr, handler Handler, lookup SecretLookup, opts ...TCPOption) (*TCPServer, error) {
	ln, err := transport.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	s := &TCPServer{
		listener: ln,
		handler:  handler,
		lookup:   lookup,
		log:      radiuslog.Default,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// LocalAddr returns the address the server is bound to.
func (s *TCPServer) LocalAddr() net.Addr { return s.listener.LocalAddr() }

// Serve accepts connections and spawns a per-connection handler until
// ctx is canceled or the listener is closed.
func (s *TCPServer) Serve(ctx context.Context) error {
	log := s.log.With("func", "server.TCPServer.Serve")
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}
		log.Info("connection accepted", "remote", conn.RemoteAddr().String())
		go s.handleConn(ctx, conn)
	}
}

// handleConn processes requests on a single TCP connection until the
// client closes it or a malformed packet is received (RFC 6613 §2.6.4
// mandates closing the connection on a framing error).
func (s *TCPServer) handleConn(ctx context.Context, conn *transport.TCPConn) {
	log := s.log.With("func", "server.TCPServer.handleConn")
	defer func() { _ = conn.Close() }()
	remoteIP := ipFromAddr(conn.RemoteAddr())
	secret, ok := s.lookup(remoteIP)
	if !ok {
		log.Warn("closing connection from unknown client",
			"remote", conn.RemoteAddr().String())
		return
	}
	for {
		raw, err := conn.ReadPacket(ctx)
		if err != nil {
			log.Debug("connection read ended",
				"remote", conn.RemoteAddr().String(),
				"error", err)
			return
		}
		pkt := &packet.Packet{}
		if err := pkt.Unmarshal(raw, secret); err != nil {
			log.Warn("dropping malformed packet",
				"remote", conn.RemoteAddr().String(),
				"error", err)
			// Per RFC 6613 §2.6.4 close on framing errors. A malformed
			// RADIUS Length field qualifies.
			return
		}
		req := &Request{
			Packet:     pkt,
			Secret:     secret,
			RemoteAddr: conn.RemoteAddr(),
		}
		reply, err := s.handler.Handle(ctx, req)
		if err != nil {
			log.Warn("handler error",
				"remote", conn.RemoteAddr().String(),
				"id", int(pkt.Identifier),
				"error", err)
			return
		}
		if reply == nil {
			continue
		}
		out, err := reply.Marshal(secret)
		if err != nil {
			log.Error("marshal reply failed",
				"remote", conn.RemoteAddr().String(),
				"id", int(pkt.Identifier),
				"error", err)
			return
		}
		if err := conn.WritePacket(out); err != nil {
			log.Warn("send reply failed",
				"remote", conn.RemoteAddr().String(),
				"id", int(pkt.Identifier),
				"error", err)
			return
		}
	}
}

// Close releases the underlying listener.
func (s *TCPServer) Close() error { return s.listener.Close() }

// ipFromAddr extracts the IP portion of a net.Addr. Returns nil for
// non-IP addresses (which will then fail SecretLookup and be dropped).
func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// AccessHandler is a convenience type for handlers that only care about
// Access-Request. It dispatches Access-Request to OnAccess and returns
// nil (silent drop) for every other code.
type AccessHandler struct {
	OnAccess func(ctx context.Context, req *Request) (*packet.Packet, error)
}

// Handle implements Handler.
func (h *AccessHandler) Handle(ctx context.Context, req *Request) (*packet.Packet, error) {
	if req.Code != types.AccessRequest {
		return nil, nil
	}
	return h.OnAccess(ctx, req)
}

// AccountingHandler dispatches Accounting-Request to OnAccount and drops
// other codes.
type AccountingHandler struct {
	OnAccount func(ctx context.Context, req *Request) (*packet.Packet, error)
}

// Handle implements Handler.
func (h *AccountingHandler) Handle(ctx context.Context, req *Request) (*packet.Packet, error) {
	if req.Code != types.AccountingRequest {
		return nil, nil
	}
	return h.OnAccount(ctx, req)
}
