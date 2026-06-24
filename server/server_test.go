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

package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/client"
	radiuslog "github.com/wxccs/radius/log"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/types"
)

// echoHandler replies with Access-Accept for any Access-Request, echoing
// the Request Authenticator so the client's VerifyResponse passes.
type echoHandler struct {
	mu       sync.Mutex
	requests int
}

func (h *echoHandler) Handle(_ context.Context, req *Request) (*packet.Packet, error) {
	h.mu.Lock()
	h.requests++
	h.mu.Unlock()
	if req.Code != types.AccessRequest {
		return nil, nil
	}
	return &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    req.Identifier,
		Authenticator: req.Authenticator,
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrReplyMessage, "accepted"),
		},
	}, nil
}

func TestUDPServer_Authenticate(t *testing.T) {
	secret := []byte("server-test-secret")
	h := &echoHandler{}
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr, ok := srv.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// Give the server a tick to start.
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "pw"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)

	h.mu.Lock()
	defer h.mu.Unlock()
	assert.Equal(t, 1, h.requests, "handler must be invoked exactly once")
}

func TestUDPServer_DropsUnknownClient(t *testing.T) {
	secret := []byte("server-test-secret")
	h := &echoHandler{}
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, func(net.IP) ([]byte, bool) { return nil, false })
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr, ok := srv.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1, Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err, "unknown client must not receive a reply")

	h.mu.Lock()
	defer h.mu.Unlock()
	assert.Equal(t, 0, h.requests, "handler must not be invoked for unknown clients")
}

func TestUDPServer_HandlerReturnsNil(t *testing.T) {
	secret := []byte("silent-secret")
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(context.Context, *Request) (*packet.Packet, error) {
			return nil, nil
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr, ok := srv.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1, Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err, "nil reply must cause client timeout")
}

func TestUDPServer_MalformedPacketDropped(t *testing.T) {
	secret := []byte("malformed-secret")
	h := &echoHandler{}
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr, ok := srv.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	// Send a raw malformed packet directly over a plain UDP socket.
	conn, err := net.DialUDP("udp4", nil, addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// 4 bytes is below PacketMinLength; server must drop silently.
	_, err = conn.Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)

	// Give the server time to process and drop.
	time.Sleep(50 * time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	assert.Equal(t, 0, h.requests, "malformed packets must not reach the handler")
}

func TestTCPServer_Authenticate(t *testing.T) {
	secret := []byte("tcp-server-secret")
	h := &echoHandler{}
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr, ok := srv.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewTCPClient(addr, secret, client.Config{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "pw"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

func TestTCPServer_DropsUnknownClient(t *testing.T) {
	secret := []byte("tcp-server-secret")
	h := &echoHandler{}
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, func(net.IP) ([]byte, bool) { return nil, false })
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	// A raw TCP connection should be accepted and immediately closed by
	// the server because the client IP is not in the secret table.
	conn, err := net.DialTCP("tcp4", nil, srv.LocalAddr().(*net.TCPAddr))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a valid Access-Request; the server should close the connection
	// without replying.
	pkt := &packet.Packet{
		Code:          types.AccessRequest,
		Identifier:    1,
		Authenticator: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Attributes:    []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	}
	raw, err := pkt.Marshal(secret)
	require.NoError(t, err)
	_, err = conn.Write(raw)
	require.NoError(t, err)

	// Read should return EOF (connection closed by server) or a short read.
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buf)
	assert.Error(t, err, "server should close connection from unknown client")
	assert.Equal(t, 0, n)

	h.mu.Lock()
	defer h.mu.Unlock()
	assert.Equal(t, 0, h.requests)
}

func TestHandlerFunc(t *testing.T) {
	called := false
	f := HandlerFunc(func(_ context.Context, _ *Request) (*packet.Packet, error) {
		called = true
		return nil, nil
	})
	_, _ = f.Handle(context.Background(), &Request{Packet: &packet.Packet{}})
	assert.True(t, called)
}

func TestAccessHandler(t *testing.T) {
	t.Run("access_request_dispatched", func(t *testing.T) {
		h := &AccessHandler{
			OnAccess: func(_ context.Context, req *Request) (*packet.Packet, error) {
				return &packet.Packet{
					Code:          types.AccessAccept,
					Identifier:    req.Identifier,
					Authenticator: req.Authenticator,
				}, nil
			},
		}
		reply, err := h.Handle(context.Background(), &Request{
			Packet: &packet.Packet{Code: types.AccessRequest, Identifier: 7},
		})
		require.NoError(t, err)
		require.NotNil(t, reply)
		assert.Equal(t, types.AccessAccept, reply.Code)
	})

	t.Run("other_code_dropped", func(t *testing.T) {
		h := &AccessHandler{
			OnAccess: func(context.Context, *Request) (*packet.Packet, error) {
				t.Fatal("OnAccess must not be called for non-Access-Request")
				return nil, nil
			},
		}
		reply, err := h.Handle(context.Background(), &Request{
			Packet: &packet.Packet{Code: types.AccountingRequest},
		})
		require.NoError(t, err)
		assert.Nil(t, reply)
	})
}

func TestAccountingHandler(t *testing.T) {
	h := &AccountingHandler{
		OnAccount: func(_ context.Context, req *Request) (*packet.Packet, error) {
			return &packet.Packet{
				Code:          types.AccountingResponse,
				Identifier:    req.Identifier,
				Authenticator: req.Authenticator,
			}, nil
		},
	}
	reply, err := h.Handle(context.Background(), &Request{
		Packet: &packet.Packet{Code: types.AccountingRequest, Identifier: 3},
	})
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.Equal(t, types.AccountingResponse, reply.Code)

	// Non-accounting codes are silently dropped.
	reply, err = h.Handle(context.Background(), &Request{
		Packet: &packet.Packet{Code: types.AccessRequest},
	})
	require.NoError(t, err)
	assert.Nil(t, reply)
}

func TestUDPServer_ServeContextCancel(t *testing.T) {
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx) }()
	cancel()
	// Close the listener to unblock the in-flight ReadPacket.
	_ = srv.Close()

	select {
	case err := <-serveErr:
		// Either ctx.Err() or a closed-listener error is acceptable.
		assert.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit within 1s of Close")
	}
}

func TestStaticSecret(t *testing.T) {
	lookup := StaticSecret([]byte("shared"))
	got, ok := lookup(net.IPv4(10, 0, 0, 1))
	assert.True(t, ok)
	assert.Equal(t, []byte("shared"), got)
}

func TestIPFromAddr(t *testing.T) {
	t.Run("udp_addr", func(t *testing.T) {
		ip := ipFromAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1812})
		assert.True(t, ip.Equal(net.IPv4(10, 0, 0, 1)))
	})
	t.Run("tcp_addr", func(t *testing.T) {
		ip := ipFromAddr(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1812})
		assert.True(t, ip.Equal(net.IPv4(10, 0, 0, 2)))
	})
	t.Run("ip_addr", func(t *testing.T) {
		ip := ipFromAddr(&net.IPAddr{IP: net.IPv4(10, 0, 0, 3)})
		assert.True(t, ip.Equal(net.IPv4(10, 0, 0, 3)))
	})
	t.Run("unknown_type", func(t *testing.T) {
		ip := ipFromAddr(&net.UnixAddr{})
		assert.Nil(t, ip)
	})
}

func TestUDPServer_HandlerError(t *testing.T) {
	secret := []byte("handler-err-secret")
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(context.Context, *Request) (*packet.Packet, error) {
			return nil, assert.AnError
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1, Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err, "handler error must surface as a timeout to the client")
}

func TestUDPServer_MarshalReplyError(t *testing.T) {
	secret := []byte("marshal-err-secret")
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
			return &packet.Packet{
				Code:       types.AccessAccept,
				Identifier: req.Identifier,
				// An over-length attribute value triggers a marshal error.
				Attributes: []packet.Attribute{{Type: 1, Value: make([]byte, 254)}},
			}, nil
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1, Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err, "marshal failure must surface as a timeout to the client")
}

func TestUDPServer_WithLogger(t *testing.T) {
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")),
		WithUDPLogger(nil))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()
	assert.NotNil(t, srv.log)

	srv2, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")),
		WithUDPLogger(nil))
	require.NoError(t, err)
	defer func() { _ = srv2.Close() }()
}

func TestTCPServer_WithLogger(t *testing.T) {
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")),
		WithTCPLogger(nil))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()
	assert.NotNil(t, srv.log)
}

func TestTCPServer_HandlerReturnsNil(t *testing.T) {
	secret := []byte("tcp-silent-secret")
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(context.Context, *Request) (*packet.Packet, error) {
			return nil, nil
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	// Open a TCP connection and send a request; the server should keep the
	// connection open (nil reply does not close TCP), so a follow-up read
	// should time out rather than EOF.
	c, err := client.NewTCPClient(addr, secret, client.Config{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err)
}

func TestTCPServer_MalformedPacketClosesConnection(t *testing.T) {
	secret := []byte("tcp-malformed-secret")
	h := &echoHandler{}
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		h, StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	conn, err := net.DialTCP("tcp4", nil, addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a 4-byte short packet (below PacketMinLength). The server's
	// ReadPacket will fail with ErrMalformedPacket and close the connection.
	_, err = conn.Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	assert.Error(t, err, "server must close the connection on a malformed packet")
}

func TestTCPServer_ServeContextCancel(t *testing.T) {
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx) }()
	cancel()
	_ = srv.Close()
	select {
	case err := <-serveErr:
		assert.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit within 1s")
	}
}

func TestNewUDPServer_ListenFailure(t *testing.T) {
	// An invalid network must surface the listen error.
	_, err := NewUDPServer("invalid-net",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")))
	assert.Error(t, err)
}

func TestNewTCPServer_ListenFailure(t *testing.T) {
	_, err := NewTCPServer("invalid-net",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")))
	assert.Error(t, err)
}

func TestWithUDPLogger_Real(t *testing.T) {
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")),
		WithUDPLogger(radiuslog.NopLogger{}))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()
}

func TestWithTCPLogger_Real(t *testing.T) {
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&echoHandler{}, StaticSecret([]byte("s")),
		WithTCPLogger(radiuslog.NopLogger{}))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()
}

func TestUDPServer_SendReplyFailure(t *testing.T) {
	// Close the server's listener after the handler runs, so SendPacket
	// fails on the closed socket. We use a handler that closes the listener
	// before returning its reply.
	secret := []byte("send-fail-secret")
	var srv *UDPServer
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
			// Close the listener mid-handler so the subsequent SendPacket
			// returns ErrConnClosed.
			_ = srv.Close()
			return &packet.Packet{
				Code:          types.AccessAccept,
				Identifier:    req.Identifier,
				Authenticator: req.Authenticator,
			}, nil
		}),
		StaticSecret(secret))
	require.NoError(t, err)

	addr := srv.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewUDPClient(addr, secret, client.Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1, Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond},
	})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	_, _ = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	// No assertion on the error: the test's goal is to exercise the
	// SendPacket-failure branch in handleOne without panicking.
}

func TestTCPServer_HandlerErrorClosesConnection(t *testing.T) {
	secret := []byte("tcp-handler-err-secret")
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(context.Context, *Request) (*packet.Packet, error) {
			return nil, assert.AnError
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewTCPClient(addr, secret, client.Config{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err, "handler error should close the TCP connection and surface to the client")
}

func TestTCPServer_MarshalReplyError(t *testing.T) {
	secret := []byte("tcp-marshal-err-secret")
	srv, err := NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
			return &packet.Packet{
				Code:       types.AccessAccept,
				Identifier: req.Identifier,
				Attributes: []packet.Attribute{{Type: 1, Value: make([]byte, 254)}},
			}, nil
		}),
		StaticSecret(secret))
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.LocalAddr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(10 * time.Millisecond)

	c, err := client.NewTCPClient(addr, secret, client.Config{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer callCancel()
	_, err = c.Authenticate(callCtx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err)
}
