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

// Package integration contains end-to-end tests that exercise the full
// client→transport→server stack against a real in-process RADIUS server.
// Each subtest spins up a server on a kernel-assigned loopback port, points
// a client at it, and asserts that the round-trip reply matches expectations.
package integration

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/client"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/server"
	"github.com/wxccs/radius/types"
)

const testSecret = "integration-secret"

// callTimeout bounds each client call. We pass an explicit deadline because
// client.Config.Timeout is not yet wired through the protocol layer; the CLI
// applies its own deadline via context.WithTimeout, and tests do the same.
const callTimeout = 3 * time.Second

// loopbackHandler records the last request seen and replies with a
// caller-chosen code. It lets every subtest share one handler factory while
// still customizing the reply per request type.
func loopbackHandler(replyCode types.Code, attr packet.Attribute) server.Handler {
	return server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
		attrs := []packet.Attribute{attr}
		// Echo the User-Name back so the client can verify attribute round-trip.
		if u, ok := findAttr(req.Attributes, types.AttrUserName); ok {
			attrs = append(attrs, u)
		}
		return &packet.Packet{
			Code:          replyCode,
			Identifier:    req.Identifier,
			Authenticator: req.Authenticator,
			Attributes:    attrs,
		}, nil
	})
}

func findAttr(attrs []packet.Attribute, t byte) (packet.Attribute, bool) {
	for _, a := range attrs {
		if a.Type == t {
			return a, true
		}
	}
	return packet.Attribute{}, false
}

func mustSplitHostPort(t *testing.T, addr net.Addr) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr.String())
	require.NoError(t, err)
	port, err := net.LookupPort("network", portStr)
	require.NoError(t, err)
	return host, port
}

// startUDPServer starts a UDP server on a kernel-assigned loopback port and
// returns its address. The server runs on a background goroutine that exits
// when ctx is canceled or the listener closes (t.Cleanup closes it).
func startUDPServer(t *testing.T, ctx context.Context, handler server.Handler) *net.UDPAddr {
	t.Helper()
	srv, err := server.NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		handler, server.StaticSecret([]byte(testSecret)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	go func() { _ = srv.Serve(ctx) }()

	addr := srv.LocalAddr().(*net.UDPAddr)
	host, port := mustSplitHostPort(t, addr)
	return &net.UDPAddr{IP: net.ParseIP(host), Port: port}
}

func startTCPServer(t *testing.T, ctx context.Context, handler server.Handler) *net.TCPAddr {
	t.Helper()
	srv, err := server.NewTCPServer("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		handler, server.StaticSecret([]byte(testSecret)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	go func() { _ = srv.Serve(ctx) }()

	addr := srv.LocalAddr().(*net.TCPAddr)
	host, port := mustSplitHostPort(t, addr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func newUDPClient(t *testing.T, addr *net.UDPAddr) (*protocol.Client, func()) {
	t.Helper()
	c, err := client.NewUDPClient(addr, []byte(testSecret), client.Config{})
	require.NoError(t, err)
	return c.Client, func() { _ = c.Close() }
}

func newTCPClient(t *testing.T, addr *net.TCPAddr) (*protocol.Client, func()) {
	t.Helper()
	c, err := client.NewTCPClient(addr, []byte(testSecret), client.Config{})
	require.NoError(t, err)
	return c.Client, func() { _ = c.Close() }
}

// callCtx returns a context bounded by callTimeout. All client calls in this
// package use it so a hung server fails the test fast instead of blocking
// until the test runner's deadline.
func callCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(t.Context(), callTimeout)
}

func TestUDP_AccessRequestAccept(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	reply := packet.NewString(types.AttrReplyMessage, "welcome")
	addr := startUDPServer(t, ctx, loopbackHandler(types.AccessAccept, reply))
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "hunter2"),
		},
		Method: protocol.AuthPAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)

	msg, ok := findAttr(resp.Attributes, types.AttrReplyMessage)
	require.True(t, ok)
	assert.Equal(t, "welcome", string(msg.Value))

	name, ok := findAttr(resp.Attributes, types.AttrUserName)
	require.True(t, ok)
	assert.Equal(t, "alice", string(name.Value))
}

func TestUDP_AccessRequestReject(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startUDPServer(t, ctx, loopbackHandler(types.AccessReject, packet.Attribute{}))
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "bob"),
		},
		Method: protocol.AuthPAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessReject, resp.Code)
}

func TestUDP_Accounting(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startUDPServer(t, ctx, loopbackHandler(types.AccountingResponse, packet.Attribute{}))
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.Account(ctx, &protocol.AccountingRequest{
		Attributes: []packet.Attribute{
			packet.NewInteger(types.AttrAcctStatusType, 1), // Start
			packet.NewString(types.AttrAcctSessionID, "sess-123"),
			packet.NewString(types.AttrUserName, "carol"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccountingResponse, resp.Code)
}

func TestUDP_CoA(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startUDPServer(t, ctx, loopbackHandler(types.CoAACK, packet.Attribute{}))
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.SendCoA(ctx, &protocol.CoARequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "dave"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.CoAACK, resp.Code)
}

func TestUDP_Disconnect(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startUDPServer(t, ctx, loopbackHandler(types.DisconnectACK, packet.Attribute{}))
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.SendDisconnect(ctx, &protocol.DisconnectRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "eve"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.DisconnectACK, resp.Code)
}

func TestTCP_AccessRequestAccept(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	reply := packet.NewString(types.AttrReplyMessage, "tcp-ok")
	addr := startTCPServer(t, ctx, loopbackHandler(types.AccessAccept, reply))
	c, closeFn := newTCPClient(t, addr)
	defer closeFn()

	resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "frank"),
			packet.NewString(types.AttrUserPassword, "secret"),
		},
		Method: protocol.AuthPAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

func TestTCP_Accounting(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startTCPServer(t, ctx, loopbackHandler(types.AccountingResponse, packet.Attribute{}))
	c, closeFn := newTCPClient(t, addr)
	defer closeFn()

	resp, err := c.Account(ctx, &protocol.AccountingRequest{
		Attributes: []packet.Attribute{
			packet.NewInteger(types.AttrAcctStatusType, 2), // Stop
			packet.NewString(types.AttrAcctSessionID, "sess-tcp"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccountingResponse, resp.Code)
}

func TestUDP_EAPMessageAuthenticator(t *testing.T) {
	// EAP-ordered Access-Request must carry a Message-Authenticator; the
	// server should still see it and reply normally.
	ctx, cancel := callCtx(t)
	defer cancel()

	var sawMsgAuth atomic.Bool
	handler := server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
		if _, ok := findAttr(req.Attributes, types.AttrMessageAuthenticator); ok {
			sawMsgAuth.Store(true)
		}
		return &packet.Packet{
			Code:          types.AccessAccept,
			Identifier:    req.Identifier,
			Authenticator: req.Authenticator,
		}, nil
	})
	addr := startUDPServer(t, ctx, handler)
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "eap-user"),
			packet.NewOctets(types.AttrEAPMessage, []byte{0x01, 0x00, 0x00, 0x05, 0x01}),
		},
		Method: protocol.AuthEAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
	assert.True(t, sawMsgAuth.Load(), "server must observe Message-Authenticator on EAP request")
}

func TestUDP_RetransmissionRecovers(t *testing.T) {
	// This scenario — server drops the first packet, client retransmits and
	// succeeds on attempt 2 — requires the transport to apply a per-attempt
	// read timeout so Exchange returns between attempts. The current
	// UDPClient.Exchange blocks on ReadFrom until the context deadline, so
	// the retransmit loop never advances for a silent server. The retransmit
	// *policy* (NextDelay, Attempts, the loop itself) is covered by
	// protocol/client_test.go using a fast-returning mock transport.
	//
	// Skip end-to-end coverage until the transport grows per-attempt timeouts.
	t.Skip("transport.UDPClient.Exchange blocks until ctx deadline; per-attempt retransmission needs transport-level timeout support")
}

func TestUDP_UnknownSecretDropped(t *testing.T) {
	// If the client uses the wrong secret, the server still replies (StaticSecret
	// here accepts any client IP), but the client's response verification must
	// fail because the Response Authenticator won't match.
	ctx, cancel := callCtx(t)
	defer cancel()

	addr := startUDPServer(t, ctx, loopbackHandler(types.AccessAccept,
		packet.NewString(types.AttrReplyMessage, "x")))

	c, err := client.NewUDPClient(addr, []byte("wrong-secret"), client.Config{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	_, err = c.Client.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "bad"),
		},
		Method: protocol.AuthPAP,
	})
	require.Error(t, err, "mismatched secret must surface as a verification error")
}

func TestUDP_ConcurrentRequests(t *testing.T) {
	// Hammer the server from many goroutines to exercise Identifier pool
	// allocation and concurrent handler dispatch.
	ctx, cancel := callCtx(t)
	defer cancel()

	var inflight, maxInflight atomic.Int32
	handler := server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
		cur := inflight.Add(1)
		for {
			m := maxInflight.Load()
			if cur <= m || maxInflight.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		inflight.Add(-1)
		return &packet.Packet{
			Code:          types.AccessAccept,
			Identifier:    req.Identifier,
			Authenticator: req.Authenticator,
		}, nil
	})
	addr := startUDPServer(t, ctx, handler)
	c, closeFn := newUDPClient(t, addr)
	defer closeFn()

	const N = 32
	errs := make(chan error, N)
	for range N {
		go func() {
			_, err := c.Authenticate(ctx, &protocol.AccessRequest{
				Attributes: []packet.Attribute{
					packet.NewString(types.AttrUserName, "concurrent"),
				},
				Method: protocol.AuthPAP,
			})
			errs <- err
		}()
	}
	for range N {
		require.NoError(t, <-errs, "all concurrent requests must succeed")
	}
	t.Logf("peak concurrent handlers: %d", maxInflight.Load())
}

func TestTCP_CoADisconnect(t *testing.T) {
	ctx, cancel := callCtx(t)
	defer cancel()

	// A single TCP server handling both CoA and Disconnect based on request code.
	handler := server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
		switch req.Code {
		case types.CoARequest:
			return &packet.Packet{Code: types.CoAACK, Identifier: req.Identifier, Authenticator: req.Authenticator}, nil
		case types.DisconnectRequest:
			return &packet.Packet{Code: types.DisconnectACK, Identifier: req.Identifier, Authenticator: req.Authenticator}, nil
		}
		return nil, fmt.Errorf("unexpected code %s", req.Code)
	})
	addr := startTCPServer(t, ctx, handler)
	c, closeFn := newTCPClient(t, addr)
	defer closeFn()

	coa, err := c.SendCoA(ctx, &protocol.CoARequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "tcp-coa")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.CoAACK, coa.Code)

	dm, err := c.SendDisconnect(ctx, &protocol.DisconnectRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "tcp-dm")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.DisconnectACK, dm.Code)
}
