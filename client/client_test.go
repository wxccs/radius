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

package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/transport"
	"github.com/wxccs/radius/types"
)

// loopbackUDPServer runs a minimal RADIUS-over-UDP echo server that
// replies to Access-Request with Access-Accept (or Access-Reject if the
// User-Name attribute is "reject"). The handler runs until ctx is canceled
// or the listener is closed.
type loopbackUDPServer struct {
	listener *transport.UDPTransport
	addr     *net.UDPAddr
	secret   []byte
	wg       sync.WaitGroup
}

func startLoopbackUDPServer(t *testing.T, secret []byte) *loopbackUDPServer {
	t.Helper()
	ln, err := transport.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	addr, ok := ln.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	srv := &loopbackUDPServer{listener: ln, addr: addr, secret: secret}
	srv.wg.Add(1)
	go srv.serve()
	return srv
}

func (s *loopbackUDPServer) serve() {
	defer s.wg.Done()
	ctx := context.Background()
	for {
		raw, src, err := s.listener.ReadPacket(ctx)
		if err != nil {
			return
		}
		req := &packet.Packet{}
		if err := req.Unmarshal(raw, s.secret); err != nil {
			continue
		}
		if req.Code != types.AccessRequest {
			continue
		}

		var replyCode types.Code = types.AccessAccept
		if nameAttr, ok := req.GetOne(types.AttrUserName); ok {
			if name, err := nameAttr.String(); err == nil && name == "reject" {
				replyCode = types.AccessReject
			}
		}

		var reqAuth [16]byte
		copy(reqAuth[:], raw[4:20])
		reply := &packet.Packet{
			Code:          replyCode,
			Identifier:    req.Identifier,
			Authenticator: reqAuth,
			Attributes: []packet.Attribute{
				packet.NewString(types.AttrReplyMessage, "ok"),
			},
		}
		out, err := reply.Marshal(s.secret)
		if err != nil {
			continue
		}
		_ = s.listener.SendPacket(out, src)
	}
}

func (s *loopbackUDPServer) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func TestUDPClient_Authenticate_Accept(t *testing.T) {
	secret := []byte("udp-test-secret")
	srv := startLoopbackUDPServer(t, secret)
	defer srv.close()

	c, err := NewUDPClient(srv.addr, secret, Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1},
	})
	require.NoError(t, err)
	defer c.Close()

	resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "hunter2"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

func TestUDPClient_Authenticate_Reject(t *testing.T) {
	secret := []byte("udp-test-secret")
	srv := startLoopbackUDPServer(t, secret)
	defer srv.close()

	c, err := NewUDPClient(srv.addr, secret, Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1},
	})
	require.NoError(t, err)
	defer c.Close()

	resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "reject"),
			packet.NewString(types.AttrUserPassword, "x"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessReject, resp.Code)
}

func TestUDPClient_DefaultNetwork(t *testing.T) {
	secret := []byte("net-secret")
	srv := startLoopbackUDPServer(t, secret)
	defer srv.close()

	// Empty Network should default to "udp4".
	c, err := NewUDPClient(srv.addr, secret, Config{
		Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1},
	})
	require.NoError(t, err)
	defer c.Close()
	assert.NotNil(t, c.Transport())
}

func TestUDPClient_RetransmitDefault(t *testing.T) {
	secret := []byte("default-policy-secret")
	srv := startLoopbackUDPServer(t, secret)
	defer srv.close()

	// Empty Retransmit must fall back to protocol.DefaultRetransmitPolicy.
	c, err := NewUDPClient(srv.addr, secret, Config{
		Timeout: 2 * time.Second,
	})
	require.NoError(t, err)
	defer c.Close()

	// Issue one call; the server will reply on the first attempt, so the
	// default policy's 3 attempts collapse into one round trip.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

// loopbackTCPServer is a minimal RADIUS-over-TCP echo server that replies
// to Access-Request with Access-Accept.
type loopbackTCPServer struct {
	listener *transport.TCPListener
	addr     *net.TCPAddr
	secret   []byte
	wg       sync.WaitGroup
}

func startLoopbackTCPServer(t *testing.T, secret []byte) *loopbackTCPServer {
	t.Helper()
	ln, err := transport.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	addr, ok := ln.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)

	srv := &loopbackTCPServer{listener: ln, addr: addr, secret: secret}
	srv.wg.Add(1)
	go srv.serve()
	return srv
}

func (s *loopbackTCPServer) serve() {
	defer s.wg.Done()
	ctx := context.Background()
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *loopbackTCPServer) handleConn(conn *transport.TCPConn) {
	defer conn.Close()
	ctx := context.Background()
	for {
		raw, err := conn.ReadPacket(ctx)
		if err != nil {
			return
		}
		req := &packet.Packet{}
		if err := req.Unmarshal(raw, s.secret); err != nil {
			return
		}
		if req.Code != types.AccessRequest {
			return
		}
		var reqAuth [16]byte
		copy(reqAuth[:], raw[4:20])
		reply := &packet.Packet{
			Code:          types.AccessAccept,
			Identifier:    req.Identifier,
			Authenticator: reqAuth,
		}
		out, err := reply.Marshal(s.secret)
		if err != nil {
			return
		}
		if err := conn.WritePacket(out); err != nil {
			return
		}
	}
}

func (s *loopbackTCPServer) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func TestTCPClient_Authenticate(t *testing.T) {
	secret := []byte("tcp-test-secret")
	srv := startLoopbackTCPServer(t, secret)
	defer srv.close()

	c, err := NewTCPClient(srv.addr, secret, Config{})
	require.NoError(t, err)
	defer c.Close()
	assert.NotNil(t, c.Transport(), "TCP transport should be accessible")

	resp, err := c.Authenticate(context.Background(), &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "hunter2"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

func TestUDPClient_DialFailure(t *testing.T) {
	// An invalid network must surface the dial error.
	_, err := NewUDPClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		[]byte("s"), Config{Network: "invalid-net"})
	assert.Error(t, err)
}

func TestTCPClient_DialFailure(t *testing.T) {
	_, err := NewTCPClient(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		[]byte("s"), Config{Network: "invalid-net"})
	assert.Error(t, err)
}
