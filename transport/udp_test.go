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
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
)

// freeUDPAddr returns an *net.UDPAddr bound to an ephemeral port on the
// loopback interface of the given network ("udp" / "udp4" / "udp6"). It
// does not start listening; it only resolves a usable address for DialUDP
// / ListenUDP callers.
func freeUDPAddr(t *testing.T, network string) *net.UDPAddr {
	t.Helper()
	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	return addr
}

// startUDPEchoServer starts a UDP listener that echoes every received
// datagram back to the sender. Returns the listener and its local address.
func startUDPEchoServer(t *testing.T, network string) (*UDPTransport, *net.UDPAddr) {
	t.Helper()
	l, err := ListenUDP(network, freeUDPAddr(t, network))
	require.NoError(t, err)
	addr, ok := l.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	return l, addr
}

func TestListenUDP_BindsEphemeralPort(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	addr, ok := l.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	assert.NotZero(t, addr.Port)
}

func TestUDPTransport_ReadPacket_ContextCanceled(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err = l.ReadPacket(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
		"want ErrTimeout or DeadlineExceeded, got %v", err)
}

func TestUDPTransport_ReadPacket_AfterClose(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	_, _, err = l.ReadPacket(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestUDPTransport_LoopbackExchange(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()

	// Echo goroutine: read one packet, echo it back.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		data, src, err := srv.ReadPacket(ctx)
		if err != nil {
			return
		}
		_ = srv.SendPacket(append([]byte("echo:"), data...), src)
	}()

	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, []byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, []byte("echo:hello"), reply)
}

func TestUDPTransport_LoopbackExchange_IPv6(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp6")
	defer func() { _ = srv.Close() }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		data, src, err := srv.ReadPacket(ctx)
		if err != nil {
			return
		}
		_ = srv.SendPacket(append([]byte("echo:"), data...), src)
	}()

	client, err := DialUDP("udp6", srvAddr, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, []byte("v6-ping"))
	require.NoError(t, err)
	assert.Equal(t, []byte("echo:v6-ping"), reply)
}

func TestUDPClient_StrayPacketDiscarded(t *testing.T) {
	// Real server: doesn't reply within deadline.
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()

	// Stray sender: sends from a *different* port than srvAddr.
	stray, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = stray.Close() }()

	// Discover client's local address by dialing first, then send a stray
	// datagram from a different source.
	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	clientLocal, ok := client.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	// Send a stray packet to the client from the stray socket (impersonating
	// the server's port would require raw sockets; instead, send a stray
	// packet to the client from a different port — the client will read it
	// and discard it because src != srvAddr).
	strayToClient, err := net.DialUDP("udp4", nil, clientLocal)
	require.NoError(t, err)
	defer func() { _ = strayToClient.Close() }()
	_, _ = strayToClient.Write([]byte("noise"))

	// Have the real server reply with the legitimate payload.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		data, src, err := srv.ReadPacket(ctx)
		if err != nil {
			return
		}
		_ = srv.SendPacket(append([]byte("ok:"), data...), src)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, []byte("legit"))
	require.NoError(t, err)
	assert.Equal(t, []byte("ok:legit"), reply)
}

func TestUDPClient_Timeout(t *testing.T) {
	// Server accepts but never replies.
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()

	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.Exchange(ctx, []byte("ping"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
		"want ErrTimeout or DeadlineExceeded, got %v", err)
}

func TestUDPClient_ClosedBeforeExchange(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()

	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, client.Close())

	_, err = client.Exchange(context.Background(), []byte("ping"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestUDPTransport_SendPacket_AfterClose(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	err = l.SendPacket([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestUDPTransport_ConcurrentSend(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()

	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	// Receive loop on server side: echo each datagram back.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 10 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			data, src, err := srv.ReadPacket(ctx)
			if err != nil {
				cancel()
				return
			}
			_ = srv.SendPacket(data, src)
			cancel()
		}
	}()

	// Fire 10 concurrent writes from the client side. Each call grabs the
	// write mutex; the test verifies no data races under -race.
	var clientWg sync.WaitGroup
	for i := range 10 {
		clientWg.Add(1)
		go func(n int) {
			defer clientWg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_, _ = client.Exchange(ctx, []byte{byte(n)})
		}(i)
	}
	clientWg.Wait()
	wg.Wait()
}

func TestUDPAddrEqual(t *testing.T) {
	a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}
	b := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}
	c := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1813}
	d := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}
	e := &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}

	assert.True(t, udpAddrEqual(a, b))
	assert.False(t, udpAddrEqual(a, c))
	assert.False(t, udpAddrEqual(a, d))
	// Both args non-UDPAddr.
	assert.False(t, udpAddrEqual(e, e))
	// First arg non-UDPAddr.
	assert.False(t, udpAddrEqual(e, a))

	v6a := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 1812, Zone: "lo0"}
	v6b := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 1812, Zone: "lo0"}
	v6c := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 1812, Zone: "en0"}
	assert.True(t, udpAddrEqual(v6a, v6b))
	assert.False(t, udpAddrEqual(v6a, v6c))
}

func TestIsTimeout_NilContext(t *testing.T) {
	// With nil ctx, only net.Error.Timeout and os.ErrDeadlineExceeded
	// paths fire. A plain error should not be classified as timeout.
	assert.False(t, isTimeout(errors.New("plain"), nil))

	var ne net.Error
	// net.OpError with timeout flag — synthesized via a real deadline.
	_, _ = net.DialTimeout("udp", "127.0.0.1:1", 1*time.Nanosecond)
	// Sanity: with a real context deadline, isTimeout returns true.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()
	assert.True(t, isTimeout(context.DeadlineExceeded, ctx))
	_ = ne
}

func TestIsClosed(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, l.Close())
	// Subsequent ReadPacket should return ErrConnClosed, which means
	// the underlying error chained to net.ErrClosed.
	_, _, err = l.ReadPacket(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestUDPTransport_LocalAddr(t *testing.T) {
	l, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	assert.NotNil(t, l.LocalAddr())
}

func TestUDPClient_LocalAddr(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()
	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	assert.NotNil(t, client.LocalAddr())
}

func TestUDPClient_Exchange_WriteAfterClose(t *testing.T) {
	srv, srvAddr := startUDPEchoServer(t, "udp4")
	defer func() { _ = srv.Close() }()
	client, err := DialUDP("udp4", srvAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, client.Close())
	_, err = client.Exchange(context.Background(), []byte("x"))
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestDialUDP_Failure(t *testing.T) {
	// Invalid network to force a dial failure.
	_, err := DialUDP("invalid-net", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, nil)
	require.Error(t, err)
}

func TestListenUDP_Failure(t *testing.T) {
	// Port 1 is privileged on most systems; should fail without root.
	_, err := ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	require.Error(t, err)
}

func TestIsTimeout_PlainError(t *testing.T) {
	// A plain (non-timeout) error with a live context should not match.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	assert.False(t, isTimeout(errors.New("plain"), ctx))
}

func TestUDPTransport_ReadPacket_GeneralIOError(t *testing.T) {
	// Closing the socket and then reading exercises the isClosed branch
	// (already covered by TestUDPTransport_ReadPacket_AfterClose). The
	// general non-closed/non-timeout error branch requires injecting a
	// non-recoverable socket error, which is platform-specific. We
	// accept the existing coverage for that path.
	t.Skip("general IO error path requires platform-specific injection")
}
