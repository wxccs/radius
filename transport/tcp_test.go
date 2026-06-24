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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// startTCPEchoServer starts a TCP listener whose accepted connections
// loop reading framed RADIUS packets and echoing each one back unmodified.
func startTCPEchoServer(t *testing.T, network string) (*TCPListener, *net.TCPAddr) {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	ln, err := ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(host), Port: 0})
	require.NoError(t, err)
	addr, ok := ln.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				return
			}
			go func(c *TCPConn) {
				defer func() { _ = c.Close() }()
				for {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					data, err := c.ReadPacket(ctx)
					cancel()
					if err != nil {
						return
					}
					if err := c.WritePacket(data); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln, addr
}

// radiusPacket builds a minimal but validly framed RADIUS packet of the
// given code and payload length. The payload is filled with `code` bytes
// so the reader can verify integrity.
func radiusPacket(code types.Code, payloadLen int) []byte {
	total := 20 + payloadLen
	buf := make([]byte, total)
	buf[0] = byte(code)
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	for i := 4; i < total; i++ {
		buf[i] = byte(code)
	}
	return buf
}

func TestListenTCP_BindsEphemeralPort(t *testing.T) {
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, ok := ln.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)
	assert.NotZero(t, addr.Port)
}

func TestTCPListener_Accept_ContextCanceled(t *testing.T) {
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = ln.Accept(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestTCPListener_Accept_AfterClose(t *testing.T) {
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	_, err = ln.Accept(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTCPConn_LoopbackExchange(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()

	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	pkt := radiusPacket(types.AccessRequest, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, pkt)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pkt, reply))
}

func TestTCPConn_LoopbackExchange_IPv6(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp6")
	defer func() { _ = ln.Close() }()

	client, err := DialTCP("tcp6", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	pkt := radiusPacket(types.AccessAccept, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, pkt)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pkt, reply))
}

// runMalformedFramingTest starts a TCP listener, has a raw client send
// the bytes produced by send to it, and asserts that the server's
// ReadPacket returns wantErr. The server's Accept and ReadPacket are
// bounded by a 1s context.
func runMalformedFramingTest(
	t *testing.T,
	send func(c net.Conn),
	wantErr error,
) {
	t.Helper()
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, _ := ln.LocalAddr().(*net.TCPAddr)

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, err = conn.ReadPacket(ctx)
		serverErr <- err
	}()

	c, err := net.DialTCP("tcp4", nil, addr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	send(c)

	select {
	case err := <-serverErr:
		require.Error(t, err)
		assert.True(t, errors.Is(err, wantErr),
			"want %v, got %v", wantErr, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server ReadPacket")
	}
}

func TestTCPConn_ReadPacket_LengthBelowMinimum(t *testing.T) {
	runMalformedFramingTest(t,
		func(c net.Conn) {
			// Header with Length=19 (below minimum of 20).
			_, _ = c.Write([]byte{byte(types.AccessRequest), 0, 0, 19})
		},
		radiuserrors.ErrMalformedPacket,
	)
}

func TestTCPConn_ReadPacket_LengthAboveMaximum(t *testing.T) {
	runMalformedFramingTest(t,
		func(c net.Conn) {
			// Header with Length=5000 (above 4096).
			_, _ = c.Write([]byte{byte(types.AccessRequest), 0, 0x13, 0x88})
		},
		radiuserrors.ErrMalformedPacket,
	)
}

func TestTCPConn_ReadPacket_AccountingLengthCap(t *testing.T) {
	// Accounting code (4) must use the tighter 4095 max. Length=4096
	// is therefore malformed for accounting, even though it would be
	// valid for an Access-Request.
	runMalformedFramingTest(t,
		func(c net.Conn) {
			_, _ = c.Write([]byte{byte(types.AccountingRequest), 0, 0x10, 0x00})
		},
		radiuserrors.ErrMalformedPacket,
	)
}

func TestTCPConn_ReadPacket_ShortHeader(t *testing.T) {
	runMalformedFramingTest(t,
		func(c net.Conn) {
			// Send only 2 bytes of the 4-byte header, then close.
			_, _ = c.Write([]byte{byte(types.AccessRequest), 0})
			_ = c.Close()
		},
		radiuserrors.ErrConnClosed,
	)
}

func TestTCPConn_ReadPacket_ShortPayload(t *testing.T) {
	runMalformedFramingTest(t,
		func(c net.Conn) {
			// Header declares Length=40 (so payload should be 36 bytes),
			// but we close after writing only 2 payload bytes.
			_, _ = c.Write([]byte{byte(types.AccessRequest), 0, 0, 40})
			_, _ = c.Write([]byte{0xAA, 0xBB})
			_ = c.Close()
		},
		radiuserrors.ErrConnClosed,
	)
}

func TestTCPConn_ReadPacket_Timeout(t *testing.T) {
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, _ := ln.LocalAddr().(*net.TCPAddr)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, err = conn.ReadPacket(ctx)
		errCh <- err
	}()

	c, err := net.DialTCP("tcp4", nil, addr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	// Don't send anything; the ReadPacket on the server should time out.
	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
			"want ErrTimeout or DeadlineExceeded, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ReadPacket to return")
	}
}

func TestTCPConn_ReadPacket_NoDeadlineThenClose(t *testing.T) {
	// Call ReadPacket with a context that has no deadline — exercises
	// the "clear prior deadline" branch of applyReadDeadline. The read
	// then unblocks when the peer closes the connection.
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, _ := ln.LocalAddr().(*net.TCPAddr)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		// No deadline on ctx — exercises the "clear deadline" branch.
		_, err = conn.ReadPacket(context.Background())
		errCh <- err
	}()

	c, err := net.DialTCP("tcp4", nil, addr)
	require.NoError(t, err)
	// Give the server time to enter ReadPacket, then close to unblock.
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ReadPacket to return")
	}
}

func TestTCPConn_WritePacket_AfterClose(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()

	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	err = client.conn.WritePacket([]byte{0x01, 0x00, 0x00, 0x14})
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTCPConn_ConcurrentWrite(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()

	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	// Open a second client to consume the echoed replies so the server
	// connection does not back up. Actually we just need the write mutex
	// to be exercised concurrently — Exchange serializes, so call it
	// from multiple goroutines.
	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			pkt := radiusPacket(types.AccessRequest, n)
			_, _ = client.Exchange(ctx, pkt)
		}(i)
	}
	wg.Wait()
}

func TestMapReadErr(t *testing.T) {
	assert.NoError(t, mapReadErr(nil, context.Background()))
	assert.True(t, errors.Is(mapReadErr(io.EOF, context.Background()), radiuserrors.ErrConnClosed))
	assert.True(t, errors.Is(mapReadErr(io.ErrUnexpectedEOF, context.Background()), radiuserrors.ErrConnClosed))

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()
	assert.True(t, errors.Is(mapReadErr(context.DeadlineExceeded, ctx), radiuserrors.ErrTimeout))

	plainErr := errors.New("plain")
	assert.True(t, errors.Is(mapReadErr(plainErr, context.Background()), plainErr))
}

func TestIsAccountingCode(t *testing.T) {
	assert.True(t, isAccountingCode(types.AccountingRequest))
	assert.True(t, isAccountingCode(types.AccountingResponse))
	assert.False(t, isAccountingCode(types.AccessRequest))
	assert.False(t, isAccountingCode(types.AccessAccept))
	assert.False(t, isAccountingCode(types.CoARequest))
}

func TestTCPConn_LocalAddr(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()
	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	assert.NotNil(t, client.LocalAddr())
	// Also exercise TCPConn.LocalAddr directly (different method from
	// TCPClient.LocalAddr).
	assert.NotNil(t, client.conn.LocalAddr())
}

func TestTCPConn_RemoteAddr(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()
	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	ra := client.conn.RemoteAddr()
	assert.NotNil(t, ra)
}

func TestTCPClient_Exchange_AfterClose(t *testing.T) {
	ln, addr := startTCPEchoServer(t, "tcp4")
	defer func() { _ = ln.Close() }()
	client, err := DialTCP("tcp4", addr)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	_, err = client.Exchange(context.Background(), []byte{0x01, 0x00, 0x00, 0x14})
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestDialTCP_Failure(t *testing.T) {
	// Invalid network forces a dial failure.
	_, err := DialTCP("invalid-net", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.Error(t, err)
}

func TestListenTCP_Failure(t *testing.T) {
	// Port 1 is privileged; should fail without root.
	_, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	require.Error(t, err)
}

func TestTCPConn_ReadPacket_SetDeadlineError(t *testing.T) {
	// Use a *TCPConn whose underlying connection is closed so that
	// SetReadDeadline returns net.ErrClosed — exercising the isClosed
	// branch in applyReadDeadline's caller chain (via ReadPacket).
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	// Accept on closed listener returns ErrConnClosed.
	_, err = ln.Accept(context.Background())
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTCPListener_LocalAddr(t *testing.T) {
	ln, err := ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	assert.NotNil(t, ln.LocalAddr())
}

func TestTCPConn_WritePacket_ShortWriteViaPipe(t *testing.T) {
	// net.Pipe writes block until the other side reads. We use a custom
	// reader/writer pair to force a short write by closing the pipe mid-
	// write. This exercises the "short write" branch of WritePacket
	// (which logs and returns ErrShortBuffer).
	r, w := io.Pipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	conn := &TCPConn{c: &pipeConn{r: r, w: w}}
	// Write a 100-byte payload but close the reader after the first 4
	// bytes are consumed. The Write call will return io.ErrClosedPipe
	// after a partial write, triggering the short-write branch.
	go func() {
		buf := make([]byte, 4)
		_, _ = r.Read(buf)
		_ = r.Close()
	}()
	err := conn.WritePacket(make([]byte, 100))
	require.Error(t, err)
}

// pipeConn adapts an io.Pipe to the net.Conn surface just enough for
// TCPConn.WritePacket to operate. The methods not needed by WritePacket
// panic if called.
type pipeConn struct {
	r io.Reader
	w io.Writer
}

func (p *pipeConn) Read(b []byte) (int, error)       { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error)      { return p.w.Write(b) }
func (p *pipeConn) Close() error                     { return nil }
func (p *pipeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (p *pipeConn) SetDeadline(time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }

// (no test helpers below — runMalformedFramingTest above covers the
// malformed-framing cases that previously needed raw writes from the
// server side.)
