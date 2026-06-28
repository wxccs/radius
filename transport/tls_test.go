package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/types"
)

// startTLSEchoServer starts a TLS listener whose accepted connections
// loop reading framed RADIUS packets and echoing each one back unmodified.
// Returns the listener and its bound local address.
func startTLSEchoServer(t *testing.T) (*TLSListener, *net.TCPAddr) {
	t.Helper()
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
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
			go func(c *TLSConn) {
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

func TestListenTLS_BindsEphemeralPort(t *testing.T) {
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, ok := ln.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)
	assert.NotZero(t, addr.Port)
}

func TestListenTLS_RequiresCertificate(t *testing.T) {
	// A nil config must be rejected with ErrInvalidAttribute.
	_, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrInvalidAttribute))
}

func TestListenTLS_RequiresNonEmptyCertList(t *testing.T) {
	_, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&tls.Config{Certificates: nil})
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrInvalidAttribute))
}

func TestTLSListener_Accept_ContextCanceled(t *testing.T) {
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = ln.Accept(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestTLSListener_Accept_AfterClose(t *testing.T) {
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	_, err = ln.Accept(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTLSConn_LoopbackExchange(t *testing.T) {
	ln, addr := startTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialTLS("tcp4", addr, selfSignedClientConfig(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	pkt := radiusPacket(types.AccessRequest, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, pkt)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pkt, reply))
}

func TestTLSConn_LoopbackExchange_MultipleRequests(t *testing.T) {
	// Multiple sequential Exchange calls on the same TLSClient to
	// exercise the exchMu serialization path.
	ln, addr := startTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialTLS("tcp4", addr, selfSignedClientConfig(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	for i := range 5 {
		pkt := radiusPacket(types.AccessRequest, i)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		reply, err := client.Exchange(ctx, pkt)
		cancel()
		require.NoError(t, err, "iteration %d", i)
		assert.True(t, bytes.Equal(pkt, reply), "iteration %d", i)
	}
}

func TestTLSConn_ReadPacket_MalformedLength(t *testing.T) {
	// Start a TLS listener, accept one connection on the server, and
	// have a raw TLS client send a header with Length below the minimum.
	// ReadPacket must reject it with ErrMalformedPacket.
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

	c, err := tls.Dial("tcp4", ln.LocalAddr().String(),
		selfSignedClientConfig(t))
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	// Length=19 below minimum of 20.
	_, _ = c.Write([]byte{byte(types.AccessRequest), 0, 0, 19})

	select {
	case err := <-serverErr:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrMalformedPacket),
			"want ErrMalformedPacket, got %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server ReadPacket")
	}
}

func TestTLSConn_ReadPacket_Timeout(t *testing.T) {
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

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

	c, err := tls.Dial("tcp4", ln.LocalAddr().String(),
		selfSignedClientConfig(t))
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	// Don't send anything; server ReadPacket should time out.
	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
			"want ErrTimeout or DeadlineExceeded, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ReadPacket to return")
	}
}

func TestTLSConn_WritePacket_AfterClose(t *testing.T) {
	ln, addr := startTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialTLS("tcp4", addr, selfSignedClientConfig(t))
	require.NoError(t, err)
	require.NoError(t, client.Close())

	err = client.conn.WritePacket([]byte{0x01, 0x00, 0x00, 0x14})
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTLSClient_Exchange_AfterClose(t *testing.T) {
	ln, addr := startTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialTLS("tcp4", addr, selfSignedClientConfig(t))
	require.NoError(t, err)
	require.NoError(t, client.Close())

	_, err = client.Exchange(context.Background(),
		[]byte{0x01, 0x00, 0x00, 0x14})
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestTLSClient_LocalAddr(t *testing.T) {
	ln, addr := startTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialTLS("tcp4", addr, selfSignedClientConfig(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	assert.NotNil(t, client.LocalAddr())
	assert.NotNil(t, client.conn.LocalAddr())
	assert.NotNil(t, client.conn.RemoteAddr())
}

func TestDialTLS_Failure(t *testing.T) {
	// Invalid network forces a dial failure.
	_, err := DialTLS("invalid-net",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedClientConfig(t))
	require.Error(t, err)
}

func TestTLSListener_LocalAddr(t *testing.T) {
	ln, err := ListenTLS("tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		selfSignedCert(t))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	assert.NotNil(t, ln.LocalAddr())
}
