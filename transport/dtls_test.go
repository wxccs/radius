package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/types"
)

// pionServerOpts reuses the self-signed cert generated for TLS tests
// and returns pion options suitable for the DTLS server side. The
// FlightInterval is shortened so handshake retransmits fire quickly
// on slow CI runners.
func pionServerOpts(t *testing.T) []piondtls.ServerOption {
	t.Helper()
	src := selfSignedCert(t)
	return []piondtls.ServerOption{
		piondtls.WithCertificates(src.Certificates...),
		piondtls.WithFlightInterval(100 * time.Millisecond),
	}
}

// pionClientOpts returns pion options suitable for the DTLS client
// side of a loopback test against a server using pionServerOpts().
// InsecureSkipVerify is set because the server cert is self-signed
// and not pinned to any trust store.
func pionClientOpts(t *testing.T) []piondtls.ClientOption {
	t.Helper()
	return []piondtls.ClientOption{
		piondtls.WithInsecureSkipVerify(true),
		piondtls.WithFlightInterval(100 * time.Millisecond),
	}
}

// startDTLSEchoServer starts a DTLS listener whose accepted connections
// loop reading framed RADIUS packets and echoing each one back unmodified.
// Returns the listener and its bound local address.
func startDTLSEchoServer(t *testing.T) (*DTLSListener, *net.UDPAddr) {
	t.Helper()
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	addr, ok := ln.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				return
			}
			go func(c *DTLSConn) {
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

func TestListenDTLS_BindsEphemeralPort(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	addr, ok := ln.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	assert.NotZero(t, addr.Port)
}

func TestListenDTLS_RequiresCertificate(t *testing.T) {
	// Passing no options must be rejected with ErrInvalidAttribute.
	_, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrInvalidAttribute))
}

func TestDTLSListener_Accept_ContextCanceled(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = ln.Accept(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestDTLSListener_Accept_AfterClose(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	_, err = ln.Accept(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestDTLSConn_LoopbackExchange(t *testing.T) {
	ln, addr := startDTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialDTLS("udp4", addr, pionClientOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	pkt := radiusPacket(types.AccessRequest, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, pkt)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pkt, reply))
}

func TestDTLSConn_LoopbackExchange_MultipleRequests(t *testing.T) {
	ln, addr := startDTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialDTLS("udp4", addr, pionClientOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	for i := range 5 {
		pkt := radiusPacket(types.AccessRequest, i)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		reply, err := client.Exchange(ctx, pkt)
		cancel()
		require.NoError(t, err, "iteration %d", i)
		assert.True(t, bytes.Equal(pkt, reply), "iteration %d", i)
	}
}

func TestDTLSConn_ReadPacket_MalformedLength(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	c, err := piondtls.DialWithOptions("udp4", ln.LocalAddr().(*net.UDPAddr), pionClientOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	// Length=19 below minimum of 20.
	_, _ = c.Write([]byte{byte(types.AccessRequest), 0, 0, 19})

	select {
	case err := <-serverErr:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrMalformedPacket),
			"want ErrMalformedPacket, got %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ReadPacket")
	}
}

func TestDTLSConn_ReadPacket_Timeout(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
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

	c, err := piondtls.DialWithOptions("udp4", ln.LocalAddr().(*net.UDPAddr), pionClientOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	// Don't send anything; server ReadPacket should time out.
	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.True(t, errors.Is(err, radiuserrors.ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
			"want ErrTimeout or DeadlineExceeded, got %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ReadPacket to return")
	}
}

func TestDTLSConn_WritePacket_AfterClose(t *testing.T) {
	ln, addr := startDTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialDTLS("udp4", addr, pionClientOpts(t)...)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	err = client.conn.WritePacket([]byte{0x01, 0x00, 0x00, 0x14})
	require.Error(t, err)
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestDTLSClient_Exchange_AfterClose(t *testing.T) {
	ln, addr := startDTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialDTLS("udp4", addr, pionClientOpts(t)...)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	_, err = client.Exchange(context.Background(),
		[]byte{0x01, 0x00, 0x00, 0x14})
	assert.True(t, errors.Is(err, radiuserrors.ErrConnClosed))
}

func TestDTLSClient_LocalAddr(t *testing.T) {
	ln, addr := startDTLSEchoServer(t)
	defer func() { _ = ln.Close() }()

	client, err := DialDTLS("udp4", addr, pionClientOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	assert.NotNil(t, client.LocalAddr())
	assert.NotNil(t, client.conn.LocalAddr())
	assert.NotNil(t, client.conn.RemoteAddr())
}

func TestDialDTLS_Failure(t *testing.T) {
	// Invalid network forces a dial failure.
	_, err := DialDTLS("invalid-net",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionClientOpts(t)...)
	require.Error(t, err)
}

func TestDTLSListener_LocalAddr(t *testing.T) {
	ln, err := ListenDTLS("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		pionServerOpts(t)...)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	assert.NotNil(t, ln.LocalAddr())
}
