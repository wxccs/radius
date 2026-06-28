package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/client"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/protocol"
	"github.com/wxccs/radius/v2/types"
)

// startUDPWithDedup launches a UDP server with dedup enabled and returns
// it together with its bound address.
func startUDPWithDedup(t *testing.T, handler Handler, ttl time.Duration) (*UDPServer, *net.UDPAddr) {
	t.Helper()
	srv, err := NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		handler, StaticSecret([]byte("k")),
		WithUDPDedup(ttl))
	require.NoError(t, err)
	addr := srv.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	return srv, addr
}

func TestUDPServer_DedupRetransmitsCachedReply(t *testing.T) {
	var handlerCalls int32
	// Block the handler so the second (duplicate) request arrives while
	// the first is still in flight, then publishes the cached reply.
	handlerReleased := make(chan struct{})
	handler := HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
		atomic.AddInt32(&handlerCalls, 1)
		<-handlerReleased
		return req.Reply(types.AccessAccept), nil
	})

	_, addr := startUDPWithDedup(t, handler, time.Second)

	c, err := client.NewUDPClient(addr, []byte("k"), client.Config{Timeout: 2 * time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	// Identifier is allocated from the client's pool; both goroutines will
	// race to acquire one. Use raw protocol.Client via the exported one to
	// force the same identifier by sending the same packet bytes.
	// Simpler: just send twice and rely on the pool recycling the id when
	// the first call's defer-Release fires. That is racy; instead, use a
	// raw UDP socket so we control the identifier explicitly.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Build an Access-Request with identifier 7 using the same path the
	// protocol layer would, so the authenticator is valid.
	pkt := &packet.Packet{
		Code:          types.AccessRequest,
		Identifier:    7,
		Authenticator: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Attributes:    []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	}
	raw, err := pkt.Marshal([]byte("k"))
	require.NoError(t, err)

	// Send twice in quick succession to trigger dedup. The second send
	// happens before the handler returns, so the server will see it as a
	// duplicate of the in-flight first request.
	_, err = conn.WriteToUDP(raw, addr)
	require.NoError(t, err)
	_, err = conn.WriteToUDP(raw, addr)
	require.NoError(t, err)

	// Allow the handler to complete; the server publishes the cached
	// reply, and the duplicate request retransmits the same bytes.
	close(handlerReleased)

	// Read both replies; they must be byte-identical (same Response
	// Authenticator because same Identifier + Request Authenticator).
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n1, _, err := conn.ReadFromUDP(buf)
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n2, _, err := conn.ReadFromUDP(buf)
	require.NoError(t, err)

	assert.Equal(t, n1, n2, "duplicate reply should have the same length")
	assert.Equal(t, buf[:n1], buf[:n2], "duplicate reply should be byte-identical")
	assert.Equal(t, int32(1), atomic.LoadInt32(&handlerCalls),
		"handler should run exactly once despite two requests")
}

func TestUDPServer_ShutdownWaitsForInFlightHandler(t *testing.T) {
	handlerStarted := make(chan struct{})
	handlerBlock := make(chan struct{})
	handler := HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
		close(handlerStarted)
		<-handlerBlock
		return req.Reply(types.AccessAccept), nil
	})

	srv, addr := startUDPWithDedup(t, handler, 0)

	// Send a request so the handler goroutine starts and blocks.
	c, err := client.NewUDPClient(addr, []byte("k"), client.Config{Timeout: 5 * time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	go func() {
		_, _ = c.Authenticate(context.Background(),
			protocol.NewAccessRequest().PAP("alice", "pw").Build())
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	// Shutdown with a 200ms deadline must time out because the handler
	// is still blocked.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer shutCancel()
	err = srv.Shutdown(shutCtx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Unblock the handler and shut down again with a fresh deadline.
	close(handlerBlock)
	shutCtx2, shutCancel2 := context.WithTimeout(context.Background(), time.Second)
	defer shutCancel2()
	err = srv.Shutdown(shutCtx2)
	assert.NoError(t, err)
}

func TestUDPServer_ShutdownWhenIdleReturnsImmediately(t *testing.T) {
	srv, _ := startUDPWithDedup(t,
		HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
			return req.Reply(types.AccessAccept), nil
		}), 0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	assert.NoError(t, err, "Shutdown on idle server must return nil quickly")
}
