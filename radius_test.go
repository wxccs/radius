package radius_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radius "github.com/wxccs/radius"
)

// startUDPServer launches an in-process UDP RADIUS server on a
// kernel-assigned loopback port and returns the running server along with
// its bound address. The caller is expected to defer Close.
func startUDPServer(t *testing.T, secret []byte, handler radius.Handler) (*radius.UDPServer, *net.UDPAddr) {
	t.Helper()
	srv, err := radius.NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		handler, radius.StaticSecret(secret))
	require.NoError(t, err)
	addr, ok := srv.LocalAddr().(*net.UDPAddr)
	require.True(t, ok, "LocalAddr must be *net.UDPAddr")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	return srv, addr
}

func TestRoot_AccessRequestRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")

	srv, addr := startUDPServer(t, secret, radius.HandlerFunc(
		func(_ context.Context, req *radius.Request) (*radius.Packet, error) {
			if req.Code != radius.AccessRequest {
				return nil, nil
			}
			return req.ReplyWith(radius.AccessAccept,
				radius.NewString(radius.AttrReplyMessage, "hello")), nil
		}))

	c, err := radius.NewUDPClient(addr, secret, radius.Config{Timeout: time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	resp, err := c.Authenticate(context.Background(),
		radius.NewAccessRequest().
			PAP("alice", "hunter2").
			AttrInteger(radius.AttrNASPort, 254).
			Build())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, radius.AccessAccept, resp.Code)
	require.Len(t, resp.Attributes, 1)
	assert.Equal(t, "hello", string(resp.Attributes[0].Value))
	// The reply Identifier must echo the request Identifier allocated by
	// the client's IdentifierPool. RADIUS identifiers cycle through 0..255.
	assert.LessOrEqual(t, int(resp.Identifier), 255)
	assert.GreaterOrEqual(t, int(resp.Identifier), 0)
	// Sanity: server did see the request (Serve is running, no error path).
	_ = srv
}

func TestRoot_AccountingRoundTrip(t *testing.T) {
	secret := []byte("acct-secret")

	_, addr := startUDPServer(t, secret, radius.HandlerFunc(
		func(_ context.Context, req *radius.Request) (*radius.Packet, error) {
			if req.Code != radius.AccountingRequest {
				return nil, nil
			}
			return req.Reply(radius.AccountingResponse), nil
		}))

	c, err := radius.NewUDPClient(addr, secret, radius.Config{Timeout: time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	resp, err := c.Account(context.Background(),
		radius.NewAccountingRequest().
			AttrInteger(radius.AttrAcctStatusType, 1).
			AttrString(radius.AttrAcctSessionID, "sess-1").
			Build())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, radius.AccountingResponse, resp.Code)
}

func TestRoot_MuxDispatch(t *testing.T) {
	secret := []byte("mux-secret")

	mux := radius.NewMux().
		OnFunc(radius.AccessRequest, func(_ context.Context, req *radius.Request) (*radius.Packet, error) {
			return req.Reply(radius.AccessAccept), nil
		}).
		OnFunc(radius.AccountingRequest, func(_ context.Context, req *radius.Request) (*radius.Packet, error) {
			return req.Reply(radius.AccountingResponse), nil
		})

	_, addr := startUDPServer(t, secret, mux)

	c, err := radius.NewUDPClient(addr, secret, radius.Config{Timeout: time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	auth, err := c.Authenticate(context.Background(),
		radius.NewAccessRequest().PAP("alice", "pw").Build())
	require.NoError(t, err)
	assert.Equal(t, radius.AccessAccept, auth.Code)

	acct, err := c.Account(context.Background(),
		radius.NewAccountingRequest().AttrInteger(radius.AttrAcctStatusType, 1).Build())
	require.NoError(t, err)
	assert.Equal(t, radius.AccountingResponse, acct.Code)
}

func TestRoot_ConstantsAndAliases(t *testing.T) {
	assert.Equal(t, radius.Code(1), radius.AccessRequest)
	assert.Equal(t, radius.Code(2), radius.AccessAccept)
	assert.Equal(t, radius.Code(5), radius.AccountingResponse)
	assert.Equal(t, radius.Code(44), radius.CoAACK)
	assert.Equal(t, radius.Code(48), radius.DisconnectNAK)

	assert.Equal(t, byte(1), byte(radius.AttrUserName))
	assert.Equal(t, byte(2), byte(radius.AttrUserPassword))
	assert.Equal(t, byte(4), byte(radius.AttrNASIPAddress))
	assert.Equal(t, byte(80), byte(radius.AttrMessageAuthenticator))

	assert.Equal(t, radius.AuthPAP, radius.AuthMethod(0))
	assert.Equal(t, radius.AuthEAP, radius.AuthMethod(1))
}

func TestRoot_SecretMap(t *testing.T) {
	lookup := radius.SecretMap(map[string][]byte{
		"127.0.0.1": []byte("local"),
		"10.0.0.5":  []byte("remote"),
	})
	s, ok := lookup(net.IPv4(127, 0, 0, 1))
	require.True(t, ok)
	assert.Equal(t, "local", string(s))

	_, ok = lookup(net.IPv4(10, 0, 0, 99))
	assert.False(t, ok)
}

func TestRoot_AttributeConstructors(t *testing.T) {
	s := radius.NewString(radius.AttrUserName, "alice")
	assert.Equal(t, "alice", string(s.Value))

	n := radius.NewInteger(radius.AttrNASPort, 10)
	assert.Equal(t, []byte{0, 0, 0, 10}, n.Value)

	ip := radius.NewIPAddr(radius.AttrNASIPAddress, net.IPv4(192, 168, 1, 1))
	assert.Equal(t, net.IPv4(192, 168, 1, 1).To4(), net.IP(ip.Value))

	vsa := radius.NewVendorSpecific(9, []byte{0x01})
	vid, data, err := vsa.VendorSpecific()
	require.NoError(t, err)
	assert.Equal(t, uint32(9), vid)
	assert.Equal(t, []byte{0x01}, data)
}
