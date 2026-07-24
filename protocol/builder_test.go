package protocol

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
)

func TestAccessRequestBuilder_PAP(t *testing.T) {
	req := NewAccessRequest().
		PAP("alice", "hunter2").
		AttrInteger(types.AttrNASPort, 10).
		Build()

	require.NotNil(t, req)
	assert.Equal(t, AuthPAP, req.Method)
	require.Len(t, req.Attributes, 3)
	assert.Equal(t, byte(types.AttrUserName), req.Attributes[0].Type)
	assert.Equal(t, "alice", string(req.Attributes[0].Value))
	assert.Equal(t, byte(types.AttrUserPassword), req.Attributes[1].Type)
	assert.Equal(t, "hunter2", string(req.Attributes[1].Value))
	assert.Equal(t, byte(types.AttrNASPort), req.Attributes[2].Type)
}

func TestAccessRequestBuilder_EAP(t *testing.T) {
	req := NewAccessRequest().
		EAP().
		AttrString(types.AttrUserName, "bob").
		Build()

	require.NotNil(t, req)
	assert.Equal(t, AuthEAP, req.Method)
	require.Len(t, req.Attributes, 1)
	assert.Equal(t, "bob", string(req.Attributes[0].Value))
}

func TestAccessRequestBuilder_MethodOverride(t *testing.T) {
	req := NewAccessRequest().
		PAP("alice", "pw").
		Method(AuthEAP).
		Build()
	assert.Equal(t, AuthEAP, req.Method)
}

func TestAccessRequestBuilder_AttrsReplaces(t *testing.T) {
	first := packet.NewString(types.AttrUserName, "alice")
	req := NewAccessRequest().
		AttrString(types.AttrUserName, "bob").
		Attrs([]packet.Attribute{first}).
		Build()
	require.Len(t, req.Attributes, 1)
	assert.Equal(t, "alice", string(req.Attributes[0].Value))
	// Mutating the input slice after Attrs must not affect the builder.
	first.Value = []byte("eve")
	assert.Equal(t, "alice", string(req.Attributes[0].Value),
		"Attrs must copy the input slice")
}

func TestAccessRequestBuilder_Authenticator(t *testing.T) {
	var a [16]byte
	for i := range a {
		a[i] = byte(i + 1)
	}
	req := NewAccessRequest().Authenticator(a).Build()
	assert.Equal(t, a, req.Authenticator)
}

func TestAccessRequestBuilder_IPAttrs(t *testing.T) {
	req := NewAccessRequest().
		AttrIP(types.AttrNASIPAddress, net.IPv4(192, 168, 1, 1)).
		AttrIPv6(types.AttrNASIPv6Address, net.ParseIP("2001:db8::1")).
		Build()
	require.Len(t, req.Attributes, 2)
	assert.Equal(t, net.IPv4(192, 168, 1, 1).To4(), net.IP(req.Attributes[0].Value))
	assert.Len(t, req.Attributes[1].Value, 16)
}

func TestAccessRequestBuilder_Empty(t *testing.T) {
	req := NewAccessRequest().Build()
	require.NotNil(t, req)
	assert.Equal(t, AuthPAP, req.Method)
	assert.Empty(t, req.Attributes)
}

func TestAccountingRequestBuilder(t *testing.T) {
	req := NewAccountingRequest().
		AttrInteger(types.AttrAcctStatusType, 1).
		AttrString(types.AttrAcctSessionID, "sess-42").
		Build()
	require.NotNil(t, req)
	require.Len(t, req.Attributes, 2)
	assert.Equal(t, byte(types.AttrAcctStatusType), req.Attributes[0].Type)
	assert.Equal(t, "sess-42", string(req.Attributes[1].Value))
}

func TestCoARequestBuilder(t *testing.T) {
	req := NewCoARequest().
		AttrString(types.AttrUserName, "alice").
		Build()
	require.NotNil(t, req)
	require.Len(t, req.Attributes, 1)
}

func TestDisconnectRequestBuilder(t *testing.T) {
	req := NewDisconnectRequest().
		AttrString(types.AttrAcctSessionID, "sess-42").
		Build()
	require.NotNil(t, req)
	require.Len(t, req.Attributes, 1)
}

func TestCoARequestBuilder_MessageAuthenticator(t *testing.T) {
	req := NewCoARequest().
		AttrString(types.AttrUserName, "alice").
		MessageAuthenticator().
		Build()
	require.NotNil(t, req)
	require.NotNil(t, req.MessageAuthenticator, "builder must set the per-request override")
	assert.True(t, *req.MessageAuthenticator)
}

func TestDisconnectRequestBuilder_WithoutMessageAuthenticator(t *testing.T) {
	req := NewDisconnectRequest().
		AttrString(types.AttrAcctSessionID, "sess-42").
		WithoutMessageAuthenticator().
		Build()
	require.NotNil(t, req)
	require.NotNil(t, req.MessageAuthenticator, "builder must set the per-request override")
	assert.False(t, *req.MessageAuthenticator)
}

func TestAccountingRequestBuilder_AttrsCopy(t *testing.T) {
	attrs := []packet.Attribute{packet.NewString(types.AttrUserName, "alice")}
	req := NewAccountingRequest().Attrs(attrs).Build()
	attrs[0] = packet.NewString(types.AttrUserName, "mallory")
	assert.Equal(t, "alice", string(req.Attributes[0].Value))
}
