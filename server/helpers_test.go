package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
)

func TestRequest_Reply(t *testing.T) {
	req := &Request{
		Packet: &packet.Packet{
			Code:          types.AccessRequest,
			Identifier:    42,
			Authenticator: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}

	reply := req.Reply(types.AccessAccept)
	assert.Equal(t, types.AccessAccept, reply.Code)
	assert.Equal(t, byte(42), reply.Identifier)
	assert.Equal(t, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, reply.Authenticator)
	assert.Empty(t, reply.Attributes)
}

func TestRequest_ReplyWith(t *testing.T) {
	req := &Request{
		Packet: &packet.Packet{
			Identifier:    7,
			Authenticator: [16]byte{0xff},
		},
	}
	attrs := []packet.Attribute{packet.NewString(types.AttrReplyMessage, "ok")}
	reply := req.ReplyWith(types.AccessAccept, attrs...)
	require.Len(t, reply.Attributes, 1)
	assert.Equal(t, "ok", string(reply.Attributes[0].Value))

	// Mutating the source slice must not affect the reply.
	attrs[0] = packet.NewString(types.AttrReplyMessage, "tampered")
	assert.Equal(t, "ok", string(reply.Attributes[0].Value))
}

func TestSecretMap(t *testing.T) {
	lookup := SecretMap(map[string][]byte{
		"10.0.0.1":    []byte("secret-a"),
		"10.0.0.2/32": []byte("secret-b"),
		" 10.0.0.3  ": []byte("secret-c"),
		"not-an-ip":   []byte("never"),
	})

	cases := []struct {
		name string
		ip   net.IP
		ok   bool
		want string
	}{
		{"exact", net.IPv4(10, 0, 0, 1), true, "secret-a"},
		{"with prefix normalized", net.IPv4(10, 0, 0, 2), true, "secret-b"},
		{"whitespace trimmed", net.IPv4(10, 0, 0, 3), true, "secret-c"},
		{"missing", net.IPv4(10, 0, 0, 99), false, ""},
		{"nil ip", nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret, ok := lookup(c.ip)
			assert.Equal(t, c.ok, ok)
			if ok {
				assert.Equal(t, c.want, string(secret))
			}
		})
	}
}

func TestSecretMap_ReturnsCopy(t *testing.T) {
	lookup := SecretMap(map[string][]byte{"10.0.0.1": []byte("orig")})
	got, ok := lookup(net.IPv4(10, 0, 0, 1))
	require.True(t, ok)
	got[0] = 'X'
	got2, _ := lookup(net.IPv4(10, 0, 0, 1))
	assert.Equal(t, "orig", string(got2), "SecretMap must not share storage with the input map")
}

func TestMux_Dispatch(t *testing.T) {
	mux := NewMux().
		OnFunc(types.AccessRequest, func(_ context.Context, req *Request) (*packet.Packet, error) {
			return req.Reply(types.AccessAccept), nil
		}).
		OnFunc(types.AccountingRequest, func(_ context.Context, req *Request) (*packet.Packet, error) {
			return req.Reply(types.AccountingResponse), nil
		})

	t.Run("access", func(t *testing.T) {
		reply, err := mux.Handle(context.Background(), &Request{
			Packet: &packet.Packet{Code: types.AccessRequest, Identifier: 5},
		})
		require.NoError(t, err)
		require.NotNil(t, reply)
		assert.Equal(t, types.AccessAccept, reply.Code)
		assert.Equal(t, byte(5), reply.Identifier)
	})

	t.Run("accounting", func(t *testing.T) {
		reply, err := mux.Handle(context.Background(), &Request{
			Packet: &packet.Packet{Code: types.AccountingRequest, Identifier: 9},
		})
		require.NoError(t, err)
		require.NotNil(t, reply)
		assert.Equal(t, types.AccountingResponse, reply.Code)
	})
}

func TestMux_Fallback(t *testing.T) {
	mux := NewMux().
		OnFunc(types.AccessRequest, func(_ context.Context, req *Request) (*packet.Packet, error) {
			return req.Reply(types.AccessAccept), nil
		}).
		Fallback(HandlerFunc(func(_ context.Context, req *Request) (*packet.Packet, error) {
			return req.Reply(types.DisconnectACK), nil
		}))

	reply, err := mux.Handle(context.Background(), &Request{
		Packet: &packet.Packet{Code: types.DisconnectRequest, Identifier: 1},
	})
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.Equal(t, types.DisconnectACK, reply.Code)
}

func TestMux_SilentDropWhenNoHandler(t *testing.T) {
	mux := NewMux()
	reply, err := mux.Handle(context.Background(), &Request{
		Packet: &packet.Packet{Code: types.AccessRequest, Identifier: 1},
	})
	require.NoError(t, err)
	assert.Nil(t, reply)
}
