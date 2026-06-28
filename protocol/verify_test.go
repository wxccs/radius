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

package protocol

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
)

// RFC 2865 §7.1 vectors, kept in sync with packet/packet_test.go for parity.
const (
	verifySecret     = "xyzzy5461"
	verifyReqAuthHex = "0f403f9473978057bd83d5cb98f4227a"
)

func mustHexAuth(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, 16)
	var out [16]byte
	copy(out[:], b)
	return out
}

func TestVerifyResponse_ValidAccessAccept(t *testing.T) {
	secret := []byte(verifySecret)
	reqAuth := mustHexAuth(t, verifyReqAuthHex)

	// Build an Access-Accept reply using packet.Marshal so the Response
	// Authenticator matches reqAuth.
	reply := &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    7,
		Authenticator: reqAuth,
		Attributes: []packet.Attribute{
			packet.NewInteger(types.AttrServiceType, 1),
		},
	}
	raw, err := reply.Marshal(secret)
	require.NoError(t, err)

	pkt, err := VerifyResponse(raw, 7, reqAuth, secret)
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, pkt.Code)
	assert.Equal(t, byte(7), pkt.Identifier)
}

func TestVerifyResponse_WrongIdentifier(t *testing.T) {
	secret := []byte(verifySecret)
	reqAuth := mustHexAuth(t, verifyReqAuthHex)

	reply := &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    7,
		Authenticator: reqAuth,
		Attributes:    []packet.Attribute{packet.NewInteger(types.AttrServiceType, 1)},
	}
	raw, err := reply.Marshal(secret)
	require.NoError(t, err)

	_, err = VerifyResponse(raw, 8, reqAuth, secret)
	assert.ErrorIs(t, err, ErrIdentifierMismatch)
}

func TestVerifyResponse_WrongResponseAuthenticator(t *testing.T) {
	secret := []byte(verifySecret)
	reqAuth := mustHexAuth(t, verifyReqAuthHex)

	reply := &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    7,
		Authenticator: reqAuth,
		Attributes:    []packet.Attribute{packet.NewInteger(types.AttrServiceType, 1)},
	}
	raw, err := reply.Marshal(secret)
	require.NoError(t, err)

	wrongAuth := reqAuth
	wrongAuth[0] ^= 0xff
	_, err = VerifyResponse(raw, 7, wrongAuth, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrAuthenticatorMismatch)
}

func TestVerifyResponse_WithMessageAuthenticator(t *testing.T) {
	secret := []byte("msg-auth-secret")
	reqAuth := mustHexAuth(t, "00112233445566778899aabbccddeeff")

	reply := &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    3,
		Authenticator: reqAuth,
		Attributes: []packet.Attribute{
			packet.NewInteger(types.AttrServiceType, 2),
			packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := reply.Marshal(secret)
	require.NoError(t, err)

	pkt, err := VerifyResponse(raw, 3, reqAuth, secret)
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, pkt.Code)

	// Tampering with the reply must fail verification. Flipping a byte in
	// the Message-Authenticator Value invalidates the Response Authenticator
	// first (it covers the body), so we accept any authenticator error.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = VerifyResponse(tampered, 3, reqAuth, secret)
	assert.Error(t, err, "tampered reply must fail verification")
}

func TestVerifyResponse_MalformedPacket(t *testing.T) {
	secret := []byte("s")
	// Short buffer must surface the underlying error.
	_, err := VerifyResponse([]byte{1, 2, 3, 4}, 0, [16]byte{}, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
}

func TestVerifyResponse_InvalidCode(t *testing.T) {
	secret := []byte("s")
	raw := make([]byte, 20)
	raw[0] = 99 // not a valid code
	raw[2] = 0
	raw[3] = 20
	_, err := VerifyResponse(raw, 0, [16]byte{}, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidCode)
}

func TestHasMessageAuthenticator(t *testing.T) {
	p := &packet.Packet{Attributes: []packet.Attribute{
		packet.NewString(types.AttrUserName, "alice"),
	}}
	assert.False(t, hasMessageAuthenticator(p))

	p.Attributes = append(p.Attributes,
		packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)))
	assert.True(t, hasMessageAuthenticator(p))
}

func TestVerifyResponse_RoundTripFromPacket(t *testing.T) {
	// Cross-check: a reply marshaled by packet.Marshal should round-trip
	// through VerifyResponse against the original Request Authenticator.
	secret := []byte("round-trip")
	reqAuth := mustHexAuth(t, "deadbeefdeadbeefdeadbeefdeadbeef")

	reply := &packet.Packet{
		Code:          types.AccessReject,
		Identifier:    42,
		Authenticator: reqAuth,
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrReplyMessage, "denied"),
			packet.NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 1, 2, 3)),
		},
	}
	raw, err := reply.Marshal(secret)
	require.NoError(t, err)

	pkt, err := VerifyResponse(raw, 42, reqAuth, secret)
	require.NoError(t, err)
	assert.Equal(t, types.AccessReject, pkt.Code)
	require.Len(t, pkt.Attributes, 2)
}
