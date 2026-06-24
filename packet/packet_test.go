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

package packet

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/crypto"
	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// RFC 2865 §7.1 test vectors (shared secret "xyzzy5461").
const (
	rfcSecret      = "xyzzy5461"
	rfcReqAuthHex  = "0f403f9473978057bd83d5cb98f4227a"
	rfcReqRawHex   = "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003"
	rfcAcctRawHex  = "0200002686fe220e7624ba2a1005f6bf9b55e0b20606000000010f06000000000e06c0a80103"
	rfcAcctAuthHex = "86fe220e7624ba2a1005f6bf9b55e0b2"
)

func mustAuth16FromHex(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, 16)
	var out [16]byte
	copy(out[:], b)
	return out
}

func TestPacketMarshal_AccessRequest_RFC2865_7_1(t *testing.T) {
	pkt := &Packet{
		Code:          types.AccessRequest,
		Identifier:    0,
		Authenticator: mustAuth16FromHex(t, rfcReqAuthHex),
		Attributes: []Attribute{
			NewString(types.AttrUserName, "nemo"),
			NewString(types.AttrUserPassword, "arctangent"),
			NewIPAddr(types.AttrNASIPAddress, net.IPv4(192, 168, 1, 16)),
			NewInteger(types.AttrNASPort, 3),
		},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	want, _ := hex.DecodeString(rfcReqRawHex)
	assert.Equal(t, want, raw, "marshaled Access-Request must match RFC 2865 §7.1 byte-for-byte")
}

func TestPacketMarshal_AccessAccept_RFC2865_7_1(t *testing.T) {
	pkt := &Packet{
		Code:          types.AccessAccept,
		Identifier:    0,
		Authenticator: mustAuth16FromHex(t, rfcReqAuthHex), // Request Authenticator of original request
		Attributes: []Attribute{
			NewInteger(types.AttrServiceType, 1),  // Login
			NewInteger(types.AttrLoginService, 0), // Telnet
			NewIPAddr(types.AttrLoginIPHost, net.IPv4(192, 168, 1, 3)),
		},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	want, _ := hex.DecodeString(rfcAcctRawHex)
	assert.Equal(t, want, raw, "marshaled Access-Accept must match RFC 2865 §7.1 byte-for-byte")
}

func TestPacketUnmarshal_AccessRequest_RFC2865_7_1(t *testing.T) {
	raw, _ := hex.DecodeString(rfcReqRawHex)
	pkt := &Packet{}
	require.NoError(t, pkt.Unmarshal(raw, []byte(rfcSecret)))

	assert.Equal(t, types.AccessRequest, pkt.Code)
	assert.Equal(t, byte(0), pkt.Identifier)
	assert.Equal(t, mustAuth16FromHex(t, rfcReqAuthHex), pkt.Authenticator)

	require.Len(t, pkt.Attributes, 4)

	userName, ok := pkt.GetOne(types.AttrUserName)
	require.True(t, ok)
	name, err := userName.String()
	require.NoError(t, err)
	assert.Equal(t, "nemo", name)

	userPw, ok := pkt.GetOne(types.AttrUserPassword)
	require.True(t, ok)
	// Value is still ciphertext (16 bytes) — verify it matches the RFC vector.
	wantCipher, _ := hex.DecodeString("0dbe708d93d413ce3196e43f782a0aee")
	assert.Equal(t, wantCipher, userPw.Value)

	nasIP, ok := pkt.GetOne(types.AttrNASIPAddress)
	require.True(t, ok)
	ip, err := nasIP.IPAddr()
	require.NoError(t, err)
	assert.True(t, ip.Equal(net.IPv4(192, 168, 1, 16)))

	nasPort, ok := pkt.GetOne(types.AttrNASPort)
	require.True(t, ok)
	port, err := nasPort.Integer()
	require.NoError(t, err)
	assert.Equal(t, uint32(3), port)
}

func TestPacketUnmarshal_AccessAccept_RFC2865_7_1(t *testing.T) {
	raw, _ := hex.DecodeString(rfcAcctRawHex)
	pkt := &Packet{}
	require.NoError(t, pkt.Unmarshal(raw, []byte(rfcSecret)))

	assert.Equal(t, types.AccessAccept, pkt.Code)
	assert.Equal(t, byte(0), pkt.Identifier)

	wantAuth := mustAuth16FromHex(t, rfcAcctAuthHex)
	assert.Equal(t, wantAuth, pkt.Authenticator)

	require.Len(t, pkt.Attributes, 3)
}

func TestVerifyResponseAuthenticator_RFC2865_7_1(t *testing.T) {
	raw, _ := hex.DecodeString(rfcAcctRawHex)
	ra := mustAuth16FromHex(t, rfcReqAuthHex)
	require.NoError(t, VerifyResponseAuthenticator(raw, ra, []byte(rfcSecret)))

	// Wrong secret must fail.
	assert.ErrorIs(t, VerifyResponseAuthenticator(raw, ra, []byte("wrong")), radiuserrors.ErrAuthenticatorMismatch)

	// Wrong request authenticator must fail.
	bad := ra
	bad[0] ^= 0xff
	assert.ErrorIs(t, VerifyResponseAuthenticator(raw, bad, []byte(rfcSecret)), radiuserrors.ErrAuthenticatorMismatch)
}

func TestPacketMarshalRoundTrip(t *testing.T) {
	ra := mustAuth16FromHex(t, "00112233445566778899aabbccddeeff")
	secret := []byte("round-trip-secret")

	cases := []struct {
		name string
		pkt  *Packet
	}{
		{
			name: "access_request",
			pkt: &Packet{
				Code:          types.AccessRequest,
				Identifier:    42,
				Authenticator: ra,
				Attributes: []Attribute{
					NewString(types.AttrUserName, "alice"),
					NewString(types.AttrUserPassword, "correct horse battery staple"),
					NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 20, 30, 40)),
				},
			},
		},
		{
			name: "access_accept",
			pkt: &Packet{
				Code:          types.AccessAccept,
				Identifier:    7,
				Authenticator: ra,
				Attributes: []Attribute{
					NewInteger(types.AttrServiceType, 2),
					NewInteger(types.AttrSessionTimeout, 3600),
				},
			},
		},
		{
			name: "access_reject",
			pkt: &Packet{
				Code:          types.AccessReject,
				Identifier:    9,
				Authenticator: ra,
				Attributes: []Attribute{
					NewString(types.AttrReplyMessage, "access denied"),
				},
			},
		},
		{
			name: "accounting_request",
			pkt: &Packet{
				Code:       types.AccountingRequest,
				Identifier: 100,
				Attributes: []Attribute{
					NewInteger(types.AttrAcctStatusType, 1), // Start
					NewString(types.AttrAcctSessionID, "sess-123"),
					NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 1)),
				},
			},
		},
		{
			name: "accounting_response",
			pkt: &Packet{
				Code:          types.AccountingResponse,
				Identifier:    100,
				Authenticator: ra,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.pkt.Marshal(secret)
			require.NoError(t, err)

			got := &Packet{}
			require.NoError(t, got.Unmarshal(raw, secret))
			assert.Equal(t, tc.pkt.Code, got.Code)
			assert.Equal(t, tc.pkt.Identifier, got.Identifier)

			// Authenticator handling differs by Code:
			// - Access-Request preserves the caller-supplied Request Authenticator.
			// - Accounting-Request's authenticator is computed by Marshal and
			//   auto-verified by Unmarshal, so a successful Unmarshal suffices.
			// - Reply packets carry a Response Authenticator derived from the
			//   original Request Authenticator; verify via the helper instead of
			//   comparing fields directly.
			switch tc.pkt.Code {
			case types.AccessRequest:
				assert.Equal(t, tc.pkt.Authenticator, got.Authenticator, "Access-Request must preserve caller-supplied Request Authenticator")
			case types.AccountingRequest:
				assert.NotEqual(t, [16]byte{}, got.Authenticator, "Accounting-Request must carry a computed authenticator")
			default:
				require.NoError(t, VerifyResponseAuthenticator(raw, tc.pkt.Authenticator, secret), "reply packet Response Authenticator must verify against original Request Authenticator")
			}

			require.Len(t, got.Attributes, len(tc.pkt.Attributes))
			for i := range tc.pkt.Attributes {
				assert.Equal(t, tc.pkt.Attributes[i].Type, got.Attributes[i].Type)
				// For Access-Request User-Password the Value differs (ciphertext); skip value check for that case.
				if tc.pkt.Code == types.AccessRequest && tc.pkt.Attributes[i].Type == types.AttrUserPassword {
					continue
				}
				assert.Equal(t, tc.pkt.Attributes[i].Value, got.Attributes[i].Value, "attribute %d (%d)", i, tc.pkt.Attributes[i].Type)
			}
		})
	}
}

func TestPacketUnmarshal_Errors(t *testing.T) {
	t.Run("short_buffer_below_min", func(t *testing.T) {
		p := &Packet{}
		err := p.Unmarshal([]byte{1, 2, 3}, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
	})
	t.Run("invalid_code", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = 99 // not a valid code
		raw[2] = 0
		raw[3] = 20
		p := &Packet{}
		err := p.Unmarshal(raw, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidCode)
	})
	t.Run("length_below_minimum", func(t *testing.T) {
		raw := []byte{1, 0, 0, 10} // length 10 < 20
		raw = append(raw, make([]byte, 16)...)
		p := &Packet{}
		err := p.Unmarshal(raw, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidLength)
	})
	t.Run("length_exceeds_max", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = 1
		raw[2] = 0x10
		raw[3] = 0x01 // length 4097 > 4096
		p := &Packet{}
		err := p.Unmarshal(raw, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidLength)
	})
	t.Run("data_shorter_than_length", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = 1
		raw[2] = 0
		raw[3] = 50 // length 50 but only 20 bytes
		p := &Packet{}
		err := p.Unmarshal(raw, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
	})
	t.Run("truncated_attribute", func(t *testing.T) {
		raw := []byte{1, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 'a', 'b'}
		// Length=23, but attribute claims length 6 with only 2 value bytes.
		p := &Packet{}
		err := p.Unmarshal(raw, []byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidLength)
	})
}

func TestPacketMarshal_Errors(t *testing.T) {
	t.Run("empty_secret", func(t *testing.T) {
		pkt := &Packet{Code: types.AccessRequest, Authenticator: mustAuth16FromHex(t, "00112233445566778899aabbccddeeff")}
		_, err := pkt.Marshal(nil)
		assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
	})
	t.Run("invalid_code", func(t *testing.T) {
		pkt := &Packet{Code: 99}
		_, err := pkt.Marshal([]byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidCode)
	})
	t.Run("attribute_too_long", func(t *testing.T) {
		pkt := &Packet{
			Code:          types.AccessAccept,
			Authenticator: mustAuth16FromHex(t, "00112233445566778899aabbccddeeff"),
			Attributes:    []Attribute{{Type: 1, Value: make([]byte, 254)}},
		}
		_, err := pkt.Marshal([]byte("s"))
		assert.ErrorIs(t, err, radiuserrors.ErrAttributeTooLong)
	})
}

func TestPacketAccountingAuthenticator_AutoVerified(t *testing.T) {
	ra := mustAuth16FromHex(t, "00112233445566778899aabbccddeeff")
	_ = ra
	pkt := &Packet{
		Code:       types.AccountingRequest,
		Identifier: 5,
		Attributes: []Attribute{
			NewInteger(types.AttrAcctStatusType, 1),
			NewString(types.AttrAcctSessionID, "sess-abc"),
		},
	}
	raw, err := pkt.Marshal([]byte("acct-secret"))
	require.NoError(t, err)

	// Unmarshal with correct secret succeeds.
	p := &Packet{}
	require.NoError(t, p.Unmarshal(raw, []byte("acct-secret")))

	// Unmarshal with wrong secret fails authenticator verification.
	p2 := &Packet{}
	assert.ErrorIs(t, p2.Unmarshal(raw, []byte("wrong-secret")), radiuserrors.ErrAuthenticatorMismatch)
}

// TestPacketCoADisconnectAuthenticator verifies that CoA-Request and
// Disconnect-Request use the Accounting-Request authenticator formula
// (RFC 5176 §2.3), not a caller-supplied random value.
func TestPacketCoADisconnectAuthenticator(t *testing.T) {
	t.Run("coa_request_uses_accounting_formula", func(t *testing.T) {
		secret := []byte("coa-secret")
		pkt := &Packet{
			Code:       types.CoARequest,
			Identifier: 7,
			Attributes: []Attribute{
				NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 1)),
				NewString(types.AttrAcctSessionID, "sess-coa"),
			},
		}
		raw, err := pkt.Marshal(secret)
		require.NoError(t, err)

		length := binary.BigEndian.Uint16(raw[2:4])
		expected := crypto.ComputeAccountingRequestAuthenticator(
			byte(types.CoARequest), 7, length, raw[20:length], secret)
		var got [16]byte
		copy(got[:], raw[4:20])
		assert.Equal(t, expected, got, "CoA-Request authenticator must be MD5-derived per RFC 5176 §2.3")

		// Unmarshal with correct secret succeeds (auto-verifies).
		p := &Packet{}
		require.NoError(t, p.Unmarshal(raw, secret))
		assert.Equal(t, types.CoARequest, p.Code)

		// Unmarshal with wrong secret fails.
		bad := &Packet{}
		assert.ErrorIs(t, bad.Unmarshal(raw, []byte("wrong")), radiuserrors.ErrAuthenticatorMismatch)
	})

	t.Run("disconnect_request_uses_accounting_formula", func(t *testing.T) {
		secret := []byte("dm-secret")
		pkt := &Packet{
			Code:       types.DisconnectRequest,
			Identifier: 9,
			Attributes: []Attribute{
				NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 2)),
				NewString(types.AttrAcctSessionID, "sess-dm"),
			},
		}
		raw, err := pkt.Marshal(secret)
		require.NoError(t, err)

		length := binary.BigEndian.Uint16(raw[2:4])
		expected := crypto.ComputeAccountingRequestAuthenticator(
			byte(types.DisconnectRequest), 9, length, raw[20:length], secret)
		var got [16]byte
		copy(got[:], raw[4:20])
		assert.Equal(t, expected, got, "Disconnect-Request authenticator must be MD5-derived per RFC 5176 §2.3")

		p := &Packet{}
		require.NoError(t, p.Unmarshal(raw, secret))
		assert.Equal(t, types.DisconnectRequest, p.Code)

		bad := &Packet{}
		assert.ErrorIs(t, bad.Unmarshal(raw, []byte("wrong")), radiuserrors.ErrAuthenticatorMismatch)
	})

	t.Run("caller_authenticator_ignored_for_coa", func(t *testing.T) {
		// A caller-supplied Authenticator must NOT be copied into the packet
		// for CoA-Request (the MD5 formula overrides it).
		secret := []byte("coa-secret")
		pkt := &Packet{
			Code:          types.CoARequest,
			Identifier:    1,
			Authenticator: mustAuth16FromHex(t, "ffffffffffffffffffffffffffffffff"),
		}
		raw, err := pkt.Marshal(secret)
		require.NoError(t, err)
		var got [16]byte
		copy(got[:], raw[4:20])
		assert.NotEqual(t, pkt.Authenticator, got, "CoA-Request must not carry caller-supplied random authenticator")
	})
}

func TestPacketAttributeOps(t *testing.T) {
	p := &Packet{}
	p.Add(NewString(1, "alice"))
	p.Add(NewInteger(6, 2))
	p.Add(NewString(1, "bob"))
	p.Add(NewInteger(27, 3600))

	// Get returns all instances of a type.
	assert.Len(t, p.Get(1), 2)
	assert.Len(t, p.Get(6), 1)

	// GetOne returns the first.
	first, ok := p.GetOne(1)
	require.True(t, ok)
	name, _ := first.String()
	assert.Equal(t, "alice", name)

	// Set replaces all instances of the type with a single one.
	p.Set(NewString(1, "carol"))
	all := p.Get(1)
	require.Len(t, all, 1)
	name, _ = all[0].String()
	assert.Equal(t, "carol", name)

	// Set on a missing type appends.
	p.Set(NewString(18, "hello"))
	require.Len(t, p.Get(18), 1)

	// Delete removes all of a type and returns count.
	removed := p.Delete(1)
	assert.Equal(t, 1, removed)
	assert.Empty(t, p.Get(1))

	// Delete on a missing type returns 0.
	assert.Equal(t, 0, p.Delete(99))
}

func TestPacketMarshal_MessageAuthenticator(t *testing.T) {
	ra := mustAuth16FromHex(t, rfcReqAuthHex)
	pkt := &Packet{
		Code:          types.AccessRequest,
		Identifier:    1,
		Authenticator: ra,
		Attributes: []Attribute{
			NewString(types.AttrUserName, "test-user"),
			NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	// Message-Authenticator must validate against the marshaled packet.
	require.NoError(t, VerifyMessageAuthenticator(raw, []byte(rfcSecret)))

	// Unmarshal round-trip preserves the attribute.
	p := &Packet{}
	require.NoError(t, p.Unmarshal(raw, []byte(rfcSecret)))
	_, ok := p.GetOne(types.AttrMessageAuthenticator)
	assert.True(t, ok)
}

func TestVerifyMessageAuthenticator_Missing(t *testing.T) {
	// An Access-Accept without Message-Authenticator attribute.
	pkt := &Packet{
		Code:          types.AccessAccept,
		Identifier:    1,
		Authenticator: mustAuth16FromHex(t, rfcReqAuthHex),
		Attributes:    []Attribute{NewInteger(types.AttrServiceType, 1)},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	err = VerifyMessageAuthenticator(raw, []byte(rfcSecret))
	assert.ErrorIs(t, err, radiuserrors.ErrMessageAuthenticatorMissing)
}

func TestVerifyMessageAuthenticator_Tampered(t *testing.T) {
	ra := mustAuth16FromHex(t, rfcReqAuthHex)
	pkt := &Packet{
		Code:          types.AccessRequest,
		Identifier:    1,
		Authenticator: ra,
		Attributes: []Attribute{
			NewString(types.AttrUserName, "test-user"),
			NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	// Flip a bit in the User-Name attribute (offset 20+2 = 22).
	tampered := append([]byte(nil), raw...)
	tampered[22] ^= 0xff
	err = VerifyMessageAuthenticator(tampered, []byte(rfcSecret))
	assert.ErrorIs(t, err, radiuserrors.ErrMessageAuthenticatorMismatch)
}

func TestPacketMarshal_MultipleMessageAuthenticator(t *testing.T) {
	pkt := &Packet{
		Code:          types.AccessRequest,
		Authenticator: mustAuth16FromHex(t, "00112233445566778899aabbccddeeff"),
		Attributes: []Attribute{
			NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
			NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	_, err := pkt.Marshal([]byte("s"))
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

// TestPacketMarshal_MessageAuthenticator_Reply verifies that a reply packet
// (Access-Accept) carrying Message-Authenticator verifies correctly. The
// Marshal code computes Message-Authenticator with the Authenticator field
// zeroed (the Response Authenticator has not yet been written); Verify
// must mirror this by zeroing the Authenticator field for non-Access-Request
// packets before recomputing the HMAC.
func TestPacketMarshal_MessageAuthenticator_Reply(t *testing.T) {
	ra := mustAuth16FromHex(t, rfcReqAuthHex)
	pkt := &Packet{
		Code:          types.AccessAccept,
		Identifier:    2,
		Authenticator: ra,
		Attributes: []Attribute{
			NewInteger(types.AttrServiceType, 1),
			NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	require.NoError(t, VerifyMessageAuthenticator(raw, []byte(rfcSecret)))
	require.NoError(t, VerifyResponseAuthenticator(raw, ra, []byte(rfcSecret)))

	// Tampering with the reply body must invalidate Message-Authenticator.
	tampered := append([]byte(nil), raw...)
	tampered[22] ^= 0xff
	assert.ErrorIs(t, VerifyMessageAuthenticator(tampered, []byte(rfcSecret)),
		radiuserrors.ErrMessageAuthenticatorMismatch)
}

func TestPacketPaddingIgnored(t *testing.T) {
	// Construct a valid Access-Accept and append trailing padding bytes.
	pkt := &Packet{
		Code:          types.AccessAccept,
		Identifier:    1,
		Authenticator: mustAuth16FromHex(t, rfcReqAuthHex),
		Attributes:    []Attribute{NewInteger(types.AttrServiceType, 1)},
	}
	raw, err := pkt.Marshal([]byte(rfcSecret))
	require.NoError(t, err)

	padded := append([]byte(nil), raw...)
	padded = append(padded, 0x00, 0x00, 0x00, 0x00) // trailing junk

	p := &Packet{}
	require.NoError(t, p.Unmarshal(padded, []byte(rfcSecret)))
	assert.Equal(t, types.AccessAccept, p.Code)
	require.Len(t, p.Attributes, 1)
}

func TestPacketIsHelpers(t *testing.T) {
	p := &Packet{Code: types.AccessRequest}
	assert.True(t, p.IsAccess())
	assert.False(t, p.IsAccounting())
	assert.False(t, p.IsCoA())

	p.Code = types.AccountingResponse
	assert.False(t, p.IsAccess())
	assert.True(t, p.IsAccounting())

	p.Code = types.CoARequest
	assert.True(t, p.IsCoA())
}

func TestGetOne_NotFound(t *testing.T) {
	p := &Packet{Attributes: []Attribute{NewString(1, "alice")}}
	_, ok := p.GetOne(99)
	assert.False(t, ok, "GetOne must return false when no attribute of the type exists")
}

func TestVerifyResponseAuthenticator_Errors(t *testing.T) {
	ra := mustAuth16FromHex(t, rfcReqAuthHex)

	t.Run("short_buffer", func(t *testing.T) {
		assert.ErrorIs(t, VerifyResponseAuthenticator([]byte{1, 2, 3}, ra, []byte("s")), radiuserrors.ErrShortBuffer)
	})
	t.Run("invalid_code", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = 99 // not a response code
		raw[2] = 0
		raw[3] = 20
		assert.ErrorIs(t, VerifyResponseAuthenticator(raw, ra, []byte("s")), radiuserrors.ErrInvalidCode)
	})
	t.Run("length_exceeds_buffer", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = byte(types.AccessAccept)
		raw[2] = 0
		raw[3] = 50 // length 50 but only 20 bytes present
		assert.ErrorIs(t, VerifyResponseAuthenticator(raw, ra, []byte("s")), radiuserrors.ErrShortBuffer)
	})
}

func TestVerifyMessageAuthenticator_Errors(t *testing.T) {
	t.Run("short_buffer", func(t *testing.T) {
		assert.ErrorIs(t, VerifyMessageAuthenticator([]byte{1, 2, 3}, []byte("s")), radiuserrors.ErrShortBuffer)
	})
	t.Run("length_exceeds_buffer", func(t *testing.T) {
		raw := make([]byte, 20)
		raw[0] = byte(types.AccessAccept)
		raw[2] = 0
		raw[3] = 50
		assert.ErrorIs(t, VerifyMessageAuthenticator(raw, []byte("s")), radiuserrors.ErrShortBuffer)
	})
}

func TestNewIPv6Addr_Invalid(t *testing.T) {
	// A nil net.IP falls back to 16 zero bytes.
	a := NewIPv6Addr(95, nil)
	assert.Len(t, a.Value, 16)
}
