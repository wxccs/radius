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

package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
)

func TestTunnelPassword_RoundTrip_NoTag(t *testing.T) {
	secret := []byte("tunnel-secret")
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(i + 1)
	}
	password := []byte("hunter2")

	enc, err := EncryptTunnelPassword(password, ra, secret, 0, false)
	require.NoError(t, err)
	// Salt (2) + at least one 16-byte block.
	assert.GreaterOrEqual(t, len(enc), 18)
	assert.Less(t, len(enc), 18+16)

	dec, tag, hasTag, err := DecryptTunnelPassword(enc, ra, secret)
	require.NoError(t, err)
	assert.Equal(t, password, dec)
	assert.False(t, hasTag)
	assert.Equal(t, byte(0), tag)
}

func TestTunnelPassword_RoundTrip_WithTag(t *testing.T) {
	secret := []byte("tagged-secret")
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(0xA0 + i)
	}
	password := []byte("tagged-password-value")

	enc, err := EncryptTunnelPassword(password, ra, secret, 0x05, true)
	require.NoError(t, err)
	// Salt high bit must be set when tag is present.
	assert.NotZero(t, enc[0]&0x80, "salt high bit must signal tag presence")

	dec, tag, hasTag, err := DecryptTunnelPassword(enc, ra, secret)
	require.NoError(t, err)
	assert.Equal(t, password, dec)
	assert.True(t, hasTag)
	assert.Equal(t, byte(0x05), tag)
}

func TestTunnelPassword_LongPasswordRoundTrip(t *testing.T) {
	secret := []byte("long-secret")
	var ra [16]byte
	password := bytes.Repeat([]byte("x"), 100)

	enc, err := EncryptTunnelPassword(password, ra, secret, 0, false)
	require.NoError(t, err)
	dec, _, _, err := DecryptTunnelPassword(enc, ra, secret)
	require.NoError(t, err)
	assert.Equal(t, password, dec)
}

func TestTunnelPassword_DistinctSalts(t *testing.T) {
	// Two encryptions of the same password must differ (random salt).
	secret := []byte("s")
	var ra [16]byte
	password := []byte("same")
	enc1, err := EncryptTunnelPassword(password, ra, secret, 0, false)
	require.NoError(t, err)
	enc2, err := EncryptTunnelPassword(password, ra, secret, 0, false)
	require.NoError(t, err)
	assert.NotEqual(t, enc1, enc2, "random salt must produce distinct ciphertexts")
}

func TestTunnelPassword_RejectsEmptySecret(t *testing.T) {
	var ra [16]byte
	_, err := EncryptTunnelPassword([]byte("p"), ra, nil, 0, false)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
}

func TestTunnelPassword_RejectsTooLongPassword(t *testing.T) {
	secret := []byte("s")
	var ra [16]byte
	_, err := EncryptTunnelPassword(make([]byte, 241), ra, secret, 0, false)
	assert.ErrorIs(t, err, radiuserrors.ErrPasswordTooLong)
}

func TestTunnelPassword_RejectsInvalidTag(t *testing.T) {
	secret := []byte("s")
	var ra [16]byte
	cases := []byte{0x00, 0x20, 0xFF}
	for _, tag := range cases {
		_, err := EncryptTunnelPassword([]byte("p"), ra, secret, tag, true)
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "tag 0x%02X must be rejected", tag)
	}
}

func TestTunnelPassword_DecryptRejectsMalformed(t *testing.T) {
	secret := []byte("s")
	var ra [16]byte
	_, _, _, err := DecryptTunnelPassword([]byte{0x01, 0x02}, ra, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "value too short")

	_, _, _, err = DecryptTunnelPassword([]byte{0x01, 0x02, 0x03, 0x04, 0x05}, ra, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "ciphertext not multiple of 16")

	// Tag present but no body after tag.
	_, _, _, err = DecryptTunnelPassword([]byte{0x80, 0x02, 0x05}, ra, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "tag with no ciphertext")
}

func TestTunnelPassword_DifferentSecretsFailToDecrypt(t *testing.T) {
	secret := []byte("correct-secret")
	wrong := []byte("wrong-secret")
	var ra [16]byte
	password := []byte("secret-value")

	enc, err := EncryptTunnelPassword(password, ra, secret, 0, false)
	require.NoError(t, err)

	dec, _, _, err := DecryptTunnelPassword(enc, ra, wrong)
	// Decryption succeeds structurally but produces garbage; it should not
	// equal the original password.
	assert.NoError(t, err)
	assert.NotEqual(t, password, dec, "wrong secret must not recover the plaintext")
}

func TestEncodeTunnelTag(t *testing.T) {
	cases := []struct {
		in    byte
		out   byte
		hasIt bool
	}{
		{0x00, 0, false},
		{0x01, 0x01, true},
		{0x1F, 0x1F, true},
		{0x20, 0, false},
		{0xFF, 0, false},
	}
	for _, tc := range cases {
		got, ok := EncodeTunnelTag(tc.in)
		assert.Equal(t, tc.out, got, "tag 0x%02X", tc.in)
		assert.Equal(t, tc.hasIt, ok, "tag 0x%02X", tc.in)
	}
}

func TestDecodeTunnelTag(t *testing.T) {
	cases := []struct {
		name    string
		value   []byte
		tag     byte
		hasTag  bool
		payload []byte
	}{
		{"with tag", []byte{0x03, 'a', 'b'}, 0x03, true, []byte{'a', 'b'}},
		{"no tag, high byte first", []byte{'a', 'b', 'c'}, 0, false, []byte{'a', 'b', 'c'}},
		{"empty", []byte{}, 0, false, []byte{}},
		{"tag with empty payload", []byte{0x05}, 0x05, true, []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tag, hasTag, payload := DecodeTunnelTag(tc.value)
			assert.Equal(t, tc.tag, tag)
			assert.Equal(t, tc.hasTag, hasTag)
			assert.Equal(t, tc.payload, payload)
		})
	}
}

func TestEncodeTunnelInteger_NoTag(t *testing.T) {
	out := EncodeTunnelInteger(0, 42)
	assert.Len(t, out, 4)
	assert.Equal(t, uint32(42), uint32(out[0])<<24|uint32(out[1])<<16|uint32(out[2])<<8|uint32(out[3]))
}

func TestEncodeTunnelInteger_WithTag(t *testing.T) {
	out := EncodeTunnelInteger(0x02, 7)
	assert.Len(t, out, 5)
	assert.Equal(t, byte(0x02), out[0])
	assert.Equal(t, uint32(7), uint32(out[1])<<24|uint32(out[2])<<16|uint32(out[3])<<8|uint32(out[4]))
}

func TestDecodeTunnelInteger(t *testing.T) {
	// With tag: tag + 4-byte int.
	encoded := EncodeTunnelInteger(0x03, 0x01020304)
	tag, hasTag, n, err := DecodeTunnelInteger(encoded)
	require.NoError(t, err)
	assert.Equal(t, byte(0x03), tag)
	assert.True(t, hasTag)
	assert.Equal(t, uint32(0x01020304), n)

	// Without tag: choose a value whose high byte is outside 0x01..0x1F so
	// the tag detector does not misread it as a tag. 0x80... is safe.
	encoded = EncodeTunnelInteger(0, 0x80224488)
	tag, hasTag, n, err = DecodeTunnelInteger(encoded)
	require.NoError(t, err)
	assert.Equal(t, byte(0), tag)
	assert.False(t, hasTag)
	assert.Equal(t, uint32(0x80224488), n)
}

func TestDecodeTunnelInteger_InvalidLength(t *testing.T) {
	_, _, _, err := DecodeTunnelInteger([]byte{0x03, 0x01, 0x02})
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}
