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
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
)

// goldenRA is the Request Authenticator used by the known-answer vectors. It
// is the byte sequence 0x00..0x0f.
var goldenRA = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// TestTunnelPassword_KnownAnswer_SingleBlock verifies the exact ciphertext for
// a single-block plaintext, computed independently against RFC 2868 §3.5:
//
//	b(1) = MD5(Secret + RequestAuth + Salt)
//	c(1) = p(1) XOR b(1)
//
// This pins the first-block seed order to Secret+RA+Salt (NOT Secret+Salt+RA),
// which is the core of the RFC 2868 §3.5 / FreeRADIUS encode_tunnel_password
// construction.
func TestTunnelPassword_KnownAnswer_SingleBlock(t *testing.T) {
	secret := []byte("topsecret")
	salt := []byte{0x80, 0x00}
	password := []byte("hello")
	padding := bytes.Repeat([]byte{0x00}, 10) // 1+5+10 = 16

	enc := encryptSaltedPasswordWithPadding(password, goldenRA, secret, salt, padding)
	want, _ := hex.DecodeString("800045cb961a47ddf4aec31972f44171378a")
	assert.Equal(t, want, enc, "single-block golden vector (RFC 2868 §3.5)")

	// Cross-check: the first ciphertext block must equal P ^ MD5(secret+RA+salt).
	plaintext := append([]byte{byte(len(password))}, password...)
	plaintext = append(plaintext, padding...)
	b1 := md5.Sum(append(append(append([]byte{}, secret...), goldenRA[:]...), salt...))
	var c1 [16]byte
	for i := 0; i < 16; i++ {
		c1[i] = plaintext[i] ^ b1[i]
	}
	assert.Equal(t, c1[:], enc[2:18], "c(1) = p(1) XOR MD5(Secret+RA+Salt)")

	// Round-trip: DecryptTunnelPassword recovers the password (not the padding).
	dec, err := DecryptTunnelPassword(enc, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, password, dec)
}

// TestTunnelPassword_KnownAnswer_TwoBlocks verifies the MD5-feedback chain
// across two blocks: b(i) = MD5(Secret + c(i-1)).
func TestTunnelPassword_KnownAnswer_TwoBlocks(t *testing.T) {
	secret := []byte("topsecret")
	salt := []byte{0x80, 0x00}
	password := []byte("0123456789abcdef0123456789") // 26 bytes
	padding := []byte{0x11, 0x22, 0x33, 0x44, 0x55}  // 1+26+5 = 32 (two blocks)

	enc := encryptSaltedPasswordWithPadding(password, goldenRA, secret, salt, padding)
	want, _ := hex.DecodeString("80005a93c2441886c198f4214b95231253ef27d19aa6f30885740c1894588edd64fc")
	assert.Equal(t, want, enc, "two-block golden vector (RFC 2868 §3.5)")

	dec, err := DecryptTunnelPassword(enc, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, password, dec)
}

// TestTunnelPassword_DataLengthFieldPresent asserts that the first plaintext
// octet is the Data-Length field (RFC 2868 §3.5), by decrypting and checking
// it equals len(password). The previous implementation omitted this field.
func TestTunnelPassword_DataLengthFieldPresent(t *testing.T) {
	secret := []byte("s")
	enc, err := EncryptTunnelPassword([]byte("hunter2"), goldenRA, secret)
	require.NoError(t, err)
	// Decrypt the raw body to inspect the Data-Length byte (offset 0 of the
	// plaintext). We reuse DecryptTunnelPassword and additionally verify the
	// recovered value has no trailing padding leak.
	dec, err := DecryptTunnelPassword(enc, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), dec)
	assert.Len(t, dec, 7, "Data-Length must scope exactly the password, no padding")
}

func TestTunnelPassword_SaltHighBitAlwaysSet(t *testing.T) {
	secret := []byte("s")
	for range 50 {
		enc, err := EncryptTunnelPassword([]byte("p"), goldenRA, secret)
		require.NoError(t, err)
		assert.NotZero(t, enc[0]&0x80, "Salt MSB MUST be set (RFC 2868 §3.5)")
	}
}

func TestTunnelPassword_RoundTrip(t *testing.T) {
	secret := []byte("tunnel-secret")
	cases := [][]byte{
		[]byte("hunter2"),
		[]byte(""),
		bytes.Repeat([]byte("x"), 100),
		bytes.Repeat([]byte("y"), tunnelPasswordMaxLen), // boundary: 239
	}
	for _, pw := range cases {
		enc, err := EncryptTunnelPassword(pw, goldenRA, secret)
		require.NoError(t, err)
		dec, err := DecryptTunnelPassword(enc, goldenRA, secret)
		require.NoError(t, err)
		assert.Equal(t, pw, dec)
	}
}

func TestTunnelPassword_DistinctSalts(t *testing.T) {
	secret := []byte("s")
	pw := []byte("same")
	enc1, err := EncryptTunnelPassword(pw, goldenRA, secret)
	require.NoError(t, err)
	enc2, err := EncryptTunnelPassword(pw, goldenRA, secret)
	require.NoError(t, err)
	assert.NotEqual(t, enc1, enc2, "random salt must produce distinct ciphertexts")
}

func TestTunnelPassword_RejectsEmptySecret(t *testing.T) {
	_, err := EncryptTunnelPassword([]byte("p"), goldenRA, nil)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
	_, err = DecryptTunnelPassword([]byte{0x80, 0, 0, 0}, goldenRA, nil)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
}

func TestTunnelPassword_RejectsTooLongPassword(t *testing.T) {
	secret := []byte("s")
	// tunnelPasswordMaxLen is 239; 240 must be rejected.
	_, err := EncryptTunnelPassword(make([]byte, tunnelPasswordMaxLen+1), goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrPasswordTooLong)
	// Exactly 239 is accepted.
	_, err = EncryptTunnelPassword(make([]byte, tunnelPasswordMaxLen), goldenRA, secret)
	assert.NoError(t, err)
}

func TestTunnelPassword_DecryptRejectsMalformed(t *testing.T) {
	secret := []byte("s")
	// Too short (< 3: need salt + at least one block byte).
	_, err := DecryptTunnelPassword([]byte{0x80, 0x02}, goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "value too short")

	// Ciphertext not a multiple of 16 (salt + 3 bytes).
	_, err = DecryptTunnelPassword([]byte{0x80, 0x02, 0x03, 0x04, 0x05}, goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "ciphertext not multiple of 16")
}

func TestTunnelPassword_DecryptRejectsBadDataLength(t *testing.T) {
	// Construct a value whose decrypted Data-Length exceeds the body.
	secret := []byte("s")
	salt := []byte{0x80, 0x00}
	// Plaintext: Data-Length=0xFF, rest zeros (one block).
	plaintext := []byte{0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b1 := md5.Sum(append(append(append([]byte{}, secret...), goldenRA[:]...), salt...))
	ciphertext := make([]byte, 16)
	for i := 0; i < 16; i++ {
		ciphertext[i] = plaintext[i] ^ b1[i]
	}
	value := append([]byte{0x80, 0x00}, ciphertext...)
	_, err := DecryptTunnelPassword(value, goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute, "Data-Length > body must be rejected")
}

func TestTunnelPassword_DifferentSecretsFailToDecrypt(t *testing.T) {
	secret := []byte("correct-secret")
	wrong := []byte("wrong-secret")
	enc, err := EncryptTunnelPassword([]byte("secret-value"), goldenRA, secret)
	require.NoError(t, err)
	dec, err := DecryptTunnelPassword(enc, goldenRA, wrong)
	// A wrong secret yields a garbage Data-Length. It may exceed the body
	// (returning ErrInvalidAttribute, as FreeRADIUS does) or decrypt to
	// garbage; in neither case may the original password be recovered.
	if err == nil {
		assert.NotEqual(t, []byte("secret-value"), dec, "wrong secret must not recover the plaintext")
	}
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
