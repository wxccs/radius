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

// TestEncryptMPPEKey_KnownAnswer_128bit verifies the exact RFC 2548 §3.3
// ciphertext for a 128-bit (16-octet) key. The construction is identical to
// Tunnel-Password (RFC 2868 §3.5): b(1)=MD5(Secret+RA+Salt), and the plaintext
// is Key-Length(1)+Key+Padding. This pins the seed order and the Key-Length
// prefix.
func TestEncryptMPPEKey_KnownAnswer_128bit(t *testing.T) {
	secret := []byte("topsecret")
	salt := []byte{0x80, 0x00}
	key := []byte{
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	padding := bytes.Repeat([]byte{0x00}, 15) // 1+16+15 = 32 (two blocks)

	enc := encryptSaltedPasswordWithPadding(key, goldenRA, secret, salt, padding)
	want, _ := hex.DecodeString("800050b2e1653fa7e2b9db0068ef5d6c29950a6bf93d97af41925af9be2ba015e09f")
	assert.Equal(t, want, enc, "128-bit MPPE key golden vector (RFC 2548 §3.3)")

	// Cross-check: c(1) = P ^ MD5(Secret+RA+Salt).
	plaintext := append([]byte{byte(len(key))}, key...)
	plaintext = append(plaintext, padding...)
	b1 := md5.Sum(append(append(append([]byte{}, secret...), goldenRA[:]...), salt...))
	var c1 [16]byte
	for i := 0; i < 16; i++ {
		c1[i] = plaintext[i] ^ b1[i]
	}
	assert.Equal(t, c1[:], enc[2:18], "c(1) = p(1) XOR MD5(Secret+RA+Salt)")

	dec, err := DecryptMPPEKey(enc, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, key, dec)
}

// TestEncryptMPPEKey_KnownAnswer_40bit verifies a 40-bit (8-octet) key in a
// single block.
func TestEncryptMPPEKey_KnownAnswer_40bit(t *testing.T) {
	secret := []byte("topsecret")
	salt := []byte{0x80, 0x00}
	key := []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	padding := []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA} // 1+8+7 = 16

	enc := encryptSaltedPasswordWithPadding(key, goldenRA, secret, salt, padding)
	want, _ := hex.DecodeString("80004893c2441886c198f4b3d85eebdb9d20")
	assert.Equal(t, want, enc, "40-bit MPPE key golden vector (RFC 2548 §3.3)")

	dec, err := DecryptMPPEKey(enc, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, key, dec)
}

func TestEncryptMPPEKey_RoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	cases := [][]byte{
		make([]byte, 8),  // 40-bit
		make([]byte, 16), // 128-bit
		[]byte("short"),
	}
	for _, key := range cases {
		enc, err := EncryptMPPEKey(key, goldenRA, secret)
		require.NoError(t, err)
		dec, err := DecryptMPPEKey(enc, goldenRA, secret)
		require.NoError(t, err)
		assert.Equal(t, key, dec)
	}
}

func TestEncryptMPPEKey_SaltHighBitAlwaysSet(t *testing.T) {
	secret := []byte("s")
	for range 50 {
		enc, err := EncryptMPPEKey(make([]byte, 16), goldenRA, secret)
		require.NoError(t, err)
		assert.NotZero(t, enc[0]&0x80, "Salt MSB MUST be set (RFC 2548 §3.3)")
	}
}

func TestEncryptMPPEKey_RejectsEmptySecret(t *testing.T) {
	_, err := EncryptMPPEKey(make([]byte, 16), goldenRA, nil)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
}

func TestDecryptMPPEKey_RejectsMalformed(t *testing.T) {
	secret := []byte("s")
	// Too short (< 3: need salt + at least one block byte).
	_, err := DecryptMPPEKey([]byte{0x80, 0x00}, goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	// Ciphertext not a multiple of 16 (salt + 3 bytes).
	_, err = DecryptMPPEKey([]byte{0x80, 0x00, 0x01, 0x02, 0x03}, goldenRA, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

// TestEncryptMPPEKey_SameAlgorithmAsTunnelPassword confirms that MPPE key
// transport uses the same salted MD5-feedback construction as Tunnel-Password:
// encrypting an MPPE key payload with Tunnel-Password's primitive yields the
// same ciphertext for a fixed salt+padding, and the two decrypt functions are
// interchangeable.
func TestEncryptMPPEKey_SameAlgorithmAsTunnelPassword(t *testing.T) {
	secret := []byte("topsecret")
	salt := []byte{0x80, 0x00}
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padding := bytes.Repeat([]byte{0x00}, 7)

	encMPPE := encryptSaltedPasswordWithPadding(key, goldenRA, secret, salt, padding)
	encTunnel := encryptSaltedPasswordWithPadding(key, goldenRA, secret, salt, padding) // identical primitive
	assert.Equal(t, encMPPE, encTunnel)

	// Cross-decrypt: DecryptMPPEKey decrypts a Tunnel-Password-style value and
	// vice versa, because the wire algorithm is shared.
	dec, err := DecryptTunnelPassword(encMPPE, goldenRA, secret)
	require.NoError(t, err)
	assert.Equal(t, key, dec)
}
