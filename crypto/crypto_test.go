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

package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
)

// mustHex decodes a hex string, failing the test if it is malformed.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoErrorf(t, err, "invalid hex in test vector: %q", s)
	return b
}

// mustAuth16 converts a 16-byte slice into a [16]byte array.
func mustAuth16(t *testing.T, s string) [16]byte {
	t.Helper()
	b := mustHex(t, s)
	require.Lenf(t, b, 16, "expected 16-byte authenticator, got %d bytes", len(b))
	var out [16]byte
	copy(out[:], b)
	return out
}

// RFC 2865 §7.1 test vector (shared secret "xyzzy5461", user nemo / arctangent).
const (
	rfc7Secret    = "xyzzy5461"
	rfc7ReqAuth   = "0f403f9473978057bd83d5cb98f4227a"
	rfc7Password  = "arctangent"
	rfc7CipherHex = "0dbe708d93d413ce3196e43f782a0aee"
	// Access-Accept attributes: Service-Type=Login, Login-Service=Telnet, Login-IP-Host=192.168.1.3
	rfc7AcceptAttrs   = "0606000000010f06000000000e06c0a80103"
	rfc7AcceptAuthHex = "86fe220e7624ba2a1005f6bf9b55e0b2"
	rfc7AcceptCode    = byte(0x02)
	rfc7AcceptID      = byte(0x00)
	rfc7AcceptLength  = uint16(38)
)

func TestComputeResponseAuthenticator_RFC2865_7_1(t *testing.T) {
	ra := mustAuth16(t, rfc7ReqAuth)
	attrs := mustHex(t, rfc7AcceptAttrs)
	want := mustHex(t, rfc7AcceptAuthHex)

	got := ComputeResponseAuthenticator(rfc7AcceptCode, rfc7AcceptID, rfc7AcceptLength, ra, attrs, []byte(rfc7Secret))
	assert.Equal(t, want, got[:], "response authenticator must match RFC 2865 §7.1 Access-Accept vector")
}

func TestComputeResponseAuthenticator_ManualRecompute(t *testing.T) {
	// Recompute with the standard library directly to cross-check the formula.
	ra := mustAuth16(t, rfc7ReqAuth)
	attrs := mustHex(t, rfc7AcceptAttrs)
	secret := []byte(rfc7Secret)

	h := md5.New()
	h.Write([]byte{rfc7AcceptCode, rfc7AcceptID})
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], rfc7AcceptLength)
	h.Write(lenBuf[:])
	h.Write(ra[:])
	h.Write(attrs)
	h.Write(secret)
	want := h.Sum(nil)

	got := ComputeResponseAuthenticator(rfc7AcceptCode, rfc7AcceptID, rfc7AcceptLength, ra, attrs, secret)
	assert.Equal(t, want, got[:])
}

func TestComputeAccountingRequestAuthenticator_Formula(t *testing.T) {
	code := byte(4)
	id := byte(7)
	length := uint16(20)
	attrs := []byte{}
	secret := []byte("accounting-secret")

	h := md5.New()
	h.Write([]byte{code, id})
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], length)
	h.Write(lenBuf[:])
	h.Write(make([]byte, 16)) // 16 zero octets in place of authenticator
	h.Write(attrs)
	h.Write(secret)
	want := h.Sum(nil)

	got := ComputeAccountingRequestAuthenticator(code, id, length, attrs, secret)
	assert.Equal(t, want, got[:])
}

func TestComputeAccountingRequestAuthenticator_WithAttributes(t *testing.T) {
	code := byte(4)
	id := byte(1)
	length := uint16(32)
	attrs := mustHex(t, "280600000001") // Acct-Status-Type=Start (28=type 40 decimal? 0x28=40 yes)
	secret := []byte("s")

	h := md5.New()
	h.Write([]byte{code, id})
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], length)
	h.Write(lenBuf[:])
	h.Write(make([]byte, 16))
	h.Write(attrs)
	h.Write(secret)
	want := h.Sum(nil)

	got := ComputeAccountingRequestAuthenticator(code, id, length, attrs, secret)
	assert.Equal(t, want, got[:])
}

func TestEncryptUserPassword_RFC2865_7_1(t *testing.T) {
	ra := mustAuth16(t, rfc7ReqAuth)
	want := mustHex(t, rfc7CipherHex)

	got, err := EncryptUserPassword([]byte(rfc7Password), ra, []byte(rfc7Secret))
	require.NoError(t, err)
	assert.Equal(t, want, got, "encrypted password must match RFC 2865 §7.1 vector")
}

func TestEncryptUserPassword_LengthClasses(t *testing.T) {
	ra := mustAuth16(t, "00112233445566778899aabbccddeeff")
	secret := []byte("sec")

	cases := []struct {
		name     string
		password string
		wantLen  int
	}{
		{"empty", "", 16},
		{"short", "a", 16},
		{"block_boundary_16", "0123456789abcdef", 16},
		{"just_over_16", "0123456789abcdefg", 32},
		{"max_128", string(make([]byte, 128)), 128},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncryptUserPassword([]byte(tc.password), ra, secret)
			require.NoError(t, err)
			assert.Len(t, got, tc.wantLen)
		})
	}
}

func TestEncryptUserPassword_Errors(t *testing.T) {
	ra := mustAuth16(t, "00112233445566778899aabbccddeeff")

	_, err := EncryptUserPassword(make([]byte, 129), ra, []byte("s"))
	assert.ErrorIs(t, err, radiuserrors.ErrPasswordTooLong)

	_, err = EncryptUserPassword([]byte("pw"), ra, nil)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
}

func TestEncryptDecryptUserPassword_RoundTrip(t *testing.T) {
	ra := mustAuth16(t, "0f403f9473978057bd83d5cb98f4227a")
	secret := []byte(rfc7Secret)

	passwords := []string{
		"",
		"a",
		"arctangent",
		"0123456789abcdef", // exactly 16
		"0123456789abcdefg",
		strings.Repeat("x", 128),
	}
	for _, pw := range passwords {
		t.Run(fmt.Sprintf("len=%d", len(pw)), func(t *testing.T) {
			ciphertext, err := EncryptUserPassword([]byte(pw), ra, secret)
			require.NoError(t, err)
			wantLen := ((len(pw) + 15) / 16) * 16
			if wantLen == 0 {
				wantLen = 16 // empty password still produces one block
			}
			assert.Len(t, ciphertext, wantLen)

			got, err := DecryptUserPassword(ciphertext, ra, secret)
			require.NoError(t, err)
			assert.Equal(t, pw, string(got))
		})
	}
}

func TestDecryptUserPassword_RFC2865_7_1(t *testing.T) {
	ra := mustAuth16(t, rfc7ReqAuth)
	ciphertext := mustHex(t, rfc7CipherHex)

	got, err := DecryptUserPassword(ciphertext, ra, []byte(rfc7Secret))
	require.NoError(t, err)
	assert.Equal(t, rfc7Password, string(got))
}

func TestDecryptUserPassword_Errors(t *testing.T) {
	ra := mustAuth16(t, "00112233445566778899aabbccddeeff")

	_, err := DecryptUserPassword(nil, ra, []byte("s"))
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)

	_, err = DecryptUserPassword([]byte("short"), ra, []byte("s"))
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)

	_, err = DecryptUserPassword(make([]byte, 129), ra, []byte("s"))
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)

	_, err = DecryptUserPassword(make([]byte, 16), ra, nil)
	assert.ErrorIs(t, err, radiuserrors.ErrSecretEmpty)
}

func TestComputeMessageAuthenticator(t *testing.T) {
	secret := []byte("shared-secret")
	packetBytes := mustHex(t, "0102002600112233445566778899aabbccddeeff00112233445566778899006c6f67696e")

	// Recompute with the standard library directly.
	mac := hmac.New(md5.New, secret)
	mac.Write(packetBytes)
	want := mac.Sum(nil)

	var wantArr [16]byte
	copy(wantArr[:], want)

	got := ComputeMessageAuthenticator(packetBytes, secret)
	assert.Equal(t, wantArr, got)
}

func TestVerifyMessageAuthenticator(t *testing.T) {
	secret := []byte("shared-secret")
	packetBytes := mustHex(t, "0102002600112233445566778899aabbccddeeff00112233445566778899006c6f67696e")

	mac := ComputeMessageAuthenticator(packetBytes, secret)
	assert.True(t, VerifyMessageAuthenticator(packetBytes, mac, secret))

	// Tamper with one byte of the packet — verification must fail.
	tampered := append([]byte(nil), packetBytes...)
	tampered[0] ^= 0xff
	assert.False(t, VerifyMessageAuthenticator(tampered, mac, secret))

	// Different received value — must fail.
	var bad [16]byte
	bad[0] = mac[0] ^ 0xff
	assert.False(t, VerifyMessageAuthenticator(packetBytes, bad, secret))

	// Different secret — must fail.
	assert.False(t, VerifyMessageAuthenticator(packetBytes, mac, []byte("other")))
}

func TestEqualConstantTime(t *testing.T) {
	assert.True(t, EqualConstantTime([]byte("abc"), []byte("abc")))
	assert.False(t, EqualConstantTime([]byte("abc"), []byte("abd")))
	assert.False(t, EqualConstantTime([]byte("abc"), []byte("ab")))
	assert.False(t, EqualConstantTime(nil, []byte("abc")))
	assert.True(t, EqualConstantTime(nil, nil))
	assert.True(t, EqualConstantTime([]byte{}, []byte{}))
}
