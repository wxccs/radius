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
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"

	radiuserrors "github.com/wxccs/radius/v2/errors"
)

// RFC 2868 §3.5 Tunnel-Password encryption.
//
// Wire layout of the Tunnel-Password attribute Value:
//
//   +--------+----------------------------------+
//   | Salt   | String (encrypted, 16-aligned)   |
//   +--------+----------------------------------+
//    2 bytes   16..240 octets of ciphertext
//
// The Salt is a 2-byte value whose most significant bit MUST be set (1); the
// remaining 15 bits MUST be random and unique within a packet to avoid
// keystream reuse. The optional Tag field that RFC 2868 §3.5 defines for the
// attribute is handled separately by EncodeTunnelTag/DecodeTunnelTag at the
// attribute layer; it is NOT encoded into the Salt.
//
// The plaintext String (RFC 2868 §3.5) is:
//
//	Data-Length (1) + Password + Padding
//
// where Data-Length is the length of the Password and Padding pads the
// plaintext to a 16-byte boundary. The keystream is derived as:
//
//	b(1) = MD5(Secret + RequestAuth + Salt)
//	b(i) = MD5(Secret + c(i-1))   for i > 1
//	c(i) = p(i) XOR b(i)
//
// This is the same MD5-feedback construction used by User-Password (RFC
// 2865 §5.2) and by the MS-MPPE-*-Key attributes (RFC 2548 §3.3); only the
// seed of the first block differs (here Secret+RA+Salt). We follow FreeRADIUS
// (src/protocols/radius/encode.c encode_tunnel_password), which fills the
// padding with random data rather than NULs.

const (
	// tunnelPasswordMaxLen is the cleartext password length limit per RFC
	// 2868 §3.5. The attribute Value is at most 253 octets; subtracting the
	// 2-byte Salt leaves 251 octets of ciphertext, which must be a multiple
	// of 16, so at most 240. The first plaintext octet is the Data-Length
	// field, leaving 239 octets for the password.
	tunnelPasswordMaxLen = 239
)

// EncryptTunnelPassword encrypts a tunnel password per RFC 2868 §3.5.
// requestAuth is the 16-byte Request Authenticator from the enclosing
// Access-Request packet. The optional Tag is NOT applied here; callers
// that need a tagged Tunnel-Password attribute should prepend the Tag byte
// via EncodeTunnelTag at the attribute layer.
//
// Returns the Value field (Salt + encrypted String) ready to be placed in a
// Tunnel-Password attribute.
func EncryptTunnelPassword(password []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(password) > tunnelPasswordMaxLen {
		return nil, radiuserrors.ErrPasswordTooLong
	}
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] |= 0x80 // RFC 2868 §3.5: the MSB of Salt MUST be set.
	return encryptSaltedPassword(password, requestAuth, secret, salt), nil
}

// encryptSaltedPassword applies the RFC 2868 §3.5 / RFC 2548 §3.3
// MD5-feedback encryption with an explicit salt. The plaintext is
// Data-Length(1) + password + random padding to a 16-byte boundary. The
// returned slice is salt + ciphertext. The padding is random to avoid
// leaking plaintext-derived bytes (matching FreeRADIUS encode_tunnel_password).
func encryptSaltedPassword(password []byte, requestAuth [16]byte, secret, salt []byte) []byte {
	padding := make([]byte, saltedPaddingLen(len(password)))
	if _, err := rand.Read(padding); err != nil {
		padding = padding[:0]
	}
	return encryptSaltedPasswordWithPadding(password, requestAuth, secret, salt, padding)
}

// saltedPaddingLen returns the number of padding octets needed so that
// 1 (Data-Length) + len(password) + padding is a multiple of 16. RFC 2868
// §3.5 requires padding when the Data-Length + Password length is not a
// multiple of 16; the total plaintext is always at least one 16-octet
// block.
func saltedPaddingLen(passwordLen int) int {
	plaintextLen := 1 + passwordLen
	padded := ((plaintextLen + 15) / 16) * 16
	return padded - plaintextLen
}

// encryptSaltedPasswordWithPadding is the deterministic core: the caller
// supplies the salt and padding bytes (whose length must equal
// saltedPaddingLen(len(password))). Used by tests for known-answer vectors
// and by MS-MPPE-*-Key encoding which carries a key rather than a password.
func encryptSaltedPasswordWithPadding(payload []byte, requestAuth [16]byte, secret, salt, padding []byte) []byte {
	paddedLen := 1 + len(payload) + len(padding)
	plaintext := make([]byte, paddedLen)
	plaintext[0] = byte(len(payload))
	copy(plaintext[1:], payload)
	copy(plaintext[1+len(payload):], padding)

	ciphertext := make([]byte, paddedLen)
	hashBuf := make([]byte, 0, len(secret)+16+2)
	// b(1) = MD5(Secret + RequestAuth + Salt)
	hashBuf = append(hashBuf, secret...)
	hashBuf = append(hashBuf, requestAuth[:]...)
	hashBuf = append(hashBuf, salt...)
	prev := md5.Sum(hashBuf)
	for j := 0; j < 16; j++ {
		ciphertext[j] = plaintext[j] ^ prev[j]
	}
	// b(i) = MD5(Secret + c(i-1))
	for i := 16; i < paddedLen; i += 16 {
		hashBuf = hashBuf[:0]
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, ciphertext[i-16:i]...)
		prev = md5.Sum(hashBuf)
		for j := 0; j < 16; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ prev[j]
		}
	}
	out := make([]byte, 0, 2+paddedLen)
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out
}

// DecryptTunnelPassword reverses EncryptTunnelPassword. value is the
// Tunnel-Password attribute Value (Salt + encrypted String). requestAuth is
// the Request Authenticator of the enclosing Access-Request.
//
// Returns the plaintext password recovered via the Data-Length field; any
// padding is discarded.
func DecryptTunnelPassword(value []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	return decryptSaltedAttribute(value, requestAuth, secret)
}

// decryptSaltedAttribute reverses the RFC 2868 §3.5 / RFC 2548 §3.3 salted
// MD5-feedback encryption and returns the payload (Password or Key) scoped by
// the leading length-prefix octet. Shared by DecryptTunnelPassword and
// DecryptMPPEKey, whose wire algorithms are identical.
func decryptSaltedAttribute(value []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(value) < 3 {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	salt := value[:2]
	body := value[2:]
	if len(body) == 0 || len(body)%16 != 0 {
		return nil, radiuserrors.ErrInvalidAttribute
	}

	plaintext := make([]byte, len(body))
	hashBuf := make([]byte, 0, len(secret)+16+2)
	// b(1) = MD5(Secret + RequestAuth + Salt)
	hashBuf = append(hashBuf, secret...)
	hashBuf = append(hashBuf, requestAuth[:]...)
	hashBuf = append(hashBuf, salt...)
	prev := md5.Sum(hashBuf)
	for j := 0; j < 16; j++ {
		plaintext[j] = body[j] ^ prev[j]
	}
	for i := 16; i < len(body); i += 16 {
		hashBuf = hashBuf[:0]
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, body[i-16:i]...)
		prev = md5.Sum(hashBuf)
		for j := 0; j < 16; j++ {
			plaintext[i+j] = body[i+j] ^ prev[j]
		}
	}
	dataLen := int(plaintext[0])
	if dataLen > len(plaintext)-1 {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	payload := make([]byte, dataLen)
	copy(payload, plaintext[1:1+dataLen])
	return payload, nil
}

// EncodeTunnelTag encodes a 1-byte tag prefix for a tagged tunnel attribute
// per RFC 2868 §3.1. Tags 0x01..0x1F are valid; tag 0x00 means "no tag"
// and the returned ok=false signals the caller to omit the prefix.
func EncodeTunnelTag(tag byte) (byte, bool) {
	if tag == 0 {
		return 0, false
	}
	if tag > 0x1F {
		return 0, false
	}
	return tag, true
}

// DecodeTunnelTag returns the tag and the remaining value bytes from a
// tagged tunnel attribute Value. If the first byte is in 0x00..0x1F it is
// treated as a tag and the rest is the payload; otherwise the entire Value
// is the payload and hasTag=false.
//
// Per RFC 2868 §3.1 the tag field is optional: a first byte in 0x20..0xFF
// is the start of the actual data, not a tag.
func DecodeTunnelTag(value []byte) (tag byte, hasTag bool, payload []byte) {
	if len(value) > 0 && value[0] >= 0x01 && value[0] <= 0x1F {
		return value[0], true, value[1:]
	}
	return 0, false, value
}

// EncodeTunnelInteger encodes a tagged integer tunnel attribute
// (Tunnel-Type, Tunnel-Medium-Type, Tunnel-Preference) per RFC 2868 §3.1.
// The wire layout is: [Tag] + 4-byte big-endian integer. When tag is 0
// the prefix is omitted.
func EncodeTunnelInteger(tag byte, n uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, n)
	if t, ok := EncodeTunnelTag(tag); ok {
		return append([]byte{t}, out...)
	}
	return out
}

// DecodeTunnelInteger decodes a tagged integer tunnel attribute. Returns
// the tag (or 0 with hasTag=false when no tag prefix is present) and the
// integer value.
//
// Ambiguity note: RFC 2868 §3.1 lets integer tunnel attributes omit the tag.
// When the first byte of the value falls in 0x01..0x1F the decoder cannot
// tell whether it is a tag or the high byte of the integer. Callers that
// know from context whether a tag is present should validate accordingly;
// this helper follows the spec's literal "0x01..0x1F means tag" rule.
func DecodeTunnelInteger(value []byte) (tag byte, hasTag bool, n uint32, err error) {
	t, ht, payload := DecodeTunnelTag(value)
	if len(payload) != 4 {
		return 0, false, 0, radiuserrors.ErrInvalidAttribute
	}
	return t, ht, binary.BigEndian.Uint32(payload), nil
}
