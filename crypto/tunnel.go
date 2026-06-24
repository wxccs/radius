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

	radiuserrors "github.com/wxccs/radius/errors"
)

// RFC 2868 §3.3 Tunnel-Password encoding.
//
// Wire layout of the Tunnel-Password attribute Value:
//
//   +------+--------+----------------------------------+
//   | Tag  | Salt   | Password (encrypted, 16-aligned) |
//   +------+--------+----------------------------------+
//    1 byte  2 bytes   16..240 octets (after padding)
//
// The Tag field is present only when the high bit of Salt (0x80) is set.
// The Salt is a random 2-byte value with the high bit acting as the
// "tag present" flag; the remaining 15 bits MUST be random and unique
// within the lifetime of a session to avoid keystream reuse.
//
// Encryption (RFC 2868 §3.3): the plaintext password is padded with NULs
// to a 16-byte boundary, then XOR-encrypted with a keystream derived as:
//
//   b1 = MD5(secret + salt [+ tag] + RA)
//   b2 = MD5(secret + b1)
//   b3 = MD5(secret + b2)
//   ...
//
// The Request Authenticator (RA) is included in b1 only. Subsequent blocks
// chain on the previous keystream block. This matches the User-Password
// feedback design from RFC 2865 §5.2 with the Salt substituting for the
// RA in the first block's seed.
//
// Note: RFC 2868 §3.3 actually specifies that b1 uses MD5(secret + salt + RA)
// when no tag is present, and MD5(secret + salt + tag + RA) when a tag is
// present. We follow that literal construction.

const (
	// tunnelPasswordMaxLen is the cleartext password length limit per RFC 2868
	// §3.3: the encrypted value must fit within a 255-octet attribute, minus
	// 3 (Type+Length) minus 2 (Salt) minus 1 (optional Tag) = 249 octets of
	// ciphertext, which is 240 octets of plaintext after rounding down to a
	// 16-byte boundary.
	tunnelPasswordMaxLen = 240
)

// EncryptTunnelPassword encrypts a tunnel password per RFC 2868 §3.3.
// requestAuth is the 16-byte Request Authenticator from the enclosing
// Access-Request packet. tag is the optional 1-byte tunnel tag; pass
// hasTag=false to omit it. When hasTag is true, tag MUST be in 0x01..0x1F.
//
// Returns the Value field (Salt + encrypted password, with the tag flag
// baked into the Salt's high bit) ready to be placed in a Tunnel-Password
// attribute.
func EncryptTunnelPassword(password []byte, requestAuth [16]byte, secret []byte, tag byte, hasTag bool) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(password) > tunnelPasswordMaxLen {
		return nil, radiuserrors.ErrPasswordTooLong
	}
	if hasTag && (tag == 0 || tag > 0x1F) {
		return nil, radiuserrors.ErrInvalidAttribute
	}

	// Generate a 2-byte salt. The high bit of salt[0] is the "tag present"
	// flag; the remaining 15 bits must be random.
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] &= 0x7F // clear high bit for now
	if hasTag {
		salt[0] |= 0x80
	}

	// Pad password to a 16-byte boundary with NULs (at least one block).
	paddedLen := ((len(password) + 15) / 16) * 16
	if paddedLen == 0 {
		paddedLen = 16
	}
	padded := make([]byte, paddedLen)
	copy(padded, password)

	// Build the keystream seed: secret + salt [+ tag] + RA (RA only in b1).
	seed := make([]byte, 0, len(secret)+2+1+16)
	seed = append(seed, secret...)
	seed = append(seed, salt...)
	if hasTag {
		seed = append(seed, tag)
	}
	seed = append(seed, requestAuth[:]...)

	b := md5.Sum(seed)
	out := make([]byte, 0, 2+paddedLen)
	out = append(out, salt...)
	if hasTag {
		out = append(out, tag)
	}
	ciphertext := make([]byte, paddedLen)
	for j := range 16 {
		ciphertext[j] = padded[j] ^ b[j]
	}
	// Subsequent blocks: b(i) = MD5(secret + c(i-1)).
	prev := make([]byte, 16)
	copy(prev, ciphertext[:16])
	for i := 16; i < paddedLen; i += 16 {
		hashBuf := make([]byte, 0, len(secret)+16)
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, prev...)
		b = md5.Sum(hashBuf)
		for j := range 16 {
			ciphertext[i+j] = padded[i+j] ^ b[j]
		}
		copy(prev, ciphertext[i:i+16])
	}
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptTunnelPassword reverses EncryptTunnelPassword. value is the
// Tunnel-Password attribute Value (Salt [+ tag] + encrypted password).
// requestAuth is the Request Authenticator of the enclosing Access-Request.
//
// Returns the plaintext password (with NUL padding stripped) and, when
// present, the tag and hasTag=true.
func DecryptTunnelPassword(value []byte, requestAuth [16]byte, secret []byte) (password []byte, tag byte, hasTag bool, err error) {
	if len(secret) == 0 {
		return nil, 0, false, radiuserrors.ErrSecretEmpty
	}
	if len(value) < 3 {
		return nil, 0, false, radiuserrors.ErrInvalidAttribute
	}
	salt := value[:2]
	hasTag = salt[0]&0x80 != 0
	body := value[2:]
	if hasTag {
		if len(body) < 1 {
			return nil, 0, false, radiuserrors.ErrInvalidAttribute
		}
		tag = body[0]
		body = body[1:]
	}
	if len(body) == 0 || len(body)%16 != 0 {
		return nil, 0, false, radiuserrors.ErrInvalidAttribute
	}

	// Rebuild the first-block keystream.
	seed := make([]byte, 0, len(secret)+2+1+16)
	seed = append(seed, secret...)
	seed = append(seed, salt...)
	if hasTag {
		seed = append(seed, tag)
	}
	seed = append(seed, requestAuth[:]...)
	b := md5.Sum(seed)

	plaintext := make([]byte, len(body))
	for j := range 16 {
		plaintext[j] = body[j] ^ b[j]
	}
	prev := make([]byte, 16)
	copy(prev, body[:16])
	for i := 16; i < len(body); i += 16 {
		hashBuf := make([]byte, 0, len(secret)+16)
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, prev...)
		b = md5.Sum(hashBuf)
		for j := range 16 {
			plaintext[i+j] = body[i+j] ^ b[j]
		}
		copy(prev, body[i:i+16])
	}
	for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
		plaintext = plaintext[:len(plaintext)-1]
	}
	return plaintext, tag, hasTag, nil
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
