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

// Package crypto implements the cryptographic primitives used by the RADIUS
// protocol:
//
//   - Response Authenticator (RFC 2865 §3): MD5 over Code+ID+Length+RequestAuth+Attributes+Secret
//   - Accounting-Request Authenticator (RFC 2866 §3): MD5 over Code+ID+Length+16 zeros+Attributes+Secret
//   - User-Password hiding (RFC 2865 §5.2): chained MD5 + XOR
//   - Message-Authenticator (RFC 2869 §5.14): HMAC-MD5 over the entire packet
//
// All functions are pure: callers pass the shared secret explicitly, and no
// state is retained. Constant-time comparison is used for verification paths.
package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"

	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// ComputeResponseAuthenticator calculates the Response Authenticator used by
// Access-Accept, Access-Reject, Access-Challenge (RFC 2865 §3), and
// Accounting-Response (RFC 2866 §3).
//
// Formula: MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
// where Length is big-endian uint16 and RequestAuth is the 16-byte
// Request Authenticator from the corresponding request packet.
func ComputeResponseAuthenticator(code byte, id byte, length uint16, requestAuth [16]byte, attributes []byte, secret []byte) [16]byte {
	h := md5.New()
	h.Write([]byte{code, id})
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], length)
	h.Write(lenBuf[:])
	h.Write(requestAuth[:])
	h.Write(attributes)
	h.Write(secret)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeAccountingRequestAuthenticator calculates the Request Authenticator
// for an Accounting-Request packet (RFC 2866 §3).
//
// Unlike Access-Request (which uses a random value), the Accounting-Request
// authenticator is itself an MD5 digest because there is no User-Password
// attribute to hide:
//
//	MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
func ComputeAccountingRequestAuthenticator(code byte, id byte, length uint16, attributes []byte, secret []byte) [16]byte {
	h := md5.New()
	h.Write([]byte{code, id})
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], length)
	h.Write(lenBuf[:])
	h.Write(zeros16[:])
	h.Write(attributes)
	h.Write(secret)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

var zeros16 [16]byte

// EncryptUserPassword hides a cleartext password using the RFC 2865 §5.2
// algorithm: the password is null-padded to a 16-byte boundary, then each
// 16-octet block is XORed with MD5(secret || previous_ciphertext_block),
// where the first block uses the Request Authenticator as the previous block.
//
// The result length is a multiple of 16, between 16 and 128 octets inclusive.
// Returns ErrPasswordTooLong if len(password) > 128, and ErrSecretEmpty if
// the shared secret is empty.
func EncryptUserPassword(password []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(password) > types.UserPasswordMaxLength {
		return nil, radiuserrors.ErrPasswordTooLong
	}
	return encryptUserPassword(password, requestAuth, secret), nil
}

// DecryptUserPassword reverses EncryptUserPassword. The ciphertext length must
// be a non-zero multiple of 16 and at most 128 octets. Trailing NUL padding
// introduced during encryption is stripped from the returned plaintext.
func DecryptUserPassword(ciphertext []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 || len(ciphertext) > types.UserPasswordMaxLength {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	plaintext := decryptUserPasswordBlocks(ciphertext, requestAuth, secret)
	for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
		plaintext = plaintext[:len(plaintext)-1]
	}
	return plaintext, nil
}

// encryptUserPassword applies the RFC 2865 §5.2 chain. The MD5 feedback is
// taken from the ciphertext (the output): b(i) = MD5(secret + c(i-1)),
// c(i) = p(i) XOR b(i). The first block uses the Request Authenticator.
//
// The input is null-padded to a 16-byte boundary (at least one block).
func encryptUserPassword(password []byte, requestAuth [16]byte, secret []byte) []byte {
	paddedLen := ((len(password) + 15) / 16) * 16
	if paddedLen == 0 {
		paddedLen = 16
	}
	padded := make([]byte, paddedLen)
	copy(padded, password)

	out := make([]byte, paddedLen)
	var prev [16]byte
	copy(prev[:], requestAuth[:])

	hashBuf := make([]byte, 0, len(secret)+16)
	for block := range paddedLen / 16 {
		i := block * 16
		hashBuf = hashBuf[:0]
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, prev[:]...)
		b := md5.Sum(hashBuf)

		for j := range 16 {
			out[i+j] = padded[i+j] ^ b[j]
		}
		// The MD5 feedback for the next block is the ciphertext block just produced.
		copy(prev[:], out[i:i+16])
	}
	return out
}

// decryptUserPasswordBlocks applies the RFC 2865 §5.2 chain in reverse.
// Here the MD5 feedback is taken from the ciphertext (the input), so that
// b(i) = MD5(secret + c(i-1)) and p(i) = c(i) XOR b(i).
func decryptUserPasswordBlocks(ciphertext []byte, requestAuth [16]byte, secret []byte) []byte {
	out := make([]byte, len(ciphertext))
	var prev [16]byte
	copy(prev[:], requestAuth[:])

	hashBuf := make([]byte, 0, len(secret)+16)
	for block := range len(ciphertext) / 16 {
		i := block * 16
		hashBuf = hashBuf[:0]
		hashBuf = append(hashBuf, secret...)
		hashBuf = append(hashBuf, prev[:]...)
		b := md5.Sum(hashBuf)

		for j := range 16 {
			out[i+j] = ciphertext[i+j] ^ b[j]
		}
		// The MD5 feedback for the next block is the ciphertext block just consumed.
		copy(prev[:], ciphertext[i:i+16])
	}
	return out
}

// ComputeMessageAuthenticator calculates the HMAC-MD5 Message-Authenticator
// (RFC 2869 §5.14) over an entire RADIUS packet.
//
// The caller MUST zero the 16-octet Value field of the Message-Authenticator
// attribute within packetBytes before calling this function. The returned
// digest is written into that field by the packet codec.
//
// The shared secret is used as the HMAC key.
func ComputeMessageAuthenticator(packetBytes []byte, secret []byte) [16]byte {
	mac := hmac.New(md5.New, secret)
	mac.Write(packetBytes)
	var out [16]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// VerifyMessageAuthenticator recomputes the HMAC-MD5 over packetBytes and
// compares it against received in constant time. As with
// ComputeMessageAuthenticator, the Value field of the Message-Authenticator
// attribute in packetBytes must be zeroed before calling.
func VerifyMessageAuthenticator(packetBytes []byte, received [16]byte, secret []byte) bool {
	expected := ComputeMessageAuthenticator(packetBytes, secret)
	return subtle.ConstantTimeCompare(expected[:], received[:]) == 1
}

// EqualConstantTime reports whether a and b are byte-for-byte equal without
// leaking timing information about the position of the first difference.
// Returns false when lengths differ.
func EqualConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
