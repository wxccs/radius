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

// Package errors defines the sentinel errors returned by the radius library.
//
// All errors use the "radius: " prefix and are comparable with errors.Is,
// enabling callers to branch on specific failure modes without string matching.
package errors

import "errors"

// New wraps errors.New with the radius: prefix convention.
//
// Exported so that subpackages can define additional sentinel errors
// with a consistent prefix.
func New(text string) error {
	return errors.New("radius: " + text)
}

// Buffer and framing errors.
var (
	ErrShortBuffer   = New("buffer too short")
	ErrInvalidLength = New("invalid length field")
)

// Packet-level errors.
var (
	ErrInvalidCode           = New("invalid code")
	ErrAuthenticatorMismatch = New("authenticator mismatch")
)

// Attribute-level errors.
var (
	ErrInvalidAttribute = New("invalid attribute")
	ErrAttributeTooLong = New("attribute value exceeds 253 octets")
	ErrUnknownAttribute = New("unknown attribute type")
)

// Crypto and secret errors.
var (
	ErrSecretEmpty     = New("shared secret must not be empty")
	ErrPasswordTooLong = New("password exceeds 128 octets")
)

// Message-Authenticator (RFC 2869 §5.14) errors.
var (
	ErrMessageAuthenticatorMissing  = New("message-authenticator required but missing")
	ErrMessageAuthenticatorMismatch = New("message-authenticator verification failed")
)

// Is reports whether any error in err's chain matches the target.
//
// Re-exported for convenience so callers can import only this package.
func Is(err, target error) bool { return errors.Is(err, target) }

// As finds the first error in err's chain that matches the target type.
func As(err error, target any) bool { return errors.As(err, target) }
