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

package protocol

import "errors"

// Protocol-layer errors. The package reuses sentinel errors from the errors
// package for packet-level failures (ErrAuthenticatorMismatch,
// ErrMessageAuthenticatorMismatch, etc.); these errors cover higher-level
// state-machine failures.
var (
	// ErrNoResponse is returned when all retransmission attempts are
	// exhausted without receiving a reply.
	ErrNoResponse = errors.New("radius: no response after all retries")

	// ErrIdentifierExhausted is returned by IdentifierPool.Acquire when the
	// context is canceled before a free Identifier becomes available.
	ErrIdentifierExhausted = errors.New("radius: no free identifier available")

	// ErrIdentifierMismatch is returned by VerifyResponse when a reply's
	// Identifier does not match the outstanding request's Identifier.
	ErrIdentifierMismatch = errors.New("radius: reply identifier mismatch")

	// ErrUnexpectedReply is returned when the server replies with a code
	// not permitted for the request (e.g. an Accounting-Response to an
	// Access-Request).
	ErrUnexpectedReply = errors.New("radius: unexpected reply code")
)
