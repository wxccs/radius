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

package protocol

import (
	"crypto/rand"
)

// NewAccessRequestAuthenticator returns a random 16-byte Request
// Authenticator suitable for an Access-Request packet (RFC 2865 §3).
//
// The Authenticator for Access-Request MUST be a globally and temporally
// unique random value so that the server can use it to detect duplicates.
// We rely on crypto/rand to provide the unpredictability required by
// RFC 4086.
//
// The MD5-derived authenticators for Accounting-Request, CoA-Request, and
// Disconnect-Request are computed by packet.Marshal; the protocol layer
// leaves the Authenticator field zero for those codes.
func NewAccessRequestAuthenticator() ([16]byte, error) {
	var a [16]byte
	if _, err := rand.Read(a[:]); err != nil {
		return [16]byte{}, err
	}
	return a, nil
}
