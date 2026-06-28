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
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
)

// VerifyResponse validates a RADIUS reply packet against the original
// request's Identifier and Request Authenticator.
//
// Steps:
//  1. Parse the reply (length bounds and attribute walk).
//  2. Match the reply's Identifier against expectedIdentifier.
//  3. Verify the Response Authenticator using the original Request
//     Authenticator and the shared secret.
//  4. If a Message-Authenticator attribute is present, verify it.
//
// Any failure is returned as the matching sentinel error from the errors
// package; on success the reply's parsed Packet is returned to the caller.
//
// Per RFC 2865 §3 a mismatched Response Authenticator mandates silent
// discard; callers should treat such errors as transport-level failures
// and wait for the next reply (subject to the retransmission policy).
func VerifyResponse(raw []byte, expectedIdentifier byte, requestAuth [16]byte, secret []byte) (*packet.Packet, error) {
	pkt := &packet.Packet{}
	if err := pkt.Unmarshal(raw, secret); err != nil {
		return nil, err
	}
	if pkt.Identifier != expectedIdentifier {
		return nil, ErrIdentifierMismatch
	}
	if err := packet.VerifyResponseAuthenticator(raw, requestAuth, secret); err != nil {
		return nil, err
	}
	if hasMessageAuthenticator(pkt) {
		if err := packet.VerifyMessageAuthenticator(raw, requestAuth, secret); err != nil {
			return nil, err
		}
	}
	return pkt, nil
}

// hasMessageAuthenticator reports whether pkt carries a Message-Authenticator
// attribute (RFC 2869 §5.14). When present in a reply the attribute MUST be
// verified.
func hasMessageAuthenticator(pkt *packet.Packet) bool {
	for _, a := range pkt.Attributes {
		if a.Type == types.AttrMessageAuthenticator {
			return true
		}
	}
	return false
}
