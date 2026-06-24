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

import (
	"math/rand"
	"time"
)

// DefaultRetransmitPolicy is the policy used when the caller does not supply
// one. It matches the values recommended by RFC 2865 §2.5 for UDP: an initial
// 2-second backoff, doubling up to a 16-second ceiling, with three attempts
// total (one initial transmission plus two retries) and ±10 % jitter.
func DefaultRetransmitPolicy() RetransmitPolicy {
	return RetransmitPolicy{
		MaxAttempts: 3,
		Initial:     2 * time.Second,
		Max:         16 * time.Second,
		Jitter:      0.1,
	}
}

// RetransmitPolicy governs UDP retransmission behavior for the Client.
//
// Per RFC 2865 §2.5 and RFC 5176 §2.3, if the attributes have not changed
// between retries the same Identifier and Request Authenticator MUST be
// reused. The Client marshals the request once and re-sends the identical
// bytes on each retry.
//
// On TCP transports (RFC 6613 §2.6.1) retransmission is disabled — the
// policy is consulted but the transport returns a single attempt result.
type RetransmitPolicy struct {
	// MaxAttempts is the total number of transmissions including the first.
	// Values <= 0 fall back to the default of 3.
	MaxAttempts int

	// Initial is the delay before the first retransmission.
	Initial time.Duration

	// Max is the upper bound on delay between retries.
	Max time.Duration

	// Jitter is the ±fraction applied to each computed delay to avoid
	// synchronized retry storms. 0.1 means ±10 %.
	Jitter float64
}

// NextDelay returns the delay before the (attempt+1)-th transmission, where
// attempt is 0-indexed (attempt 0 is the initial send, so NextDelay(0) is
// the delay before the first retransmission).
//
// The base delay is Initial << attempt, capped at Max. Jitter is applied as
// base * (1 + rand[-Jitter, +Jitter]).
func (p RetransmitPolicy) NextDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	base := p.Initial << uint(attempt)
	if base <= 0 || base > p.Max {
		base = p.Max
	}
	if p.Jitter <= 0 {
		return base
	}
	factor := 1.0 + (rand.Float64()*2-1)*p.Jitter
	return time.Duration(float64(base) * factor)
}

// Attempts returns the number of transmissions to perform, clamped to >=1.
func (p RetransmitPolicy) Attempts() int {
	if p.MaxAttempts <= 0 {
		return DefaultRetransmitPolicy().MaxAttempts
	}
	return p.MaxAttempts
}
