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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRetransmitPolicy(t *testing.T) {
	p := DefaultRetransmitPolicy()
	assert.Equal(t, 3, p.MaxAttempts)
	assert.Equal(t, 2*time.Second, p.Initial)
	assert.Equal(t, 16*time.Second, p.Max)
	assert.Equal(t, 0.1, p.Jitter)
}

func TestRetransmitPolicy_NextDelay_GrowsExponentially(t *testing.T) {
	p := RetransmitPolicy{
		Initial: 1 * time.Second,
		Max:     64 * time.Second,
		Jitter:  0,
	}
	// attempt 0 → 1s, 1 → 2s, 2 → 4s, 3 → 8s
	assert.Equal(t, 1*time.Second, p.NextDelay(0))
	assert.Equal(t, 2*time.Second, p.NextDelay(1))
	assert.Equal(t, 4*time.Second, p.NextDelay(2))
	assert.Equal(t, 8*time.Second, p.NextDelay(3))
}

func TestRetransmitPolicy_NextDelay_CappedAtMax(t *testing.T) {
	p := RetransmitPolicy{
		Initial: 1 * time.Second,
		Max:     5 * time.Second,
		Jitter:  0,
	}
	// 1 << 3 = 8s exceeds Max; should be capped.
	assert.Equal(t, 5*time.Second, p.NextDelay(3))
	// Even further attempts stay at Max.
	assert.Equal(t, 5*time.Second, p.NextDelay(10))
}

func TestRetransmitPolicy_NextDelay_JitterBounds(t *testing.T) {
	p := RetransmitPolicy{
		Initial: 2 * time.Second,
		Max:     16 * time.Second,
		Jitter:  0.1,
	}
	for attempt := range 5 {
		base := p.Initial << uint(attempt)
		base = min(base, p.Max)
		lo := time.Duration(float64(base) * 0.9)
		hi := time.Duration(float64(base) * 1.1)
		d := p.NextDelay(attempt)
		assert.GreaterOrEqual(t, d, lo, "attempt %d: delay %v below jitter floor %v", attempt, d, lo)
		assert.LessOrEqual(t, d, hi, "attempt %d: delay %v above jitter ceiling %v", attempt, d, hi)
	}
}

func TestRetransmitPolicy_Attempts_DefaultsWhenZero(t *testing.T) {
	p := RetransmitPolicy{}
	// MaxAttempts <= 0 should fall back to default (3).
	assert.Equal(t, 3, p.Attempts())
}

func TestRetransmitPolicy_Attempts_RespectsExplicitValue(t *testing.T) {
	p := RetransmitPolicy{MaxAttempts: 5}
	assert.Equal(t, 5, p.Attempts())
}

func TestRetransmitPolicy_NextDelay_NegativeAttemptClamped(t *testing.T) {
	p := RetransmitPolicy{Initial: 1 * time.Second, Max: 8 * time.Second, Jitter: 0}
	// Negative attempt should be treated as 0.
	assert.Equal(t, 1*time.Second, p.NextDelay(-1))
}
