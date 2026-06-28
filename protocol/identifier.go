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
	"context"

	radiuslog "github.com/wxccs/radius/v2/log"
)

// IdentifierPool allocates RADIUS Identifier values (0..255) for in-flight
// requests. Each Client owns one pool; concurrent Acquire calls are safe.
//
// The pool is a buffered channel of 256 byte tokens. Acquire receives one
// token; Release puts it back. When all 256 tokens are in flight, Acquire
// blocks until a Release frees one or the context is canceled.
//
// Per RFC 2865 §3, the Identifier allows the server to detect duplicate
// requests; reusing an Identifier while the original request is still
// outstanding would conflate the two replies.
type IdentifierPool struct {
	tokens chan byte
}

// NewIdentifierPool returns a pool seeded with all 256 Identifier values.
func NewIdentifierPool() *IdentifierPool {
	p := &IdentifierPool{tokens: make(chan byte, 256)}
	for i := range 256 {
		p.tokens <- byte(i)
	}
	return p
}

// Acquire returns a free Identifier, blocking until one is available or ctx
// is canceled. Returns ErrIdentifierExhausted on context cancellation.
func (p *IdentifierPool) Acquire(ctx context.Context) (byte, error) {
	log := radiuslog.Default.With("func", "protocol.IdentifierPool.Acquire")
	select {
	case id := <-p.tokens:
		log.Debug("identifier acquired", "id", int(id))
		return id, nil
	case <-ctx.Done():
		log.Info("identifier acquire canceled")
		return 0, ErrIdentifierExhausted
	}
}

// Release returns id to the pool. Double-releasing the same id is a
// programming error and would corrupt the pool; callers must release
// exactly the identifiers they acquired.
func (p *IdentifierPool) Release(id byte) {
	select {
	case p.tokens <- id:
	default:
		// The pool is already full, which means Release was called more
		// times than Acquire. Drop the duplicate silently rather than
		// panicking, but log a warning so the bug is observable.
		radiuslog.Default.With("func", "protocol.IdentifierPool.Release").
			Warn("release into full pool; identifier leak detected", "id", int(id))
	}
}
