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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifierPool_AcquireRelease(t *testing.T) {
	p := NewIdentifierPool()
	ctx := context.Background()

	seen := make(map[byte]bool)
	for i := range 256 {
		id, err := p.Acquire(ctx)
		require.NoError(t, err)
		require.False(t, seen[id], "duplicate identifier %d on iteration %d", id, i)
		seen[id] = true
	}
	assert.Len(t, seen, 256, "pool must yield all 256 unique identifiers")

	// Pool is now exhausted; Acquire should block.
	ctx2, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err := p.Acquire(ctx2)
	assert.ErrorIs(t, err, ErrIdentifierExhausted)

	// Release one and Acquire should succeed.
	p.Release(42)
	id, err := p.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, byte(42), id)
}

func TestIdentifierPool_AcquireCanceledContext(t *testing.T) {
	p := NewIdentifierPool()
	ctx, cancel := context.WithCancel(context.Background())

	// Drain the pool.
	for range 256 {
		_, err := p.Acquire(ctx)
		require.NoError(t, err)
	}

	// Acquire on a to-be-canceled context.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := p.Acquire(ctx)
	assert.ErrorIs(t, err, ErrIdentifierExhausted)
}

func TestIdentifierPool_Concurrent(t *testing.T) {
	p := NewIdentifierPool()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	inUse := make([]atomic.Bool, 256)
	for range 16 {
		wg.Go(func() {
			for range 64 {
				id, err := p.Acquire(ctx)
				if err != nil {
					return
				}
				require.False(t, inUse[id].Swap(true), "identifier %d acquired concurrently", id)
				// Brief hold.
				time.Sleep(time.Microsecond)
				inUse[id].Store(false)
				p.Release(id)
			}
		})
	}
	wg.Wait()
}

func TestIdentifierPool_ReleaseIntoFullPoolDoesNotPanic(t *testing.T) {
	p := NewIdentifierPool()
	// Releasing into a full pool must not panic; it logs a warning and drops.
	p.Release(0)
	p.Release(1)
	// Pool must still be usable.
	ctx := context.Background()
	id, err := p.Acquire(ctx)
	require.NoError(t, err)
	assert.True(t, int(id) < 256)
}
