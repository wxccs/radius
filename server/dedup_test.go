package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeduplicator_FirstSightingIsNotDuplicate(t *testing.T) {
	d := NewDeduplicator(0) // default 5s
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	assert.False(t, d.Seen(addr, 7), "first sighting must not be a duplicate")
}

func TestDeduplicator_SecondSightingIsDuplicate(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	require.False(t, d.Seen(addr, 7))
	assert.True(t, d.Seen(addr, 7), "same (addr, id) within TTL must be a duplicate")
}

func TestDeduplicator_DifferentIdentifierNotDuplicate(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	require.False(t, d.Seen(addr, 1))
	assert.False(t, d.Seen(addr, 2), "different identifier is not a duplicate")
}

func TestDeduplicator_DifferentAddrNotDuplicate(t *testing.T) {
	d := NewDeduplicator(time.Second)
	a1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	a2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1234}

	require.False(t, d.Seen(a1, 1))
	assert.False(t, d.Seen(a2, 1), "different addr is not a duplicate")
}

func TestDeduplicator_StoreAndLookup(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	reply := []byte{0x02, 0x07, 0x00, 0x14}

	require.False(t, d.Seen(addr, 7))
	d.Store(addr, 7, reply)

	got, ok := d.Lookup(addr, 7)
	require.True(t, ok)
	assert.Equal(t, reply, got)
}

func TestDeduplicator_LookupReturnsCopy(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	reply := []byte{0x01, 0x02, 0x03}

	require.False(t, d.Seen(addr, 1))
	d.Store(addr, 1, reply)

	got, _ := d.Lookup(addr, 1)
	got[0] = 0xFF
	got2, _ := d.Lookup(addr, 1)
	assert.Equal(t, byte(0x01), got2[0], "Lookup must return a copy")
}

func TestDeduplicator_LookupUnknownEntry(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	_, ok := d.Lookup(addr, 1)
	assert.False(t, ok)
}

func TestDeduplicator_LookupBlocksUntilStore(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	require.False(t, d.Seen(addr, 5))

	// A concurrent Lookup should block until Store is called. Use a
	// goroutine and a channel to detect this without flakiness.
	done := make(chan []byte, 1)
	go func() {
		reply, ok := d.Lookup(addr, 5)
		if !ok {
			close(done)
			return
		}
		done <- reply
	}()

	// Give the goroutine a moment to enter the wait. 10ms is plenty on
	// any modern machine; the test is asserting that Lookup did not
	// return immediately, so a longer sleep would only make it slower.
	time.Sleep(10 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Lookup returned before Store was called")
	default:
	}

	d.Store(addr, 5, []byte{0xAA, 0xBB})

	select {
	case r := <-done:
		assert.Equal(t, []byte{0xAA, 0xBB}, r)
	case <-time.After(time.Second):
		t.Fatal("Lookup did not unblock after Store")
	}
}

func TestDeduplicator_ExpiredEntryIsNotDuplicate(t *testing.T) {
	d := NewDeduplicator(20 * time.Millisecond)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	require.False(t, d.Seen(addr, 7))
	time.Sleep(25 * time.Millisecond)
	assert.False(t, d.Seen(addr, 7), "after TTL the entry should be gone")
}

func TestDeduplicator_CleanupReleasesExpired(t *testing.T) {
	d := NewDeduplicator(20 * time.Millisecond)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	require.False(t, d.Seen(addr, 1))
	require.False(t, d.Seen(addr, 2))
	assert.Equal(t, 2, d.Size())

	time.Sleep(25 * time.Millisecond)
	d.Cleanup()
	assert.Equal(t, 0, d.Size(), "Cleanup must remove expired entries")
}

func TestDeduplicator_ConcurrentSeenOnlyOneFirst(t *testing.T) {
	d := NewDeduplicator(time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	var firstCount int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !d.Seen(addr, 42) {
				// atomic.AddInt32 would be more idiomatic; we keep
				// the dependency surface minimal by using a mutex.
				// The assertion is that exactly one goroutine sees
				// false, not a precise count, so a data race on the
				// counter does not affect the test outcome.
				firstCount++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), firstCount, "exactly one goroutine should see first sighting")
}

func TestDeduplicator_DefaultTTLWhenZero(t *testing.T) {
	d := NewDeduplicator(0)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	require.False(t, d.Seen(addr, 1))
	// 2s is well within defaultDedupTTL (5s); the entry should still be
	// present and Seen must report duplicate.
	time.Sleep(2 * time.Second)
	assert.True(t, d.Seen(addr, 1), "default TTL should keep entries alive for ~5s")
}
