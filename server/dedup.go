package server

import (
	"net"
	"sync"
	"time"
)

// defaultDedupTTL is the duration a (remoteAddr, identifier) entry is
// considered "in flight". RFC 2865 §2.5 specifies a 5-second window within
// which a duplicate request (same Identifier from the same source) should be
// detected and the cached reply retransmitted rather than re-processed.
const defaultDedupTTL = 5 * time.Second

// dedupKeySize bounds the byte length of the stringified key so a malicious
// client cannot exhaust memory by sending absurdly-long addresses. In
// practice net.Addr.String() returns short host:port strings.
const dedupKeySize = 128

// Deduplicator tracks in-flight (remoteAddr, identifier) tuples within a
// sliding TTL window. Its purpose is RFC 2865 §2.5 duplicate detection:
//
//   - On the first sighting of (addr, id), Seen reports false and the caller
//     is expected to process the request and call Store with the marshaled
//     reply. Subsequent sightings within the TTL will report true.
//   - On a duplicate sighting, Lookup returns the cached reply (if the
//     first handler has finished) so the server can retransmit it without
//     re-running the handler. When the first handler has not yet finished,
//     Lookup returns (nil, true); the caller should silently drop the
//     duplicate per RFC 2865 §3 (servers are permitted to ignore unwanted
//     packets).
//
// Deduplicator is safe for concurrent use. A zero-value Deduplicator is not
// usable; obtain one via NewDeduplicator.
//
// The dedup map is bounded by (peer count × 256 identifiers). A background
// goroutine is not started: entries are evicted lazily on the next Seen call
// after they expire, and the map size is capped by the active peer set.
// Long-lived servers with churning peers should call Cleanup periodically
// from a ticker to release expired entries.
type Deduplicator struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*dedupEntry
}

type dedupEntry struct {
	reply   []byte
	done    chan struct{}
	expires time.Time
}

// NewDeduplicator returns a Deduplicator with the given TTL. A TTL of zero
// falls back to defaultDedupTTL (5s) per RFC 2865 §2.5.
func NewDeduplicator(ttl time.Duration) *Deduplicator {
	if ttl <= 0 {
		ttl = defaultDedupTTL
	}
	return &Deduplicator{
		ttl:     ttl,
		entries: make(map[string]*dedupEntry),
	}
}

// Seen reports whether (addr, id) has been observed within the TTL window.
// If this is the first sighting, the tuple is recorded with the current
// time and a freshly allocated done channel; the caller is then expected
// to process the request and call Store to publish the reply. If it is a
// duplicate, Seen returns true and Lookup may return a cached reply.
//
// Concurrent calls with the same (addr, id) are serialized through the
// entry's done channel: only the first caller sees false; subsequent
// callers within the TTL window see true.
func (d *Deduplicator) Seen(addr net.Addr, id byte) bool {
	key := dedupKey(addr, id)
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.evictExpiredLocked(now)
	if _, ok := d.entries[key]; ok {
		return true
	}
	d.entries[key] = &dedupEntry{
		done:    make(chan struct{}),
		expires: now.Add(d.ttl),
	}
	return false
}

// Store caches reply as the response for (addr, id) and closes the entry's
// done channel so any concurrent duplicate waiter can proceed. Calling
// Store without a prior Seen that returned false is a no-op.
//
// reply is copied so the caller may reuse the underlying buffer.
func (d *Deduplicator) Store(addr net.Addr, id byte, reply []byte) {
	key := dedupKey(addr, id)
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.entries[key]
	if !ok {
		return
	}
	e.reply = append([]byte(nil), reply...)
	select {
	case <-e.done:
	default:
		close(e.done)
	}
}

// Lookup returns the cached reply for (addr, id) when Store has been called
// for it. Returns (nil, false) when the tuple is unknown, never seen, or the
// handler has not yet finished publishing the reply.
func (d *Deduplicator) Lookup(addr net.Addr, id byte) ([]byte, bool) {
	key := dedupKey(addr, id)
	d.mu.Lock()
	e, ok := d.entries[key]
	d.mu.Unlock()
	if !ok {
		return nil, false
	}
	<-e.done
	if e.reply == nil {
		return nil, false
	}
	return append([]byte(nil), e.reply...), true
}

// Cleanup removes expired entries. Intended to be called periodically by a
// long-lived server; See Seen also evicts lazily so Cleanup is not strictly
// required for correctness, only for bounding memory growth in churning
// deployments.
func (d *Deduplicator) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evictExpiredLocked(time.Now())
}

// Size returns the current number of tracked (addr, id) entries, including
// expired-but-not-yet-evicted ones. Useful for tests and metrics.
func (d *Deduplicator) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// evictExpiredLocked removes entries whose TTL has elapsed. Caller must
// hold d.mu.
func (d *Deduplicator) evictExpiredLocked(now time.Time) {
	for k, e := range d.entries {
		if !now.Before(e.expires) {
			// Ensure any concurrent Lookup waiter does not block forever:
			// closing done signals that no reply will ever be published.
			select {
			case <-e.done:
			default:
				close(e.done)
			}
			delete(d.entries, k)
		}
	}
}

// dedupKey returns the map key for (addr, id). The key is truncated to
// dedupKeySize bytes to bound memory use against pathological addr strings.
func dedupKey(addr net.Addr, id byte) string {
	var s string
	if addr != nil {
		s = addr.String()
	}
	if len(s) > dedupKeySize {
		s = s[:dedupKeySize]
	}
	return s + "\x00" + string([]byte{id})
}
