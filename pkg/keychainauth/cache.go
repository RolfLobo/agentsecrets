package keychainauth

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// Secret reads go through the daemon over a Unix socket, and the same
// non-secret metadata (key-name listings, per-key policy) is frequently
// re-read within a single command. A short-lived in-process cache collapses
// those duplicate round-trips.
//
// IMPORTANT: this cache holds ONLY non-secret data — key names (search
// results) and policy/authorization metadata. Plaintext secret values are
// never stored here; GetSecret / GetAllProjectSecrets always hit the daemon so
// a rotation or revocation is reflected immediately.
//
// The TTL is deliberately small and is invalidated on any write/delete so a
// mutation is never masked by a stale read. It can be tuned or disabled via
// AGENTSECRETS_KEYCHAIN_CACHE_TTL_MS (0 disables the cache entirely).

const defaultCacheTTL = 5 * time.Second

type cacheEntry struct {
	// exactly one of the value fields is meaningful per entry kind
	bytesVal []byte   // policy metadata
	listVal  []string // key-name listings
	storedAt time.Time
}

type secretCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]cacheEntry
}

var valueCache = newSecretCache()

func newSecretCache() *secretCache {
	ttl := defaultCacheTTL
	if v := os.Getenv("AGENTSECRETS_KEYCHAIN_CACHE_TTL_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			ttl = time.Duration(ms) * time.Millisecond
		}
	}
	return &secretCache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func (c *secretCache) enabled() bool { return c != nil && c.ttl > 0 }

func (c *secretCache) get(key string) (cacheEntry, bool) {
	if !c.enabled() {
		return cacheEntry{}, false
	}
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Since(e.storedAt) > c.ttl {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *secretCache) put(key string, e cacheEntry) {
	if !c.enabled() {
		return
	}
	e.storedAt = time.Now()
	c.mu.Lock()
	c.m[key] = e
	c.mu.Unlock()
}

// invalidateAll clears the entire cache (used when the connection resets or a
// bulk mutation makes targeted invalidation impractical).
func (c *secretCache) invalidateAll() {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	c.m = make(map[string]cacheEntry)
	c.mu.Unlock()
}
