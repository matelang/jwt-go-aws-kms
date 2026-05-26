package jwtkms

import (
	"crypto"
	"sync"
	"time"
)

type cacheEntry struct {
	key     crypto.PublicKey
	addedAt time.Time
}

type pubKeyCache struct {
	pubKeys map[string]cacheEntry
	ttl     time.Duration
	now     func() time.Time
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

func (c *pubKeyCache) Add(keyID string, key crypto.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.pubKeys[keyID] = cacheEntry{key: key, addedAt: c.now()}
}

func (c *pubKeyCache) Get(keyID string) crypto.PublicKey {
	c.mutex.RLock()
	e, ok := c.pubKeys[keyID]
	ttl := c.ttl
	c.mutex.RUnlock()
	if !ok {
		return nil
	}
	if ttl > 0 && c.now().Sub(e.addedAt) > ttl {
		return nil
	}
	return e.key
}

func (c *pubKeyCache) SetTTL(d time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ttl = d
}

func (c *pubKeyCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pubKeys = make(map[string]cacheEntry)
}

// SetPubKeyCacheTTL configures a time-to-live for the in-memory public key
// cache used during local verification (verifyWithKMS=false).
//
// Default is 0, which means cached keys never expire — matching the historical
// behavior. Set this to a non-zero duration if KMS keys can rotate during the
// process lifetime and you want verification to pick up the new key material
// without restarts.
//
// The setting is process-global because the cache is a process-wide singleton.
func SetPubKeyCacheTTL(d time.Duration) {
	pubkeyCache.SetTTL(d)
}

// ClearPubKeyCache evicts all cached public keys. Call this after a known KMS
// key rotation to force the next verification to refetch the public key.
func ClearPubKeyCache() {
	pubkeyCache.Clear()
}
