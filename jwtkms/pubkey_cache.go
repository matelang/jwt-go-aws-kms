package jwtkms

import (
	"crypto"
	"sync"
)

type pubKeyCache struct {
	pubKeys map[string]crypto.PublicKey
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]crypto.PublicKey),
	}
}

func (c *pubKeyCache) Add(keyID string, key crypto.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.pubKeys[keyID] = key
}

func (c *pubKeyCache) Get(keyID string) crypto.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.pubKeys[keyID]
}
