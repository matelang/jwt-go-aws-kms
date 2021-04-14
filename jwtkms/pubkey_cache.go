package jwtkms

import (
	"crypto"
	"sync"
)

type pubKeyCache struct {
	pubKeys map[string]crypto.PublicKey
	mutex   *sync.Mutex
}

func (c *pubKeyCache) Add(keyId string, key crypto.PublicKey) {
	c.mutex.Lock()
	c.pubKeys[keyId] = key
	c.mutex.Unlock()
}

func (c *pubKeyCache) Get(keyId string) crypto.PublicKey {
	return c.pubKeys[keyId]
}
