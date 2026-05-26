package jwtkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

func TestPubKeyCache_ConcurrentAccess(t *testing.T) {
	c := newPubKeyCache()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := keyIDFor(id, j)
				c.Add(key, &priv.PublicKey)
				_ = c.Get(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestPubKeyCache_TTLExpiry(t *testing.T) {
	c := newPubKeyCache()
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.SetTTL(1 * time.Minute)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	c.Add("k", &priv.PublicKey)

	if c.Get("k") == nil {
		t.Fatal("expected cache hit immediately after Add")
	}

	now = now.Add(30 * time.Second)
	if c.Get("k") == nil {
		t.Fatal("expected cache hit within TTL")
	}

	now = now.Add(31 * time.Second)
	if c.Get("k") != nil {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestPubKeyCache_Clear(t *testing.T) {
	c := newPubKeyCache()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	c.Add("a", &priv.PublicKey)
	c.Add("b", &priv.PublicKey)
	c.Clear()

	if c.Get("a") != nil || c.Get("b") != nil {
		t.Fatal("expected cache miss after Clear")
	}
}

func TestPubKeyCache_NoTTLByDefault(t *testing.T) {
	c := newPubKeyCache()
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	c.Add("k", &priv.PublicKey)

	now = now.Add(100 * 365 * 24 * time.Hour) // 100 years
	if c.Get("k") == nil {
		t.Fatal("expected cache hit with default no-TTL behavior even after long elapsed time")
	}
}

func keyIDFor(g, i int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 8)
	for _, v := range []int{g, i} {
		for shift := 28; shift >= 0; shift -= 4 {
			b = append(b, hex[(v>>shift)&0xf])
		}
	}
	return string(b)
}

func TestPackageLevelCacheControls(t *testing.T) {
	// Restore state at end so other tests are unaffected.
	t.Cleanup(func() {
		SetPubKeyCacheTTL(0)
		ClearPubKeyCache()
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubkeyCache.Add("ttl-test", &priv.PublicKey)
	if pubkeyCache.Get("ttl-test") == nil {
		t.Fatal("expected hit before clear")
	}
	ClearPubKeyCache()
	if pubkeyCache.Get("ttl-test") != nil {
		t.Fatal("expected miss after ClearPubKeyCache")
	}

	SetPubKeyCacheTTL(1 * time.Nanosecond)
	pubkeyCache.Add("ttl-test", &priv.PublicKey)
	time.Sleep(2 * time.Millisecond)
	if pubkeyCache.Get("ttl-test") != nil {
		t.Fatal("expected miss after TTL expiry on package cache")
	}
}
