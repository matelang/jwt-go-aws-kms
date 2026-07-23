package jwtkms

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms/internal/mockkms"
)

func TestWarmPubKeyCache(t *testing.T) {
	t.Cleanup(ClearPubKeyCache)

	kms := mockkms.NewMockKMS()
	id, err := kms.GenerateKey(mockkms.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	if pubkeyCache.Get(id) != nil {
		t.Fatal("expected cache miss before warming")
	}

	if err := WarmPubKeyCache(context.Background(), kms, id); err != nil {
		t.Fatalf("WarmPubKeyCache: %v", err)
	}

	if pubkeyCache.Get(id) == nil {
		t.Fatal("expected cache hit after warming")
	}
}

func TestWarmPubKeyCache_NonExistentKey(t *testing.T) {
	t.Cleanup(ClearPubKeyCache)

	kms := mockkms.NewMockKMS()

	err := WarmPubKeyCache(context.Background(), kms, "non-existent-key-id")
	if err == nil {
		t.Fatal("expected error warming cache for non-existent key")
	}
	if !strings.Contains(err.Error(), "no such key") {
		t.Errorf("expected 'no such key' error, got: %v", err)
	}

	if pubkeyCache.Get("non-existent-key-id") != nil {
		t.Fatal("expected no cache entry after failed warm")
	}
}

func TestWarmPubKeyCache_SkipsKMSOnSubsequentVerify(t *testing.T) {
	t.Cleanup(ClearPubKeyCache)

	underlying := mockkms.NewMockKMS()
	id, err := underlying.GenerateKey(mockkms.KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Sign a real token before wrapping the client, so its GetPublicKey can be
	// disabled below without affecting Sign.
	token := jwt.NewWithClaims(SigningMethodECDSA256, &jwt.MapClaims{"claim": "value"})
	signed, err := token.SignedString(NewKMSConfig(underlying, id, false))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	if err := WarmPubKeyCache(context.Background(), underlying, id); err != nil {
		t.Fatalf("WarmPubKeyCache: %v", err)
	}
	if pubkeyCache.Get(id) == nil {
		t.Fatal("expected cache hit after warming")
	}

	// Verifying through a client whose GetPublicKey always fails proves the
	// warmed cache entry is used instead of fetching again.
	client := &failingGetPublicKeyKMS{MockKMS: underlying}
	config := NewKMSConfig(client, id, false)

	var claims jwt.MapClaims
	_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) {
		return config, nil
	})
	if err != nil {
		t.Fatalf("expected verify to succeed using warmed cache, got: %v", err)
	}
}

// failingGetPublicKeyKMS wraps a KMSClient and fails any GetPublicKey call, to
// prove Verify uses the pre-warmed cache instead of fetching again.
type failingGetPublicKeyKMS struct {
	*mockkms.MockKMS
}

func (f *failingGetPublicKeyKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return nil, fmt.Errorf("GetPublicKey should not be called")
}
