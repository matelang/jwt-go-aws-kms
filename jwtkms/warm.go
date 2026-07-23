package jwtkms

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fetchAndCachePublicKey retrieves keyID's public key from KMS, parses it, and
// stores it in the process-wide public key cache used for local (non-KMS)
// verification. It is shared by KMSSigningMethod.Verify's cache-miss path and
// WarmPubKeyCache.
func fetchAndCachePublicKey(ctx context.Context, client KMSClient, keyID string) (crypto.PublicKey, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("kms get public key: %w", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing kms public key: %w", err)
	}

	pubkeyCache.Add(keyID, pubKey)
	return pubKey, nil
}

// WarmPubKeyCache eagerly fetches keyID's public key from KMS and stores it in
// the process-wide public key cache, returning any error from the KMS call or
// key parsing.
//
// Call this at process startup for every KMS key ID used with
// verifyWithKMS=false so a bad key ID or a missing kms:GetPublicKey IAM
// permission fails fast at boot instead of on the first Verify call. Without
// this, KMSSigningMethod.Verify fetches and caches the key lazily on first
// use, so a misconfiguration is only discovered when the first token arrives.
func WarmPubKeyCache(ctx context.Context, client KMSClient, keyID string) error {
	_, err := fetchAndCachePublicKey(ctx, client, keyID)
	return err
}
