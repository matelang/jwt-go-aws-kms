package jwtkms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMSClient is the subset of `*kms.Client` functionality used when signing and
// verifying JWTs. It is an interface here so users do not need to depend on
// the full-sized `*kms.Client` object and can substitute their own
// implementation.
type KMSClient interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, in *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// Config is a struct to be passed to token signing/verification.
type Config struct {
	// context used for kms operations
	ctx context.Context

	// A configured kms client pointer to AWS KMS
	kmsClient KMSClient

	// AWS KMS Key ID to be used
	kmsKeyID string

	// If set to true JWT verification will be performed using KMS's Verify method
	//
	// In normal scenarios this can be left on the default false value, which will get, cache(forever) in memory and
	// use the KMS key's public key to verify signatures
	verifyWithKMS bool
}

// NewKMSConfig create a new Config with specified parameters.
func NewKMSConfig(client KMSClient, keyID string, verify bool) *Config {
	return &Config{
		ctx:           context.Background(),
		kmsClient:     client,
		kmsKeyID:      keyID,
		verifyWithKMS: verify,
	}
}

// WithContext returns a copy of Config with context.
func (c *Config) WithContext(ctx context.Context) *Config {
	c2 := new(Config)
	*c2 = *c
	c2.ctx = ctx

	return c2
}
