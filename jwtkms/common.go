package jwtkms

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const messageTypeDigest = "DIGEST"

// Config is a struct to be passed to token signing/verification.
type Config struct {
	// context used for kms operations
	ctx context.Context

	// A configured kms client pointer to AWS KMS
	kmsClient *kms.Client

	// AWS KMS Key ID to be used
	kmsKeyID string

	// If set to true JWT verification will be performed using KMS's Verify method
	//
	// In normal scenarios this can be left on the default false value, which will get, cache(forever) in memory and
	// use the KMS key's public key to verify signatures
	verifyWithKMS bool
}

// NewKMSConfig create a new Config with specified parameters.
func NewKMSConfig(client *kms.Client, keyID string, verify bool) *Config {
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
