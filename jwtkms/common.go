package jwtkms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const messageTypeDigest = "DIGEST"

// Config is a struct to be passed to token signing/verification.
type Config struct {
	// context used for kms operations
	Ctx context.Context

	// A configured kms client pointer to AWS KMS
	KMSClient *kms.Client

	// AWS KMS Key ID to be used
	KMSKeyID string

	// If set to true JWT verification will be performed using KMS's Verify method
	//
	// In normal scenarios this can be left on the default false value, which will get, cache(forever) in memory and
	// use the KMS key's public key to verify signatures
	VerifyWithKMS bool
}
