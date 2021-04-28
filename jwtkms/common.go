package jwtkms

import "github.com/aws/aws-sdk-go/service/kms"

const messageTypeDigest = "DIGEST"

// KmsConfig is a struct to be passed to token signing/verification
type KmsConfig struct {
	//A configured svc pointer to AWS KMS
	Svc *kms.KMS

	//AWS KMS Key ID to be used
	KmsKeyId string

	//If set to true JWT verification will be performed using KMS's Verify method
	//
	//In normal scenarios this can be left on the default false value, which will get, cache(forever) in memory and
	//use the KMS key's public key to verify signatures
	VerifyWithKMS bool
}
