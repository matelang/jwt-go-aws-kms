package jwtkms

import "github.com/aws/aws-sdk-go/service/kms"

const messageTypeDigest = "DIGEST"

type KmsConfig struct {
	Svc           *kms.KMS
	KmsKeyId      string
	VerifyWithKMS bool
}
