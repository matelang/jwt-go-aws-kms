package jwtkms

import "github.com/aws/aws-sdk-go-v2/service/kms"

var _ KMSClient = &kms.Client{}
