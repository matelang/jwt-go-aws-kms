// Package jwtkms provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library
//
// Importing this package will auto register the provided SigningMethods and make them available for use.
// Make sure to use a keyConfig with a keyId that provides the requested SigningMethod's algorithm for Sign/Verify.
//
// By default JWT signature verification will happen by downloading and caching the public key of the KMS key,
// but you can also set verifyWithKMS to true if you want the KMS to verify the signature instead.
package jwtkms

import (
	"crypto"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

var (
	SigningMethodECDSA256 *KMSSigningMethod
	SigningMethodECDSA384 *KMSSigningMethod
	SigningMethodECDSA512 *KMSSigningMethod

	SigningMethodRS256 *KMSSigningMethod
	SigningMethodRS384 *KMSSigningMethod
	SigningMethodRS512 *KMSSigningMethod

	SigningMethodPS256 *KMSSigningMethod
	SigningMethodPS384 *KMSSigningMethod
	SigningMethodPS512 *KMSSigningMethod
)

var pubkeyCache = newPubKeyCache()

func init() {
	registerESSigningMethods()
	registerRSSigningMethods()
	registerPSSigningMethods()
}

func registerESSigningMethods() {
	const (
		ecdsa256KeySize = 32
		ecdsa384KeySize = 48
		ecdsa512KeySize = 66

		ecdsa256CurveBits = 256
		ecdsa384CurveBits = 384
		ecdsa512CurveBits = 521
	)

	SigningMethodECDSA256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodES256,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		preVerificationSigFormatterFunc:           ecdsaVerificationSigFormatter(ecdsa256KeySize),
		postSignatureSigFormatterFunc:             ecdsaSignerSigFormatter(ecdsa256CurveBits),
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA256
	})

	SigningMethodECDSA384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha384,
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodES384,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		preVerificationSigFormatterFunc:           ecdsaVerificationSigFormatter(ecdsa384KeySize),
		postSignatureSigFormatterFunc:             ecdsaSignerSigFormatter(ecdsa384CurveBits),
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA384
	})

	SigningMethodECDSA512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha512,
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodES512,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		preVerificationSigFormatterFunc:           ecdsaVerificationSigFormatter(ecdsa512KeySize),
		postSignatureSigFormatterFunc:             ecdsaSignerSigFormatter(ecdsa512CurveBits),
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA512
	})
}

func registerRSSigningMethods() {
	SigningMethodRS256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodRS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS256
	})

	SigningMethodRS384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodRS384,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodRS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS384
	})

	SigningMethodRS512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodRS512,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS512
	})
}

func registerPSSigningMethods() {
	SigningMethodPS256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodPS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS256
	})

	SigningMethodPS384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha384,
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodPS384,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodPS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS384
	})

	SigningMethodPS512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha512,
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodPS512,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodPS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS512
	})
}
