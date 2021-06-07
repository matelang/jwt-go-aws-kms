// Package jwtkms provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library
//
// Importing this package will auto register the provided SigningMethods and make them available for use.
// Make sure to use a keyConfig with a keyId that provides the requested SigningMethod's algorithm for Sign/Verify.
//
// By default JWT signature verification will happen by downloading and caching the public key of the KMS key,
// but you can also set VerifyWithKMS to true if you want the KMS to verify the signature instead.
//
package jwtkms

import (
	"crypto"

	"github.com/dgrijalva/jwt-go"
)

var (
	SigningMethodKmsEcdsa256 *KmsEcdsaSigningMethod
	SigningMethodKmsEcdsa384 *KmsEcdsaSigningMethod
	SigningMethodKmsEcdsa512 *KmsEcdsaSigningMethod

	SigningMethodRs256 *KmsRsaSigningMethod
	SigningMethodRs384 *KmsRsaSigningMethod
	SigningMethodRs512 *KmsRsaSigningMethod
)

var pubkeyCache = newPubKeyCache()

func init() {
	registerEcdsaSigningMethods()
	registerRsaSigningMethods()
}

func registerEcdsaSigningMethods() {
	SigningMethodKmsEcdsa256 = &KmsEcdsaSigningMethod{
		name:                  "ES256",
		algo:                  "ECDSA_SHA_256",
		hash:                  crypto.SHA256,
		keySize:               32,
		curveBits:             256,
		fallbackSigningMethod: jwt.SigningMethodES256,
	}

	jwt.RegisterSigningMethod(SigningMethodKmsEcdsa256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa256
	})

	SigningMethodKmsEcdsa384 = &KmsEcdsaSigningMethod{
		name:                  "ES384",
		algo:                  "ECDSA_SHA_384",
		hash:                  crypto.SHA384,
		keySize:               48,
		curveBits:             384,
		fallbackSigningMethod: jwt.SigningMethodES384,
	}

	jwt.RegisterSigningMethod(jwt.SigningMethodES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa384
	})

	SigningMethodKmsEcdsa512 = &KmsEcdsaSigningMethod{
		name:                  "ES512",
		algo:                  "ECDSA_SHA_512",
		hash:                  crypto.SHA512,
		keySize:               66,
		curveBits:             521,
		fallbackSigningMethod: jwt.SigningMethodES512,
	}

	jwt.RegisterSigningMethod(jwt.SigningMethodES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa512
	})
}

func registerRsaSigningMethods() {
	SigningMethodRs256 = &KmsRsaSigningMethod{
		name:                  "RS256",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_256",
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodRS256,
	}

	jwt.RegisterSigningMethod(SigningMethodRs256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs256
	})

	SigningMethodRs384 = &KmsRsaSigningMethod{
		name:                  "RS384",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_384",
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodRS384,
	}

	jwt.RegisterSigningMethod(SigningMethodRs384.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs384
	})

	SigningMethodRs512 = &KmsRsaSigningMethod{
		name:                  "RS512",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_512",
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodRS512,
	}

	jwt.RegisterSigningMethod(SigningMethodRs512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs512
	})
}
