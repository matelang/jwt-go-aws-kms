// Package jwtkms provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library
//
// Importing this package will auto register the provided SigningMethods and make them available for use.
// Make sure to use a keyConfig with a keyId that provides the requested SigningMethod's algorithm for Sign/Verify.
//
// By default JWT signature verification will happen by downloading and caching the public key of the KMS key,
// but you can also set verifyWithKMS to true if you want the KMS to verify the signature instead.
//
package jwtkms

import (
	"crypto"

	"github.com/dgrijalva/jwt-go"
)

var (
	SigningMethodKmsECDSA256 *ECDSASigningMethod
	SigningMethodKmsECDSA384 *ECDSASigningMethod
	SigningMethodKmsECDSA512 *ECDSASigningMethod

	SigningMethodRS256 *RSASigningMethod
	SigningMethodRS384 *RSASigningMethod
	SigningMethodRS512 *RSASigningMethod
)

var pubkeyCache = newPubKeyCache()

func init() {
	registerECDSASigningMethods()
	registerRSASigningMethods()
}

func registerECDSASigningMethods() {
	SigningMethodKmsECDSA256 = &ECDSASigningMethod{
		name:                  "ES256",
		algo:                  "ECDSA_SHA_256",
		hash:                  crypto.SHA256,
		keySize:               32,
		curveBits:             256,
		fallbackSigningMethod: jwt.SigningMethodES256,
	}

	jwt.RegisterSigningMethod(SigningMethodKmsECDSA256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsECDSA256
	})

	SigningMethodKmsECDSA384 = &ECDSASigningMethod{
		name:                  "ES384",
		algo:                  "ECDSA_SHA_384",
		hash:                  crypto.SHA384,
		keySize:               48,
		curveBits:             384,
		fallbackSigningMethod: jwt.SigningMethodES384,
	}

	jwt.RegisterSigningMethod(jwt.SigningMethodES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsECDSA384
	})

	SigningMethodKmsECDSA512 = &ECDSASigningMethod{
		name:                  "ES512",
		algo:                  "ECDSA_SHA_512",
		hash:                  crypto.SHA512,
		keySize:               66,
		curveBits:             521,
		fallbackSigningMethod: jwt.SigningMethodES512,
	}

	jwt.RegisterSigningMethod(jwt.SigningMethodES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsECDSA512
	})
}

func registerRSASigningMethods() {
	SigningMethodRS256 = &RSASigningMethod{
		name:                  "RS256",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_256",
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodRS256,
	}

	jwt.RegisterSigningMethod(SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS256
	})

	SigningMethodRS384 = &RSASigningMethod{
		name:                  "RS384",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_384",
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodRS384,
	}

	jwt.RegisterSigningMethod(SigningMethodRS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS384
	})

	SigningMethodRS512 = &RSASigningMethod{
		name:                  "RS512",
		algo:                  "RSASSA_PKCS1_V1_5_SHA_512",
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodRS512,
	}

	jwt.RegisterSigningMethod(SigningMethodRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS512
	})
}
