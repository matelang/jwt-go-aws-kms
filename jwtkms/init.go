package jwtkms

import (
	"crypto"
	"github.com/dgrijalva/jwt-go"
	"sync"
)

var (
	SigningMethodKmsEcdsa256 *KmsEcdsaSigningMethod
	SigningMethodKmsEcdsa384 *KmsEcdsaSigningMethod
	SigningMethodKmsEcdsa512 *KmsEcdsaSigningMethod

	SigningMethodRs256 *KmsRsaSigningMethod
	SigningMethodRs384 *KmsRsaSigningMethod
	SigningMethodRs512 *KmsRsaSigningMethod
)

var pubkeyCache *pubKeyCache = &pubKeyCache{
	pubKeys: make(map[string]crypto.PublicKey),
	mutex:   &sync.Mutex{},
}

func init() {
	registerEcdsaSigningMethods()
	registerRsaSigningMethods()
}

func registerEcdsaSigningMethods() {
	SigningMethodKmsEcdsa256 = &KmsEcdsaSigningMethod{
		name:      "ES256",
		algo:      "ECDSA_SHA_256",
		hash:      crypto.SHA256,
		keySize:   32,
		curveBits: 256,
	}
	jwt.RegisterSigningMethod(SigningMethodKmsEcdsa256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa256
	})

	SigningMethodKmsEcdsa384 = &KmsEcdsaSigningMethod{
		name:      "ES384",
		algo:      "ECDSA_SHA_384",
		hash:      crypto.SHA384,
		keySize:   48,
		curveBits: 384,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa384
	})

	SigningMethodKmsEcdsa512 = &KmsEcdsaSigningMethod{
		name:      "ES512",
		algo:      "ECDSA_SHA_512",
		hash:      crypto.SHA512,
		keySize:   66,
		curveBits: 521,
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodKmsEcdsa512
	})
}

func registerRsaSigningMethods() {
	SigningMethodRs256 = &KmsRsaSigningMethod{
		name: "RS256",
		algo: "RSASSA_PKCS1_V1_5_SHA_256",
		hash: crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodRs256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs256
	})

	SigningMethodRs384 = &KmsRsaSigningMethod{
		name: "RS384",
		algo: "RSASSA_PKCS1_V1_5_SHA_384",
		hash: crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodRs384.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs384
	})

	SigningMethodRs512 = &KmsRsaSigningMethod{
		name: "RS512",
		algo: "RSASSA_PKCS1_V1_5_SHA_512",
		hash: crypto.SHA512,
	}
	jwt.RegisterSigningMethod(SigningMethodRs512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRs512
	})
}
