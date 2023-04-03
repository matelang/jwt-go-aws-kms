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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"math/big"

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

var ecdsaPubKeyCheckerFunc = func(cfg interface{}) bool {
	_, isBuiltInECDSA := cfg.(*ecdsa.PublicKey)
	return isBuiltInECDSA
}

var rsaPubKeyCheckerFunc = func(cfg interface{}) bool {
	_, isBuiltInECDSA := cfg.(*rsa.PublicKey)
	return isBuiltInECDSA
}

var ecdsaVerificationSigFormatter = func(keySize int) func(sig []byte) ([]byte, error) {
	return func(sig []byte) ([]byte, error) {

		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])

		p := struct {
			R *big.Int
			S *big.Int
		}{r, s}

		derSig, err := asn1.Marshal(p)
		if err != nil {
			return nil, err
		}

		return derSig, nil
	}
}

var rsaPKCS1LocalVerificationFunc = func(hash crypto.Hash) func(cfg *Config, hashedSigningString []byte, sig []byte) error {
	return func(cfg *Config, hashedSigningString []byte, sig []byte) error {
		var rsaPublicKey *rsa.PublicKey

		cachedKey := pubkeyCache.Get(cfg.kmsKeyID)
		if cachedKey == nil {
			getPubKeyOutput, err := cfg.kmsClient.GetPublicKey(cfg.ctx, &kms.GetPublicKeyInput{
				KeyId: aws.String(cfg.kmsKeyID),
			})
			if err != nil {
				return err
			}

			cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
			if err != nil {
				return err
			}

			pubkeyCache.Add(cfg.kmsKeyID, cachedKey)
		}

		rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type for key")
		}

		return rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashedSigningString, sig)
	}
}

var rsaPSSLocalVerificationFunc = func(hash crypto.Hash, opts *rsa.PSSOptions) func(cfg *Config, hashedSigningString []byte, sig []byte) error {
	return func(cfg *Config, hashedSigningString []byte, sig []byte) error {
		var rsaPublicKey *rsa.PublicKey

		cachedKey := pubkeyCache.Get(cfg.kmsKeyID)
		if cachedKey == nil {
			getPubKeyOutput, err := cfg.kmsClient.GetPublicKey(cfg.ctx, &kms.GetPublicKeyInput{
				KeyId: aws.String(cfg.kmsKeyID),
			})
			if err != nil {
				return fmt.Errorf("getting public key: %w", err)
			}

			cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
			if err != nil {
				return fmt.Errorf("parsing public key: %w", err)
			}

			pubkeyCache.Add(cfg.kmsKeyID, cachedKey)
		}

		rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type for key")
		}

		if err := rsa.VerifyPSS(rsaPublicKey, hash, hashedSigningString, sig, opts); err != nil {
			return fmt.Errorf("verifying signature locally: %w", err)
		}

		return nil
	}
}

var ecdsaLocalVerificationFunc = func(keySize int) func(cfg *Config, hashedSigningString []byte, sig []byte) error {
	return func(cfg *Config, hashedSigningString []byte, sig []byte) error {
		var ecdsaPublicKey *ecdsa.PublicKey

		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])

		cachedKey := pubkeyCache.Get(cfg.kmsKeyID)
		if cachedKey == nil {
			getPubKeyOutput, err := cfg.kmsClient.GetPublicKey(cfg.ctx, &kms.GetPublicKeyInput{
				KeyId: aws.String(cfg.kmsKeyID),
			})
			if err != nil {
				return err
			}

			cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
			if err != nil {
				return err
			}

			pubkeyCache.Add(cfg.kmsKeyID, cachedKey)
		}

		ecdsaPublicKey, ok := cachedKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid key type for key")
		}

		valid := ecdsa.Verify(ecdsaPublicKey, hashedSigningString, r, s)
		if !valid {
			return jwt.ErrSignatureInvalid
		}

		return nil
	}
}

var ecdsaSignerSigFormatter = func(curveBits int) func(sig []byte) ([]byte, error) {
	return func(sig []byte) ([]byte, error) {
		p := struct {
			R *big.Int
			S *big.Int
		}{}

		_, err := asn1.Unmarshal(sig, &p)
		if err != nil {
			return nil, err
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		// We serialize the outpus (r and s) into big-endian byte arrays and pad
		// them with zeros on the left to make sure the sizes work out. Both arrays
		// must be keyBytes long, and the output must be 2*keyBytes long.
		rBytes := p.R.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := p.S.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)
		return out, nil
	}
}

func init() {
	registerSigningMethods()
}

func registerSigningMethods() {
	SigningMethodECDSA256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodES256,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		verificationSigFormatterFunc:              ecdsaVerificationSigFormatter(32),
		signatureSigFormatterFunc:                 ecdsaSignerSigFormatter(256),
		localVerificationFunc:                     ecdsaLocalVerificationFunc(32),
	}
	jwt.RegisterSigningMethod(SigningMethodECDSA256.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA256
	})

	SigningMethodECDSA384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha384,
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodES384,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		verificationSigFormatterFunc:              ecdsaVerificationSigFormatter(48),
		signatureSigFormatterFunc:                 ecdsaSignerSigFormatter(384),
		localVerificationFunc:                     ecdsaLocalVerificationFunc(48),
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA384
	})

	SigningMethodECDSA512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecEcdsaSha512,
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodES512,
		fallbackSigningMethodKeyConfigCheckerFunc: ecdsaPubKeyCheckerFunc,
		verificationSigFormatterFunc:              ecdsaVerificationSigFormatter(66),
		signatureSigFormatterFunc:                 ecdsaSignerSigFormatter(521),
		localVerificationFunc:                     ecdsaLocalVerificationFunc(66),
	}
	jwt.RegisterSigningMethod(jwt.SigningMethodES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodECDSA512
	})

	SigningMethodRS256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodRS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPKCS1LocalVerificationFunc(crypto.SHA256),
	}
	jwt.RegisterSigningMethod(SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS256
	})

	SigningMethodRS384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		hash:                  crypto.SHA384,
		fallbackSigningMethod: jwt.SigningMethodRS384,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPKCS1LocalVerificationFunc(crypto.SHA384),
	}
	jwt.RegisterSigningMethod(SigningMethodRS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS384
	})

	SigningMethodRS512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		hash:                  crypto.SHA512,
		fallbackSigningMethod: jwt.SigningMethodRS512,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPKCS1LocalVerificationFunc(crypto.SHA512),
	}
	jwt.RegisterSigningMethod(SigningMethodRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS512
	})

	SigningMethodPS256 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodPS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPSSLocalVerificationFunc(crypto.SHA256, jwt.SigningMethodPS256.Options),
	}
	jwt.RegisterSigningMethod(SigningMethodPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS256
	})

	SigningMethodPS384 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodPS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPSSLocalVerificationFunc(crypto.SHA384, jwt.SigningMethodPS384.Options),
	}
	jwt.RegisterSigningMethod(SigningMethodPS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS384
	})

	SigningMethodPS512 = &KMSSigningMethod{
		algo:                  types.SigningAlgorithmSpecRsassaPssSha256,
		hash:                  crypto.SHA256,
		fallbackSigningMethod: jwt.SigningMethodPS256,
		fallbackSigningMethodKeyConfigCheckerFunc: rsaPubKeyCheckerFunc,
		localVerificationFunc:                     rsaPSSLocalVerificationFunc(crypto.SHA512, jwt.SigningMethodPS512.Options),
	}
	jwt.RegisterSigningMethod(SigningMethodPS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodPS512
	})
}
