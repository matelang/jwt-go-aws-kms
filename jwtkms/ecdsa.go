package jwtkms

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v4"
	"math/big"
)

var ecdsaPubKeyCheckerFunc = func(cfg interface{}) bool {
	_, isBuiltInECDSA := cfg.(*ecdsa.PublicKey)
	return isBuiltInECDSA
}

var ecdsaVerificationSigFormatter = func(keySize int) sigFormatterFunc {
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

var ecdsaSignerSigFormatter = func(curveBits int) sigFormatterFunc {
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
