package jwtkms

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

// RSASigningMethod is an RSA implementation of the SigningMethod interface that uses KMS to Sign/Verify JWTs.
type RSASigningMethod struct {
	name                  string
	algo                  string
	hash                  crypto.Hash
	fallbackSigningMethod *jwt.SigningMethodRSA
}

func (m *RSASigningMethod) Alg() string {
	return m.name
}

func (m *RSASigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
	cfg, ok := keyConfig.(*Config)
	if !ok {
		_, isBuiltInRsa := keyConfig.(*rsa.PublicKey)
		if isBuiltInRsa {
			return m.fallbackSigningMethod.Verify(signingString, signature, keyConfig)
		}

		return jwt.ErrInvalidKeyType
	}

	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	if !m.hash.Available() {
		return jwt.ErrHashUnavailable
	}

	hasher := m.hash.New()
	hasher.Write([]byte(signingString)) //nolint:errcheck
	hashedSigningString := hasher.Sum(nil)

	if cfg.verifyWithKMS {
		return verifyRSAOrPSS(cfg, m.algo, hashedSigningString, sig)
	}

	return localVerifyRSA(cfg, m.hash, hashedSigningString, sig)
}

func (m *RSASigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
	cfg, ok := keyConfig.(*Config)
	if !ok {
		_, isBuiltInRsa := keyConfig.(*rsa.PublicKey)
		if isBuiltInRsa {
			return m.fallbackSigningMethod.Sign(signingString, keyConfig)
		}

		return "", jwt.ErrInvalidKeyType
	}

	if !m.hash.Available() {
		return "", jwt.ErrHashUnavailable
	}

	hasher := m.hash.New()
	hasher.Write([]byte(signingString)) //nolint:errcheck
	hashedSigningString := hasher.Sum(nil)

	signInput := &kms.SignInput{
		KeyId:            aws.String(cfg.kmsKeyID),
		Message:          hashedSigningString,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpec(m.algo),
	}

	signOutput, err := cfg.kmsClient.Sign(cfg.ctx, signInput)
	if err != nil {
		return "", fmt.Errorf("signing digest: %w", err)
	}

	return jwt.EncodeSegment(signOutput.Signature), nil
}

func verifyRSAOrPSS(cfg *Config, algo string, hashedSigningString []byte, sig []byte) error {
	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(cfg.kmsKeyID),
		Message:          hashedSigningString,
		Signature:        sig,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpec(algo),
	}

	verifyOutput, err := cfg.kmsClient.Verify(cfg.ctx, verifyInput)
	if err != nil {
		return fmt.Errorf("verifying signature remotely: %w", err)
	}

	if !verifyOutput.SignatureValid {
		return jwt.ErrSignatureInvalid
	}

	return nil
}

func localVerifyRSA(cfg *Config, hash crypto.Hash, hashedSigningString []byte, sig []byte) error {
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

	if err := rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashedSigningString, sig); err != nil {
		return fmt.Errorf("verifying signature locally: %w", err)
	}

	return nil
}
