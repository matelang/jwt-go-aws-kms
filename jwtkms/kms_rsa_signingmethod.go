package jwtkms

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/dgrijalva/jwt-go"
)

// KmsRsaSigningMethod is an RSA implementation of the SigningMethod interface that uses KMS to Sign/Verify JWTs.
type KmsRsaSigningMethod struct {
	name                  string
	algo                  string
	hash                  crypto.Hash
	fallbackSigningMethod *jwt.SigningMethodRSA
}

func (m *KmsRsaSigningMethod) Alg() string {
	return m.name
}

func (m *KmsRsaSigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
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
		return err
	}

	if !m.hash.Available() {
		return jwt.ErrHashUnavailable
	}

	hasher := m.hash.New()
	hasher.Write([]byte(signingString))
	hashedSigningString := hasher.Sum(nil)

	if cfg.VerifyWithKMS {
		return kmsVerifyRsa(cfg, m.algo, hashedSigningString, sig)
	}

	return localKmsVerifyRsa(cfg, m.hash, hashedSigningString, sig)
}

func (m *KmsRsaSigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
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
	hasher.Write([]byte(signingString))
	hashedSigningString := hasher.Sum(nil)

	signInput := &kms.SignInput{
		KeyId:            aws.String(cfg.KMSKeyID),
		Message:          hashedSigningString,
		MessageType:      types.MessageType(messageTypeDigest),
		SigningAlgorithm: types.SigningAlgorithmSpec(m.algo),
	}

	signOutput, err := cfg.KMSClient.Sign(cfg.Ctx, signInput)
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signOutput.Signature), nil
}

func kmsVerifyRsa(cfg *Config, algo string, hashedSigningString []byte, sig []byte) error {
	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(cfg.KMSKeyID),
		Message:          hashedSigningString,
		Signature:        sig,
		MessageType:      types.MessageType(messageTypeDigest),
		SigningAlgorithm: types.SigningAlgorithmSpec(algo),
	}

	verifyOutput, err := cfg.KMSClient.Verify(cfg.Ctx, verifyInput)
	if err != nil {
		return err
	}

	if !verifyOutput.SignatureValid {
		return jwt.ErrSignatureInvalid
	}

	return nil
}

func localKmsVerifyRsa(cfg *Config, hash crypto.Hash, hashedSigningString []byte, sig []byte) error {
	var rsaPublicKey *rsa.PublicKey

	cachedKey := pubkeyCache.Get(cfg.KMSKeyID)
	if cachedKey == nil {
		getPubKeyOutput, err := cfg.KMSClient.GetPublicKey(cfg.Ctx, &kms.GetPublicKeyInput{
			KeyId: aws.String(cfg.KMSKeyID),
		})
		if err != nil {
			return err
		}

		cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
		if err != nil {
			return err
		}

		pubkeyCache.Add(cfg.KMSKeyID, cachedKey)
	}

	rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for key")
	}

	return rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashedSigningString, sig)
}
