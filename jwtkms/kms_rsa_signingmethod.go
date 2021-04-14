package jwtkms

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/dgrijalva/jwt-go"
)

type KmsRsaSigningMethod struct {
	name string
	algo string
	hash crypto.Hash
}

func (m *KmsRsaSigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
	cfg, ok := keyConfig.(*KmsConfig)
	if !ok {
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
	} else {
		return localKmsVerifyRsa(cfg, m.hash, hashedSigningString, sig)
	}
}

func kmsVerifyRsa(cfg *KmsConfig, algo string, hashedSigningString []byte, sig []byte) error {
	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(cfg.KmsKeyId),
		Message:          hashedSigningString,
		MessageType:      aws.String(messageTypeDigest),
		Signature:        sig,
		SigningAlgorithm: aws.String(algo),
	}

	verifyOutput, err := cfg.Svc.Verify(verifyInput)
	if err != nil {
		return err
	}

	if !*verifyOutput.SignatureValid {
		return jwt.ErrSignatureInvalid
	}

	return nil
}

func localKmsVerifyRsa(cfg *KmsConfig, hash crypto.Hash, hashedSigningString []byte, sig []byte) error {
	var rsaPublicKey *rsa.PublicKey
	cachedKey := pubkeyCache.Get(cfg.KmsKeyId)
	if cachedKey == nil {
		getPubKeyOutput, err := cfg.Svc.GetPublicKey(&kms.GetPublicKeyInput{
			KeyId: aws.String(cfg.KmsKeyId),
		})
		if err != nil {
			return err
		}

		cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
		if err != nil {
			return err
		}

		pubkeyCache.Add(cfg.KmsKeyId, cachedKey)
	}

	rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for key")
	}

	return rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashedSigningString, sig)
}

func (m *KmsRsaSigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
	cfg, ok := keyConfig.(*KmsConfig)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	if !m.hash.Available() {
		return "", jwt.ErrHashUnavailable
	}

	hasher := m.hash.New()
	hasher.Write([]byte(signingString))
	hashedSigningString := hasher.Sum(nil)

	signInput := &kms.SignInput{
		KeyId:            aws.String(cfg.KmsKeyId),
		Message:          hashedSigningString,
		MessageType:      aws.String(messageTypeDigest),
		SigningAlgorithm: aws.String(m.algo),
	}

	signOutput, err := cfg.Svc.Sign(signInput)
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signOutput.Signature), nil
}

func (m *KmsRsaSigningMethod) Alg() string {
	return m.name
}
