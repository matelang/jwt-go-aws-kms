package jwtkms

import (
	"crypto"
	"crypto/ecdsa"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

// KMSSigningMethod is a ...
type KMSSigningMethod struct {
	algo                                      types.SigningAlgorithmSpec
	hash                                      crypto.Hash
	fallbackSigningMethod                     jwt.SigningMethod
	fallbackSigningMethodKeyConfigCheckerFunc func(interface{}) bool
	verificationSigFormatterFunc              func(sig []byte) ([]byte, error)
	signatureSigFormatterFunc                 func(sig []byte) ([]byte, error)
	localVerificationFunc                     func(cfg *Config, hashedSigningString []byte, sig []byte) error
}

func (m *KMSSigningMethod) Alg() string {
	return m.fallbackSigningMethod.Alg()
}

func (m *KMSSigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
	cfg, ok := keyConfig.(*Config)
	if !ok {
		isBuiltInSigningMethod := m.fallbackSigningMethodKeyConfigCheckerFunc(keyConfig)

		if isBuiltInSigningMethod {
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
	hasher.Write([]byte(signingString)) //nolint:errcheck
	hashedSigningString := hasher.Sum(nil)

	if cfg.verifyWithKMS {
		formattedSig := sig
		if m.verificationSigFormatterFunc != nil {
			formattedSig, err = m.verificationSigFormatterFunc(sig)
			if err != nil {
				return err
			}
		}

		verifyInput := &kms.VerifyInput{
			KeyId:            aws.String(cfg.kmsKeyID),
			Message:          hashedSigningString,
			MessageType:      types.MessageType(messageTypeDigest),
			Signature:        formattedSig,
			SigningAlgorithm: m.algo,
		}

		verifyOutput, err := cfg.kmsClient.Verify(cfg.ctx, verifyInput)
		if err != nil {
			return err
		}

		if !verifyOutput.SignatureValid {
			return jwt.ErrSignatureInvalid
		}

		return nil
	}

	return m.localVerificationFunc(cfg, hashedSigningString, sig)
}

func (m *KMSSigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
	cfg, ok := keyConfig.(*Config)
	if !ok {
		_, isBuiltInEcdsa := keyConfig.(*ecdsa.PublicKey)
		if isBuiltInEcdsa {
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
		MessageType:      types.MessageType(messageTypeDigest),
		SigningAlgorithm: m.algo,
	}

	signOutput, err := cfg.kmsClient.Sign(cfg.ctx, signInput)
	if err != nil {
		return "", err
	}

	formatted, err := m.signatureSigFormatterFunc(signOutput.Signature)
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(formatted), nil
}
