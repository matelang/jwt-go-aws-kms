package jwtkms

import (
	"crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

type fallbackSigningMethodCompatibilityCheckerFunc func(keyConfig interface{}) bool
type sigFormatterFunc func(sig []byte) ([]byte, error)

// KMSSigningMethod is a ...
type KMSSigningMethod struct {
	algo types.SigningAlgorithmSpec
	hash crypto.Hash

	fallbackSigningMethod                     jwt.SigningMethod
	fallbackSigningMethodKeyConfigCheckerFunc fallbackSigningMethodCompatibilityCheckerFunc

	preVerificationSigFormatterFunc sigFormatterFunc
	postSignatureSigFormatterFunc   sigFormatterFunc

	localVerificationFunc func(cfg *Config, hashedSigningString []byte, sig []byte) error
}

func (m *KMSSigningMethod) Alg() string {
	return m.fallbackSigningMethod.Alg()
}

func (m *KMSSigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
	// Expecting a jwtkms.Config as the keyConfig to use AWS KMS to Verify tokens.
	cfg, ok := keyConfig.(*Config)

	// To keep compatibility with the golang-jwt library and since we've hijacked the flow on the signing method,
	// we check whether the keyConfig is for the expected underlying jwt.SigningMethod and proxy the call accordingly.
	if !ok {
		keyConfigIsForFallbackSigningMethod := m.fallbackSigningMethodKeyConfigCheckerFunc(keyConfig)

		if keyConfigIsForFallbackSigningMethod {
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
		if m.preVerificationSigFormatterFunc != nil {
			formattedSig, err = m.preVerificationSigFormatterFunc(sig)
			if err != nil {
				return err
			}
		}

		verifyInput := &kms.VerifyInput{
			KeyId:            aws.String(cfg.kmsKeyID),
			Message:          hashedSigningString,
			MessageType:      types.MessageTypeDigest,
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
	// Expecting a jwtkms.Config as the keyConfig to use AWS KMS to Sign tokens.
	cfg, ok := keyConfig.(*Config)

	// To keep compatibility with the golang-jwt library and since we've hijacked the flow on the signing method,
	// we check whether the keyConfig is for the expected underlying jwt.SigningMethod and proxy the call accordingly.
	if !ok {
		keyConfigIsForFallbackSigningMethod := m.fallbackSigningMethodKeyConfigCheckerFunc(keyConfig)

		if keyConfigIsForFallbackSigningMethod {
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
		SigningAlgorithm: m.algo,
	}

	signOutput, err := cfg.kmsClient.Sign(cfg.ctx, signInput)
	if err != nil {
		return "", err
	}

	formattedSig := signOutput.Signature
	if m.postSignatureSigFormatterFunc != nil {
		formattedSig, err = m.postSignatureSigFormatterFunc(signOutput.Signature)
		if err != nil {
			return "", err
		}
	}

	return jwt.EncodeSegment(formattedSig), nil
}
