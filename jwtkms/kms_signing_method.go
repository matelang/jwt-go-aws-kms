package jwtkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"math/big"
)

type fallbackSigningMethodCompatibilityCheckerFunc func(keyConfig interface{}) bool
type sigFormatterFunc func(sig []byte) ([]byte, error)

var rsaPubKeyCheckerFunc = func(cfg interface{}) bool {
	_, isBuiltInRSA := cfg.(*rsa.PublicKey)
	return isBuiltInRSA
}

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

// KMSSigningMethod is a jwt.SigningMethod that uses AWS KMS to sign JWT tokens.
type KMSSigningMethod struct {
	algo types.SigningAlgorithmSpec
	hash crypto.Hash

	fallbackSigningMethod                     jwt.SigningMethod
	fallbackSigningMethodKeyConfigCheckerFunc fallbackSigningMethodCompatibilityCheckerFunc

	preVerificationSigFormatterFunc sigFormatterFunc
	postSignatureSigFormatterFunc   sigFormatterFunc
}

func (m *KMSSigningMethod) Alg() string {
	return m.fallbackSigningMethod.Alg()
}

func (m *KMSSigningMethod) Verify(signingString string, signature string, keyConfig interface{}) error {
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

	return m.fallbackSigningMethod.Verify(signingString, signature, cachedKey)
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
