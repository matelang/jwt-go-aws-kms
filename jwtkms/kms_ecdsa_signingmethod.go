package jwtkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

// ECDSASigningMethod is an ECDSA implementation of the SigningMethod interface that uses KMS to Sign/Verify JWTs.
type ECDSASigningMethod struct {
	name                  string
	algo                  string
	hash                  crypto.Hash
	keySize               int
	curveBits             int
	fallbackSigningMethod *jwt.SigningMethodECDSA
}

func (m *ECDSASigningMethod) Alg() string {
	return m.name
}

func (m *ECDSASigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
	cfg, ok := keyConfig.(*Config)
	if !ok {
		_, isBuiltInECDSA := keyConfig.(*ecdsa.PublicKey)
		if isBuiltInECDSA {
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

	r := new(big.Int).SetBytes(sig[:m.keySize])
	s := new(big.Int).SetBytes(sig[m.keySize:])

	if cfg.verifyWithKMS {
		return verifyECDSA(cfg, m.algo, hashedSigningString, r, s)
	}

	return localVerifyECDSA(cfg, hashedSigningString, r, s)
}

func (m *ECDSASigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
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
		SigningAlgorithm: types.SigningAlgorithmSpec(m.algo),
	}

	signOutput, err := cfg.kmsClient.Sign(cfg.ctx, signInput)
	if err != nil {
		return "", err
	}

	p := struct {
		R *big.Int
		S *big.Int
	}{}

	_, err = asn1.Unmarshal(signOutput.Signature, &p)
	if err != nil {
		return "", err
	}

	curveBits := m.curveBits
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	// We serialize the outputs (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := p.R.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := p.S.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return jwt.EncodeSegment(out), nil
}

func verifyECDSA(cfg *Config, algo string, hashedSigningString []byte, r *big.Int, s *big.Int) error {
	p := struct {
		R *big.Int
		S *big.Int
	}{r, s}

	derSig, err := asn1.Marshal(p)
	if err != nil {
		return err
	}

	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(cfg.kmsKeyID),
		Message:          hashedSigningString,
		MessageType:      types.MessageType(messageTypeDigest),
		Signature:        derSig,
		SigningAlgorithm: types.SigningAlgorithmSpec(algo),
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

func localVerifyECDSA(cfg *Config, hashedSigningString []byte, r *big.Int, s *big.Int) error {
	var ecdsaPublicKey *ecdsa.PublicKey

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
