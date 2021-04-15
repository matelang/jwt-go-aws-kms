package jwtkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/dgrijalva/jwt-go"
	"math/big"
)

// KmsEcdsaSigningMethod is an ECDSA implementation of the SigningMethod interface that uses KMS to Sign/Verify JWTs
type KmsEcdsaSigningMethod struct {
	name      string
	algo      string
	hash      crypto.Hash
	keySize   int
	curveBits int
}

func (m *KmsEcdsaSigningMethod) Alg() string {
	return m.name
}

func (m *KmsEcdsaSigningMethod) Verify(signingString, signature string, keyConfig interface{}) error {
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

	r := new(big.Int).SetBytes(sig[:m.keySize])
	s := new(big.Int).SetBytes(sig[m.keySize:])

	if cfg.VerifyWithKMS {
		return kmsVerifyEcdsa(cfg, m.algo, hashedSigningString, r, s)
	}

	return localVerifyEcdsa(cfg, hashedSigningString, r, s)
}

func (m *KmsEcdsaSigningMethod) Sign(signingString string, keyConfig interface{}) (string, error) {
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
		keyBytes += 1
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

	return jwt.EncodeSegment(out), nil
}

func kmsVerifyEcdsa(cfg *KmsConfig, algo string, hashedSigningString []byte, r *big.Int, s *big.Int) error {
	p := struct {
		R *big.Int
		S *big.Int
	}{r, s}

	derSig, err := asn1.Marshal(p)
	if err != nil {
		return err
	}

	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(cfg.KmsKeyId),
		Message:          hashedSigningString,
		MessageType:      aws.String(messageTypeDigest),
		Signature:        derSig,
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

func localVerifyEcdsa(cfg *KmsConfig, hashedSigningString []byte, r *big.Int, s *big.Int) error {
	var ecdsaPublicKey *ecdsa.PublicKey
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
