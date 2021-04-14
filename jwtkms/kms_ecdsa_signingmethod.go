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

	r := big.NewInt(0).SetBytes(sig[:m.keySize])
	s := big.NewInt(0).SetBytes(sig[m.keySize:])

	if cfg.VerifyWithKMS {
		return kmsVerifyEcdsa(cfg, m.algo, hashedSigningString, r, s)
	} else {
		return localVerifyEcdsa(cfg, hashedSigningString, r, s)
	}
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

	r, s := pointsFromDER(signOutput.Signature)

	curveBits := m.curveBits
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return jwt.EncodeSegment(out), nil
}

func kmsVerifyEcdsa(cfg *KmsConfig, algo string, hashedSigningString []byte, r *big.Int, s *big.Int) error {
	derSig := pointsToDER(r, s)

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

// From https://github.com/codelittinc/gobitauth/blob/master/sign.go
// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
func pointsToDER(r, s *big.Int) []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs
	prefixPoint := func(b []byte) []byte {
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			paddedBytes := make([]byte, len(b)+1)
			copy(paddedBytes[1:], b)
			b = paddedBytes
		}
		return b
	}

	rb := prefixPoint(r.Bytes())
	sb := prefixPoint(s.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	return der
}

// From https://github.com/codelittinc/gobitauth/blob/master/sign.go
// Modified in order not to hex encode before returning since we don't need it
func pointsFromDER(der []byte) (R, S *big.Int) {
	R, S = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	if _, err := asn1.Unmarshal(der, &data); err != nil {
		panic(err.Error())
	}

	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := data.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := data.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := data.Bytes[rLen+4:]

	R.SetBytes(r)
	S.SetBytes(s)

	return
}
