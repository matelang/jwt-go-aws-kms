// Package mockkms provides a partial implementation of AWS' KMS interface
// sufficient to satisfy the KMSClient interface.
package mockkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
)

// KeyType describes the type of a key.
type KeyType int

const (
	KeyTypeECCNISTP256 KeyType = iota
	KeyTypeECCNISTP384
	KeyTypeECCNISTP521
	KeyTypeRSA2048
)

// MockKMS implements the KMSClient interface backed by in-memory storage. It
// is safe for concurrent use.
type MockKMS struct {
	mu   sync.Mutex
	keys map[string]interface{}
}

// NewMockKMS constructs a new MockKMS instance.
func NewMockKMS() *MockKMS {
	return &MockKMS{
		keys: make(map[string]interface{}),
	}
}

// GenerateKey generates a key of the type described by kt and returns the
// KeyId which can be used by subsequent calls to refer to the generated key.
func (k *MockKMS) GenerateKey(kt KeyType) (string, error) {
	var err error
	var key interface{}
	switch kt {
	case KeyTypeECCNISTP256, KeyTypeECCNISTP384, KeyTypeECCNISTP521:
		key, err = generateECCKey(kt)

	case KeyTypeRSA2048:
		key, err = generateRSAKey(kt)

	default:
		return "", fmt.Errorf("unknown key type: %v", kt)
	}
	if err != nil {
		return "", fmt.Errorf("generating key: %w", err)
	}

	id := uuid.NewString()

	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[id] = key

	return id, nil
}

var keyTypeECCCurves = map[KeyType]elliptic.Curve{
	KeyTypeECCNISTP256: elliptic.P256(),
	KeyTypeECCNISTP384: elliptic.P384(),
	KeyTypeECCNISTP521: elliptic.P521(),
}

func generateECCKey(kt KeyType) (*ecdsa.PrivateKey, error) {
	pk, err := ecdsa.GenerateKey(keyTypeECCCurves[kt], rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return pk, nil
}

var keyTypeRSABits = map[KeyType]int{
	KeyTypeRSA2048: 2048,
}

func generateRSAKey(kt KeyType) (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, keyTypeRSABits[kt])
	if err != nil {
		return nil, fmt.Errorf("generating key: %v", err)
	}
	return pk, nil
}

func (k *MockKMS) getKey(id string) (interface{}, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[id]
	if !ok {
		return nil, fmt.Errorf("no such key: %v", id)
	}
	return key, nil
}

func (k *MockKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	key, err := k.getKey(*in.KeyId)
	if err != nil {
		return nil, err
	}

	if in.MessageType != types.MessageTypeDigest {
		return nil, fmt.Errorf("unsupported message type: %v", in.MessageType)
	}

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return signECSDA(key, in)

	case *rsa.PrivateKey:
		return signRSAorPSS(key, in)

	default:
		panic("unreachable")
	}
}

var ecdsaSigningAlgorithms = map[types.SigningAlgorithmSpec]bool{
	types.SigningAlgorithmSpecEcdsaSha256: true,
	types.SigningAlgorithmSpecEcdsaSha384: true,
	types.SigningAlgorithmSpecEcdsaSha512: true,
}

func signECSDA(key *ecdsa.PrivateKey, in *kms.SignInput) (*kms.SignOutput, error) {
	if !ecdsaSigningAlgorithms[in.SigningAlgorithm] {
		return nil, fmt.Errorf("unknowning signing algorithm: %v", in.SigningAlgorithm)
	}

	sig, err := key.Sign(rand.Reader, in.Message, nil)
	if err != nil {
		return nil, fmt.Errorf("signing message: %w", err)
	}

	return &kms.SignOutput{
		Signature: sig,
	}, nil
}

var rsaHashAlgorithms = map[types.SigningAlgorithmSpec]crypto.Hash{
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: crypto.SHA256,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha384: crypto.SHA384,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha512: crypto.SHA512,
}

var pssHashAlgorithms = map[types.SigningAlgorithmSpec]crypto.Hash{
	types.SigningAlgorithmSpecRsassaPssSha256: crypto.SHA256,
	types.SigningAlgorithmSpecRsassaPssSha384: crypto.SHA384,
	types.SigningAlgorithmSpecRsassaPssSha512: crypto.SHA512,
}

func signRSAorPSS(key *rsa.PrivateKey, in *kms.SignInput) (*kms.SignOutput, error) {
	// test if the algorithm is PSS, else use rss
	_, ok := pssHashAlgorithms[in.SigningAlgorithm]
	if ok {
		return signPSS(key, in)
	}

	return signRSA(key, in)
}

func signRSA(key *rsa.PrivateKey, in *kms.SignInput) (*kms.SignOutput, error) {
	hash, ok := rsaHashAlgorithms[in.SigningAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unknown signing algorithm: %v", in.SigningAlgorithm)
	}

	// PS 512 expect message to be hashed
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, in.Message)
	if err != nil {
		return nil, fmt.Errorf("signing message: %w", err)
	}

	return &kms.SignOutput{
		Signature: sig,
	}, nil
}

func signPSS(key *rsa.PrivateKey, in *kms.SignInput) (*kms.SignOutput, error) {
	hash, ok := pssHashAlgorithms[in.SigningAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unknown signing algorithm: %v", in.SigningAlgorithm)
	}

	sig, err := rsa.SignPSS(rand.Reader, key, hash, in.Message, &rsa.PSSOptions{})
	if err != nil {
		return nil, fmt.Errorf("signing message: %w", err)
	}

	return &kms.SignOutput{
		Signature: sig,
	}, nil
}

func (k *MockKMS) Verify(ctx context.Context, in *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	key, err := k.getKey(*in.KeyId)
	if err != nil {
		return nil, err
	}

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return &kms.VerifyOutput{
			SignatureValid: ecdsa.VerifyASN1(&key.PublicKey, in.Message, in.Signature),
		}, nil

	case *rsa.PrivateKey:
		return verifyRSA(key, in)

	default:
		panic("unreachable")
	}
}

func verifyRSA(key *rsa.PrivateKey, in *kms.VerifyInput) (*kms.VerifyOutput, error) {
	hash, ok := rsaHashAlgorithms[in.SigningAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unknown signing algorithm: %v", in.SigningAlgorithm)
	}

	err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, in.Message, in.Signature)

	return &kms.VerifyOutput{
		SignatureValid: err == nil,
	}, nil
}

func (k *MockKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	key, err := k.getKey(*in.KeyId)
	if err != nil {
		return nil, err
	}

	var public interface{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		public = &key.PublicKey

	case *rsa.PrivateKey:
		public = &key.PublicKey
	}

	m, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}

	return &kms.GetPublicKeyOutput{
		PublicKey: m,
	}, nil
}
