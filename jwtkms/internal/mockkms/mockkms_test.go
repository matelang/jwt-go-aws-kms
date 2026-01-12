package mockkms

import (
	"context"
	"crypto"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestNewMockKMS(t *testing.T) {
	mockKMS := NewMockKMS()
	if mockKMS == nil {
		t.Fatal("Expected NewMockKMS to return non-nil")
	}
	if mockKMS.keys == nil {
		t.Error("Expected keys map to be initialized")
	}
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		wantErr bool
	}{
		{"ECC P256", KeyTypeECCNISTP256, false},
		{"ECC P384", KeyTypeECCNISTP384, false},
		{"ECC P521", KeyTypeECCNISTP521, false},
		{"RSA 2048", KeyTypeRSA2048, false},
		{"Invalid key type", KeyType(999), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKMS := NewMockKMS()
			id, err := mockKMS.GenerateKey(tt.keyType)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error for invalid key type")
				}
				if !strings.Contains(err.Error(), "unknown key type") {
					t.Errorf("Expected 'unknown key type' error, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if id == "" {
				t.Error("Expected non-empty key ID")
			}

			// Verify key was stored
			key, err := mockKMS.getKey(id)
			if err != nil {
				t.Errorf("Key not found after generation: %v", err)
			}
			if key == nil {
				t.Error("Expected non-nil key")
			}
		})
	}
}

func TestGetKeyNonExistent(t *testing.T) {
	mockKMS := NewMockKMS()
	_, err := mockKMS.getKey("non-existent-key")
	if err == nil {
		t.Fatal("Expected error when getting non-existent key")
	}
	if !strings.Contains(err.Error(), "no such key") {
		t.Errorf("Expected 'no such key' error, got: %v", err)
	}
}

func TestSignECDSA(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		algorithm types.SigningAlgorithmSpec
	}{
		{"ES256", KeyTypeECCNISTP256, types.SigningAlgorithmSpecEcdsaSha256},
		{"ES384", KeyTypeECCNISTP384, types.SigningAlgorithmSpecEcdsaSha384},
		{"ES512", KeyTypeECCNISTP521, types.SigningAlgorithmSpecEcdsaSha512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKMS := NewMockKMS()
			id, err := mockKMS.GenerateKey(tt.keyType)
			if err != nil {
				t.Fatalf("Error generating key: %v", err)
			}

			message := []byte("test message digest")
			signInput := &kms.SignInput{
				KeyId:            aws.String(id),
				Message:          message,
				MessageType:      types.MessageTypeDigest,
				SigningAlgorithm: tt.algorithm,
			}

			signOutput, err := mockKMS.Sign(context.Background(), signInput)
			if err != nil {
				t.Fatalf("Error signing: %v", err)
			}
			if signOutput.Signature == nil || len(signOutput.Signature) == 0 {
				t.Error("Expected non-empty signature")
			}

			// Verify the signature
			verifyInput := &kms.VerifyInput{
				KeyId:            aws.String(id),
				Message:          message,
				Signature:        signOutput.Signature,
				SigningAlgorithm: tt.algorithm,
			}

			verifyOutput, err := mockKMS.Verify(context.Background(), verifyInput)
			if err != nil {
				t.Fatalf("Error verifying: %v", err)
			}
			if !verifyOutput.SignatureValid {
				t.Error("Expected signature to be valid")
			}
		})
	}
}

func TestSignRSAPKCS1(t *testing.T) {
	tests := []struct {
		name      string
		algorithm types.SigningAlgorithmSpec
		hash      crypto.Hash
	}{
		{"RS256", types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, crypto.SHA256},
		{"RS384", types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, crypto.SHA384},
		{"RS512", types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKMS := NewMockKMS()
			id, err := mockKMS.GenerateKey(KeyTypeRSA2048)
			if err != nil {
				t.Fatalf("Error generating key: %v", err)
			}

			// Hash the message
			hasher := tt.hash.New()
			hasher.Write([]byte("test message"))
			digest := hasher.Sum(nil)

			signInput := &kms.SignInput{
				KeyId:            aws.String(id),
				Message:          digest,
				MessageType:      types.MessageTypeDigest,
				SigningAlgorithm: tt.algorithm,
			}

			signOutput, err := mockKMS.Sign(context.Background(), signInput)
			if err != nil {
				t.Fatalf("Error signing: %v", err)
			}
			if signOutput.Signature == nil || len(signOutput.Signature) == 0 {
				t.Error("Expected non-empty signature")
			}

			// Verify the signature
			verifyInput := &kms.VerifyInput{
				KeyId:            aws.String(id),
				Message:          digest,
				Signature:        signOutput.Signature,
				SigningAlgorithm: tt.algorithm,
			}

			verifyOutput, err := mockKMS.Verify(context.Background(), verifyInput)
			if err != nil {
				t.Fatalf("Error verifying: %v", err)
			}
			if !verifyOutput.SignatureValid {
				t.Error("Expected signature to be valid")
			}
		})
	}
}

func TestSignRSAPSS(t *testing.T) {
	tests := []struct {
		name      string
		algorithm types.SigningAlgorithmSpec
		hash      crypto.Hash
	}{
		{"PS256", types.SigningAlgorithmSpecRsassaPssSha256, crypto.SHA256},
		{"PS384", types.SigningAlgorithmSpecRsassaPssSha384, crypto.SHA384},
		{"PS512", types.SigningAlgorithmSpecRsassaPssSha512, crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKMS := NewMockKMS()
			id, err := mockKMS.GenerateKey(KeyTypeRSA2048)
			if err != nil {
				t.Fatalf("Error generating key: %v", err)
			}

			// Hash the message
			hasher := tt.hash.New()
			hasher.Write([]byte("test message"))
			digest := hasher.Sum(nil)

			signInput := &kms.SignInput{
				KeyId:            aws.String(id),
				Message:          digest,
				MessageType:      types.MessageTypeDigest,
				SigningAlgorithm: tt.algorithm,
			}

			signOutput, err := mockKMS.Sign(context.Background(), signInput)
			if err != nil {
				t.Fatalf("Error signing: %v", err)
			}
			if signOutput.Signature == nil || len(signOutput.Signature) == 0 {
				t.Error("Expected non-empty signature")
			}

			// Verify the signature
			verifyInput := &kms.VerifyInput{
				KeyId:            aws.String(id),
				Message:          digest,
				Signature:        signOutput.Signature,
				SigningAlgorithm: tt.algorithm,
			}

			verifyOutput, err := mockKMS.Verify(context.Background(), verifyInput)
			if err != nil {
				t.Fatalf("Error verifying: %v", err)
			}
			if !verifyOutput.SignatureValid {
				t.Error("Expected signature to be valid")
			}
		})
	}
}

func TestSignWithUnsupportedAlgorithm(t *testing.T) {
	t.Run("ECDSA with unsupported algorithm", func(t *testing.T) {
		mockKMS := NewMockKMS()
		id, err := mockKMS.GenerateKey(KeyTypeECCNISTP256)
		if err != nil {
			t.Fatalf("Error generating key: %v", err)
		}

		signInput := &kms.SignInput{
			KeyId:            aws.String(id),
			Message:          []byte("test"),
			MessageType:      types.MessageTypeDigest,
			SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, // Wrong for ECDSA
		}

		_, err = mockKMS.Sign(context.Background(), signInput)
		if err == nil {
			t.Fatal("Expected error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "unknown signing algorithm") {
			t.Errorf("Expected 'unknown signing algorithm' error, got: %v", err)
		}
	})

	t.Run("RSA with unsupported algorithm", func(t *testing.T) {
		mockKMS := NewMockKMS()
		id, err := mockKMS.GenerateKey(KeyTypeRSA2048)
		if err != nil {
			t.Fatalf("Error generating key: %v", err)
		}

		signInput := &kms.SignInput{
			KeyId:            aws.String(id),
			Message:          []byte("test"),
			MessageType:      types.MessageTypeDigest,
			SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256, // Wrong for RSA
		}

		_, err = mockKMS.Sign(context.Background(), signInput)
		if err == nil {
			t.Fatal("Expected error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "unsupported signing algorithm") {
			t.Errorf("Expected 'unsupported signing algorithm' error, got: %v", err)
		}
	})
}

func TestSignWithUnsupportedMessageType(t *testing.T) {
	mockKMS := NewMockKMS()
	id, err := mockKMS.GenerateKey(KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(id),
		Message:          []byte("test"),
		MessageType:      types.MessageTypeRaw, // Not supported
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	}

	_, err = mockKMS.Sign(context.Background(), signInput)
	if err == nil {
		t.Fatal("Expected error for unsupported message type")
	}
	if !strings.Contains(err.Error(), "unsupported message type") {
		t.Errorf("Expected 'unsupported message type' error, got: %v", err)
	}
}

func TestVerifyWithInvalidSignature(t *testing.T) {
	mockKMS := NewMockKMS()
	id, err := mockKMS.GenerateKey(KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	message := []byte("test message digest")
	invalidSignature := []byte("invalid signature data")

	verifyInput := &kms.VerifyInput{
		KeyId:            aws.String(id),
		Message:          message,
		Signature:        invalidSignature,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	}

	verifyOutput, err := mockKMS.Verify(context.Background(), verifyInput)
	if err == nil && verifyOutput.SignatureValid {
		t.Error("Expected invalid signature to fail verification")
	}
}

func TestGetPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
	}{
		{"ECDSA P256", KeyTypeECCNISTP256},
		{"ECDSA P384", KeyTypeECCNISTP384},
		{"ECDSA P521", KeyTypeECCNISTP521},
		{"RSA 2048", KeyTypeRSA2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKMS := NewMockKMS()
			id, err := mockKMS.GenerateKey(tt.keyType)
			if err != nil {
				t.Fatalf("Error generating key: %v", err)
			}

			getPubKeyInput := &kms.GetPublicKeyInput{
				KeyId: aws.String(id),
			}

			output, err := mockKMS.GetPublicKey(context.Background(), getPubKeyInput)
			if err != nil {
				t.Fatalf("Error getting public key: %v", err)
			}
			if output.PublicKey == nil || len(output.PublicKey) == 0 {
				t.Error("Expected non-empty public key")
			}
		})
	}
}

func TestGetPublicKeyNonExistent(t *testing.T) {
	mockKMS := NewMockKMS()
	getPubKeyInput := &kms.GetPublicKeyInput{
		KeyId: aws.String("non-existent-key"),
	}

	_, err := mockKMS.GetPublicKey(context.Background(), getPubKeyInput)
	if err == nil {
		t.Fatal("Expected error when getting public key for non-existent key")
	}
	if !strings.Contains(err.Error(), "no such key") {
		t.Errorf("Expected 'no such key' error, got: %v", err)
	}
}
