package jwtkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms/internal/mockkms"
)

func TestSigningMethod(t *testing.T) {
	tests := []struct {
		name          string
		keyType       mockkms.KeyType
		signingMethod jwt.SigningMethod
	}{
		{
			name:          "ES256",
			keyType:       mockkms.KeyTypeECCNISTP256,
			signingMethod: SigningMethodECDSA256,
		},
		{
			name:          "ES384",
			keyType:       mockkms.KeyTypeECCNISTP384,
			signingMethod: SigningMethodECDSA384,
		},
		{
			name:          "ES512",
			keyType:       mockkms.KeyTypeECCNISTP521,
			signingMethod: SigningMethodECDSA512,
		},
		{
			name:          "RS256",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodRS256,
		},
		{
			name:          "RS384",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodRS384,
		},
		{
			name:          "RS512",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodRS512,
		},
		{
			name:          "PS256",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodPS256,
		},
		{
			name:          "PS384",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodPS384,
		},
		{
			name:          "PS512",
			keyType:       mockkms.KeyTypeRSA2048,
			signingMethod: SigningMethodPS512,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := jwt.NewWithClaims(test.signingMethod, &jwt.MapClaims{
				"claim": "value",
			})

			kms := mockkms.NewMockKMS()
			id, err := kms.GenerateKey(test.keyType)
			if err != nil {
				t.Fatalf("Error generating key: %v", err)
			}

			config := NewKMSConfig(kms, id, false)
			signed, err := token.SignedString(config)
			if err != nil {
				t.Fatalf("Error signing token: %v", err)
			}

			var claims jwt.MapClaims
			_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
				return NewKMSConfig(kms, id, false), nil
			})
			if err != nil {
				t.Fatalf("Error validating token offline: %v", err)
			}

			_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
				return NewKMSConfig(kms, id, true), nil
			})
			if err != nil {
				t.Fatalf("Error validating token online: %v", err)
			}
		})
	}
}

func TestConfigWithContext(t *testing.T) {
	kms := mockkms.NewMockKMS()
	id, err := kms.GenerateKey(mockkms.KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	config := NewKMSConfig(kms, id, false)
	if config.ctx != context.Background() {
		t.Error("Expected default context to be Background()")
	}

	customCtx := context.WithValue(context.Background(), "test", "value")
	configWithCtx := config.WithContext(customCtx)

	if configWithCtx.ctx != customCtx {
		t.Error("Expected context to be custom context")
	}

	// Verify original config is unchanged
	if config.ctx != context.Background() {
		t.Error("Expected original config context to remain unchanged")
	}

	// Verify other fields are copied
	if configWithCtx.kmsClient != config.kmsClient {
		t.Error("Expected kmsClient to be copied")
	}
	if configWithCtx.kmsKeyID != config.kmsKeyID {
		t.Error("Expected kmsKeyID to be copied")
	}
	if configWithCtx.verifyWithKMS != config.verifyWithKMS {
		t.Error("Expected verifyWithKMS to be copied")
	}
}

func TestSigningMethodWithInvalidKeyConfig(t *testing.T) {
	token := jwt.NewWithClaims(SigningMethodECDSA256, &jwt.MapClaims{
		"claim": "value",
	})

	// Test with invalid key config type (string)
	_, err := token.SignedString("invalid-key-config")
	if err == nil {
		t.Fatal("Expected error when signing with invalid key config")
	}
	if !strings.Contains(err.Error(), "key is of invalid type") {
		t.Errorf("Expected 'key is of invalid type' error, got: %v", err)
	}
}

func TestSigningMethodFallbackToStandardJWT(t *testing.T) {
	// Test ECDSA fallback - sign with private key, verify with public key
	t.Run("ECDSA fallback", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Error generating ECDSA key: %v", err)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.MapClaims{
			"claim": "value",
		})

		// Sign with pointer to the private key (golang-jwt expects *ecdsa.PrivateKey)
		signed, err := token.SignedString(ecdsaKey)
		if err != nil {
			t.Fatalf("Error signing token with ECDSA key: %v", err)
		}

		// Verify with public key
		var claims jwt.MapClaims
		_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
			return &ecdsaKey.PublicKey, nil
		})
		if err != nil {
			t.Fatalf("Error validating token with ECDSA public key: %v", err)
		}
	})

	// Test RSA fallback - sign with private key, verify with public key
	t.Run("RSA fallback", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Error generating RSA key: %v", err)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.MapClaims{
			"claim": "value",
		})

		// Sign with pointer to the private key (golang-jwt expects *rsa.PrivateKey)
		signed, err := token.SignedString(rsaKey)
		if err != nil {
			t.Fatalf("Error signing token with RSA key: %v", err)
		}

		// Verify with public key
		var claims jwt.MapClaims
		_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
			return &rsaKey.PublicKey, nil
		})
		if err != nil {
			t.Fatalf("Error validating token with RSA public key: %v", err)
		}
	})
}

func TestVerifyWithInvalidSignature(t *testing.T) {
	kms := mockkms.NewMockKMS()
	id, err := kms.GenerateKey(mockkms.KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	token := jwt.NewWithClaims(SigningMethodECDSA256, &jwt.MapClaims{
		"claim": "value",
	})

	config := NewKMSConfig(kms, id, false)
	signed, err := token.SignedString(config)
	if err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	// Tamper with the signature
	tamperedToken := signed[:len(signed)-10] + "tamperedXX"

	var claims jwt.MapClaims
	_, err = jwt.ParseWithClaims(tamperedToken, &claims, func(*jwt.Token) (interface{}, error) {
		return config, nil
	})
	if err == nil {
		t.Fatal("Expected error when verifying tampered token")
	}
}

func TestVerifyWithNonExistentKey(t *testing.T) {
	kms := mockkms.NewMockKMS()
	id, err := kms.GenerateKey(mockkms.KeyTypeECCNISTP256)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	token := jwt.NewWithClaims(SigningMethodECDSA256, &jwt.MapClaims{
		"claim": "value",
	})

	config := NewKMSConfig(kms, id, false)
	signed, err := token.SignedString(config)
	if err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	// Try to verify with a non-existent key
	badConfig := NewKMSConfig(kms, "non-existent-key-id", false)
	var claims jwt.MapClaims
	_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return badConfig, nil
	})
	if err == nil {
		t.Fatal("Expected error when verifying with non-existent key")
	}
	if !strings.Contains(err.Error(), "no such key") {
		t.Errorf("Expected 'no such key' error, got: %v", err)
	}
}

func TestAlgMethod(t *testing.T) {
	tests := []struct {
		name          string
		signingMethod *KMSSigningMethod
		expectedAlg   string
	}{
		{"ES256", SigningMethodECDSA256, "ES256"},
		{"ES384", SigningMethodECDSA384, "ES384"},
		{"ES512", SigningMethodECDSA512, "ES512"},
		{"RS256", SigningMethodRS256, "RS256"},
		{"RS384", SigningMethodRS384, "RS384"},
		{"RS512", SigningMethodRS512, "RS512"},
		{"PS256", SigningMethodPS256, "PS256"},
		{"PS384", SigningMethodPS384, "PS384"},
		{"PS512", SigningMethodPS512, "PS512"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if alg := test.signingMethod.Alg(); alg != test.expectedAlg {
				t.Errorf("Expected Alg() to return %s, got %s", test.expectedAlg, alg)
			}
		})
	}
}
