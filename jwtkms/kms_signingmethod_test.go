package jwtkms

import (
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
