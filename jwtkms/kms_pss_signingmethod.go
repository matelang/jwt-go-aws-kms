package jwtkms

import (
	"github.com/golang-jwt/jwt/v4"
)

// RSASigningMethod is an RSA implementation of the SigningMethod interface that uses KMS to Sign/Verify JWTs.
// PS uses the same key as RSA but differ in the algo
type PSSSigningMethod struct {
	RSASigningMethod
	fallbackSigningMethod *jwt.SigningMethodRSAPSS
}
