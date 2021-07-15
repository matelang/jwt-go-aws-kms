# AWS KMS adapter for dgrijalva/jwt-go library
This library provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library
[golang-jwt/jwt-go](https://github.com/golang-jwt/jwt).

It will *Sign* a JWT token using an assymetric key stored in AWS KMS.

Verification can be done both using KMS *Verify* method or locally with a cached public key (default).

# Supported key types
| Signature Algorithm       | JWT `alg` | Note                              |
|---------------------------|-----------|-----------------------------------|
| ECC_NIST_P256             | ES256     |                                   |
| ECC_NIST_P384             | ES384     |                                   |
| ECC_NIST_P521             | ES512     |                                   |
| ECC_SECG_P256K1           | -         | secp256k1 is not supported by JWT |
| ECC_NIST_P521             | ES512     |                                   |
| RSASSA_PKCS1_V1_5_SHA_256 | RS256     |                                   |
| RSASSA_PKCS1_V1_5_SHA_384 | RS384     |                                   |
| RSASSA_PKCS1_V1_5_SHA_512 | RS512     |                                   |

# Usage example
See [example.go](./example/example.go)

## Special thanks
Shouting out to:

* [dgrijalva](https://github.com/dgrijalva)

  for the easy to extend GoLang JWT Library

* [golang-jwt](https://github.com/golang-jwt)

  for taking over the project from dgrijalva

* [Mikael Gidmark](https://stackoverflow.com/users/300598/mikael-gidmark)

  AWS KMS ECC returns the signature in DER-encoded object as defined by ANS X9.62–2005 as
  mentioned [here](https://stackoverflow.com/a/66205185/8195214)

* [codelittinc](https://github.com/codelittinc)

  for their DER to (R,S) and (R,S) to DER methods
  found [here](https://github.com/codelittinc/gobitauth/blob/master/sign.go#L70)

* [karalabe](https://github.com/karalabe)

  for reviewing my code