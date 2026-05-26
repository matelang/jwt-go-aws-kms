# AWS KMS adapter for golang-jwt/jwt-go library

[![Go](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/go.yml/badge.svg)](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/go.yml)
[![Lint](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/lint.yml/badge.svg)](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/lint.yml)
[![Security](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/security.yml/badge.svg)](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/security.yml)
[![CodeQL](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/codeql.yml/badge.svg)](https://github.com/matelang/jwt-go-aws-kms/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/matelang/jwt-go-aws-kms/badge)](https://scorecard.dev/viewer/?uri=github.com/matelang/jwt-go-aws-kms)
[![Go Reference](https://pkg.go.dev/badge/github.com/matelang/jwt-go-aws-kms/v2.svg)](https://pkg.go.dev/github.com/matelang/jwt-go-aws-kms/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/matelang/jwt-go-aws-kms/v2)](https://goreportcard.com/report/github.com/matelang/jwt-go-aws-kms/v2)
[![License](https://img.shields.io/github/license/matelang/jwt-go-aws-kms)](LICENSE)

This library provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library
[golang-jwt/jwt-go](https://github.com/golang-jwt/jwt).

It will *Sign* a JWT token using an asymmetric key stored in AWS KMS.

Verification can be done both using KMS *Verify* method or locally with a cached public key (default).

# Supported key types
| Signature Algorithm       | JWT `alg` | Note                              |
|---------------------------|-----------|-----------------------------------|
| ECC_NIST_P256             | ES256     |                                   |
| ECC_NIST_P384             | ES384     |                                   |
| ECC_NIST_P521             | ES512     |                                   |
| ECC_SECG_P256K1           | -         | secp256k1 is not supported by JWT |
| RSASSA_PKCS1_V1_5_SHA_256 | RS256     |                                   |
| RSASSA_PKCS1_V1_5_SHA_384 | RS384     |                                   |
| RSASSA_PKCS1_V1_5_SHA_512 | RS512     |                                   |
| RSASSA_PSS_SHA_256        | PS256     |                                   |
| RSASSA_PSS_SHA_384        | PS384     |                                   |
| RSASSA_PSS_SHA_512        | PS512     |                                   |

# Usage example
See [example.go](./example/example.go)

# Public-key cache and KMS key rotation
When `verifyWithKMS=false` (the default), the first verification call fetches
the KMS key's public key via `GetPublicKey` and caches it in process memory.
Subsequent verifications use the cached key and standard `golang-jwt`
verification — no KMS calls. This is efficient for high-volume verification but
has an important caveat: **the cache has no TTL by default, so KMS-side key
rotations are not picked up until the process restarts**.

For deployments where keys can rotate, either:

1. Enable a TTL on the cache (recommended for most cases):
   ```go
   import "time"
   jwtkms.SetPubKeyCacheTTL(15 * time.Minute)
   ```
2. Call `jwtkms.ClearPubKeyCache()` explicitly when you know a rotation has
   occurred (e.g. from a CloudWatch / EventBridge handler).
3. Or set `verifyWithKMS=true` on the `Config` to have every verification hit
   KMS — always uses current key material, at the cost of latency and per-call
   billing.

# Security
Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

# Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow,
required checks, and backward-compatibility expectations.

# Installation
```bash
go get github.com/matelang/jwt-go-aws-kms/v2
```

# Versioning
This module follows [semantic import versioning](https://go.dev/ref/mod#major-version-suffixes)
and is published as `github.com/matelang/jwt-go-aws-kms/v2`.

Historical release tags (`2.0.0` through `2.2.0`) were published without the
leading `v` required by the Go [modules spec](https://go.dev/ref/mod#versions).
Those tags are intentionally preserved so that existing consumers (who pin via
pseudo-versions such as `v2.0.0-YYYYMMDDhhmmss-abcdef012345`) continue to
resolve. As a side effect, `go get github.com/matelang/jwt-go-aws-kms/v2@vX.Y.Z`
will not work against those legacy tags — use a pseudo-version or `@latest`
instead.

**Starting with the next release, all tags will use the canonical `vX.Y.Z`
format**, enabling normal version pinning:
```bash
go get github.com/matelang/jwt-go-aws-kms/v2@vX.Y.Z
```

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
  
* [gkelly](https://github.com/gkelly)

  for various contributions especially around the library's unit testability
