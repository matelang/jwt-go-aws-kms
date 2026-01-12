# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an AWS KMS (Key Management Service) adapter for the golang-jwt/jwt library. It provides custom JWT signing methods that use AWS KMS asymmetric keys for signing JWT tokens, with verification done either via KMS or locally using cached public keys.

## Development Commands

### Build
```bash
go build -v ./...
```

### Test
```bash
# Run all tests
go test -v ./...

# Run tests for a specific package
go test -v ./jwtkms

# Run a specific test
go test -v ./jwtkms -run TestSigningMethod
```

### Dependency Management
```bash
# Tidy dependencies
go mod tidy
```

## Architecture

### Core Components

**jwtkms.KMSSigningMethod** (`jwtkms/kms_signing_method.go`)
- Implements `jwt.SigningMethod` interface from golang-jwt/jwt
- Wraps standard JWT signing methods (ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512)
- Routes signing/verification to either AWS KMS or fallback to built-in golang-jwt methods
- Handles signature format conversion between KMS (DER-encoded for ECDSA) and JWT (R||S format)

**jwtkms.Config** (`jwtkms/common.go`)
- Configuration object passed as `keyConfig` to JWT signing/verification methods
- Contains: KMS client, key ID, context, and `verifyWithKMS` flag
- Use `NewKMSConfig()` to create, `WithContext()` to add context

**Public Key Cache** (`jwtkms/pubkey_cache.go`)
- Thread-safe in-memory cache of KMS public keys (maps key ID to crypto.PublicKey)
- Cache is permanent (no TTL or eviction) to avoid repeated KMS GetPublicKey calls
- Used during local verification when `verifyWithKMS=false`

**Registration System** (`jwtkms/init.go`)
- Auto-registers KMS signing methods with golang-jwt on package import via `init()`
- Replaces standard signing methods (ES256, RS256, etc.) with KMS-aware versions
- Maintains backward compatibility: if passed RSA/ECDSA public keys, delegates to standard methods

### Signature Format Conversion

**ECDSA signatures require format conversion:**
- AWS KMS returns ECDSA signatures in DER-encoded ASN.1 format
- JWT spec requires raw R||S format (concatenated big-endian byte arrays)
- `ecdsaSignerSigFormatter`: DER → R||S (after signing with KMS)
- `ecdsaVerificationSigFormatter`: R||S → DER (before verifying with KMS)
- RSA signatures (RS*/PS*) require no conversion

### Dual Verification Modes

**Local verification (default, `verifyWithKMS=false`):**
1. Calls `kmsClient.GetPublicKey()` on first verification
2. Caches public key in memory indefinitely
3. Uses standard golang-jwt verification with cached public key
4. More efficient for high-volume verification

**KMS verification (`verifyWithKMS=true`):**
1. Calls `kmsClient.Verify()` for every verification
2. No caching involved
3. Higher latency and cost, but avoids local key management

### Testing Strategy

Tests use `internal/mockkms` package which implements an in-memory KMS simulator. The mock generates real RSA/ECDSA keys and performs actual cryptographic operations without AWS API calls.

## Key Design Patterns

**Hijacking golang-jwt signing methods:**
The library registers its KMSSigningMethod instances as replacements for standard methods (e.g., ES256). When `jwt.SignedString()` is called, it routes through KMSSigningMethod which checks the keyConfig type:
- If `*jwtkms.Config`: use AWS KMS
- If `*rsa.PublicKey` or `*ecdsa.PublicKey`: delegate to original golang-jwt method

This allows backward compatibility and mixing KMS-signed tokens with standard RSA/ECDSA verification in the same codebase.

**KMSClient interface:**
The library defines a minimal `KMSClient` interface instead of requiring `*kms.Client`. This enables:
- Testing with mock implementations
- Custom KMS client wrappers
- Reduced coupling to AWS SDK

## Supported Algorithms

| AWS KMS Key Type          | JWT alg | Notes                             |
|---------------------------|---------|-----------------------------------|
| ECC_NIST_P256             | ES256   |                                   |
| ECC_NIST_P384             | ES384   |                                   |
| ECC_NIST_P521             | ES512   |                                   |
| RSASSA_PKCS1_V1_5_SHA_256 | RS256   |                                   |
| RSASSA_PKCS1_V1_5_SHA_384 | RS384   |                                   |
| RSASSA_PKCS1_V1_5_SHA_512 | RS512   |                                   |
| RSASSA_PSS_SHA_256        | PS256   |                                   |
| RSASSA_PSS_SHA_384        | PS384   |                                   |
| RSASSA_PSS_SHA_512        | PS512   |                                   |

Note: ECC_SECG_P256K1 (secp256k1) is not supported as it's not part of the JWT specification.
