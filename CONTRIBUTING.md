# Contributing

Thanks for considering a contribution. This module signs JWTs with AWS KMS keys,
so changes are held to a high correctness and security bar.

## Local development

Required: Go 1.24 or newer (CI runs the matrix 1.24 → 1.26).

```bash
# Build everything
go build ./...

# Unit tests, race detector on
go test -race ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Lint (matches CI)
golangci-lint run ./...

# Vulnerability scan
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Fuzz the DER<->R||S converter (the riskiest code in the repo)
go test -run=- -fuzz=FuzzECDSAFormatterRoundTrip -fuzztime=2m ./jwtkms/
```

## Pull requests

- Keep changes focused. Crypto and JWT code is reviewed line-by-line; large
  drive-by refactors slow that down.
- Add tests for any new code path. Reach for fuzz tests when the input could
  be attacker-controlled (sign/verify byte parsing, public-key parsing).
- Run `go mod tidy` before submitting — CI fails if `go.mod`/`go.sum` aren't
  tidy.
- Update `README.md` if behavior or configuration knobs change.
- Mark behavior-affecting changes clearly in the PR description.

## Backward compatibility

This module has consumers using it in production JWT signing. Treat the public
API as stable:

- Do not change the `KMSClient` interface, `Config` constructors, or the
  exported `SigningMethod*` variables without a major version bump.
- New configuration is added as additional `Config` methods (see
  `WithContext`) or new package-level functions (see `SetPubKeyCacheTTL`).
- The default behavior of `verifyWithKMS=false` (forever-cache the public key)
  must remain unchanged so existing applications continue to work after an
  upgrade.

## Releases

Tags follow Go's [semantic import versioning](https://go.dev/ref/mod#versions).
New tags use the canonical `vX.Y.Z` format. See the *Versioning* section in
[README.md](README.md) for notes on historical tags.

Signed annotated tags are preferred (`git tag -as vX.Y.Z`).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.
