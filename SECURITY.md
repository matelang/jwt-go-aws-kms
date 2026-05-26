# Security Policy

## Supported Versions

This module is published as `github.com/matelang/jwt-go-aws-kms/v2`. Security
fixes will be issued against the latest released `v2.x.y` tag. Older patch
versions will not be backported unless a maintainer explicitly indicates so on
a release.

| Version | Supported          |
|---------|--------------------|
| latest `v2.x.y` | :white_check_mark: |
| earlier `v2.x.y` | best-effort     |
| `v1.x.y`         | :x:             |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
<https://github.com/matelang/jwt-go-aws-kms/security/advisories/new>

If you cannot use that channel, email the maintainer at
798365+matelang@users.noreply.github.com with the subject prefix
`[jwt-go-aws-kms security]` and include:

- A description of the issue and its impact
- Steps to reproduce, ideally with a minimal Go program or test
- Affected version(s) / commit SHA
- Any mitigations or workarounds you have identified

You should expect an acknowledgement within **7 days**. Once a fix is ready a
GitHub Security Advisory will be published, the fix will be released as a new
`vX.Y.Z` tag, and credit will be given to the reporter unless they request
otherwise.

## Scope

In scope:

- Signature forgery, verification bypass, or panics triggered by attacker-
  controlled JWTs.
- Issues in the DER ↔ R‖S signature format conversion.
- Public-key cache correctness issues that could let a rotated/revoked key
  remain valid past its intended lifetime.
- Issues in the `mockkms` package that could mask incorrect behavior in real
  KMS deployments.

Out of scope:

- Vulnerabilities in AWS KMS itself or in the AWS SDK for Go.
- Issues that require attacker control over the application's KMS IAM policy,
  KMS key material, or process memory.
- Configuration mistakes by the consuming application (e.g. accepting `none`
  algorithm — that is a `golang-jwt/jwt` concern).
