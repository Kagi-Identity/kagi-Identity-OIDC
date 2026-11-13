# Security Policy

Kagi Identity is a security-sensitive authentication and identity provider. Do not disclose exploitable vulnerabilities in public issues or pull requests.

## Reporting a vulnerability

1. Prefer GitHub's **Private vulnerability reporting** for this repository, if enabled.
2. If private reporting is unavailable, contact the maintainer privately through their GitHub profile and request a secure disclosure channel.
3. Include the affected commit/version, impact, prerequisites, and a minimal reproduction where safe.
4. Never include real user data, production credentials, private keys, authorization codes, access/refresh tokens, or session cookies.

Please allow time for triage and coordinated remediation before publishing details. A report is not considered accepted until the maintainer confirms it.

## Deployment requirements

Before any deployment beyond local evaluation, review the [deployment guide](docs/DEPLOYMENT.md) and [configuration reference](docs/CONFIGURATION.md).

At minimum:

- Use HTTPS and align the issuer, browser origin, and WebAuthn RP ID.
- Disable demo-client seeding in production and deliberately choose the account-signup policy.
- Store administrative and registration tokens in a secret manager; rotate them if exposure is suspected.
- Keep Rust dependencies updated and review automated dependency updates before deployment.
- Keep edge/WAF request and body-size limits enabled. The application uses atomic PostgreSQL-backed rate-limit counters; configure a trusted proxy and exact `KAGI_CORS_ORIGINS` allowlist.
- Keep DPoP nonce enforcement enabled in production (`KAGI_DPOP_NONCE=1`) with a dedicated shared `KAGI_DPOP_NONCE_SECRET`, and verify the audit chain (`/admin/audit/verify`) on a schedule. Export NDJSON to append-only storage if the database is not trusted operationally.
- Protect database access, signing keys, backups, and restore credentials; test recovery procedures.
- Do not log tokens, authorization codes, session identifiers, or credential material.
- Run independent security review and the exact OAuth/OIDC/FAPI conformance tests relevant to the intended profile.

## Certification status

This project does **not** claim formal OAuth, OpenID Connect, WebAuthn, or FAPI certification. A passing unit test, integration test, or CI workflow is not a certification and is not by itself evidence that a deployment is production-ready.

## License

Kagi Identity is open source software licensed under the [MIT License](LICENSE). Security reports and responsible disclosure are welcome under the terms above.
