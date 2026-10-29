# Security Policy

Kagi Identity is a security-sensitive authentication and identity provider. Please do not report exploitable vulnerabilities in public issues or pull requests.

## Reporting a vulnerability

- Prefer GitHub's **Private vulnerability reporting** for this repository, if enabled.
- If private reporting is unavailable, contact the repository maintainer privately through their GitHub profile and request a secure disclosure channel.
- Include the affected commit or version, impact, prerequisites, and a minimal reproduction where safe.
- Do not include real user data, live credentials, private keys, or production tokens in a report.

Please allow time for triage and a coordinated fix before publishing details. Do not assume a report is accepted as a vulnerability until the maintainer confirms it.

## Deployment guidance

- Use HTTPS in production and keep issuer, origin, and WebAuthn RP ID aligned.
- Store admin and registration tokens in a secret manager; rotate them if exposure is suspected.
- Keep Rust dependencies updated and review automated dependency updates before deployment.
- Use a shared edge/WAF rate limit when running multiple instances.
- Back up signing keys and the database securely, and test recovery procedures.
- This project does not claim formal OAuth, OpenID Connect, or FAPI certification. Run independent security review and conformance testing before production use.
