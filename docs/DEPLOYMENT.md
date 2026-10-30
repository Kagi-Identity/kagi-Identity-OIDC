# Deployment guide

This guide is a checklist for operators. Kagi Identity is a security-sensitive reference implementation; it is not certified as OAuth, OpenID Connect, or FAPI conformant. A successful build does not replace threat modeling, independent review, or profile-specific conformance testing.

## 1. Production architecture

A typical deployment is:

1. Public HTTPS reverse proxy / load balancer
2. Kagi Identity bound to a private interface or private container network
3. Persistent database and protected backups
4. Centralized secret storage and monitoring

Terminate TLS at a maintained reverse proxy. Ensure the proxy overwrites forwarded headers rather than accepting client-supplied values. Only enable `KAGI_TRUST_PROXY=1` when the service is reachable exclusively through a trusted proxy configured to overwrite `X-Forwarded-For`.

Do not publish the Kagi port directly to the internet. Apply request/body-size limits and timeouts at the edge. The application also uses atomic PostgreSQL-backed rate-limit counters so enforcement is shared across independently scaled function instances. The forwarded client IP is trusted only when `KAGI_TRUST_PROXY=1`; enable it only behind the Vercel proxy or another proxy that overwrites `X-Forwarded-For`.

## 2. Required identity settings

Choose one public origin and use it consistently. Example values below are placeholders:

```dotenv
KAGI_ISSUER=https://id.example.com
KAGI_ORIGIN=https://id.example.com
KAGI_RP_ID=example.com
KAGI_RP_NAME=Example Identity
KAGI_BIND=127.0.0.1:8080
KAGI_COOKIE_SECURE=1
KAGI_HSTS=1
KAGI_SEED_DEMO=0
KAGI_ALLOW_SIGNUP=0
KAGI_REQUIRE_PAR=1
KAGI_REQUIRE_DPOP=1
KAGI_RATE_LIMIT=1
KAGI_TRUST_PROXY=1
KAGI_CORS_ORIGINS=https://your-rp.example.com
```

Replace every example with your real deployment values. `KAGI_ISSUER` and `KAGI_ORIGIN` are origins, not URLs with a path, query, fragment, or trailing slash. `KAGI_RP_ID` is the host/domain only (no scheme or port). WebAuthn passkeys will fail if the RP ID and browser origin are inconsistent.

`KAGI_REQUIRE_PAR=1` and `KAGI_REQUIRE_DPOP=1` enable stricter request handling; they do not prove FAPI 2.0 compliance. Validate every relying party's supported flow before enabling these settings.

## 3. Vercel Rust Runtime

For Vercel, the repository uses the official Rust Runtime with an Axum adapter in `api/index.rs`. All HTTP paths are rewritten to the same Axum router. Do not run the local `TcpListener` server as a Vercel Function.

Vercel production startup fails closed unless PostgreSQL is configured, the issuer and WebAuthn origin are HTTPS and identical, Secure cookies and HSTS are enabled, demo seeding is disabled, PAR is required, the trusted proxy setting is enabled, an exact HTTPS CORS allowlist is present, and strong admin/registration tokens are configured. Set these values in Vercel Project Settings → Environment Variables; never commit actual credentials.

Example Vercel settings:

```dotenv
KAGI_ISSUER=https://your-identity-domain.example
KAGI_ORIGIN=https://your-identity-domain.example
KAGI_RP_ID=your-identity-domain.example
KAGI_DATABASE_URL=<TLS-enabled PostgreSQL pooler URL>
KAGI_COOKIE_SECURE=1
KAGI_HSTS=1
KAGI_SEED_DEMO=0
KAGI_REQUIRE_PAR=1
KAGI_TRUST_PROXY=1
KAGI_RATE_LIMIT=1
KAGI_CORS_ORIGINS=https://your-rp.example.com
KAGI_ADMIN_TOKEN=<random secret, 32+ characters>
KAGI_REGISTRATION_TOKEN=<different random secret, 32+ characters>
```

Use a managed PostgreSQL pooler for serverless connection limits. Each warm function instance currently maintains one serialized database connection; this is safe for correctness but is not a high-throughput connection pool. Validate provider connection limits and load-test before production traffic.

## 4. Secrets

Generate high-entropy values outside source control. For example, on a machine with OpenSSL:

```bash
openssl rand -base64 48
```

Use separate values for `KAGI_ADMIN_TOKEN` and `KAGI_REGISTRATION_TOKEN`. Store them in a secret manager, limit access, rotate after suspected exposure, and never paste them into issues, chat logs, or source code.

- `KAGI_ADMIN_TOKEN` protects administrative key rotation.
- `KAGI_REGISTRATION_TOKEN` gates dynamic client registration.
- Do not enable either endpoint with a known or short placeholder token.
- Keep secrets out of logs, crash reports, CI output, and shell history where practical.

## 5. Storage and key protection

SQLite is convenient for local development and single-node deployments. For PostgreSQL/Supabase, set `KAGI_DATABASE_URL` to a private TLS-enabled connection string. Keep the database inaccessible to public clients; use a least-privilege database account where supported.

Signing keys are persisted in the database in this implementation. Consequently, database backups contain sensitive key material. Encrypt backups, restrict restore permissions, test recovery, and define retention. Consider external KMS/HSM-backed key custody before high-assurance production use.

PostgreSQL stores sessions, authorization codes, flows, refresh/access-token state, signing keys, DPoP replay entries, and shared rate-limit counters. Each instance caches its signing-key ring briefly and refreshes it every five seconds to converge after rotation. The database connection itself is serialized within each warm instance; use a pooler and load-test. This is multi-instance-capable, but it is not a claim of unlimited horizontal scalability or zero-downtime failover.

## 6. Suggested rollout

1. Configure the public origin, RP ID, TLS, and secret management.
2. Disable demo seeding and decide whether self-signup is appropriate.
3. Register one test client with exact redirect URI matches.
4. Run unit and integration tests in an isolated environment.
5. Run profile-specific OAuth/OIDC conformance tests and an independent security review.
6. Test backup restoration, signing-key rotation, incident response, and log redaction.
7. Monitor authentication failures, rate limiting, database health, and key-rotation events.
8. Roll out to a small set of test clients before general availability.

## 7. Pre-launch checklist

- [ ] HTTPS is enforced end-to-end; HTTP redirects and proxy behavior are reviewed.
- [ ] Issuer, WebAuthn origin, and RP ID are aligned.
- [ ] `KAGI_SEED_DEMO=0` and signup policy is deliberate.
- [ ] Administrative and registration tokens are strong, private, and separately managed.
- [ ] Rate limiting and body-size limits are enforced at a trusted edge.
- [ ] Database access, backups, restore tests, and key material are protected.
- [ ] Log output excludes authorization codes, access/refresh tokens, session IDs, and credential material.
- [ ] OAuth/OIDC/FAPI conformance and independent security reviews have been completed for the exact intended profile.
- [ ] Rollback and incident-response procedures have been rehearsed.
