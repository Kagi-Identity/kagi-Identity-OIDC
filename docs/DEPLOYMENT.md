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

## 2. Self-hosted Docker deployment

The repository includes a production Compose template for a Linux host with Docker Engine and Compose. It runs Kagi as a non-root, read-only container behind Caddy, which obtains and renews HTTPS certificates automatically. PostgreSQL is intentionally external: use a managed PostgreSQL service or a separately operated database with TLS, backups, monitoring, and restricted network access.

1. Point the identity hostname (for example, `identity.example.com`) at the Docker host. Allow inbound TCP ports 80 and 443; UDP 443 is optional for HTTP/3.
2. Create a database and a least-privilege account. Set `KAGI_DATABASE_URL` to a TLS-enabled PostgreSQL URL reachable from the host.
3. Apply the schema once, before starting Kagi:

   ```bash
   read -r -s -p "PostgreSQL TLS URL: " KAGI_DATABASE_URL
   echo
   export KAGI_DATABASE_URL
   psql "$KAGI_DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/schema.sql
   unset KAGI_DATABASE_URL
   ```

   Use a secret manager or protected shell environment for the URL. Do not paste it into a command literal that will be saved in shell history.
4. Copy `.env.production.example` to `.env.production`. Replace the domain, email, database URL, relying-party origins, and both random secrets. Generate the secrets separately with `openssl rand -base64 48`. Keep `.env.production` out of version control.
5. Check the rendered deployment configuration and start the stack:

   ```bash
   docker compose --env-file .env.production -f compose.production.yaml config --quiet
   docker compose --env-file .env.production -f compose.production.yaml up --build -d
   docker compose --env-file .env.production -f compose.production.yaml ps
   docker compose --env-file .env.production -f compose.production.yaml logs -f kagi caddy
   ```
6. Verify the HTTPS endpoints:

   ```bash
   curl --fail https://identity.example.com/healthz
   curl --fail https://identity.example.com/.well-known/openid-configuration
   curl --fail https://identity.example.com/jwks.json
   ```

   The discovery document's `issuer` must exactly match `KAGI_ISSUER`.

The production stack exposes only Caddy on the host. Kagi is reachable on the private Compose network, runs as UID 10001, drops Linux capabilities, uses a read-only root filesystem, and has a database-backed readiness check. Caddy overwrites the forwarding headers used by Kagi's trusted-proxy rate limiter.

To update, pull/review the intended source revision, back up PostgreSQL and the Caddy data volume, then rebuild with the same Compose command. Apply any future schema migration as a controlled one-off operation before rolling out application instances. Do not enable automatic schema migration during concurrent production starts.

The example uses an external PostgreSQL service on purpose; it does not install, secure, back up, or monitor a database for you. A ready container is not proof of an operationally safe identity service. Configure database backups and restore drills, secret rotation, alerting, rate/connection limits, and an incident-response process.

## 3. Required identity settings

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
KAGI_DPOP_NONCE=1
KAGI_DPOP_NONCE_SECRET=retrieve-from-secret-manager
KAGI_RATE_LIMIT=1
KAGI_TRUST_PROXY=1
KAGI_CORS_ORIGINS=https://your-rp.example.com
```

Replace every example with your real deployment values. `KAGI_ISSUER` and `KAGI_ORIGIN` are origins, not URLs with a path, query, fragment, or trailing slash. `KAGI_RP_ID` is the host/domain only (no scheme or port). WebAuthn passkeys will fail if the RP ID and browser origin are inconsistent.

`KAGI_REQUIRE_PAR=1` and `KAGI_REQUIRE_DPOP=1` enable stricter request handling; they do not prove FAPI 2.0 compliance. Validate every relying party's supported flow before enabling these settings.

## 4. Any OCI-compatible container platform

The same `Dockerfile` builds a portable OCI image. Build it in CI or on a trusted build host, publish it to your private container registry, and deploy it to a platform that can run containers. Configure the platform ingress to terminate HTTPS and forward to container port `8080`; do not expose the Kagi container directly to the public internet.

Set the required production variables described in [Configuration](CONFIGURATION.md), including `KAGI_ENV=production`, `KAGI_BIND=0.0.0.0:8080`, a TLS-enabled PostgreSQL URL, exact issuer/origin/RP ID values, separate strong administration/registration secrets, and a shared 32+ character `KAGI_DPOP_NONCE_SECRET`. Apply `supabase/schema.sql` as a one-off migration before the first rollout. Configure the platform readiness probe as `GET /healthz`; this endpoint checks the database and signing-key tables, not merely process liveness.

Set `KAGI_TRUST_PROXY=1` only when the platform's trusted ingress overwrites `X-Forwarded-For`. If it does not, keep Kagi private and use a proxy configuration that sanitizes forwarded headers before enabling this option. Keep the application port private, persist the external database, and configure backup/restore, secret rotation, monitoring, and rolling-deploy behavior in the platform.

## 5. Vercel Rust Runtime

For Vercel, the repository uses the official Rust Runtime with an Axum adapter in `api/index.rs`. All HTTP paths are rewritten to the same Axum router. Do not run the local `TcpListener` server as a Vercel Function.

Vercel production startup fails closed unless PostgreSQL is configured, the issuer and WebAuthn origin are HTTPS and identical, Secure cookies and HSTS are enabled, demo seeding is disabled, PAR is required, the trusted proxy setting is enabled, an exact HTTPS CORS allowlist is present, and strong admin/registration tokens are configured. Set these values in Vercel Project Settings → Environment Variables; never commit actual credentials.

Example Vercel settings:

```dotenv
KAGI_ISSUER=https://your-identity-domain.example
KAGI_ORIGIN=https://your-identity-domain.example
KAGI_RP_ID=your-identity-domain.example
KAGI_DATABASE_URL=<TLS-enabled PostgreSQL pooler URL>
KAGI_AUTO_MIGRATE=0
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

Before deploying, apply `supabase/schema.sql` once using your database's migration workflow, then set `KAGI_AUTO_MIGRATE=0`. This avoids concurrent DDL races when multiple serverless instances cold-start. Each warm function instance currently maintains one serialized database connection; use a managed PostgreSQL pooler for serverless connection limits and load-test before production traffic.

## 6. Secrets

Generate high-entropy values outside source control. For example, on a machine with OpenSSL:

```bash
openssl rand -base64 48
```

Use separate values for `KAGI_ADMIN_TOKEN` and `KAGI_REGISTRATION_TOKEN`. Store them in a secret manager, limit access, rotate after suspected exposure, and never paste them into issues, chat logs, or source code.

- `KAGI_ADMIN_TOKEN` protects administrative key rotation.
- `KAGI_REGISTRATION_TOKEN` gates dynamic client registration.
- Do not enable either endpoint with a known or short placeholder token.
- Keep secrets out of logs, crash reports, CI output, and shell history where practical.

## 7. Storage and key protection

SQLite is convenient for local development and single-node deployments. For PostgreSQL/Supabase, set `KAGI_DATABASE_URL` to a private TLS-enabled connection string. Keep the database inaccessible to public clients; use a least-privilege database account where supported.

Signing keys are persisted in the database in this implementation. Consequently, database backups contain sensitive key material. Encrypt backups, restrict restore permissions, test recovery, and define retention. Consider external KMS/HSM-backed key custody before high-assurance production use.

PostgreSQL stores sessions, authorization codes, flows, refresh/access-token state, signing keys, DPoP replay entries, and shared rate-limit counters. Each instance caches its signing-key ring briefly and refreshes it every five seconds to converge after rotation. The database connection itself is serialized within each warm instance; use a pooler and load-test. This is multi-instance-capable, but it is not a claim of unlimited horizontal scalability or zero-downtime failover.

## 8. Suggested rollout

1. Configure the public origin, RP ID, TLS, and secret management.
2. Disable demo seeding and decide whether self-signup is appropriate.
3. Register one test client with exact redirect URI matches.
4. Run unit and integration tests in an isolated environment.
5. Run profile-specific OAuth/OIDC conformance tests and an independent security review.
6. Test backup restoration, signing-key rotation, incident response, and log redaction.
7. Monitor authentication failures, rate limiting, database health, and key-rotation events.
8. Roll out to a small set of test clients before general availability.

## 9. Pre-launch checklist

- [ ] HTTPS is enforced end-to-end; HTTP redirects and proxy behavior are reviewed.
- [ ] Issuer, WebAuthn origin, and RP ID are aligned.
- [ ] `KAGI_SEED_DEMO=0` and signup policy is deliberate.
- [ ] Administrative and registration tokens are strong, private, and separately managed.
- [ ] Rate limiting and body-size limits are enforced at a trusted edge.
- [ ] Database access, backups, restore tests, and key material are protected.
- [ ] Log output excludes authorization codes, access/refresh tokens, session IDs, and credential material.
- [ ] OAuth/OIDC/FAPI conformance and independent security reviews have been completed for the exact intended profile.
- [ ] Rollback and incident-response procedures have been rehearsed.
