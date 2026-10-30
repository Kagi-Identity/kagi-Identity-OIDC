# Kagi Identity

**Kagi Identity (Kagi ID)** is a passkey-first identity and authentication service built in Rust. It provides WebAuthn-based sign-in and OpenID Connect / OAuth endpoints for applications that need an identity provider.

> **Status and security note:** This repository is a reference implementation under active development. Passing its tests does not establish formal OAuth, OpenID Connect, FAPI, or WebAuthn certification. Do not use it as a production identity provider without profile-specific conformance testing, independent security review, and a deployment threat model.

## Get started in minutes

The fastest way to try Kagi Identity is Docker Compose. You need Docker Engine/Desktop with the Compose plugin.

```bash
docker compose up --build -d
docker compose logs -f kagi
```

Then open:

| What | URL |
| --- | --- |
| Identity home | [http://localhost:8080/](http://localhost:8080/) |
| Create a passkey account | [http://localhost:8080/signup](http://localhost:8080/signup) |
| Try the built-in demo app | [http://localhost:8080/demo](http://localhost:8080/demo) |
| OIDC discovery document | [http://localhost:8080/.well-known/openid-configuration](http://localhost:8080/.well-known/openid-configuration) |
| Public signing keys | [http://localhost:8080/jwks.json](http://localhost:8080/jwks.json) |

1. Open `/signup` and create an account with a passkey.
2. Open `/demo` and sign in to see the authorization-code flow.
3. Stop the service with `docker compose down`. Your local database and signing keys remain in the `kagi-data` volume.

To delete the local test database and keys as well, run `docker compose down --volumes`. This deletion is irreversible.

**This Compose configuration is for local evaluation only.** It uses HTTP, seeds a demo client, allows signup, and binds the published port to loopback. Never expose it as-is to the public internet.

### Run without Docker

Install the Rust toolchain required by `Cargo.toml`, then:

```bash
cp .env.example .env
set -a
. ./.env
set +a
cargo run
```

Open [http://localhost:8080](http://localhost:8080). The `.env` file is local configuration; do not commit secrets. On Windows, set environment variables in PowerShell or use WSL rather than sourcing the POSIX file.

For troubleshooting, configuration, and setup options, see the [Quickstart guide](docs/QUICKSTART.md).

## What it provides

| Area | Capabilities |
| --- | --- |
| Authentication | Passkey-first WebAuthn registration and sign-in |
| Authorization | Authorization Code flow, PKCE S256, state/nonce handling, consent, prompt controls |
| OAuth/OIDC | Discovery, JWKS, UserInfo, introspection, revocation, logout, dynamic client registration |
| Advanced profiles | PAR, DPoP, JAR, JARM and supported client authentication methods |
| Tokens | ES256-signed JWT access tokens, refresh-token rotation and reuse detection |
| Key lifecycle | Persistent signing keys, JWKS publication, administrative key rotation |
| Storage | SQLite by default; PostgreSQL/Supabase via `KAGI_DATABASE_URL` |
| Integration | Built-in demo RP and browser SDK at `/static/kagi.js` |
| Security controls | PKCE enforcement, exact redirect URI matching, CSRF protections, security headers, token hashing at rest |

Feature presence does not imply full normative compliance with every RFC or certification profile. Confirm actual behavior against the exact commit and configuration you deploy.

## Documentation

**[日本語ドキュメントサイト](https://kagi-docs-gakusei-bot.vercel.app)** — overview, quickstart, OIDC integration, deployment, security, and testing.

| Guide | Use it for |
| --- | --- |
| [Quickstart](docs/QUICKSTART.md) | First run with Docker Compose or Rust, troubleshooting |
| [Deployment](docs/DEPLOYMENT.md) | HTTPS, reverse proxies, secrets, storage, production checklist |
| [Client integration](docs/CLIENT_INTEGRATION.md) | Registering an RP and connecting a web app |
| [Configuration reference](docs/CONFIGURATION.md) | Environment variables and recommended baselines |
| [Testing](docs/TESTING.md) | Rust checks, E2E tests, security regression tests |
| [Security policy](SECURITY.md) | Vulnerability reporting and security expectations |

## Integration at a glance

For evaluation, the built-in SDK can initiate a login from a browser:

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });
  Kagi.login();
</script>
```

Register the exact callback URL first. For production applications, prefer a maintained OIDC client library and validate the protocol, token, and session behavior appropriate to your application. See [Client integration](docs/CLIENT_INTEGRATION.md).

## Configuration essentials

The most important values are:

- `KAGI_ISSUER`: public issuer origin, without a trailing slash.
- `KAGI_ORIGIN`: browser origin used for WebAuthn validation; usually the same as the issuer.
- `KAGI_RP_ID`: bare WebAuthn domain, with no scheme or port.
- `KAGI_DATABASE_URL`: optional PostgreSQL/Supabase connection string; when set, it takes precedence over `KAGI_DB`.
- `KAGI_SEED_DEMO`: enables the local demo RP; keep it disabled in production.
- `KAGI_ADMIN_TOKEN` and `KAGI_REGISTRATION_TOKEN`: administrative and client-registration secrets; keep them in a secret manager.

See the full [configuration reference](docs/CONFIGURATION.md). Keep the issuer, origin, RP ID, and browser-visible URL aligned or passkey ceremonies will fail.

## Run tests

```bash
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets
cargo build --release
```

For Python end-to-end and security regression tests, install `requirements-test.txt` and follow the isolated test setup in [Testing](docs/TESTING.md). Tests may seed records directly into their database: never point them at production data.

## Architecture and operational boundaries

- SQLite is convenient for local development. Vercel production requires PostgreSQL; shared records and rate-limit counters are stored there, while each warm function instance maintains a short-lived in-memory signing-key cache.
- Signing keys are persisted in the database in this implementation; database backups therefore contain sensitive key material. Encrypt and restrict backups.
- Production deployments use PostgreSQL-backed shared rate-limit counters and persisted OAuth/WebAuthn artifacts. Signing-key caches refresh across instances; use a managed pooler and load-test the deployment.
- Run behind HTTPS in production. Keep administrative endpoints private, limit request size and rate, and prevent secrets or tokens from entering logs.

For a deployment checklist, see [Deployment](docs/DEPLOYMENT.md). For security reports, follow [SECURITY.md](SECURITY.md).

## License

MIT
