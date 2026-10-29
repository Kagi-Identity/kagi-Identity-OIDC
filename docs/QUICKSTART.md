# Quickstart

This guide gets a local Kagi Identity instance running with a demo relying party. It is intended for development and evaluation only.

## Option A — Docker Compose (recommended)

Prerequisites: Docker Engine/Desktop with the Compose plugin.

From the repository root:

```bash
docker compose up --build -d
docker compose logs -f kagi
```

Open these URLs:

- [Kagi Identity](http://localhost:8080/)
- [Create an account](http://localhost:8080/signup)
- [Built-in relying-party demo](http://localhost:8080/demo)
- [OpenID Connect discovery](http://localhost:8080/.well-known/openid-configuration)
- [JSON Web Key Set](http://localhost:8080/jwks.json)

Create a passkey on the signup page using your device's screen lock, biometrics, or security key. Then open `/demo` and sign in. The local SQLite database and signing keys persist in the Docker volume named `kagi-data`.

Stop the server with:

```bash
docker compose down
```

This keeps the database volume. To remove the volume and **permanently delete local test data and signing keys**, use `docker compose down --volumes`.

### Local Compose settings

Compose defaults are intentionally suitable only for local evaluation: HTTP, loopback-only port publishing, demo client seeding, and open signup. Do not expose this configuration to the internet.

You can override values by creating a local `.env` file. Start from the template:

```bash
cp .env.example .env
```

Edit `.env` before restarting. Never commit `.env`; it may contain secrets.

## Option B — Run with Rust

Prerequisites: Rust stable (minimum version listed in `Cargo.toml`) and Cargo.

```bash
cp .env.example .env
# Keep the defaults for local development; review them before using the service elsewhere.
set -a
. ./.env
set +a
cargo run --locked
```

Open [http://localhost:8080](http://localhost:8080).

On PowerShell, set the environment variables in the current terminal instead of sourcing the POSIX `.env` file. For example:

```powershell
$env:KAGI_ISSUER = "http://localhost:8080"
$env:KAGI_RP_ID = "localhost"
$env:KAGI_ORIGIN = "http://localhost:8080"
$env:KAGI_SEED_DEMO = "1"
cargo run --locked
```

## Verify the service

```bash
curl --fail http://localhost:8080/.well-known/openid-configuration
curl --fail http://localhost:8080/jwks.json
```

The discovery document should return JSON with an issuer matching the URL you use to access the service. Keep the issuer consistent; `localhost` and `127.0.0.1` are different origins.

## Common issues

- **Passkey creation fails:** use `localhost` in the browser for local development. WebAuthn requires a secure context; ordinary HTTP on a LAN IP is not equivalent to localhost.
- **Issuer/origin mismatch:** set `KAGI_ISSUER` and `KAGI_ORIGIN` to the exact browser-visible origin, without a trailing slash. Set `KAGI_RP_ID` to the hostname only, without scheme or port.
- **Port 8080 is occupied:** change the Compose port mapping and all related issuer/origin values together. Do not change just one of them.
- **Demo page says the demo client is missing:** local Compose seeds it by default. For a manual run, set `KAGI_SEED_DEMO=1` before the first start.
- **Database reset needed:** stop the service first and back up anything you need. For Compose, `docker compose down --volumes` deletes the test volume and all data in it.

## Before using beyond local development

Read [Deployment](DEPLOYMENT.md), [Configuration](CONFIGURATION.md), and [Security Policy](../SECURITY.md). Do not reuse demo credentials, local HTTP settings, or a development database for production.
