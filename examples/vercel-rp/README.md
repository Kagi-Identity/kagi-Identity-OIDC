# Kagi Identity — Vercel RP Demo

A minimal, static relying-party (RP) integration playground for Kagi Identity.

## What it checks

- OIDC discovery endpoint returns JSON.
- The discovered `issuer` exactly matches the configured issuer.
- The JWKS endpoint returns at least one public key.
- The browser SDK at `/static/kagi.js` can be loaded.
- A manual Authorization Code + PKCE login entry point and callback page.

## Deploy

This folder is intended to be a separate Vercel project root:

- Framework preset: **Other**
- Root Directory: `examples/vercel-rp`
- Build Command: leave empty
- Output Directory: leave empty / project root (static files)
- Install Command: leave empty

The RP demo does not host the identity provider itself. Kagi Identity needs a compatible long-running server runtime and durable shared storage (PostgreSQL for hosted deployments). Vercel's current `kagi` project build is marked READY, but its runtime logs show that the Rust server exits on startup when it cannot open the default SQLite database. A READY build alone is not a successful runtime health check.

## Configure and test

1. Open the deployed demo and set the HTTPS issuer.
2. Click **接続をテスト**. It checks discovery, issuer equality, JWKS, and the SDK fetch.
3. Register the exact callback URL shown by the page in Kagi Identity.
4. Enter the registered client ID and click **Identity でログイン**.
5. Verify the callback, then validate tokens server-side for any real application.

The seeded `demo-web` client is only registered for local development callback URLs; it will not work from a hosted Vercel domain unless that exact callback is registered. Do not treat browser-side decoding as token validation. This playground is not an OAuth/OIDC/FAPI conformance certification.

## Security notes

- Use HTTPS for both the issuer and the RP.
- Never put confidential client secrets in browser code.
- Prefer a maintained OIDC client library and server-side token validation for production applications.
- Do not use ephemeral SQLite storage for a production identity provider.
