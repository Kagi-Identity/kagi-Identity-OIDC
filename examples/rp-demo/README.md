# Kagi Identity RP Demo

Static, browser-based OIDC connection demo for evaluating a Kagi Identity deployment.

## Vercel deployment

The project is deployed as static files from the project root:
- `index.html` — endpoint diagnostics and Authorization Code + PKCE initiation
- `callback.html` — state/PKCE/token exchange and UserInfo demo

Set the Identity issuer and public client ID in the UI. The default issuer is the production project domain and the default client is `demo-web`.

## Important integration requirement

The Identity server must be reachable from browsers and expose `/healthz`, OIDC discovery, `/jwks.json`, `/token`, and `/userinfo` with the required CORS behavior. The public client must be registered with the exact callback URI `https://kagi-rp-demo-gakusei-bot.vercel.app/callback.html` and support Authorization Code + PKCE (S256). If the demo client is not registered, the UI will show the Identity Provider's error rather than pretending login worked.

The callback validates state, PKCE, issuer, audience, nonce, and expiration for demonstration purposes, but it does not validate the ID Token signature. Never use this browser-only sample as production authentication. Use a maintained server-side OIDC library.

No client secret or user token is persisted to localStorage. The short-lived PKCE verifier is stored in sessionStorage only while the authorization request is pending.
