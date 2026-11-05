# Client integration

This guide explains how a relying party (RP) can use Kagi Identity. Prefer a maintained OIDC client library for production applications; use the built-in SDK as a minimal demonstration and review its behavior against your own threat model.

## 1. Register a client

Register the exact callback URI. Scheme, host, port, path, and trailing slash must match exactly.

For a local demo, the seeded client ID is `demo-web`. For a new public browser client, register it through the authenticated dynamic registration endpoint:

```bash
export KAGI_REGISTRATION_TOKEN='use-the-secret-from-your-secret-manager'
curl --fail-with-body --request POST 'https://id.example.com/register' \
  --header "Authorization: Bearer $KAGI_REGISTRATION_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{
    "client_name": "Example Web App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access",
    "token_endpoint_auth_method": "none"
  }'
```

Treat the registration response as sensitive. Do not log client credentials if a confidential client was registered.

Public clients (browser/mobile) cannot keep a client secret confidential; use Authorization Code + PKCE. Confidential clients should perform the token exchange on a trusted backend and use a supported client-authentication method.

## 2. Minimal browser SDK example

Load the SDK from the Kagi Identity origin:

```html
<script src="https://id.example.com/static/kagi.js"></script>
<button id="sign-in" type="button">Sign in</button>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  document.querySelector("#sign-in").addEventListener("click", () => {
    Kagi.login();
  });
</script>
```

On the callback route, load the SDK and configure the same issuer, client ID, and redirect URI:

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  (async () => {
    const session = await Kagi.handleCallback();
    const profile = await Kagi.userinfo();
    // Render only the profile fields the application actually needs.
    console.log({ subject: profile.sub, session });
  })();
</script>
```

API details can change; inspect `/demo` and `static/kagi.js` in the version you deploy. Never assume a successful callback alone is enough: validate the token and protocol requirements appropriate to your application. For production, prefer a mature OIDC library and validate issuer, audience, signature, expiry, nonce, state, and PKCE using the library's supported APIs.

## 3. Discovery and keys

Fetch the discovery document instead of hardcoding endpoint paths:

```bash
curl --fail 'https://id.example.com/.well-known/openid-configuration'
curl --fail 'https://id.example.com/jwks.json'
```

Cache JWKS according to the relying-party library's guidance and support key refresh when an unknown `kid` is encountered. Do not pin a single signing key indefinitely.

## 4. Redirect and token safety

- Register exact redirect URIs; do not use wildcard callback URLs.
- Use Authorization Code + PKCE with S256; do not use the implicit flow.
- Generate cryptographically random `state` and `nonce` values and validate them in the callback.
- Do not put tokens in query strings, analytics events, or application logs.
- Avoid storing long-lived credentials in browser-accessible persistent storage.
- Keep access tokens short-lived and request only the scopes needed.
- For server-side sessions, keep tokens on the backend and issue an application session cookie with appropriate Secure, HttpOnly, and SameSite settings.

The built-in SDK is a convenience for evaluation, not a blanket recommendation to build production authentication logic by hand.
