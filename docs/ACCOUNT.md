# Account console and recovery

After sign-in, `/` is a passkey-only account console. Users can manage their profile, authenticators, sessions and connected applications without operator intervention.

## Profile

- Update display name and email address.
- Changes are reflected by UserInfo immediately.
- Empty or over-long display names are rejected.

## Passkeys

- Add, rename and delete passkeys.
- **The last remaining passkey cannot be deleted.** This is enforced atomically in a transaction, so concurrent requests cannot lock a user out.
- The per-account limit is `KAGI_MAX_PASSKEYS` (default 10, clamped to 1–100).
- A new passkey is created with the device's screen lock, biometrics or security key.

> Generate recovery codes in advance in case every passkey is lost.

## Devices (sessions)

- List active sessions with device information, IP and last activity.
- The current device is marked.
- Revoke one session, or all sessions except the current one.
- Revoking a session also **revokes access and refresh tokens issued from it**, so a copied token does not survive until `exp`.
- Session lifetimes are controlled by `KAGI_SESSION_TTL` (absolute, default 8 hours) and `KAGI_SESSION_IDLE_TTL` (idle, default 2 hours). Tokens belonging to expired sessions are also revoked by the periodic sweep.

## Connected applications (consent)

- List authorized clients and their approved scopes.
- Revoking consent invalidates the stored consent row and the client's access and refresh tokens.
- The next authorization request from that client shows the consent screen again.

## Recovery codes

Fallback when no passkey is available. Enabled by `KAGI_RECOVERY_ENABLED=1` (the default).

1. Generate a new set from the account console.
2. Ten single-use codes (for example `ABCDE-FGHJK`) are shown **once**. Closing the page means they cannot be shown again.
3. A code is invalid on first use. Regenerating the set invalidates every previous code.
4. Sign in with "recover using a recovery code" using the username and code.

Only a salted, iterated SHA-256 digest (20,000 iterations over the normalized code and user id) is stored. Consumption is a single atomic `UPDATE ... WHERE used_at IS NULL`, so a code is single-use even under concurrency.

A recovery session has `acr=urn:kagi:acr:recovery` and `amr=["pwd","otp"]`; it never claims passkey authentication. A client requiring `acr_values=urn:kagi:acr:passkey` cannot authorize this session (`unmet_authentication_requirements`).

## Security events

The console shows recent sign-ins, failures, passkey changes and session revocations from the audit log. Retention is controlled by `KAGI_AUDIT_RETENTION_DAYS` (default 90, `0` keeps events indefinitely).

## Delete account

1. Re-enter the username on the delete panel.
2. Passkeys, sessions, tokens and consents are removed.
3. The audit trail is kept so the deletion itself remains auditable, then purged after the retention period.

Account deletion is irreversible. Back up anything you need first.

## Browser-facing API protection

Account POSTs are protected by `Origin` and `Sec-Fetch-Site` validation and CSRF tokens. OAuth protocol endpoints (`/par`, `/token`, ...) are exempt because relying parties call them cross-origin; they are protected by OAuth/DPoP validation instead.

Session cookies are `HttpOnly; SameSite=Lax`. On HTTPS the console uses `__Host-kagi_sid`, which browsers refuse to set over HTTP or from a sibling subdomain. The legacy `kagi_sid` name is still read and cleared, so an upgrade does not immediately sign existing browsers out.

## Administrative endpoints

When `KAGI_ADMIN_TOKEN` is set, these endpoints are enabled. Without it they are disabled.

| Endpoint | Purpose |
| --- | --- |
| `POST /admin/keys/rotate` | Rotate signing keys and publish the new `kid` |
| `GET /admin/stats` | Aggregate users, sessions, audit events and recovery-code counts |

Use a strong random administrative token and keep it in a secret manager. Production startup rejects known or short values.
