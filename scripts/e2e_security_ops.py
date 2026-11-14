#!/usr/bin/env python3
"""End-to-end checks for the security-operations surfaces:

* tamper-evident audit chain (listing, verification, NDJSON export)
* Prometheus /metrics and the admin token gate
* DPoP nonce issuance and enforcement (RFC 9449 section 8)
* administrative user revocation, user inspection and secret rotation
* the absolute refresh-token lifetime

Start the server with nonce enforcement enabled, for example:
    KAGI_SEED_DEMO=1 KAGI_ADMIN_TOKEN=test-admin \
    KAGI_DPOP_NONCE=1 KAGI_DPOP_NONCE_SECRET=shared-secret \
    KAGI_DB=kagi-security-ops-e2e.db cargo run

The tamper check edits the SQLite file directly; set KAGI_DB to the same path
the server uses. PostgreSQL deployments skip that one check.
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as acu

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080")
ADMIN = os.environ.get("KAGI_ADMIN_TOKEN", "test-admin")
DB = os.environ.get("KAGI_DB")

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))
    if not cond:
        fails.append(name)


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def es256(key, header, payload):
    hb = b64u(json.dumps(header, separators=(",", ":")).encode())
    pb = b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign((hb + "." + pb).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = acu.decode_dss_signature(der)
    return hb + "." + pb + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()
jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": b64u(numbers.x.to_bytes(32, "big")),
    "y": b64u(numbers.y.to_bytes(32, "big")),
}


def dpop_headers(htm, htu, nonce=None):
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
        "jti": b64u(secrets.token_bytes(16)),
    }
    if nonce:
        payload["nonce"] = nonce
    return {"DPoP": es256(key, header, payload)}


admin = {"Authorization": "Bearer " + ADMIN}

# ---------------- admin token gate ----------------
for path in ("/admin/stats", "/admin/audit", "/admin/audit/verify", "/admin/audit/export", "/metrics"):
    r = requests.get(BASE + path, timeout=10)
    check(f"{path} rejects an anonymous request", r.status_code == 401, (r.status_code, r.text[:200]))

# ---------------- generate chained audit events ----------------
for _ in range(3):
    requests.post(
        BASE + "/api/recover",
        json={"username": "no-such-user", "code": "ABCDE-FGHJK"},
        timeout=10,
    )

# ---------------- audit listing ----------------
r = requests.get(BASE + "/admin/audit", headers=admin, timeout=10)
check("admin audit listing succeeds", r.status_code == 200, (r.status_code, r.text[:300]))
listing = r.json() if r.status_code == 200 else {}
events = listing.get("events", [])
check("audit listing contains chained events", len(events) >= 1, listing)
check(
    "every listed event carries a chain position and hash",
    all(e.get("seq") and e.get("hash") and e.get("prev_hash") for e in events),
    events[:2],
)
chain_ok = all(
    events[i]["prev_hash"] == events[i - 1]["hash"] and events[i]["seq"] == events[i - 1]["seq"] + 1
    for i in range(1, len(events))
)
check("listed events are linked oldest-first", chain_ok, events[:3])
check("listing reports the chain head", isinstance(listing.get("head"), dict), listing.get("head"))

# Cursor paging: one event per page must expose the next cursor.
r = requests.get(BASE + "/admin/audit?after=0&limit=1", headers=admin, timeout=10)
page = r.json() if r.status_code == 200 else {}
check("audit paging returns a next cursor", page.get("count") == 1 and page.get("next_after"), page)

# ---------------- verification ----------------
r = requests.get(BASE + "/admin/audit/verify", headers=admin, timeout=10)
verification = r.json() if r.status_code == 200 else {}
check("audit verification succeeds", r.status_code == 200 and verification.get("ok") is True, (r.status_code, verification))
check("verification re-hashed every chained event", verification.get("checked", 0) >= 1, verification)
check(
    "verification reports the same head as the listing",
    verification.get("head_seq") == listing.get("head", {}).get("seq"),
    (verification, listing.get("head")),
)

# ---------------- NDJSON export ----------------
r = requests.get(BASE + "/admin/audit/export?limit=100", headers=admin, timeout=10)
check("audit export succeeds", r.status_code == 200, (r.status_code, r.text[:200]))
check(
    "audit export is NDJSON with an attachment disposition",
    "application/x-ndjson" in r.headers.get("Content-Type", "")
    and "attachment" in r.headers.get("Content-Disposition", ""),
    dict(r.headers),
)
lines = [line for line in r.text.splitlines() if line.strip()]
parsed = []
for line in lines:
    try:
        parsed.append(json.loads(line))
    except ValueError:
        parsed = []
        break
check("every export line is valid JSON", lines and len(parsed) == len(lines), lines[:2])
check(
    "exported events keep their chain hashes",
    all(e.get("hash") and e.get("seq") for e in parsed),
    parsed[:1],
)

r = requests.get(BASE + "/admin/audit/export?after=0&limit=1", headers=admin, timeout=10)
check(
    "export exposes the next cursor header",
    r.headers.get("X-Kagi-Next-After", "") != "",
    dict(r.headers),
)

# ---------------- Prometheus metrics ----------------
r = requests.get(BASE + "/metrics", headers=admin, timeout=10)
body = r.text
check("metrics endpoint succeeds", r.status_code == 200, (r.status_code, body[:200]))
check("metrics use the Prometheus text format", "version=0.0.4" in r.headers.get("Content-Type", ""), dict(r.headers))
for metric in ("kagi_build_info", "kagi_uptime_seconds", "kagi_users", "kagi_audit_events", "kagi_audit_chain_seq"):
    check(f"metrics expose {metric}", f"\n{metric} " in "\n" + body or f"\n{metric}{{" in "\n" + body)

# ---------------- DPoP nonce ----------------
verifier = secrets.token_urlsafe(64)[:64]
challenge = b64u(hashlib.sha256(verifier.encode()).digest())
# The seeded demo client only registers the canonical localhost redirect URIs,
# so the form uses one of them regardless of the port under test.
par_form = {
    "client_id": "demo-web",
    "response_type": "code",
    "redirect_uri": "http://localhost:8080/demo/callback",
    "scope": "openid profile",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
}

# A proof without the server nonce must be rejected with a fresh nonce.
r = requests.post(
    BASE + "/par",
    data=par_form,
    headers=dpop_headers("POST", BASE + "/par"),
    timeout=10,
)
initial_nonce = r.headers.get("DPoP-Nonce")
check(
    "PAR without a nonce is rejected with use_dpop_nonce",
    r.status_code == 400 and r.json().get("error") == "use_dpop_nonce",
    (r.status_code, r.text[:300]),
)
check("the rejection advertises a DPoP-Nonce", bool(initial_nonce), dict(r.headers))

# Retrying with the advertised nonce must succeed.
r = requests.post(
    BASE + "/par",
    data=par_form,
    headers=dpop_headers("POST", BASE + "/par", nonce=initial_nonce),
    timeout=10,
)
check("PAR with the server nonce succeeds", r.status_code == 201, (r.status_code, r.text[:300]))
check("successful response rotates or repeats DPoP-Nonce", bool(r.headers.get("DPoP-Nonce")), dict(r.headers))

# A stale/forged nonce is rejected even with a valid signature.
r = requests.post(
    BASE + "/par",
    data=par_form,
    headers=dpop_headers("POST", BASE + "/par", nonce="0." + "A" * 43),
    timeout=10,
)
check(
    "PAR with a forged nonce is rejected",
    r.status_code == 400 and r.json().get("error") == "use_dpop_nonce",
    (r.status_code, r.text[:300]),
)

# The token endpoint enforces the same nonce before looking at the grant.
r = requests.post(
    BASE + "/token",
    data={"grant_type": "client_credentials", "client_id": "demo-web"},
    headers=dpop_headers("POST", BASE + "/token"),
    timeout=10,
)
check(
    "token endpoint requires a DPoP nonce",
    r.status_code == 400 and r.json().get("error") == "use_dpop_nonce",
    (r.status_code, r.text[:300]),
)
token_nonce = r.headers.get("DPoP-Nonce")
check("token endpoint advertises DPoP-Nonce", bool(token_nonce), dict(r.headers))

# ---------------- administrative revocation ----------------
if DB and os.path.exists(DB):
    revoked_user = "e2e-admin-revoke"
    now = int(time.time())
    connection = sqlite3.connect(DB, timeout=10)
    try:
        connection.execute(
            "INSERT OR REPLACE INTO users (id, username, display_name, created_at) VALUES (?, ?, ?, ?)",
            (revoked_user, revoked_user, "E2E Revoke", now),
        )
        connection.execute(
            "INSERT OR REPLACE INTO sessions (id, user_id, auth_time, amr, acr, expires_at, created_at) "
            "VALUES (?, ?, ?, '[]', 'urn:kagi:acr:passkey', ?, ?)",
            ("e2e-session", revoked_user, now, now + 3600, now),
        )
        connection.execute(
            "INSERT OR REPLACE INTO refresh_tokens "
            "(token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, '[]', 'urn:kagi:acr:passkey', ?, ?)",
            ("e2e-refresh", "e2e-family", revoked_user, "demo-web", "openid", now, now, now + 3600),
        )
        connection.execute(
            "INSERT OR REPLACE INTO access_tokens "
            "(jti, user_id, client_id, scope, audience, subject, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("e2e-access", revoked_user, "demo-web", "openid", BASE, revoked_user, now, now + 300),
        )
        connection.commit()
    finally:
        connection.close()

    r = requests.get(BASE + f"/admin/users/{revoked_user}", headers=admin, timeout=10)
    view = r.json() if r.status_code == 200 else {}
    activity = view.get("activity", {})
    check("admin user view succeeds", r.status_code == 200, (r.status_code, view))
    check(
        "admin user view reports live state without PII",
        activity.get("sessions") == 1
        and activity.get("active_refresh_tokens") == 1
        and activity.get("active_access_tokens") == 1
        and "email" not in view.get("user", {}),
        view,
    )

    r = requests.get(BASE + "/admin/users/no-such-user", headers=admin, timeout=10)
    check(
        "admin user view reports an unknown user",
        r.status_code == 404,
        (r.status_code, r.text[:200]),
    )

    r = requests.post(BASE + f"/admin/users/{revoked_user}/revoke", timeout=10)
    check(
        "user revocation rejects an anonymous request",
        r.status_code == 401,
        (r.status_code, r.text[:200]),
    )

    r = requests.post(
        BASE + "/admin/users/no-such-user/revoke", headers=admin, timeout=10
    )
    check(
        "user revocation reports an unknown user",
        r.status_code == 404,
        (r.status_code, r.text[:200]),
    )

    r = requests.post(
        BASE + f"/admin/users/{revoked_user}/revoke", headers=admin, timeout=10
    )
    payload = r.json() if r.status_code == 200 else {}
    revoked = payload.get("revoked", {})
    check("user revocation succeeds", r.status_code == 200, (r.status_code, payload))
    check(
        "revocation reports what it changed",
        revoked.get("sessions") == 1
        and revoked.get("refresh_tokens") == 1
        and revoked.get("access_tokens") == 1,
        revoked,
    )

    connection = sqlite3.connect(DB, timeout=10)
    try:
        sessions = connection.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (revoked_user,)
        ).fetchone()[0]
        refresh = connection.execute(
            "SELECT revoked FROM refresh_tokens WHERE token_hash = 'e2e-refresh'"
        ).fetchone()[0]
        access = connection.execute(
            "SELECT revoked FROM access_tokens WHERE jti = 'e2e-access'"
        ).fetchone()[0]
    finally:
        connection.close()
    check("revocation deleted the sessions", sessions == 0, sessions)
    check("revocation invalidated refresh tokens", refresh == 1, refresh)
    check("revocation invalidated access tokens", access == 1, access)

    r = requests.post(
        BASE + f"/admin/users/{revoked_user}/revoke", headers=admin, timeout=10
    )
    again = r.json().get("revoked", {}) if r.status_code == 200 else {}
    check(
        "revocation is idempotent",
        r.status_code == 200
        and all(value == 0 for value in again.values()),
        (r.status_code, again),
    )

    r = requests.get(BASE + "/admin/audit?limit=1000", headers=admin, timeout=10)
    events = r.json().get("events", []) if r.status_code == 200 else []
    check(
        "revocation is written to the audit chain",
        any(event.get("kind") == "admin.user_revoke" for event in events),
        [event.get("kind") for event in events[-5:]],
    )
else:
    print("SKIP administrative revocation (KAGI_DB is not a local SQLite file)")

# ---------------- absolute refresh-token lifetime ----------------
if DB and os.path.exists(DB):
    now = int(time.time())
    rt_user = "e2e-rt-user"
    expired_token = "e2e-absolute-expired"
    fresh_token = "e2e-absolute-fresh"
    connection = sqlite3.connect(DB, timeout=10)
    try:
        connection.execute(
            "INSERT OR REPLACE INTO users (id, username, display_name, created_at) VALUES (?, ?, ?, ?)",
            (rt_user, rt_user, "E2E RT", now),
        )
        for token, auth_time, family in (
            (expired_token, now - 31 * 86400, "e2e-family-expired"),
            (fresh_token, now - 60, "e2e-family-fresh"),
        ):
            connection.execute(
                "INSERT OR REPLACE INTO refresh_tokens "
                "(token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr, issued_at, expires_at) "
                "VALUES (?, ?, ?, 'demo-web', 'openid', ?, '[]', 'urn:kagi:acr:passkey', ?, ?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    family,
                    rt_user,
                    auth_time,
                    now,
                    now + 3600,
                ),
            )
        connection.commit()
    finally:
        connection.close()

    r = requests.post(
        BASE + "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": expired_token,
            "client_id": "demo-web",
        },
        timeout=10,
    )
    check(
        "refresh token past the absolute lifetime is rejected",
        r.status_code == 400 and r.json().get("error") == "invalid_grant",
        (r.status_code, r.text[:300]),
    )

    r = requests.post(
        BASE + "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": fresh_token,
            "client_id": "demo-web",
        },
        timeout=10,
    )
    payload = r.json() if r.status_code == 200 else {}
    check("refresh within the absolute lifetime succeeds", r.status_code == 200, (r.status_code, payload))
    rotated = payload.get("refresh_token")
    if rotated:
        connection = sqlite3.connect(DB, timeout=10)
        try:
            row = connection.execute(
                "SELECT auth_time, expires_at FROM refresh_tokens WHERE token_hash = ?",
                (hashlib.sha256(rotated.encode()).hexdigest(),),
            ).fetchone()
        finally:
            connection.close()
        check(
            "rotated refresh tokens cannot pass the absolute cap",
            row is not None and row[1] <= row[0] + 30 * 86400 + 5,
            row,
        )
    else:
        check("rotated refresh tokens cannot pass the absolute cap", False, payload)
else:
    print("SKIP absolute refresh-token lifetime (KAGI_DB is not a local SQLite file)")

# ---------------- client secret rotation ----------------
if DB and os.path.exists(DB):
    now = int(time.time())
    client_id = "e2e-confidential"
    original_secret = secrets.token_urlsafe(24)
    wrong_secret = secrets.token_urlsafe(24)
    connection = sqlite3.connect(DB, timeout=10)
    try:
        connection.execute(
            "INSERT OR REPLACE INTO clients "
            "(id, name, secret_hash, redirect_uris, grant_types, scopes, auth_method, created_at) "
            "VALUES (?, ?, ?, '[]', '[\"client_credentials\"]', '[\"openid\"]', "
            "'client_secret_post', ?)",
            (
                client_id,
                "E2E Confidential",
                hashlib.sha256(original_secret.encode()).hexdigest(),
                now,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    r = requests.post(BASE + f"/admin/clients/{client_id}/rotate-secret", timeout=10)
    check(
        "secret rotation rejects an anonymous request",
        r.status_code == 401,
        (r.status_code, r.text[:200]),
    )

    r = requests.post(
        BASE + "/admin/clients/no-such-client/rotate-secret", headers=admin, timeout=10
    )
    check(
        "secret rotation reports an unknown client",
        r.status_code == 404,
        (r.status_code, r.text[:200]),
    )

    r = requests.post(
        BASE + "/admin/clients/demo-web/rotate-secret", headers=admin, timeout=10
    )
    check(
        "secret rotation refuses a public client",
        r.status_code == 400 and r.json().get("error") == "public_client",
        (r.status_code, r.text[:200]),
    )

    r = requests.post(
        BASE + f"/admin/clients/{client_id}/rotate-secret", headers=admin, timeout=10
    )
    payload = r.json() if r.status_code == 200 else {}
    new_secret = payload.get("client_secret", "")
    check(
        "secret rotation returns a new secret",
        r.status_code == 200 and len(new_secret) >= 32 and new_secret != original_secret,
        (r.status_code, payload),
    )
    check(
        "secret rotation does not cache the response",
        r.headers.get("Cache-Control") == "no-store",
        dict(r.headers),
    )

    def introspect(secret):
        return requests.post(
            BASE + "/introspect",
            data={"token": "unknown", "client_id": client_id, "client_secret": secret},
            timeout=10,
        )

    check("the new secret authenticates", introspect(new_secret).status_code == 200)
    check("the previous secret works during the grace period", introspect(original_secret).status_code == 200)
    check("an unrelated secret is rejected", introspect(wrong_secret).status_code == 401)

    connection = sqlite3.connect(DB, timeout=10)
    try:
        connection.execute(
            "UPDATE clients SET previous_secret_expires_at = ? WHERE id = ?",
            (now - 1, client_id),
        )
        connection.commit()
    finally:
        connection.close()
    check(
        "the previous secret stops working after the grace period",
        introspect(original_secret).status_code == 401,
    )
    check("the new secret still works", introspect(new_secret).status_code == 200)

    r = requests.get(BASE + "/admin/audit?limit=1000", headers=admin, timeout=10)
    events = r.json().get("events", []) if r.status_code == 200 else []
    check(
        "secret rotation is written to the audit chain",
        any(event.get("kind") == "admin.client_secret_rotate" for event in events),
        [event.get("kind") for event in events[-5:]],
    )
else:
    print("SKIP client secret rotation (KAGI_DB is not a local SQLite file)")

# ---------------- tamper detection (SQLite only) ----------------
if DB and os.path.exists(DB):
    r = requests.get(BASE + "/admin/audit?limit=100", headers=admin, timeout=10)
    rows = r.json().get("events", []) if r.status_code == 200 else []
    if rows:
        target = rows[len(rows) // 2]
        connection = sqlite3.connect(DB, timeout=10)
        try:
            connection.execute(
                "UPDATE audit_events SET detail = ? WHERE seq = ?",
                ("tampered by e2e", target["seq"]),
            )
            connection.commit()
        finally:
            connection.close()
        time.sleep(0.2)
        r = requests.get(BASE + "/admin/audit/verify", headers=admin, timeout=10)
        result = r.json() if r.status_code in (200, 409) else {}
        check(
            "verification detects a modified event",
            r.status_code == 409 and result.get("ok") is False,
            (r.status_code, result),
        )
        check(
            "verification names the failing position",
            "mismatch" in (result.get("error") or "") or "link" in (result.get("error") or ""),
            result,
        )
else:
    print("SKIP tamper detection (KAGI_DB is not a local SQLite file)")

print()
if fails:
    print(f"FAILURES: {len(fails)}")
    for name in fails:
        print(" - " + name)
    sys.exit(1)
print("FAILURES: none")
