"""Security regression tests for authorization-code races, DPoP replay, key rotation and OIDC metadata.

Run against a local Kagi server with KAGI_SEED_DEMO=1 and KAGI_DB pointing
at the same SQLite database used by the server. This is an integration test,
not an OAuth/OIDC certification suite.
"""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

BASE = os.environ.get("KAGI_BASE", "http://127.0.0.1:8080").rstrip("/")
DB = os.environ.get("KAGI_DB", "kagi-security-e2e.db")
ADMIN = os.environ.get("KAGI_ADMIN_TOKEN", "test-admin")
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"
failures = []

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f" -> {str(detail)[:400]}"), flush=True)
    if not ok:
        failures.append(name)

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def pkce():
    verifier = b64u(secrets.token_bytes(32))
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())

def insert_code(code, challenge):
    now = int(time.time())
    digest = hashlib.sha256(code.encode()).hexdigest()
    with sqlite3.connect(DB, timeout=10) as con:
        con.execute(
            """INSERT INTO auth_codes
            (code_hash, client_id, user_id, redirect_uri, scope, nonce,
             code_challenge, auth_time, amr, acr, dpop_jkt, session_id,
             expires_at, created_at, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 0)""",
            (digest, CLIENT, "security-test-user", REDIRECT,
             "openid profile email offline_access", "security-test-nonce",
             challenge, now, '["passkey"]', "urn:kagi:acr:passkey", now + 120, now),
        )

def exchange(code, verifier):
    try:
        return requests.post(BASE + "/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": verifier,
        }, timeout=10)
    except Exception as exc:
        return exc

def make_dpop_proof(key, jwk, jti, method, url):
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"jti": jti, "htm": method, "htu": url, "iat": int(time.time())}
    head = b64u(json.dumps(header, separators=(",", ":")).encode())
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign((head + "." + body).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return head + "." + body + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

def main():
    # Seed only isolated test records in the dedicated CI database.
    now = int(time.time())
    with sqlite3.connect(DB, timeout=10) as con:
        con.execute(
            """INSERT OR REPLACE INTO users
            (id, username, display_name, email, email_verified, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            ("security-test-user", "security-test-user", "Security Test",
             "security-test@example.invalid", 0, now),
        )
        con.execute(
            """INSERT OR REPLACE INTO consents (user_id, client_id, scope, created_at)
            VALUES (?, ?, ?, ?)""",
            ("security-test-user", CLIENT, "openid profile email offline_access", now),
        )

    # OAuth/OIDC metadata sanity checks: assertions are intentionally focused
    # on advertised features and do not claim full normative conformance.
    try:
        discovery = requests.get(BASE + "/.well-known/openid-configuration", timeout=5)
        doc = discovery.json()
        check("OIDC discovery responds", discovery.status_code == 200, discovery.status_code)
        check("OIDC issuer and endpoints are absolute", doc.get("issuer") == BASE
              and doc.get("authorization_endpoint", "").startswith("http")
              and doc.get("token_endpoint", "").startswith("http")
              and doc.get("jwks_uri", "").startswith("http"), doc)
        check("OIDC advertises code + S256", "code" in doc.get("response_types_supported", [])
              and "S256" in doc.get("code_challenge_methods_supported", []), doc)
        check("OAuth metadata alias responds", requests.get(
            BASE + "/.well-known/oauth-authorization-server", timeout=5).status_code == 200)
    except Exception as exc:
        check("OIDC discovery requests", False, exc)
        return 1

    # Two simultaneous exchanges of the exact same authorization code must
    # never both mint tokens. The database CAS is the security boundary.
    verifier, challenge = pkce()
    code = secrets.token_urlsafe(32)
    insert_code(code, challenge)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: exchange(code, verifier), range(2)))
    statuses = [r.status_code if isinstance(r, requests.Response) else -1 for r in results]
    check("authorization code concurrent exchange: exactly one success",
          statuses.count(200) == 1 and sum(s >= 400 for s in statuses) == 1, statuses)
    success = next((r for r in results if isinstance(r, requests.Response) and r.status_code == 200), None)
    token_kid = None
    if success is not None:
        try:
            access = success.json()["access_token"]
            token_kid = json.loads(unb64(access.split(".")[0])).get("kid")
            check("access token has a signing kid", bool(token_kid), token_kid)
        except Exception as exc:
            check("successful exchange returns parseable token", False, exc)

    # DPoP proof replay: concurrent requests share a single signed proof/jti.
    # Only one can insert the unique replay-cache key.
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": b64u(nums.x.to_bytes(32, "big")),
           "y": b64u(nums.y.to_bytes(32, "big"))}
    verifier2, challenge2 = pkce()
    proof_jti = b64u(secrets.token_bytes(16))
    proof = make_dpop_proof(key, jwk, proof_jti, "POST", BASE + "/par")
    par = {"client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
           "scope": "openid profile email", "state": secrets.token_urlsafe(12),
           "nonce": secrets.token_urlsafe(12), "code_challenge": challenge2,
           "code_challenge_method": "S256"}
    def submit_par(_):
        try:
            return requests.post(BASE + "/par", data=par, headers={"DPoP": proof}, timeout=10)
        except Exception as exc:
            return exc
    with ThreadPoolExecutor(max_workers=2) as pool:
        par_results = list(pool.map(submit_par, range(2)))
    par_statuses = [r.status_code if isinstance(r, requests.Response) else -1 for r in par_results]
    check("DPoP replay under concurrency: exactly one accepted",
          par_statuses.count(200) == 1 and sum(s >= 400 for s in par_statuses) == 1,
          par_statuses)

    # Rotate the signing key, verify overlap publication, and ensure a token
    # issued after rotation uses the new key while the old key remains served.
    try:
        before = requests.get(BASE + "/jwks.json", timeout=5).json()
        old_kids = {k.get("kid") for k in before.get("keys", [])}
        rotate = requests.post(BASE + "/admin/keys/rotate",
                               headers={"Authorization": "Bearer " + ADMIN}, timeout=10)
        check("key rotation endpoint succeeds", rotate.status_code == 200, rotate.text[:300])
        rotated = rotate.json() if rotate.status_code == 200 else {}
        new_kid = rotated.get("kid")
        after = requests.get(BASE + "/jwks.json", timeout=5).json()
        after_kids = {k.get("kid") for k in after.get("keys", [])}
        check("rotation publishes new key and retains old verification keys",
              bool(new_kid) and new_kid in after_kids and old_kids.issubset(after_kids),
              {"old": sorted(old_kids), "after": sorted(after_kids), "new": new_kid})
        if token_kid:
            check("pre-rotation token key remains in JWKS",
                  token_kid in after_kids, {"token_kid": token_kid, "after": sorted(after_kids)})

        verifier3, challenge3 = pkce()
        code3 = secrets.token_urlsafe(32)
        insert_code(code3, challenge3)
        post_rotate = exchange(code3, verifier3)
        post_kid = None
        if isinstance(post_rotate, requests.Response) and post_rotate.status_code == 200:
            post_kid = json.loads(unb64(post_rotate.json()["access_token"].split(".")[0])).get("kid")
        check("post-rotation token uses the new key",
              isinstance(post_rotate, requests.Response) and post_rotate.status_code == 200
              and post_kid == new_kid, {"status": getattr(post_rotate, "status_code", -1),
                                        "token_kid": post_kid, "new_kid": new_kid})
    except Exception as exc:
        check("key rotation integration checks", False, exc)

    print("\nFailures:", failures if failures else "none", flush=True)
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
