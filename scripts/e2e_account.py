"""End-to-end checks for the account console, recovery codes and admin APIs.

The script uses a software authenticator (no browser). It covers profile
updates, passkey rename/add/delete, session revocation, consent revocation,
recovery-code sign-in, cross-origin POST rejection, admin stats and account
deletion.

    cargo run   (or target/debug/kagi.exe)
    python scripts/e2e_account.py

Required server environment:

    KAGI_SEED_DEMO=1
    KAGI_RECOVERY_ENABLED=1
    KAGI_ADMIN_TOKEN=test-admin

Optional: KAGI_BASE / KAGI_ORIGIN select a non-default base URL and the
browser origin used for WebAuthn client data.
"""

import base64, hashlib, json, os, re, secrets, struct, sys
import urllib.parse as up
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080").rstrip("/")
ORIGIN = os.environ.get("KAGI_ORIGIN", BASE).rstrip("/")
RPID = up.urlsplit(ORIGIN).hostname or "localhost"
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"
ADMIN_TOKEN = os.environ.get("KAGI_ADMIN_TOKEN", "test-admin")

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))
    if not cond:
        fails.append(name)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- minimal CBOR encoder (attestation objects only) ----------------------
def cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    return bytes([(major << 5) | 26]) + struct.pack(">I", n)


def cbor(v):
    if isinstance(v, dict):
        out = cbor_head(5, len(v))
        for k, val in v.items():
            out += cbor(k) + cbor(val)
        return out
    if isinstance(v, bytes):
        return cbor_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return cbor_head(3, len(b)) + b
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
    raise TypeError(v)


def cose_key(pub):
    n = pub.public_numbers()
    return cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})


def auth_data(cred_id, pub, flags, count, include_cred=True):
    ad = hashlib.sha256(RPID.encode()).digest() + bytes([flags]) + struct.pack(">I", count)
    if include_cred:
        ad += b"\x00" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cose_key(pub)
    return ad


def client_data(typ, challenge):
    return json.dumps(
        {"type": typ, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
        separators=(",", ":"),
    ).encode()


def make_credential(challenge):
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = secrets.token_bytes(32)
    cdj = client_data("webauthn.create", challenge)
    att = cbor(
        {
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data(cred_id, key.public_key(), 0x45, 0),
        }
    )
    cred = {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(cdj),
            "attestationObject": b64u(att),
            "transports": ["internal"],
        },
        "clientExtensionResults": {"credProps": {"rk": True}},
    }
    return key, cred_id, cred


def sign_assertion(key, cred_id, challenge, count):
    cdj = client_data("webauthn.get", challenge)
    ad = auth_data(cred_id, key.public_key(), 0x05, count, include_cred=False)
    der = key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(cdj),
            "authenticatorData": b64u(ad),
            "signature": b64u(der),
            "userHandle": b64u(b""),
        },
        "clientExtensionResults": {},
    }


def signup():
    username = "dave" + secrets.token_hex(3)
    s = requests.Session()
    r = s.post(
        BASE + "/api/webauthn/signup/options",
        json={"username": username, "display_name": "Dave", "email": "dave@example.com"},
    )
    check("signup options", r.status_code == 200, r.text)
    opts = r.json()["publicKey"]
    rid = r.json()["rid"]
    key, cred_id, cred = make_credential(opts["challenge"])
    user_handle = unb64(opts["user"]["id"]).decode()
    r = s.post(BASE + "/api/webauthn/signup/verify", json={"rid": rid, "credential": cred})
    check("signup verify", r.status_code == 200 and r.json().get("ok") is True, r.text)
    return s, username, key, cred_id, user_handle


def second_session(key, cred_id, user_handle):
    """Run an authorize/PAR/login/consent round trip in a fresh cookie jar."""
    s = requests.Session()
    verifier = b64u(secrets.token_bytes(48))
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    r = s.post(
        BASE + "/par",
        data={
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "scope": "openid profile email",
            "state": "state-account",
            "nonce": "nonce-account",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    check("par for second session", r.status_code == 201, r.text)
    ru = r.json()["request_uri"]
    r = s.get(
        BASE + "/authorize",
        params={"client_id": CLIENT, "request_uri": ru},
        allow_redirects=False,
    )
    loc = r.headers.get("Location", "")
    check("authorize redirects to login", r.status_code == 303 and loc.startswith("/login?rid="), loc)
    arid = up.parse_qs(up.urlparse(loc).query)["rid"][0]
    r = s.post(BASE + "/api/webauthn/login/options", json={"rid": arid})
    check("login options for second session", r.status_code == 200, r.text)
    assertion = sign_assertion(key, cred_id, r.json()["publicKey"]["challenge"], 1)
    assertion["response"]["userHandle"] = b64u(user_handle.encode())
    r = s.post(BASE + "/api/webauthn/login/verify", json={"rid": arid, "credential": assertion})
    check("login verify for second session", r.status_code == 200, r.text)
    r = s.get(BASE + "/consent", params={"rid": arid})
    check("consent page for second session", r.status_code == 200, r.text)
    match = re.search(r'name="csrf" value="([^"]+)"', r.text)
    check("consent csrf present", bool(match), r.text[:300])
    r = s.post(
        BASE + "/consent",
        data={"rid": arid, "csrf": match.group(1) if match else "", "decision": "allow"},
        allow_redirects=False,
    )
    check("consent grants access", r.status_code == 303 and "code=" in r.headers.get("Location", ""), r.text)
    return s


def main():
    print("== signup and account console ==")
    s, username, key, cred_id, user_handle = signup()
    r = s.get(BASE + "/")
    page = r.text
    check("account page renders", r.status_code == 200, r.status_code)
    for label in (
        "プロフィール",
        "パスキー",
        "サインイン中のデバイス",
        "連携アプリ",
        "リカバリーコード",
        "最近のセキュリティイベント",
        "アカウント削除",
    ):
        check(f"account page shows {label}", label in page, page[:200])

    print()
    print("== profile ==")
    r = s.post(
        BASE + "/api/account/profile",
        json={"display_name": "Dave Updated", "email": "dave.updated@example.com"},
    )
    check("profile update", r.status_code == 200, r.text)
    r = s.get(BASE + "/")
    check("profile update is rendered", "Dave Updated" in r.text and "dave.updated@example.com" in r.text, r.text[:300])
    r = s.post(BASE + "/api/account/profile", json={"display_name": "  "})
    check("empty profile name rejected", r.status_code == 400, r.text)

    print()
    print("== passkeys ==")
    r = s.post(
        BASE + "/api/account/passkey/rename",
        json={"id": b64u(cred_id), "name": "My Phone"},
    )
    check("passkey rename", r.status_code == 200, r.text)
    r = s.get(BASE + "/")
    check("passkey name is rendered", "My Phone" in r.text, r.text[:400])

    r = s.post(BASE + "/api/webauthn/passkey/options", json={})
    check("add passkey options", r.status_code == 200, r.text)
    start = r.json()
    _, cred2_id, cred2 = make_credential(start["publicKey"]["challenge"])
    r = s.post(
        BASE + "/api/webauthn/passkey/verify",
        json={"rid": start["rid"], "credential": cred2},
    )
    check("add passkey verify", r.status_code == 200 and r.json().get("ok") is True, r.text)
    r = s.get(BASE + "/")
    check("second passkey shown", "My Phone" in r.text and r.text.count("data-action=\"delete-passkey\"") == 2, r.text[:300])

    r = s.post(BASE + "/api/account/passkey/delete", json={"id": b64u(cred2_id)})
    check("delete second passkey", r.status_code == 200, r.text)
    r = s.post(BASE + "/api/account/passkey/delete", json={"id": b64u(cred_id)})
    check("last passkey cannot be deleted", r.status_code == 400, r.text)

    print()
    print("== sessions and consent ==")
    other = second_session(key, cred_id, user_handle)
    r = s.get(BASE + "/")
    check("two sessions listed", r.text.count("data-action=\"revoke-session\"") >= 2, r.text[:400])
    check("current device is marked", "このデバイス" in r.text, r.text[:400])
    check("consent app is listed", "kagi demo" in r.text, r.text[:400])

    r = s.post(BASE + "/api/account/sessions/revoke-others", json={})
    check("revoke other sessions", r.status_code == 200 and r.json().get("revoked", 0) >= 1, r.text)
    r = other.get(BASE + "/", allow_redirects=False)
    check("revoked session is signed out", r.status_code in (302, 303), r.status_code)

    r = s.post(BASE + "/api/account/consent/revoke", json={"client_id": CLIENT})
    check("revoke consent", r.status_code == 200, r.text)
    r = s.get(BASE + "/")
    check("consent is gone", "kagi demo" not in r.text, r.text[:400])

    print()
    print("== recovery codes ==")
    r = s.get(BASE + "/recover")
    check("recovery page renders", r.status_code == 200 and "リカバリーコード" in r.text, r.status_code)
    r = s.post(BASE + "/api/account/recovery/generate", json={})
    check("generate recovery codes", r.status_code == 200 and len(r.json().get("codes", [])) == 10, r.text)
    codes = r.json()["codes"]
    r = s.get(BASE + "/")
    check("remaining recovery count shown", ">10<" in r.text, r.text[:400])

    recovered = requests.Session()
    r = recovered.post(BASE + "/api/recover", json={"username": username, "code": codes[0]})
    check("recovery sign-in", r.status_code == 200 and r.json().get("ok") is True, r.text)
    check("recovery sets session cookie", "kagi_sid" in recovered.cookies, list(recovered.cookies.keys()))
    r = recovered.get(BASE + "/")
    check("recovered session reaches account", r.status_code == 200 and username in r.text, r.status_code)

    r = requests.post(BASE + "/api/recover", json={"username": username, "code": codes[0]})
    check("recovery code is single use", r.status_code == 400, r.text)
    r = requests.post(BASE + "/api/recover", json={"username": username, "code": "AAAAA-AAAAA"})
    check("wrong recovery code rejected", r.status_code == 400, r.text)
    r = s.get(BASE + "/")
    check("remaining recovery count decreases", ">9<" in r.text, r.text[:400])

    print()
    print("== CSRF and admin ==")
    r = requests.post(
        BASE + "/api/account/profile",
        json={"display_name": "Evil"},
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        cookies=s.cookies,
    )
    check("cross-origin account POST rejected", r.status_code == 403, r.status_code)

    r = requests.get(BASE + "/healthz")
    check("healthz is ok", r.status_code == 200 and r.json().get("database_ready") is True, r.text)
    r = requests.get(BASE + "/readyz")
    check("readyz is ok", r.status_code == 200, r.text)
    r = requests.get(BASE + "/admin/stats")
    check("admin stats requires a token", r.status_code == 401, r.status_code)
    r = requests.get(BASE + "/admin/stats", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    check("admin stats", r.status_code == 200 and r.json().get("stats", {}).get("users", 0) >= 1, r.text)

    print()
    print("== account deletion ==")
    r = s.post(BASE + "/api/account/delete", json={"username": "not-the-name"})
    check("delete requires the exact username", r.status_code == 400, r.text)
    r = s.post(BASE + "/api/account/delete", json={"username": username})
    check("delete account", r.status_code == 200, r.text)
    r = s.get(BASE + "/", allow_redirects=False)
    check("deleted account is signed out", r.status_code in (302, 303), r.status_code)
    r = recovered.get(BASE + "/", allow_redirects=False)
    check("other sessions are deleted with the account", r.status_code in (302, 303), r.status_code)

    print()
    print("FAILURES:", fails if fails else "none")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
