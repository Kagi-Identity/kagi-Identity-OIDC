"""End-to-end checks for passkey sign-up and sign-in using a software
authenticator (no browser needed). Exercises the server-side WebAuthn
implementation, including clientData/origin/type validation, COSE keys,
assertion signatures and the signature counter.

    cargo run
    python scripts/e2e_webauthn.py
"""

import base64, hashlib, json, secrets, struct, sys, time
import urllib.parse as up
import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils as acu
from cryptography.hazmat.primitives import hashes

BASE = "http://localhost:8080"
ORIGIN = "http://localhost:8080"
RPID = "localhost"
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"

fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))
    if not cond:
        fails.append(name)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# ---- minimal CBOR encoder (only what an attestation object needs) ----
def cbor_head(major, n):
    if n < 24: return bytes([(major << 5) | n])
    if n < 256: return bytes([(major << 5) | 24, n])
    if n < 65536: return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    return bytes([(major << 5) | 26]) + struct.pack(">I", n)

def cbor(v):
    if isinstance(v, dict):
        out = cbor_head(5, len(v))
        for k, val in v.items(): out += cbor(k) + cbor(val)
        return out
    if isinstance(v, bytes): return cbor_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return cbor_head(3, len(b)) + b
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
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
    return json.dumps({"type": typ, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
                      separators=(",", ":")).encode()

print("== signup with a software authenticator ==")
username = "carol" + secrets.token_hex(3)
s = requests.Session()
r = s.post(BASE + "/api/webauthn/signup/options", json={"username": username, "display_name": "Carol", "email": "carol@example.com"})
check("signup options", r.status_code == 200, r.text)
opts = r.json()["publicKey"]; rid = r.json()["rid"]
challenge = opts["challenge"]
check("options are discoverable+uv", opts["authenticatorSelection"]["residentKey"] == "required"
      and opts["authenticatorSelection"]["userVerification"] == "required", opts.get("authenticatorSelection"))
check("options include ES256", any(p["alg"] == -7 for p in opts["pubKeyCredParams"]), opts["pubKeyCredParams"])
user_handle = opts["user"]["id"]

key = ec.generate_private_key(ec.SECP256R1())
cred_id = secrets.token_bytes(32)
cdj = client_data("webauthn.create", challenge)
att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data(cred_id, key.public_key(), 0x45, 0)})
cred = {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att), "transports": ["internal"]},
    "clientExtensionResults": {"credProps": {"rk": True}},
}
r = s.post(BASE + "/api/webauthn/signup/verify", json={"rid": rid, "credential": cred})
check("signup verify", r.status_code == 200 and r.json().get("ok") is True, r.text)
check("signup sets a session cookie", "kagi_sid" in s.cookies, list(s.cookies.keys()))
r = s.get(BASE + "/")
check("account page works after signup", r.status_code == 200 and username in r.text, r.status_code)

# replay the same signup flow
r2 = s.post(BASE + "/api/webauthn/signup/verify", json={"rid": rid, "credential": cred})
check("signup flow is single use", r2.status_code >= 400, (r2.status_code, r2.text))

# duplicate username
r = requests.post(BASE + "/api/webauthn/signup/options", json={"username": username, "display_name": "Carol"})
check("duplicate username rejected", r.status_code == 400, r.text)

# ---- a wrong origin must fail ----
r = requests.post(BASE + "/api/webauthn/signup/options", json={"username": username + "x", "display_name": "Carol"})
o2 = r.json()["publicKey"]; rid2 = r.json()["rid"]
bad_cdj = json.dumps({"type": "webauthn.create", "challenge": o2["challenge"], "origin": "http://evil.example"}).encode()
bad_att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data(secrets.token_bytes(32), key.public_key(), 0x45, 0)})
r = requests.post(BASE + "/api/webauthn/signup/verify", json={"rid": rid2, "credential": {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(bad_cdj), "attestationObject": b64u(bad_att)}}})
check("wrong origin rejected", r.status_code == 400, r.text)

# wrong type
r = requests.post(BASE + "/api/webauthn/signup/options", json={"username": username + "y", "display_name": "Carol"})
o3 = r.json()["publicKey"]; rid3 = r.json()["rid"]
bad_cdj = client_data("webauthn.get", o3["challenge"])
bad_att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data(secrets.token_bytes(32), key.public_key(), 0x45, 0)})
r = requests.post(BASE + "/api/webauthn/signup/verify", json={"rid": rid3, "credential": {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(bad_cdj), "attestationObject": b64u(bad_att)}}})
check("wrong clientData type rejected", r.status_code == 400, r.text)

print()
print("== login through /authorize ==")
new = requests.Session()
verifier = b64u(secrets.token_bytes(48))
challenge_pkce = b64u(hashlib.sha256(verifier.encode()).digest())
authz = {"client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
         "scope": "openid profile email", "state": "st-login", "nonce": "n-login",
         "code_challenge": challenge_pkce, "code_challenge_method": "S256"}
r = new.post(BASE + "/par", data=authz)
ru = r.json()["request_uri"]
r = new.get(BASE + "/authorize", params={"client_id": CLIENT, "request_uri": ru}, allow_redirects=False)
loc = r.headers.get("Location", "")
check("authorize -> login", r.status_code == 303 and loc.startswith("/login?rid="), (r.status_code, loc))
arid = up.parse_qs(up.urlparse(loc).query)["rid"][0]

r = new.get(BASE + "/login", params={"rid": arid})
check("login page renders", r.status_code == 200 and "パスキー" in r.text, r.status_code)
r = new.post(BASE + "/api/webauthn/login/options", json={"rid": arid})
check("login options", r.status_code == 200, r.text)
opts = r.json()["publicKey"]
ch = opts["challenge"]

cdj = client_data("webauthn.get", ch)
ad = auth_data(cred_id, key.public_key(), 0x05, 1, include_cred=False)
der = key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
assertion = {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(ad),
                 "signature": b64u(der), "userHandle": user_handle},
    "clientExtensionResults": {},
}
r = new.post(BASE + "/api/webauthn/login/verify", json={"rid": arid, "credential": assertion})
check("login verify", r.status_code == 200 and r.json().get("ok") is True, r.text)
check("login next is consent", r.json().get("next", "").startswith("/consent?rid="), r.json() if r.ok else r.text)
check("login sets session cookie", "kagi_sid" in new.cookies, list(new.cookies.keys()))

# tampered signature
r = new.post(BASE + "/api/webauthn/login/options", json={"rid": arid})
ch2 = r.json()["publicKey"]["challenge"]
cdj2 = client_data("webauthn.get", ch2)
ad2 = auth_data(cred_id, key.public_key(), 0x05, 2, include_cred=False)
bad = bytearray(key.sign(ad2 + hashlib.sha256(cdj2).digest(), ec.ECDSA(hashes.SHA256())))
bad[-5] ^= 0xFF
r = new.post(BASE + "/api/webauthn/login/verify", json={"rid": arid, "credential": {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(cdj2), "authenticatorData": b64u(ad2),
                 "signature": b64u(bytes(bad)), "userHandle": user_handle}}})
check("tampered assertion rejected", r.status_code == 400, r.text)

# counter regression (clone)
r = new.post(BASE + "/api/webauthn/login/options", json={"rid": arid})
ch3 = r.json()["publicKey"]["challenge"]
cdj3 = client_data("webauthn.get", ch3)
ad3 = auth_data(cred_id, key.public_key(), 0x05, 1, include_cred=False)
sig3 = key.sign(ad3 + hashlib.sha256(cdj3).digest(), ec.ECDSA(hashes.SHA256()))
r = new.post(BASE + "/api/webauthn/login/verify", json={"rid": arid, "credential": {
    "id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
    "response": {"clientDataJSON": b64u(cdj3), "authenticatorData": b64u(ad3),
                 "signature": b64u(sig3), "userHandle": user_handle}}})
check("signature counter regression rejected", r.status_code == 400, r.text)

# complete the flow with the session from the successful login
nxt = r.json()["next"] if False else None
r = new.get(BASE + "/consent", params={"rid": arid})
check("consent page after login", r.status_code == 200 and 'name="csrf"' in r.text, r.status_code)
import re
csrf = re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
r = new.post(BASE + "/consent", data={"rid": arid, "csrf": csrf, "decision": "allow"}, allow_redirects=False)
loc = r.headers.get("Location", "")
check("consent completes to redirect_uri", r.status_code == 303 and "code=" in loc, (r.status_code, loc))
code = up.parse_qs(up.urlparse(loc).query)["code"][0]
r = new.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": REDIRECT, "client_id": CLIENT,
                                    "code_verifier": verifier})
check("passkey login grants tokens", r.status_code == 200 and "access_token" in r.json(), r.text)
if r.status_code == 200:
    idt = r.json()["id_token"]
    claims = json.loads(unb64(idt.split(".")[1]))
    check("id token amr is passkey", claims.get("amr") in (["pop", "hwk"], ["pop", "swk"]), claims.get("amr"))
    check("id token sub is the new user", claims.get("sub") == unb64(user_handle).decode(), claims.get("sub"))

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
