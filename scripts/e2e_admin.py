"""End-to-end checks for admin surfaces: dynamic client registration with an
initial access token, private_key_jwt, JAR request objects, key rotation and
logout redirect validation.

Start the server with:
    KAGI_ADMIN_TOKEN=test-admin KAGI_REGISTRATION_TOKEN=reg-secret KAGI_SEED_DEMO=1 cargo run
"""

import base64, hashlib, json, secrets, sys, time
import urllib.parse as up
import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils as acu
from cryptography.hazmat.primitives import hashes

BASE = "http://localhost:8080"
ADMIN = "test-admin"
REG = "reg-secret"

fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))
    if not cond: fails.append(name)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def es256(key, header, payload):
    hb = b64u(json.dumps(header, separators=(",", ":")).encode())
    pb = b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign((hb + "." + pb).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = acu.decode_dss_signature(der)
    return hb + "." + pb + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

key = ec.generate_private_key(ec.SECP256R1())
pn = key.public_key().public_numbers()
jwk = {"kty": "EC", "crv": "P-256", "x": b64u(pn.x.to_bytes(32, "big")), "y": b64u(pn.y.to_bytes(32, "big"))}
thumb = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
kid = b64u(hashlib.sha256(thumb.encode()).digest())
jwk["kid"] = kid

# ---------------- dynamic registration gate ----------------
body = {"client_name": "p2", "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["client_credentials"], "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [jwk]}}
r = requests.post(BASE + "/register", json=body)
check("DCR without initial access token rejected", r.status_code == 401, (r.status_code, r.text))
r = requests.post(BASE + "/register", json=body, headers={"Authorization": "Bearer " + REG})
check("DCR with initial access token", r.status_code == 201, (r.status_code, r.text))
if r.status_code != 201:
    print(r.text); sys.exit(1)
reg = r.json()
cid = reg["client_id"]
check("private_key_jwt registration has no secret", "client_secret" not in reg, reg)
check("registration returns the registered auth method", reg.get("token_endpoint_auth_method") == "private_key_jwt", reg)

# Registration must not accept a look-alike HTTP host, private key material or
# an unsafe post-logout URI.
for label, bad_body in [
    ("DCR rejects a locale-lookalike HTTP redirect",
     {"client_name": "bad-host", "redirect_uris": ["http://localhost.evil.example/cb"]}),
    ("DCR rejects private JWK material",
     {"client_name": "bad-jwk", "redirect_uris": ["https://rp.example/cb"],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks": {"keys": [{**jwk, "d": b64u(secrets.token_bytes(32))}]}}),
    ("DCR rejects an unsafe post-logout URI",
     {"client_name": "bad-logout", "redirect_uris": ["https://rp.example/cb"],
      "post_logout_redirect_uris": ["http://localhost.evil.example/out"]}),
]:
    r = requests.post(BASE + "/register", json=bad_body,
                      headers={"Authorization": "Bearer " + REG})
    check(label, r.status_code == 400, (r.status_code, r.text[:300]))

# ---------------- private_key_jwt ----------------
now = int(time.time())
assertion = es256(key, {"alg": "ES256", "kid": kid, "typ": "jwt"}, {
    "iss": cid, "sub": cid, "aud": BASE + "/token", "jti": b64u(secrets.token_bytes(16)),
    "iat": now, "exp": now + 120,
})
r = requests.post(BASE + "/token", data={
    "grant_type": "client_credentials", "scope": "openid",
    "client_id": cid, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": assertion})
check("private_key_jwt client_credentials", r.status_code == 200 and "access_token" in r.json(), (r.status_code, r.text))
at = r.json().get("access_token")

# replay protection for the assertion
r = requests.post(BASE + "/token", data={
    "grant_type": "client_credentials", "scope": "openid",
    "client_id": cid, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": assertion})
check("client assertion replay rejected", r.status_code == 401, (r.status_code, r.text))

# wrong audience
assertion = es256(key, {"alg": "ES256", "kid": kid}, {
    "iss": cid, "sub": cid, "aud": "http://evil.example/token", "jti": b64u(secrets.token_bytes(16)),
    "iat": now, "exp": now + 120})
r = requests.post(BASE + "/token", data={
    "grant_type": "client_credentials", "client_id": cid,
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": assertion})
check("client assertion wrong aud rejected", r.status_code == 401, (r.status_code, r.text))

# ---------------- JAR (request object) ----------------
req_obj = es256(key, {"alg": "ES256", "kid": kid, "typ": "oauth-authz-req+jwt"}, {
    "iss": cid, "aud": BASE, "client_id": cid,
    "iat": now, "exp": now + 120,
    "redirect_uri": "https://rp.example/cb", "response_type": "code",
    "scope": "openid", "state": "jar-state", "nonce": "jar-nonce",
    "code_challenge": b64u(hashlib.sha256(b"verifier" * 8).digest()), "code_challenge_method": "S256",
})
r = requests.get(BASE + "/authorize", params={"client_id": cid, "request": req_obj}, allow_redirects=False)
loc = r.headers.get("Location", "")
check("JAR request object accepted", r.status_code == 303 and loc.startswith("/login?rid="), (r.status_code, loc, r.text[:300]))

# request object with a bad signature
bad = req_obj[:-4] + ("AAAA" if not req_obj.endswith("AAAA") else "BBBB")
r = requests.get(BASE + "/authorize", params={"client_id": cid, "request": bad}, allow_redirects=False)
check("JAR bad signature rejected", r.status_code == 400, (r.status_code, r.text[:300]))

# ---------------- key rotation ----------------
r = requests.post(BASE + "/admin/keys/rotate")
check("key rotation requires admin token", r.status_code == 401, r.status_code)
r = requests.post(BASE + "/admin/keys/rotate", headers={"Authorization": "Bearer wrong"})
check("key rotation rejects wrong token", r.status_code == 401, r.status_code)
r = requests.post(BASE + "/admin/keys/rotate", headers={"Authorization": "Bearer " + ADMIN})
check("key rotation works", r.status_code == 200 and r.json().get("kid"), (r.status_code, r.text))
new_kid = r.json()["kid"]
jwks = requests.get(BASE + "/jwks.json").json()
kids = [k.get("kid") for k in jwks["keys"]]
check("new key published in jwks", new_kid in kids and len(kids) >= 2, kids)
check("no private material in jwks", all("d" not in k for k in jwks["keys"]), jwks)

# ---------------- logout ----------------
r = requests.get(BASE + "/logout", params={"client_id": cid}, allow_redirects=False)
check("logout without session returns a page", r.status_code in (200, 302), r.status_code)
r = requests.get(BASE + "/logout", params={"client_id": cid, "post_logout_redirect_uri": "https://evil.example/x"},
                 allow_redirects=False)
check("logout rejects unregistered post_logout_redirect_uri", r.status_code == 400, (r.status_code, r.text[:200]))

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
