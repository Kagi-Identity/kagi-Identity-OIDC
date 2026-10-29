"""End-to-end checks for JARM, DPoP binding across PAR/code/token, CORS and
max_age. Seeds a session directly in the database.

    KAGI_SEED_DEMO=1 KAGI_DB=kagi-e2e.db cargo run
    KAGI_DB=kagi-e2e.db python scripts/e2e_advanced.py

With PostgreSQL / Supabase, seed through psycopg2 instead:
    KAGI_SEED_DEMO=1 KAGI_DATABASE_URL=postgresql://... cargo run
    KAGI_DATABASE_URL=postgresql://... python scripts/e2e_advanced.py
"""

import base64, hashlib, json, os, re, secrets, sqlite3, sys, time
import urllib.parse as up
import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils as acu
from cryptography.hazmat.primitives import hashes

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080")
DB = os.environ.get("KAGI_DB", "kagi-e2e.db")
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"

fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"))
    if not cond: fails.append(name)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

sid = secrets.token_urlsafe(32)
now = int(time.time())
sid_hash = hashlib.sha256(sid.encode()).hexdigest()
DATABASE_URL = os.environ.get("KAGI_DATABASE_URL")
if DATABASE_URL:
    # PostgreSQL / Supabase backend: seed through psycopg2.
    import psycopg2
    con = psycopg2.connect(DATABASE_URL)
    cur = con.cursor()
    cur.execute("""INSERT INTO users (id,username,display_name,email,email_verified,created_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO UPDATE SET username=excluded.username,
                     display_name=excluded.display_name, email=excluded.email,
                     email_verified=excluded.email_verified""",
                ("user-alice", "alice", "Alice Example", "alice@example.com", 1, now))
    cur.execute("""INSERT INTO sessions (id,user_id,auth_time,amr,acr,expires_at,created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO UPDATE SET auth_time=excluded.auth_time,
                     expires_at=excluded.expires_at""",
                (sid_hash, "user-alice", now, '["passkey"]', "urn:kagi:acr:passkey", now + 3600, now))
    con.commit(); con.close()
else:
    con = sqlite3.connect(DB, timeout=10)
    con.execute("INSERT OR REPLACE INTO users (id,username,display_name,email,email_verified,created_at) VALUES (?,?,?,?,?,?)",
                ("user-alice", "alice", "Alice Example", "alice@example.com", 1, now))
    con.execute("INSERT OR REPLACE INTO sessions (id,user_id,auth_time,amr,acr,expires_at,created_at) VALUES (?,?,?,?,?,?,?)",
                (sid_hash, "user-alice", now, '["passkey"]', "urn:kagi:acr:passkey", now + 3600, now))
    con.commit(); con.close()

S = requests.Session()
S.cookies.set("kagi_sid", sid)

def authorize(ru, **extra):
    r = S.get(BASE + "/authorize", params={"client_id": CLIENT, "request_uri": ru, **extra}, allow_redirects=False)
    return r

def approve(rid):
    r = S.get(BASE + "/consent", params={"rid": rid})
    csrf = re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
    return S.post(BASE + "/consent", data={"rid": rid, "csrf": csrf, "decision": "allow"}, allow_redirects=False)

# ---------------- JARM ----------------
verifier = b64u(secrets.token_bytes(48))
ch = b64u(hashlib.sha256(verifier.encode()).digest())
authz = {"client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
         "scope": "openid profile email", "state": "jarm-state", "nonce": "jarm-nonce",
         "code_challenge": ch, "code_challenge_method": "S256", "response_mode": "query.jwt"}
r = S.post(BASE + "/par", data=authz)
ru = r.json()["request_uri"]
r = authorize(ru)
check("JARM authorize -> consent", r.status_code == 303 and "/consent?rid=" in r.headers.get("Location", ""), r.headers.get("Location"))
rid = up.parse_qs(up.urlparse(r.headers["Location"]).query)["rid"][0]
r = approve(rid)
loc = r.headers.get("Location", "")
check("JARM response in query", r.status_code == 303 and "response=" in loc, (r.status_code, loc))
q = up.parse_qs(up.urlparse(loc).query)
jwt = q["response"][0]
h, p, sg = jwt.split(".")
jh = json.loads(unb64(h)); jc = json.loads(unb64(p))
jwks = requests.get(BASE + "/jwks.json").json()
k = next(x for x in jwks["keys"] if x.get("kid") == jh.get("kid"))
pub = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(k["x"]), "big"), int.from_bytes(unb64(k["y"]), "big"), ec.SECP256R1()).public_key()
sig = unb64(sg)
pub.verify(acu.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
           (h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
check("JARM signature valid", True)
check("JARM claims", jc.get("iss") == BASE and jc.get("aud") == CLIENT and jc.get("state") == "jarm-state" and jc.get("code"), jc)
jarm_code = jc["code"]
r = S.post(BASE + "/token", data={"grant_type": "authorization_code", "code": jarm_code, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier})
check("JARM code exchanges", r.status_code == 200 and "id_token" in r.json(), (r.status_code, r.text[:300]))

# ---------------- DPoP binding across PAR -> code -> token ----------------
def mkkey():
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    t = json.dumps({kk: jwk[kk] for kk in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return k, jwk, b64u(hashlib.sha256(t.encode()).digest())

def proof(k, jwk, htm, htu):
    pl = {"jti": b64u(secrets.token_bytes(16)), "htm": htm, "htu": htu, "iat": int(time.time())}
    hb = b64u(json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}, separators=(",", ":")).encode())
    pb = b64u(json.dumps(pl, separators=(",", ":")).encode())
    der = k.sign((hb + "." + pb).encode(), ec.ECDSA(hashes.SHA256()))
    a, b = acu.decode_dss_signature(der)
    return hb + "." + pb + "." + b64u(a.to_bytes(32, "big") + b.to_bytes(32, "big"))

kA, jwkA, jktA = mkkey()
kB, jwkB, jktB = mkkey()
authz2 = {**authz, "state": "dpop-state", "response_mode": "query", "dpop_jkt": jktA, "prompt": "none"}
r = S.post(BASE + "/par", data=authz2, headers={"DPoP": proof(kA, jwkA, "POST", BASE + "/par")})
check("PAR DPoP", r.status_code == 200, r.text)
ru2 = r.json()["request_uri"]
r = authorize(ru2)
loc = r.headers.get("Location", "")
check("authorize with consent and prompt=none", r.status_code == 303 and "code=" in loc, (r.status_code, loc))
code2 = up.parse_qs(up.urlparse(loc).query)["code"][0]

r = S.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code2, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier},
           headers={"DPoP": proof(kB, jwkB, "POST", BASE + "/token")})
check("code bound to key A rejects key B", r.status_code == 400, (r.status_code, r.text[:200]))
r = S.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code2, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier})
check("dpop-bound code requires a proof", r.status_code == 400, (r.status_code, r.text[:200]))
r = S.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code2, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier},
           headers={"DPoP": proof(kA, jwkA, "POST", BASE + "/token")})
check("code bound to key A accepts key A", r.status_code == 200 and r.json().get("token_type") == "DPoP", (r.status_code, r.text[:200]))

# ---------------- CORS preflight ----------------
r = requests.options(BASE + "/token", headers={"Origin": "https://rp.example",
                                              "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": "dpop"})
check("CORS preflight", r.status_code == 204 and r.headers.get("access-control-allow-origin") == "*"
      and "dpop" in r.headers.get("access-control-allow-headers", ""), dict(r.headers))

# ---------------- max_age ----------------
authz3 = {**authz, "state": "maxage", "response_mode": "query", "max_age": "0"}
r = S.post(BASE + "/par", data=authz3)
ru3 = r.json()["request_uri"]
r = authorize(ru3)
check("max_age=0 forces re-login", r.status_code == 303 and r.headers.get("Location", "").startswith("/login?rid="), r.headers.get("Location"))

# ---------------- prompt=none after consent, without nonce ----------------
authz4 = {**authz, "state": "nonce-less", "response_mode": "query", "prompt": "none"}
# nonce is required for implicit/hybrid only; code flow may omit it
authz4.pop("nonce", None)
r = S.post(BASE + "/par", data=authz4)
ru4 = r.json()["request_uri"]
r = authorize(ru4)
check("prompt=none silent re-authorization", r.status_code == 303 and "code=" in r.headers.get("Location", ""), r.headers.get("Location"))

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
