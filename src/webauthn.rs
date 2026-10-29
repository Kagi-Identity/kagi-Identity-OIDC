//! Minimal WebAuthn (Level 2/3) relying-party implementation: passkey
//! registration and authentication, COSE key parsing and attestation checks.
//!
//! Only `none` and `packed` (self-attestation) attestation statements are
//! accepted. Certificate-chain attestation is deliberately rejected: verifying
//! vendor roots is a policy decision that belongs in configuration, not in a
//! default-deny RP.

use crate::config::Config;
use crate::db::{Credential, User};
use crate::util::{b64, b64d, sha256};
use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

pub fn registration_options(cfg: &Config, user: &User, existing: &[Credential]) -> (Value, String) {
    let challenge = crate::util::random_token(32);
    let exclude: Vec<Value> = existing
        .iter()
        .map(|c| {
            json!({
                "type": "public-key",
                "id": c.id,
                "transports": c.transports,
            })
        })
        .collect();

    let public_key = json!({
        "challenge": challenge,
        "rp": { "id": cfg.rp_id, "name": cfg.rp_name },
        "user": {
            "id": b64(user.id.as_bytes()),
            "name": user.username,
            "displayName": user.display_name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },    // ES256
            { "type": "public-key", "alg": -8 },    // EdDSA
            { "type": "public-key", "alg": -257 }   // RS256
        ],
        "timeout": 120_000,
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "attestation": "none",
        "extensions": { "credProps": true }
    });
    (public_key, challenge)
}

pub fn authentication_options(cfg: &Config, allow: &[Credential]) -> (Value, String) {
    let challenge = crate::util::random_token(32);
    let allow_credentials: Vec<Value> = allow
        .iter()
        .map(|c| json!({ "type": "public-key", "id": c.id, "transports": c.transports }))
        .collect();

    let mut public_key = json!({
        "challenge": challenge,
        "rpId": cfg.rp_id,
        "timeout": 120_000,
        "userVerification": "required",
    });
    // An empty allowCredentials list enables discoverable-credential flows
    // (conditional UI / usernameless sign-in).
    if !allow_credentials.is_empty() {
        public_key["allowCredentials"] = json!(allow_credentials);
    }
    (public_key, challenge)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: String,
    pub cose: Vec<u8>,
    pub alg_name: String,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub aaguid: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

pub fn verify_registration(
    cfg: &Config,
    challenge: &str,
    user: &User,
    response: &Value,
) -> anyhow::Result<NewCredential> {
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        bail!("credential type must be public-key");
    }
    let resp = response
        .get("response")
        .ok_or_else(|| anyhow!("missing response object"))?;

    let client_data_json = b64d(
        resp.get("clientDataJSON")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing clientDataJSON"))?,
    )?;
    let attestation_object = b64d(
        resp.get("attestationObject")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing attestationObject"))?,
    )?;

    verify_client_data(cfg, challenge, &client_data_json, "webauthn.create")?;
    let client_hash = sha256(&client_data_json);

    let cbor = cbor::decode(&attestation_object)?;
    let fmt = cbor
        .text_get("fmt")
        .ok_or_else(|| anyhow!("attestationObject has no fmt"))?
        .as_text()
        .ok_or_else(|| anyhow!("fmt must be a string"))?;
    let auth_data_bytes = cbor
        .text_get("authData")
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| anyhow!("attestationObject has no authData"))?;
    let att_stmt = cbor.text_get("attStmt");

    let ad = AuthData::parse(auth_data_bytes, true)?;
    if ad.rp_id_hash != sha256(cfg.rp_id.as_bytes()) {
        bail!("rpIdHash does not match this relying party");
    }
    if ad.flags & (FLAG_UP | FLAG_UV) != (FLAG_UP | FLAG_UV) {
        bail!("user presence and verification are required");
    }
    if ad.flags & FLAG_AT == 0 {
        bail!("attested credential data is missing");
    }

    let cose = ad.cose_key_bytes().to_vec();
    let key = CoseKey::parse(&cose)?;
    verify_attestation(fmt, att_stmt, &key, auth_data_bytes, &client_hash)?;

    let id = b64(ad.credential_id.as_slice());
    let transports: Vec<String> = resp
        .get("transports")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .filter(|t| matches!(t.as_str(), "usb" | "nfc" | "ble" | "internal" | "hybrid"))
                .collect()
        })
        .unwrap_or_default();

    if let Some(handle) = resp.get("userHandle").and_then(Value::as_str) {
        if !handle.is_empty() {
            let raw = b64d(handle)?;
            if raw != user.id.as_bytes() {
                bail!("userHandle does not match the registering user");
            }
        }
    }

    Ok(NewCredential {
        id,
        cose,
        alg_name: key.alg_name().to_string(),
        sign_count: ad.sign_count as i64,
        transports,
        aaguid: crate::util::hex(&ad.aaguid),
        backup_eligible: ad.flags & FLAG_BE != 0,
        backup_state: ad.flags & FLAG_BS != 0,
    })
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthOutcome {
    pub sign_count: i64,
    pub backup_state: bool,
    pub user_id: String,
}

pub fn verify_authentication(
    cfg: &Config,
    challenge: &str,
    response: &Value,
    credential: &Credential,
) -> anyhow::Result<AuthOutcome> {
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        bail!("credential type must be public-key");
    }
    let raw_id = response
        .get("rawId")
        .and_then(Value::as_str)
        .or_else(|| response.get("id").and_then(Value::as_str))
        .ok_or_else(|| anyhow!("missing rawId"))?;
    if b64d(raw_id)? != b64d(&credential.id)? {
        bail!("credential id does not match");
    }

    let resp = response
        .get("response")
        .ok_or_else(|| anyhow!("missing response object"))?;
    let client_data_json = b64d(
        resp.get("clientDataJSON")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing clientDataJSON"))?,
    )?;
    let authenticator_data = b64d(
        resp.get("authenticatorData")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing authenticatorData"))?,
    )?;
    let signature = b64d(
        resp.get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing signature"))?,
    )?;

    verify_client_data(cfg, challenge, &client_data_json, "webauthn.get")?;

    let ad = AuthData::parse(&authenticator_data, false)?;
    if ad.rp_id_hash != sha256(cfg.rp_id.as_bytes()) {
        bail!("rpIdHash does not match this relying party");
    }
    if ad.flags & (FLAG_UP | FLAG_UV) != (FLAG_UP | FLAG_UV) {
        bail!("user presence and verification are required");
    }

    if let Some(handle) = resp.get("userHandle").and_then(Value::as_str) {
        if !handle.is_empty() {
            let raw = b64d(handle)?;
            if raw != credential.user_id.as_bytes() {
                bail!("userHandle does not match the credential owner");
            }
        }
    }

    let key = CoseKey::parse(&credential.public_key)?;
    if key.alg_name() != credential.key_type.as_str() {
        bail!("stored credential algorithm mismatch");
    }

    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client_data_json));
    key.verify(&signed, &signature)?;

    // Signature counter: platform passkeys often report 0 forever, so a
    // non-zero counter that fails to advance is the clone signal.
    let new_count = ad.sign_count as i64;
    if (new_count != 0 || credential.sign_count != 0) && new_count <= credential.sign_count {
        bail!("signature counter did not advance (possible cloned authenticator)");
    }

    let _ = ad.flags & FLAG_ED; // extensions are parsed but not interpreted

    Ok(AuthOutcome {
        sign_count: new_count,
        backup_state: ad.flags & FLAG_BS != 0,
        user_id: credential.user_id.clone(),
    })
}

// ---------------------------------------------------------------------------
// clientDataJSON
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

fn verify_client_data(
    cfg: &Config,
    challenge: &str,
    raw: &[u8],
    expected_type: &str,
) -> anyhow::Result<ClientData> {
    let data: ClientData = serde_json::from_slice(raw).context("clientDataJSON is not JSON")?;
    if data.typ != expected_type {
        bail!("unexpected clientData type {}", data.typ);
    }
    if data.challenge != challenge {
        bail!("challenge mismatch");
    }
    if data.origin.trim_end_matches('/') != cfg.webauthn_origin().trim_end_matches('/') {
        bail!("origin mismatch: {}", data.origin);
    }
    if data.cross_origin {
        bail!("cross-origin WebAuthn ceremonies are not allowed");
    }
    Ok(data)
}

// ---------------------------------------------------------------------------
// Authenticator data
// ---------------------------------------------------------------------------

struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    cose: Vec<u8>,
}

impl AuthData {
    fn parse(bytes: &[u8], expect_attested: bool) -> anyhow::Result<Self> {
        if bytes.len() < 37 {
            bail!("authenticator data is truncated");
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[..32]);
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

        let mut out = Self {
            rp_id_hash,
            flags,
            sign_count,
            aaguid: [0u8; 16],
            credential_id: Vec::new(),
            cose: Vec::new(),
        };

        if flags & FLAG_AT != 0 {
            if bytes.len() < 55 {
                bail!("attested credential data is truncated");
            }
            out.aaguid.copy_from_slice(&bytes[37..53]);
            let cred_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
            let start = 55;
            let end = start + cred_len;
            if bytes.len() < end {
                bail!("credential id is truncated");
            }
            out.credential_id = bytes[start..end].to_vec();
            // The credential public key is a CBOR map; anything after it (for
            // example authenticator extensions) is intentionally ignored.
            let (_, consumed) = cbor::decode_one(&bytes[end..])?;
            out.cose = bytes[end..end + consumed].to_vec();
            // Validate that the COSE key is well formed now, not at login time.
            CoseKey::parse(&out.cose)?;
        } else if expect_attested {
            bail!("attested credential data is missing");
        }

        Ok(out)
    }

    fn cose_key_bytes(&self) -> &[u8] {
        &self.cose
    }
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

fn verify_attestation(
    fmt: &str,
    att_stmt: Option<&Cbor>,
    key: &CoseKey,
    auth_data: &[u8],
    client_hash: &[u8; 32],
) -> anyhow::Result<()> {
    match fmt {
        "none" => Ok(()),
        "packed" => {
            let stmt = att_stmt.ok_or_else(|| anyhow!("packed attestation has no attStmt"))?;
            if stmt.text_get("x5c").is_some() {
                bail!("certificate-based attestation is not accepted by this RP");
            }
            let alg = stmt
                .text_get("alg")
                .and_then(Cbor::as_int)
                .ok_or_else(|| anyhow!("packed attestation has no alg"))?;
            if alg != key.alg as i128 {
                bail!("attestation alg does not match the credential key");
            }
            let sig = stmt
                .text_get("sig")
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| anyhow!("packed attestation has no sig"))?;
            let mut signed = auth_data.to_vec();
            signed.extend_from_slice(client_hash);
            key.verify(&signed, sig)?;
            Ok(())
        }
        other => bail!("unsupported attestation format {other}"),
    }
}

// ---------------------------------------------------------------------------
// COSE keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CoseKey {
    kty: i128,
    alg: i128,
    crv: Option<i128>,
    x: Vec<u8>,
    y: OptionalBytes,
    n: OptionalBytes,
    e: OptionalBytes,
}

type OptionalBytes = Option<Vec<u8>>;

impl CoseKey {
    fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let map = cbor::decode(bytes)?;
        if !matches!(map, Cbor::Map(_)) {
            bail!("COSE key must be a CBOR map");
        }
        let kty = map.map_int(1).ok_or_else(|| anyhow!("COSE key has no kty"))?;
        let alg = map.map_int(3).ok_or_else(|| anyhow!("COSE key has no alg"))?;
        let crv = map.map_int(-1);
        let x = map.map_bytes(-2).unwrap_or_default();
        let y = map.map_bytes(-3);
        let n = map.map_bytes(-1);
        let e = map.map_bytes(-2);

        let key = Self { kty, alg, crv, x, y, n, e };
        key.validate()?;
        Ok(key)
    }

    fn validate(&self) -> anyhow::Result<()> {
        match (self.kty, self.alg) {
            (2, -7) => {
                if self.crv != Some(1) {
                    bail!("ES256 key must use the P-256 curve");
                }
                if self.x.len() != 32 || self.y.as_ref().map(|y| y.len()) != Some(32) {
                    bail!("P-256 coordinates must be 32 bytes");
                }
            }
            (1, -8) => {
                if self.crv != Some(6) {
                    bail!("EdDSA key must use Ed25519");
                }
                if self.x.len() != 32 {
                    bail!("Ed25519 public key must be 32 bytes");
                }
            }
            (3, -257) => {
                if self.n.is_none() || self.e.is_none() {
                    bail!("RSA key is incomplete");
                }
            }
            (kty, alg) => bail!("unsupported COSE key (kty={kty}, alg={alg})"),
        }
        Ok(())
    }

    fn alg_name(&self) -> &'static str {
        match self.alg {
            -7 => "ES256",
            -8 => "EdDSA",
            -257 => "RS256",
            _ => "unknown",
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> anyhow::Result<()> {
        match self.alg {
            -7 => {
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(&self.x);
                sec1.extend_from_slice(self.y.as_ref().expect("validated"));
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|_| anyhow!("invalid P-256 public key"))?;
                // WebAuthn uses ASN.1 DER encoded ECDSA signatures.
                let signature = p256::ecdsa::Signature::from_der(sig)
                    .map_err(|_| anyhow!("invalid DER ECDSA signature"))?;
                p256::ecdsa::signature::Verifier::verify(&vk, msg, &signature)
                    .map_err(|_| anyhow!("ECDSA signature verification failed"))?;
            }
            -8 => {
                let raw: [u8; 32] = self
                    .x
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("invalid Ed25519 key"))?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                    .map_err(|_| anyhow!("invalid Ed25519 public key"))?;
                let signature = ed25519_dalek::Signature::from_slice(sig)
                    .map_err(|_| anyhow!("invalid Ed25519 signature"))?;
                ed25519_dalek::Verifier::verify(&vk, msg, &signature)
                    .map_err(|_| anyhow!("Ed25519 signature verification failed"))?;
            }
            -257 => {
                let key = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(self.n.as_ref().expect("validated")),
                    rsa::BigUint::from_bytes_be(self.e.as_ref().expect("validated")),
                )
                .map_err(|_| anyhow!("invalid RSA public key"))?;
                let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
                let signature = rsa::pkcs1v15::Signature::try_from(sig)
                    .map_err(|_| anyhow!("invalid RSA signature encoding"))?;
                rsa::signature::Verifier::verify(&vk, msg, &signature)
                    .map_err(|_| anyhow!("RSA signature verification failed"))?;
            }
            _ => bail!("unsupported signature algorithm"),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tiny definite-length CBOR decoder (enough for WebAuthn structures)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Uint(u64),
    Nint(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(t) => Some(t),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Uint(v) => Some(*v as i128),
            Cbor::Nint(v) => Some(*v),
            _ => None,
        }
    }

    fn text_get(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Cbor::Text(t) if t == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    fn map_int(&self, key: i128) -> Option<i128> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| {
                if k.as_int() == Some(key) {
                    v.as_int()
                } else {
                    None
                }
            }),
            _ => None,
        }
    }

    fn map_bytes(&self, key: i128) -> Option<Vec<u8>> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| {
                if k.as_int() == Some(key) {
                    v.as_bytes().map(|b| b.to_vec())
                } else {
                    None
                }
            }),
            _ => None,
        }
    }
}

mod cbor {
    use super::Cbor;
    use anyhow::{anyhow, bail, Result};

    pub fn decode(bytes: &[u8]) -> Result<Cbor> {
        let (value, used) = decode_one(bytes)?;
        if used != bytes.len() {
            bail!("trailing bytes after CBOR value");
        }
        Ok(value)
    }

    pub fn decode_one(bytes: &[u8]) -> Result<(Cbor, usize)> {
        let mut d = Decoder { b: bytes, pos: 0 };
        let v = d.value()?;
        Ok((v, d.pos))
    }

    struct Decoder<'a> {
        b: &'a [u8],
        pos: usize,
    }

    impl<'a> Decoder<'a> {
        fn byte(&mut self) -> Result<u8> {
            let b = *self.b.get(self.pos).ok_or_else(|| anyhow!("unexpected end of CBOR"))?;
            self.pos += 1;
            Ok(b)
        }

        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            if self.pos + n > self.b.len() {
                bail!("unexpected end of CBOR");
            }
            let s = &self.b[self.pos..self.pos + n];
            self.pos += n;
            Ok(s)
        }

        fn len(&mut self, ai: u8) -> Result<usize> {
            Ok(match ai {
                0..=23 => ai as usize,
                24 => self.byte()? as usize,
                25 => u16::from_be_bytes([self.byte()?, self.byte()?]) as usize,
                26 => {
                    let b = self.take(4)?;
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
                }
                27 => {
                    let b = self.take(8)?;
                    let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    usize::try_from(v).map_err(|_| anyhow!("CBOR length too large"))?
                }
                _ => bail!("indefinite-length CBOR is not supported"),
            })
        }

        fn value(&mut self) -> Result<Cbor> {
            let initial = self.byte()?;
            let major = initial >> 5;
            let ai = initial & 0x1f;
            match major {
                0 => Ok(Cbor::Uint(self.len(ai)? as u64)),
                1 => Ok(Cbor::Nint(-1 - self.len(ai)? as i128)),
                2 => {
                    let n = self.len(ai)?;
                    Ok(Cbor::Bytes(self.take(n)?.to_vec()))
                }
                3 => {
                    let n = self.len(ai)?;
                    let s = std::str::from_utf8(self.take(n)?)?;
                    Ok(Cbor::Text(s.to_string()))
                }
                4 => {
                    let n = self.len(ai)?;
                    let mut items = Vec::with_capacity(n.min(64));
                    for _ in 0..n {
                        items.push(self.value()?);
                    }
                    Ok(Cbor::Array(items))
                }
                5 => {
                    let n = self.len(ai)?;
                    let mut items = Vec::with_capacity(n.min(64));
                    for _ in 0..n {
                        let k = self.value()?;
                        let v = self.value()?;
                        items.push((k, v));
                    }
                    Ok(Cbor::Map(items))
                }
                6 => {
                    let _tag = self.len(ai)?;
                    self.value()
                }
                7 => match ai {
                    20 => Ok(Cbor::Bool(false)),
                    21 => Ok(Cbor::Bool(true)),
                    22 => Ok(Cbor::Null),
                    _ => bail!("unsupported CBOR simple value"),
                },
                _ => bail!("invalid CBOR major type"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_uint(major: u8, v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        if v < 24 {
            out.push((major << 5) | v as u8);
        } else if v <= u8::MAX as u64 {
            out.push((major << 5) | 24);
            out.push(v as u8);
        } else {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        out
    }

    #[test]
    fn parses_cose_like_map() {
        // {1: 2, 3: -7, -1: 1, -2: h'00..', -3: h'00..'}
        let mut bytes = vec![0xa5];
        bytes.extend(encode_uint(0, 1));
        bytes.extend(encode_uint(0, 2));
        bytes.extend(encode_uint(0, 3));
        bytes.extend(encode_uint(1, 6)); // -7
        bytes.extend(encode_uint(1, 0)); // -1
        bytes.extend(encode_uint(0, 1));
        bytes.extend(encode_uint(1, 1)); // -2
        bytes.push(0x58);
        bytes.push(32);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend(encode_uint(1, 2)); // -3
        bytes.push(0x58);
        bytes.push(32);
        bytes.extend_from_slice(&[0u8; 32]);

        let v = cbor::decode(&bytes).unwrap();
        assert_eq!(v.map_int(1), Some(2));
        assert_eq!(v.map_int(3), Some(-7));
        assert_eq!(v.map_int(-1), Some(1));
        assert_eq!(v.map_bytes(-2).unwrap().len(), 32);
    }
}
