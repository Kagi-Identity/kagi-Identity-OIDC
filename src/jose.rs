use crate::util::{b64, b64d, sha256};
use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};

/// An ES256 signing key with its key id.
#[derive(Clone)]
pub struct SigKey {
    pub kid: String,
    pub key: p256::ecdsa::SigningKey,
}

impl SigKey {
    pub fn public_jwk(&self) -> Value {
        let vk = self.key.verifying_key();
        let point = vk.to_sec1_point(false);
        let x = point.x().expect("uncompressed point has x");
        let y = point.y().expect("uncompressed point has y");
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64(&x[..]),
            "y": b64(&y[..]),
            "kid": self.kid,
            "use": "sig",
            "alg": "ES256",
        })
    }

    pub fn private_jwk(&self) -> Value {
        let mut jwk = self.public_jwk();
        jwk["d"] = json!(b64(&self.key.to_bytes()[..]));
        jwk
    }

    pub fn from_jwk(jwk: &Value, kid: &str) -> anyhow::Result<Self> {
        let d = jwk
            .get("d")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("private JWK has no `d`"))?;
        let raw = b64d(d)?;
        let key = p256::ecdsa::SigningKey::from_slice(&raw)
            .map_err(|_| anyhow!("invalid P-256 private scalar"))?;
        Ok(Self { kid: kid.to_string(), key })
    }

    /// Compact JWS over `claims`, signed with ES256.
    pub fn sign(&self, typ: Option<&str>, claims: &Value) -> anyhow::Result<String> {
        let mut header = json!({"alg": "ES256", "kid": self.kid});
        if let Some(t) = typ {
            header["typ"] = json!(t);
        }
        let h = b64(&serde_json::to_vec(&header)?);
        let p = b64(&serde_json::to_vec(claims)?);
        let input = format!("{h}.{p}");
        let sig: p256::ecdsa::Signature =
            p256::ecdsa::signature::Signer::sign(&self.key, input.as_bytes());
        let bytes = sig.to_bytes();
        Ok(format!("{input}.{}", b64(&bytes[..])))
    }
}

/// Split a compact JWS and decode the header and payload without verifying.
pub fn decode_segments(token: &str) -> anyhow::Result<(Value, Value, String, Vec<u8>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("malformed JWT: expected 3 segments");
    }
    let header: Value = serde_json::from_slice(&b64d(parts[0])?).context("JWT header is not JSON")?;
    let claims: Value = serde_json::from_slice(&b64d(parts[1])?).context("JWT payload is not JSON")?;
    let sig = b64d(parts[2])?;
    Ok((header, claims, format!("{}.{}", parts[0], parts[1]), sig))
}

fn typ_ok(header: &Value, expected: &str) -> bool {
    match header.get("typ").and_then(Value::as_str) {
        Some(t) if t.eq_ignore_ascii_case(expected) => true,
        // RFC 9101 request objects and RFC 7523 client assertions commonly use
        // the generic `JWT` typ, and typ is optional for assertions.
        Some(t) if expected == "oauth-authz-req+jwt" && t.eq_ignore_ascii_case("JWT") => true,
        Some(t) if expected == "JWT" && t.eq_ignore_ascii_case("oauth-client-assertion+jwt") => true,
        None => expected == "oauth-authz-req+jwt" || expected == "JWT",
        _ => false,
    }
}

/// Verify a compact JWS against an embedded/public JWK.
pub fn verify_with_jwk(jwk: &Value, token: &str, expected_typ: Option<&str>) -> anyhow::Result<(Value, Value)> {
    let (header, claims, input, sig) = decode_segments(token)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWT header has no alg"))?;
    if let Some(exp) = expected_typ {
        if !typ_ok(&header, exp) {
            bail!("unexpected JWT typ");
        }
    }
    verify_signature(alg, jwk, input.as_bytes(), &sig)?;
    Ok((header, claims))
}

/// Verify a compact JWS against a JWK Set, selecting by `kid`.
pub fn verify_with_jwks(jwks: &Value, token: &str, expected_typ: Option<&str>) -> anyhow::Result<(Value, Value)> {
    let (header, _claims, _input, _sig) = decode_segments(token)?;
    let kid = header.get("kid").and_then(Value::as_str);
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("jwks has no keys array"))?;

    let candidates: Vec<&Value> = match kid {
        Some(kid) => keys
            .iter()
            .filter(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
            .collect(),
        None if keys.len() == 1 => keys.iter().collect(),
        None => keys.iter().collect(),
    };
    if candidates.is_empty() {
        bail!("no matching key for kid");
    }
    let mut last_err = anyhow!("no usable key");
    for jwk in candidates {
        match verify_with_jwk(jwk, token, expected_typ) {
            Ok(v) => return Ok(v),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub fn verify_signature(alg: &str, jwk: &Value, msg: &[u8], sig: &[u8]) -> anyhow::Result<()> {
    match alg {
        "ES256" => {
            let x = b64d(jwk.get("x").and_then(Value::as_str).ok_or_else(|| anyhow!("EC JWK missing x"))?)?;
            let y = b64d(jwk.get("y").and_then(Value::as_str).ok_or_else(|| anyhow!("EC JWK missing y"))?)?;
            if x.len() != 32 || y.len() != 32 {
                bail!("EC JWK coordinates must be 32 bytes");
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| anyhow!("invalid P-256 public key"))?;
            let signature = p256::ecdsa::Signature::from_slice(sig)
                .map_err(|_| anyhow!("invalid ES256 signature"))?;
            p256::ecdsa::signature::Verifier::verify(&vk, msg, &signature)
                .map_err(|_| anyhow!("ES256 signature verification failed"))?;
        }
        "EdDSA" => {
            let x = b64d(jwk.get("x").and_then(Value::as_str).ok_or_else(|| anyhow!("OKP JWK missing x"))?)?;
            let raw: [u8; 32] = x.try_into().map_err(|_| anyhow!("Ed25519 key must be 32 bytes"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map_err(|_| anyhow!("invalid Ed25519 public key"))?;
            let signature = ed25519_dalek::Signature::from_slice(sig)
                .map_err(|_| anyhow!("invalid Ed25519 signature"))?;
            ed25519_dalek::Verifier::verify(&vk, msg, &signature)
                .map_err(|_| anyhow!("EdDSA signature verification failed"))?;
        }
        "RS256" | "PS256" => {
            let n = b64d(jwk.get("n").and_then(Value::as_str).ok_or_else(|| anyhow!("RSA JWK missing n"))?)?;
            let e = b64d(jwk.get("e").and_then(Value::as_str).ok_or_else(|| anyhow!("RSA JWK missing e"))?)?;
            let key = ring::signature::RsaPublicKeyComponents { n: &n, e: &e };
            let verification_algorithm = if alg == "RS256" {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &ring::signature::RSA_PSS_2048_8192_SHA256
            };
            key.verify(verification_algorithm, msg, sig)
                .map_err(|_| anyhow!("{alg} signature verification failed"))?;
        }
        other => bail!("unsupported JWS alg {other}"),
    }
    Ok(())
}

/// RFC 7638 JWK thumbprint (sha256, base64url).
pub fn thumbprint(jwk: &Value) -> anyhow::Result<String> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWK has no kty"))?;
    let canonical = match kty {
        "EC" => json!({
            "crv": jwk.get("crv").cloned().unwrap_or(Value::Null),
            "kty": "EC",
            "x": jwk.get("x").cloned().unwrap_or(Value::Null),
            "y": jwk.get("y").cloned().unwrap_or(Value::Null),
        }),
        "OKP" => json!({
            "crv": jwk.get("crv").cloned().unwrap_or(Value::Null),
            "kty": "OKP",
            "x": jwk.get("x").cloned().unwrap_or(Value::Null),
        }),
        "RSA" => json!({
            "e": jwk.get("e").cloned().unwrap_or(Value::Null),
            "kty": "RSA",
            "n": jwk.get("n").cloned().unwrap_or(Value::Null),
        }),
        other => bail!("unsupported kty {other}"),
    };
    // serde_json's default map is a BTreeMap, so keys are already sorted and
    // the serialisation matches the RFC 7638 canonical form.
    Ok(b64(&sha256(&serde_json::to_vec(&canonical)?)))
}

/// Experimental: derive a stable, non-secret handle for a JWK.
#[allow(dead_code)]
pub fn jwk_kid(jwk: &Value) -> String {
    thumbprint(jwk).unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = crate::util::random_p256_signing_key();
        let key = SigKey { kid: "k1".into(), key: sk };
        let token = key.sign(Some("JWT"), &json!({"sub": "alice"})).unwrap();
        let (h, c) = verify_with_jwk(&key.public_jwk(), &token, Some("JWT")).unwrap();
        assert_eq!(h["alg"], "ES256");
        assert_eq!(c["sub"], "alice");
    }

    #[test]
    fn tampered_token_is_rejected() {
        let sk = crate::util::random_p256_signing_key();
        let key = SigKey { kid: "k1".into(), key: sk };
        let token = key.sign(None, &json!({"sub": "alice"})).unwrap();
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[1] = b64(serde_json::to_string(&json!({"sub": "mallory"})).unwrap().as_bytes());
        let bad = parts.join(".");
        assert!(verify_with_jwk(&key.public_jwk(), &bad, None).is_err());
    }

    #[test]
    fn thumbprint_is_stable() {
        let sk = crate::util::random_p256_signing_key();
        let key = SigKey { kid: "k1".into(), key: sk };
        let a = thumbprint(&key.public_jwk()).unwrap();
        let b = thumbprint(&key.public_jwk()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 43);
    }
}
