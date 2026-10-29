use crate::config::Config;
use crate::db::Db;
use crate::error::OauthError;
use crate::jose::{self, thumbprint};
use crate::util::{b64, normalize_htu, now, sha256};
use axum::http::HeaderMap;
use crate::db::params;
use serde_json::Value;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DpopProof {
    pub jkt: String,
    pub jti: String,
    pub jwk: Value,
}

fn dpop_error(msg: impl Into<String>) -> OauthError {
    OauthError::invalid_dpop_proof(msg)
}

/// Validate a DPoP proof (RFC 9449) for the given method/path.
///
/// * `access_token` is `Some` when the proof accompanies a resource request:
///   the `ath` claim then becomes mandatory.
pub fn inspect(
    cfg: &Config,
    db: &Db,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    access_token: Option<&str>,
) -> Result<Option<DpopProof>, OauthError> {
    let Some(raw) = headers.get("dpop") else {
        return Ok(None);
    };
    let proof = raw
        .to_str()
        .map_err(|_| dpop_error("DPoP header is not ASCII"))?;

    let (header, claims, _, _) =
        jose::decode_segments(proof).map_err(|e| dpop_error(format!("malformed DPoP proof: {e}")))?;

    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err(dpop_error("DPoP typ must be dpop+jwt"));
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| dpop_error("DPoP proof has no alg"))?;
    if !matches!(alg, "ES256" | "EdDSA" | "RS256" | "PS256") {
        return Err(dpop_error(format!("unsupported DPoP alg {alg}")));
    }
    let jwk = header
        .get("jwk")
        .cloned()
        .ok_or_else(|| dpop_error("DPoP proof has no jwk header"))?;
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if jwk.get(private).is_some() {
            return Err(dpop_error("DPoP jwk must be public"));
        }
    }

    let (_, _claims_unused) = jose::verify_with_jwk(&jwk, proof, Some("dpop+jwt"))
        .map_err(|e| dpop_error(format!("bad DPoP signature: {e}")))?;

    let htm = claims
        .get("htm")
        .and_then(Value::as_str)
        .ok_or_else(|| dpop_error("DPoP proof has no htm"))?;
    if !htm.eq_ignore_ascii_case(method) {
        return Err(dpop_error("DPoP htm does not match the request method"));
    }

    let htu = claims
        .get("htu")
        .and_then(Value::as_str)
        .ok_or_else(|| dpop_error("DPoP proof has no htu"))?;
    let expected = cfg.endpoint(path);
    if normalize_htu(htu) != normalize_htu(&expected) {
        return Err(dpop_error("DPoP htu does not match this endpoint"));
    }

    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| dpop_error("DPoP proof has no iat"))?;
    if (now() - iat).abs() > 300 {
        return Err(dpop_error("DPoP proof is too old or from the future"));
    }

    if let Some(at) = access_token {
        let ath = claims
            .get("ath")
            .and_then(Value::as_str)
            .ok_or_else(|| dpop_error("DPoP proof for a resource request needs ath"))?;
        let expected_ath = b64(&sha256(at.as_bytes()));
        if ath != expected_ath {
            return Err(dpop_error("DPoP ath does not match the access token"));
        }
    }

    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| dpop_error("DPoP proof has no jti"))?
        .to_string();
    if jti.len() < 8 {
        return Err(dpop_error("DPoP jti is too short"));
    }

    let jkt = thumbprint(&jwk).map_err(|e| dpop_error(format!("bad DPoP jwk: {e}")))?;

    // Replay protection. A unique constraint violation means we have seen it.
    let inserted = db
        .with(|c| {
            Ok(c.execute(
                "INSERT OR IGNORE INTO dpop_replay (jti, expires_at) VALUES (?1, ?2)",
                params![jti, now() + 600],
            )?)
        })
        .map_err(|_| dpop_error("could not record DPoP proof"))?;
    if inserted == 0 {
        return Err(dpop_error("DPoP proof replayed"));
    }

    Ok(Some(DpopProof { jkt, jti, jwk }))
}

pub fn require(
    cfg: &Config,
    db: &Db,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    access_token: Option<&str>,
) -> Result<DpopProof, OauthError> {
    inspect(cfg, db, headers, method, path, access_token)?
        .ok_or_else(|| dpop_error("DPoP proof required"))
}
