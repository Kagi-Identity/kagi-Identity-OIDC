use crate::config::Config;
use crate::db::params;
use crate::db::Db;
use crate::error::OauthError;
use crate::jose::{self, thumbprint};
use crate::util::{b64, normalize_htu, now, sha256};
use axum::http::HeaderMap;
use ring::hmac;
use serde_json::Value;

/// Nonce rotation window. A nonce is accepted for the window it was issued in
/// and the following one, so a client has at most ~10 minutes to retry while
/// an intercepted proof cannot be replayed with an old nonce indefinitely.
const NONCE_WINDOW_SECS: i64 = 300;

/// Deterministic HMAC tag binding a nonce to one rotation window.
fn nonce_tag(secret: &[u8], window: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, format!("kagi-dpop-nonce:v1:{window}").as_bytes());
    b64(tag.as_ref())
}

/// Mint the nonce for the window that contains `at`.
pub fn issue_nonce_at(secret: &[u8], at: i64) -> String {
    let window = at.div_euclid(NONCE_WINDOW_SECS);
    format!("{window}.{}", nonce_tag(secret, window))
}

/// Accept the current window and the previous one; reject anything else.
pub fn nonce_valid_at(secret: &[u8], nonce: &str, at: i64) -> bool {
    let Some((raw_window, tag)) = nonce.split_once('.') else {
        return false;
    };
    let Ok(window) = raw_window.parse::<i64>() else {
        return false;
    };
    let current = at.div_euclid(NONCE_WINDOW_SECS);
    if window != current && window != current - 1 {
        return false;
    }
    crate::util::ct_eq(tag, &nonce_tag(secret, window))
}

/// Current nonce, or `None` when nonce enforcement is disabled.
pub fn current_nonce(cfg: &Config) -> Option<String> {
    if !cfg.dpop_nonce {
        return None;
    }
    let secret = cfg.dpop_nonce_secret.as_deref()?;
    Some(issue_nonce_at(secret.as_bytes(), now()))
}

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

    let (header, claims, _, _) = jose::decode_segments(proof)
        .map_err(|e| dpop_error(format!("malformed DPoP proof: {e}")))?;

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

    // RFC 9449 §8: a server-chosen nonce prevents an attacker from preparing a
    // proof in advance (and gives the server a cheap replay/clock bound). The
    // `use_dpop_nonce` error carries the fresh value in `DPoP-Nonce`.
    if cfg.dpop_nonce {
        let secret = cfg
            .dpop_nonce_secret
            .as_deref()
            .ok_or_else(|| OauthError::server_error("DPoP nonce secret is not configured"))?;
        match claims.get("nonce").and_then(Value::as_str) {
            Some(nonce) if nonce_valid_at(secret.as_bytes(), nonce, now()) => {}
            Some(_) => {
                return Err(OauthError::use_dpop_nonce(
                    "DPoP nonce is stale or invalid",
                    issue_nonce_at(secret.as_bytes(), now()),
                ))
            }
            None => {
                return Err(OauthError::use_dpop_nonce(
                    "DPoP nonce is required",
                    issue_nonce_at(secret.as_bytes(), now()),
                ))
            }
        }
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

#[cfg(test)]
mod nonce_tests {
    use super::{issue_nonce_at, nonce_valid_at};

    const SECRET: &[u8] = b"test-nonce-secret";

    #[test]
    fn accepts_the_current_and_previous_window() {
        let at = 1_000_000;
        let nonce = issue_nonce_at(SECRET, at);
        assert!(nonce_valid_at(SECRET, &nonce, at));
        // A nonce minted in the previous rotation window is still accepted,
        // which gives a client one window to retry after a clock skew.
        let previous = issue_nonce_at(SECRET, at - 300);
        assert!(nonce_valid_at(SECRET, &previous, at));
    }

    #[test]
    fn rejects_expired_future_and_forged_nonces() {
        let at = 1_000_000;
        let nonce = issue_nonce_at(SECRET, at);
        assert!(!nonce_valid_at(SECRET, &nonce, at - 600));
        assert!(!nonce_valid_at(SECRET, &nonce, at + 600));
        assert!(!nonce_valid_at(SECRET, &nonce, at + 5 * 300));
        assert!(!nonce_valid_at(b"another-secret", &nonce, at));
        // Malformed inputs are derived from the valid nonce rather than written
        // as literals: a value shaped like a nonce must never appear verbatim
        // in the source, even in a test.
        let (window, _) = nonce.split_once('.').expect("nonce has a window prefix");
        assert!(!nonce_valid_at(SECRET, window, at));
        let mut non_numeric = nonce.clone();
        non_numeric.insert(0, 'x');
        assert!(!nonce_valid_at(SECRET, &non_numeric, at));
        let mut tampered = nonce.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(!nonce_valid_at(SECRET, &tampered, at));
    }

    #[test]
    fn issuance_is_deterministic_within_a_window() {
        assert_eq!(
            issue_nonce_at(SECRET, 1_000_000),
            issue_nonce_at(SECRET, 1_000_100)
        );
        assert_ne!(
            issue_nonce_at(SECRET, 1_000_000),
            issue_nonce_at(SECRET, 1_000_300)
        );
    }
}
