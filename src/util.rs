use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("operating-system CSPRNG unavailable");
    buf
}

/// Generate a valid P-256 signing key from the operating-system CSPRNG.
/// Invalid scalars are discarded and sampled again.
pub fn random_p256_signing_key() -> p256::ecdsa::SigningKey {
    loop {
        let candidate = random_bytes(32);
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&candidate) {
            return key;
        }
    }
}

/// URL-safe, unpadded base64 of `n` random bytes.
pub fn random_token(n: usize) -> String {
    b64(&random_bytes(n))
}

/// 128-bit identifier, suitable for flow ids.
pub fn new_id() -> String {
    random_token(16)
}

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Human-friendly, single-use recovery code: `ABCDE-FGHJK`.
///
/// The alphabet omits 0/O and 1/I/L so codes can be read aloud or copied by
/// hand without ambiguity.
pub fn recovery_code() -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = random_bytes(10);
    let mut out = String::with_capacity(11);
    for (i, byte) in bytes.iter().enumerate() {
        if i == 5 {
            out.push('-');
        }
        out.push(ALPHABET[(*byte as usize) & 31] as char);
    }
    out
}

/// Normalise a recovery code before hashing: uppercase, drop separators and
/// whitespace. The resulting string is what users effectively type.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Iterations applied to recovery-code hashes. A short code is guessable in
/// bulk, so a plain SHA-256 of the code would be cheap to invert offline if a
/// database backup leaked. Keying by user id and iterating the digest makes
/// that search far more expensive while a single online check stays fast.
const RECOVERY_HASH_ROUNDS: usize = 20_000;

/// Hash a normalised recovery code for storage and lookup.
///
/// Must be used with the same `user_id` on generation and verification; the
/// user id acts as a per-account salt.
pub fn hash_recovery_code(user_id: &str, normalized_code: &str) -> String {
    let mut digest = sha256_hex(&format!("kagi-recovery-v1:{user_id}:{normalized_code}"));
    for _ in 0..RECOVERY_HASH_ROUNDS {
        digest = sha256_hex(&digest);
    }
    digest
}

pub fn b64d(s: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| anyhow::anyhow!("invalid base64url: {e}"))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_hex(data: &str) -> String {
    hex(&sha256(data.as_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Constant-time string comparison, used for secrets and hashes.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// application/x-www-form-urlencoded component encoding.
pub fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

pub fn build_url(base: &str, params: &[(&str, String)]) -> String {
    let mut out = String::from(base);
    let mut sep = if base.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        out.push(sep);
        sep = '&';
        out.push_str(&urlenc(k));
        out.push('=');
        out.push_str(&urlenc(v));
    }
    out
}

pub fn parse_cookies(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for value in headers.get_all(axum::http::header::COOKIE) {
        let Ok(raw) = value.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

/// Normalise an `htu` for DPoP comparison: scheme://authority/path, no
/// query/fragment, lowercase scheme and host, default port removed.
pub fn normalize_htu(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.split(['?', '#']).next().unwrap_or(authority);
    let mut host = authority.to_ascii_lowercase();
    match (scheme.as_str(), host.as_str()) {
        ("http", h) if h.ends_with(":80") => host.truncate(h.len() - 3),
        ("https", h) if h.ends_with(":443") => host.truncate(h.len() - 4),
        _ => {}
    }
    let path = path.split(['?', '#']).next().unwrap_or("/");
    format!("{scheme}://{host}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htu_normalisation() {
        assert_eq!(
            normalize_htu("HTTP://Localhost:80/token?x=1#f"),
            "http://localhost/token"
        );
        assert_eq!(
            normalize_htu("https://id.example.com:443/authorize"),
            "https://id.example.com/authorize"
        );
    }

    #[test]
    fn urlenc_matches_form_encoding() {
        assert_eq!(urlenc("a b/c?d=e"), "a%20b%2Fc%3Fd%3De");
    }

    #[test]
    fn recovery_code_shape_and_normalisation() {
        let code = recovery_code();
        assert_eq!(code.len(), 11);
        assert_eq!(&code[5..6], "-");
        let normalized = normalize_recovery_code(&code.to_ascii_lowercase());
        assert_eq!(normalized.len(), 10);
        assert!(normalized.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(normalize_recovery_code(" abcde-fghjk "), "ABCDEFGHJK");
    }

    #[test]
    fn recovery_code_hash_is_salted_and_normalised() {
        let hash = hash_recovery_code("user-a", "ABCDEFGHJK");
        assert_eq!(hash.len(), 64);
        // Normalisation is stable, so a lower-case code matches its hash.
        assert_eq!(
            hash,
            hash_recovery_code("user-a", &normalize_recovery_code("abcde-fghjk"))
        );
        // The user id is part of the digest, so two accounts cannot share
        // a precomputed table.
        assert_ne!(hash, hash_recovery_code("user-b", "ABCDEFGHJK"));
    }
}
