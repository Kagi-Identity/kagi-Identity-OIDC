use std::env;

/// Runtime configuration, resolved once at start-up.
#[derive(Clone, Debug)]
pub struct Config {
    /// Public origin of the OP, without a trailing slash. e.g. `https://id.example.com`
    pub issuer: String,
    /// Socket address to bind.
    pub bind: String,
    /// WebAuthn RP ID (registrable domain, no scheme, no port).
    pub rp_id: String,
    pub rp_name: String,
    /// Expected WebAuthn origin, e.g. `https://id.example.com`.
    pub origin: String,
    pub db_path: String,
    /// PostgreSQL / Supabase connection string. When set, it takes precedence
    /// over `db_path` (SQLite).
    pub database_url: Option<String>,
    /// Apply schema migrations at process startup (disable for serverless production).
    pub auto_migrate: bool,
    pub allow_signup: bool,
    pub seed_demo: bool,
    pub require_par: bool,
    pub require_dpop: bool,
    pub admin_token: Option<String>,
    pub registration_token: Option<String>,
    /// Explicit browser origins allowed to call API endpoints.
    pub cors_origins: Vec<String>,
    pub cookie_secure: bool,
    /// Send `Strict-Transport-Security` (only makes sense on HTTPS).
    pub hsts: bool,
    /// Trust the first `X-Forwarded-For` hop. Enable only behind a proxy that
    /// overwrites the header.
    pub trust_proxy: bool,
    /// Enable the shared PostgreSQL-backed rate limiter.
    pub rate_limit: bool,
    /// Enable single-use recovery codes as a passkey fallback.
    pub recovery_enabled: bool,
    /// Maximum number of passkeys per account.
    pub max_passkeys: i64,
    /// Audit-log retention in days (0 keeps events forever).
    pub audit_retention_days: i64,
    /// Session lifetime in seconds.
    pub session_ttl: i64,
    /// Idle timeout in seconds (0 disables the idle check).
    pub session_idle_ttl: i64,
    /// Authorization code lifetime in seconds (FAPI: short).
    pub code_ttl: i64,
    /// Access token lifetime in seconds.
    pub access_ttl: i64,
    /// Refresh token lifetime in seconds.
    pub refresh_ttl: i64,
    /// ID token lifetime in seconds.
    pub id_ttl: i64,
    /// PAR request_uri lifetime in seconds (RFC 9126 recommends <= 600).
    pub par_ttl: i64,
}

fn flag(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn num(name: &str, default: i64) -> i64 {
    env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn non_empty(name: &str) -> Option<String> {
    env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}


/// Validate a WebAuthn origin as a scheme + authority only.
///
/// WebAuthn clientDataJSON contains the browser origin, never an application
/// path. Accepting a path here creates a configuration that can start
/// successfully but can never match a real browser origin during verification.
fn validate_origin(origin: &str) -> anyhow::Result<()> {
    let uri = origin
        .parse::<axum::http::Uri>()
        .map_err(|_| anyhow::anyhow!("KAGI_ORIGIN must be a valid absolute URL"))?;

    anyhow::ensure!(
        matches!(uri.scheme_str(), Some("http" | "https")),
        "KAGI_ORIGIN must use http:// or https://"
    );

    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("KAGI_ORIGIN must include a host"))?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "KAGI_ORIGIN must not contain credentials"
    );

    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    anyhow::ensure!(
        path_and_query == "/",
        "KAGI_ORIGIN must not contain a path, query, or fragment"
    );

    Ok(())
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let issuer = non_empty("KAGI_ISSUER").unwrap_or_else(|| "http://localhost:8080".to_string());
        let issuer = issuer.trim_end_matches('/').to_string();
        anyhow::ensure!(
            issuer.starts_with("https://") || issuer.starts_with("http://"),
            "KAGI_ISSUER must start with http:// or https://"
        );
        anyhow::ensure!(
            !issuer.contains('?') && !issuer.contains('#'),
            "KAGI_ISSUER must not contain a query or fragment"
        );

        let secure_default = issuer.starts_with("https://");

        let host = issuer
            .split("://")
            .nth(1)
            .unwrap_or("localhost")
            .split('/')
            .next()
            .unwrap_or("localhost")
            .to_string();

        // Strip a port but keep IPv6 brackets intact.
        let host_only = if host.starts_with('[') {
            host.split(']').next().map(|h| format!("{h}]")).unwrap_or(host.clone())
        } else {
            host.split(':').next().unwrap_or("localhost").to_string()
        };

        let rp_id = non_empty("KAGI_RP_ID").unwrap_or(host_only);
        anyhow::ensure!(
            !rp_id.contains("://") && !rp_id.contains('/') && !rp_id.contains(':'),
            "KAGI_RP_ID must be a bare domain (no scheme, path or port)"
        );

        let origin = non_empty("KAGI_ORIGIN")
            .unwrap_or_else(|| issuer.clone())
            .trim_end_matches('/')
            .to_string();
        validate_origin(&origin)?;

        let session_ttl = num("KAGI_SESSION_TTL", 8 * 3600);
        let session_idle_ttl = num("KAGI_SESSION_IDLE_TTL", 2 * 3600);
        let code_ttl = num("KAGI_CODE_TTL", 60);
        let access_ttl = num("KAGI_ACCESS_TTL", 300);
        let refresh_ttl = num("KAGI_REFRESH_TTL", 30 * 24 * 3600);
        let id_ttl = num("KAGI_ID_TTL", 300);
        let par_ttl = num("KAGI_PAR_TTL", 90);
        let cors_origins: Vec<String> = non_empty("KAGI_CORS_ORIGINS")
            .map(|raw| raw.split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_string).collect())
            .unwrap_or_default();
        for origin in &cors_origins {
            let host = origin.strip_prefix("https://").unwrap_or("");
            anyhow::ensure!(
                !host.is_empty()
                    && !host.contains('/')
                    && !host.contains('@')
                    && !host.contains(' ')
                    && !origin.contains('*'),
                "KAGI_CORS_ORIGINS must contain exact HTTPS origins without paths, credentials, or wildcards"
            );
            anyhow::ensure!(
                !origin.contains('?') && !origin.contains('#'),
                "KAGI_CORS_ORIGINS entries must not contain query strings or fragments"
            );
        }

        for (name, value) in [
            ("KAGI_SESSION_TTL", session_ttl),
            ("KAGI_CODE_TTL", code_ttl),
            ("KAGI_ACCESS_TTL", access_ttl),
            ("KAGI_REFRESH_TTL", refresh_ttl),
            ("KAGI_ID_TTL", id_ttl),
            ("KAGI_PAR_TTL", par_ttl),
        ] {
            anyhow::ensure!(value > 0, "{name} must be greater than zero");
        }
        anyhow::ensure!(
            session_idle_ttl >= 0 && (session_idle_ttl == 0 || session_idle_ttl <= session_ttl),
            "KAGI_SESSION_IDLE_TTL must be 0 or between 1 and KAGI_SESSION_TTL"
        );

        Ok(Self {
            bind: non_empty("KAGI_BIND").unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            rp_name: non_empty("KAGI_RP_NAME").unwrap_or_else(|| "Kagi Identity".to_string()),
            db_path: non_empty("KAGI_DB").unwrap_or_else(|| "kagi.db".to_string()),
            database_url: non_empty("KAGI_DATABASE_URL").or_else(|| non_empty("DATABASE_URL")),
            auto_migrate: flag("KAGI_AUTO_MIGRATE", true),
            allow_signup: flag("KAGI_ALLOW_SIGNUP", true),
            seed_demo: flag("KAGI_SEED_DEMO", false),
            require_par: flag("KAGI_REQUIRE_PAR", false),
            require_dpop: flag("KAGI_REQUIRE_DPOP", false),
            admin_token: non_empty("KAGI_ADMIN_TOKEN"),
            registration_token: non_empty("KAGI_REGISTRATION_TOKEN"),
            cors_origins,
            cookie_secure: flag("KAGI_COOKIE_SECURE", secure_default),
            hsts: flag("KAGI_HSTS", secure_default),
            trust_proxy: flag("KAGI_TRUST_PROXY", false),
            rate_limit: flag("KAGI_RATE_LIMIT", true),
            recovery_enabled: flag("KAGI_RECOVERY_ENABLED", true),
            max_passkeys: num("KAGI_MAX_PASSKEYS", 10).clamp(1, 100),
            audit_retention_days: num("KAGI_AUDIT_RETENTION_DAYS", 90).max(0),
            session_ttl,
            session_idle_ttl,
            code_ttl,
            access_ttl,
            refresh_ttl,
            id_ttl,
            par_ttl,
            rp_id,
            origin,
            issuer,
        })
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }

    /// Origin used to validate WebAuthn clientDataJSON.
    pub fn webauthn_origin(&self) -> &str {
        &self.origin
    }

    pub fn is_local(&self) -> bool {
        let host = self
            .issuer
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
    }

    /// Human-readable warnings printed at start-up. These do not block boot:
    /// local development intentionally uses HTTP and a demo client.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.cookie_secure {
            out.push(
                "cookies are not marked Secure (set KAGI_COOKIE_SECURE=1 behind HTTPS)".into(),
            );
        }
        if !self.is_local() && self.issuer.starts_with("http://") {
            out.push(
                "KAGI_ISSUER uses http:// on a non-local host; passkeys require a secure context"
                    .into(),
            );
        }
        if self.seed_demo && !self.is_local() {
            out.push("KAGI_SEED_DEMO=1 is enabled on a non-local host; disable it in production".into());
        }
        if !self.rate_limit {
            out.push("the in-process rate limiter is disabled (KAGI_RATE_LIMIT=0)".into());
        }
        if let Some(token) = &self.admin_token {
            if token.len() < 24 {
                out.push("KAGI_ADMIN_TOKEN is shorter than 24 characters".into());
            }
        }
        if self.trust_proxy && self.bind.starts_with("0.0.0.0") {
            out.push(
                "KAGI_TRUST_PROXY=1 with a public bind address: ensure only your proxy can reach kagi"
                    .into(),
            );
        }
        out
    }
}

#[cfg(test)]
mod origin_tests {
    use super::validate_origin;

    #[test]
    fn accepts_http_and_https_origins() {
        assert!(validate_origin("http://localhost:8080").is_ok());
        assert!(validate_origin("https://id.example.com").is_ok());
        assert!(validate_origin("https://[::1]:8443").is_ok());
    }

    #[test]
    fn rejects_non_origin_urls() {
        for value in [
            "https://id.example.com/login",
            "https://id.example.com/?next=/account",
            "https://user:password@id.example.com",
            "ftp://id.example.com",
            "/relative/path",
        ] {
            assert!(validate_origin(value).is_err(), "accepted invalid origin: {value}");
        }
    }
}
