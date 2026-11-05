use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// RFC 6749 / RFC 6750 style error, rendered as JSON.
#[derive(Debug, Clone)]
pub struct OauthError {
    pub status: StatusCode,
    pub code: &'static str,
    pub description: String,
    /// Optional `WWW-Authenticate` challenge for 401 responses.
    pub challenge: Option<HeaderValue>,
}

pub type ApiResult<T> = Result<T, OauthError>;

impl OauthError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
            challenge: None,
        }
    }

    /// Override the HTTP status, e.g. to turn an endpoint error into a 401 for
    /// a protected resource.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Override the `WWW-Authenticate` challenge sent with a 401.
    pub fn with_challenge(mut self, challenge: &'static str) -> Self {
        self.challenge = HeaderValue::from_str(challenge).ok();
        self
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    pub fn invalid_dpop_proof(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_dpop_proof", description)
    }

    pub fn unauthorized(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            description,
        )
    }

    pub fn server_error(description: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", description)
    }

    pub fn unsupported(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", description)
    }
}

impl std::fmt::Display for OauthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.description)
    }
}

impl std::error::Error for OauthError {}

impl From<anyhow::Error> for OauthError {
    fn from(value: anyhow::Error) -> Self {
        // Storage, I/O and crypto errors can contain SQL, paths, identifiers or
        // key material. Log the full chain for operators, but never reflect it
        // to the caller.
        eprintln!("[kagi] internal error: {value:#}");
        OauthError::server_error("internal server error")
    }
}

impl IntoResponse for OauthError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "error": self.code,
            "error_description": self.description,
        });
        if self.status == StatusCode::UNAUTHORIZED {
            body["error_uri"] = json!("https://www.rfc-editor.org/rfc/rfc6749#section-5.2");
        }
        let mut res = (self.status, axum::Json(body)).into_response();
        let h = res.headers_mut();
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if self.status == StatusCode::UNAUTHORIZED {
            let challenge = self.challenge.clone().unwrap_or_else(|| {
                HeaderValue::from_static("Basic realm=\"kagi\", charset=\"UTF-8\"")
            });
            h.insert(header::WWW_AUTHENTICATE, challenge);
        }
        res
    }
}

/// Small helper so handlers can bail with an OAuth error.
#[macro_export]
macro_rules! bail_oauth {
    ($kind:ident, $($arg:tt)*) => {
        return Err($crate::error::OauthError::$kind(format!($($arg)*)))
    };
}
