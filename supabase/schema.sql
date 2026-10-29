-- kagi schema for PostgreSQL / Supabase.
--
-- Apply this either automatically at start-up (KAGI_DATABASE_URL is set) or
-- manually in the Supabase SQL editor. Booleans are stored as BIGINT (0/1) so
-- the same 64-bit integer bindings work against both SQLite and PostgreSQL.

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    email           TEXT,
    email_verified  BIGINT NOT NULL DEFAULT 0,
    created_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,          -- credential id (base64url)
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      BYTEA NOT NULL,            -- COSE_Key
    key_type        TEXT NOT NULL,             -- ES256 | EdDSA | RS256
    sign_count      BIGINT NOT NULL,
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          TEXT,
    backup_eligible BIGINT NOT NULL DEFAULT 0,
    backup_state    BIGINT NOT NULL DEFAULT 0,
    nickname        TEXT,
    created_at      BIGINT NOT NULL,
    last_used_at    BIGINT
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS clients (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    secret_hash               TEXT,
    redirect_uris             TEXT NOT NULL,
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types               TEXT NOT NULL,
    scopes                    TEXT NOT NULL,
    auth_method               TEXT NOT NULL,
    jwks                      TEXT,
    require_dpop              BIGINT NOT NULL DEFAULT 0,
    require_par               BIGINT NOT NULL DEFAULT 0,
    id_token_alg              TEXT NOT NULL DEFAULT 'ES256',
    created_at                BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,              -- sha256(sid)
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time   BIGINT NOT NULL,
    amr         TEXT NOT NULL,
    acr         TEXT NOT NULL,
    expires_at  BIGINT NOT NULL,
    created_at  BIGINT NOT NULL
);

-- Remembered user consent so that prompt=none can complete silently.
CREATE TABLE IF NOT EXISTS consents (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

-- Short-lived interaction state: PAR requests, authorize flows,
-- WebAuthn ceremonies, sign-up flows.
CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    user_id     TEXT,
    client_id   TEXT,
    payload     TEXT NOT NULL,
    challenge   TEXT,
    csrf        TEXT,
    expires_at  BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    consumed    BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_kind ON flows(kind, expires_at);

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash       TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scope           TEXT NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT NOT NULL,
    auth_time       BIGINT NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    expires_at      BIGINT NOT NULL,
    created_at      BIGINT NOT NULL,
    consumed        BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,
    auth_time       BIGINT NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    issued_at       BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    rotated_to      TEXT,
    revoked         BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    audience    TEXT NOT NULL,
    dpop_jkt    TEXT,
    subject     TEXT NOT NULL,                 -- sub claim (user id or client id)
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    revoked     BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_at_user ON access_tokens(user_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_jwk TEXT NOT NULL,
    public_jwk  TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    active      BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dpop_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS assertion_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  BIGINT NOT NULL
);
