//! Storage layer.
//!
//! kagi supports two backends behind one small synchronous API:
//!
//! * SQLite (default, local development) — `KAGI_DB=./kagi.db`
//! * PostgreSQL / Supabase — `KAGI_DATABASE_URL=postgres://...`
//!
//! The data-access code below is written in portable SQL (`?N` placeholders,
//! 64-bit integers for booleans). The PostgreSQL path rewrites the placeholders
//! and a few SQLite-isms on the way in, so both backends share the same queries.

use anyhow::Context;
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

const POSTGRES_SCHEMA: &str = include_str!("../supabase/schema.sql");

/// Previous hash of the first chained event: 32 zero bytes, hex encoded.
const AUDIT_GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Advisory-lock key for the audit chain (`kagi` in ASCII, hex).
const AUDIT_CHAIN_LOCK: i64 = 0x6b616769;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    email           TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,          -- credential id (base64url)
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      BLOB NOT NULL,             -- COSE_Key
    key_type        TEXT NOT NULL,             -- ES256 | EdDSA | RS256
    sign_count      INTEGER NOT NULL,
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          TEXT,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    nickname        TEXT,
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS clients (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    secret_hash           TEXT,
    redirect_uris         TEXT NOT NULL,
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types           TEXT NOT NULL,
    scopes                TEXT NOT NULL,
    auth_method           TEXT NOT NULL,
    jwks                  TEXT,
    require_dpop          INTEGER NOT NULL DEFAULT 0,
    require_par           INTEGER NOT NULL DEFAULT 0,
    id_token_alg          TEXT NOT NULL DEFAULT 'ES256',
    registration_token_hash TEXT,
    backchannel_logout_uri TEXT,
    backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,           -- sha256(sid)
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time     INTEGER NOT NULL,
    amr           TEXT NOT NULL,
    acr           TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL DEFAULT 0,
    user_agent    TEXT,
    ip            TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Remembered user consent so that prompt=none can complete silently.
CREATE TABLE IF NOT EXISTS consents (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
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
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0
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
    auth_time       INTEGER NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    claims          TEXT,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    consumed        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,
    auth_time       INTEGER NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    claims          TEXT,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    rotated_to      TEXT,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

-- RFC 8628 device authorization grants. Only hashes of the device code and
-- the human-entered user code are stored.
CREATE TABLE IF NOT EXISTS device_codes (
    device_hash     TEXT PRIMARY KEY,
    user_code_hash  TEXT NOT NULL UNIQUE,
    client_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,
    user_id         TEXT,
    auth_time       INTEGER,
    amr             TEXT NOT NULL DEFAULT '[]',
    acr             TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    interval_secs   INTEGER NOT NULL,
    last_polled_at  INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_expires ON device_codes(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    audience    TEXT NOT NULL,
    dpop_jkt    TEXT,
    subject     TEXT NOT NULL,               -- sub claim (user id or client id)
    session_id  TEXT,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_at_user ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_at_session ON access_tokens(session_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_jwk TEXT NOT NULL,
    public_jwk  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dpop_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS assertion_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL
);

-- Security-relevant events shown in the account console and admin stats.
--
-- The trail is an append-only hash chain: `seq` is the position, `prev_hash`
-- is the previous event's `hash`, and `hash` covers the whole event. A single
-- UPDATE or DELETE therefore breaks every later link, which `audit_verify`
-- reports. Rows written by earlier releases predate the chain (NULL seq/hash)
-- and are reported as `unhashed` instead of silently passing verification.
CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    client_id   TEXT,
    kind        TEXT NOT NULL,
    detail      TEXT,
    ip          TEXT,
    user_agent  TEXT,
    created_at  INTEGER NOT NULL,
    seq         INTEGER,
    prev_hash   TEXT,
    hash        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);

-- Chain head ('head') and the pruning anchor ('anchor'). The anchor records
-- the last event removed by retention so verification can start from it
-- instead of treating the oldest retained row as a broken link. The unique
-- index on `seq` is created after the column migrations in `Db::migrate`.
CREATE TABLE IF NOT EXISTS audit_head (
    id          TEXT PRIMARY KEY,
    seq         INTEGER NOT NULL,
    hash        TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Single-use recovery codes. Only the SHA-256 of a normalised code is stored.
CREATE TABLE IF NOT EXISTS recovery_codes (
    code_hash   TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    used_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

-- Shared, atomic rate-limit counters; safe across independently scaled instances.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key  TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    hits        INTEGER NOT NULL,
    PRIMARY KEY (bucket_key, window_start)
);
"#;

// ---------------------------------------------------------------------------
// Values and parameters
// ---------------------------------------------------------------------------

/// Backend-neutral SQL value.
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Convert a Rust value into a [`Value`] for binding.
pub trait ToValue {
    fn to_value(&self) -> Value;
}

impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::Text(self.to_string())
    }
}

impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
}

impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (*self).to_value()
    }
}

impl<T: ToValue> ToValue for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            Some(v) => v.to_value(),
            None => Value::Null,
        }
    }
}

macro_rules! int_value {
    ($($t:ty),* $(,)?) => {$(
        impl ToValue for $t {
            fn to_value(&self) -> Value {
                Value::Integer(*self as i64)
            }
        }
    )*};
}
int_value!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Integer(*self as i64)
    }
}

impl ToValue for f64 {
    fn to_value(&self) -> Value {
        Value::Real(*self)
    }
}

impl ToValue for [u8] {
    fn to_value(&self) -> Value {
        Value::Blob(self.to_vec())
    }
}

impl ToValue for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Blob(self.clone())
    }
}

/// Positional parameters, built with [`params!`].
#[derive(Clone, Debug, Default)]
pub struct Params(Vec<Value>);

impl Params {
    pub fn new(values: Vec<Value>) -> Self {
        Self(values)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    fn values(&self) -> &[Value] {
        &self.0
    }
}

/// `params![a, b, c]` — same shape as the rusqlite macro, but backend neutral.
macro_rules! params {
    () => {
        $crate::db::Params::empty()
    };
    ($($v:expr),+ $(,)?) => {
        $crate::db::Params::new(vec![$($crate::db::ToValue::to_value(&$v)),+])
    };
}
pub(crate) use params;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DbError {
    NoRows,
    Message(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::NoRows => f.write_str("query returned no rows"),
            DbError::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NoRows,
            other => DbError::Message(other.to_string()),
        }
    }
}

impl From<postgres::Error> for DbError {
    fn from(e: postgres::Error) -> Self {
        DbError::Message(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DbError>;

/// `Result<T>` → `Result<Option<T>>`, turning "no rows" into `None`.
pub trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>>;
}

impl<T> OptionalExt<T> for Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(DbError::NoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// Materialised row: column names plus values. Rows are small in this schema,
/// so materialising keeps both backends on the same mapping code.
pub struct Row {
    cols: Vec<String>,
    vals: Vec<Value>,
}

pub trait Column {
    fn index(&self, cols: &[String]) -> Option<usize>;
}

impl Column for usize {
    fn index(&self, cols: &[String]) -> Option<usize> {
        if *self < cols.len() {
            Some(*self)
        } else {
            None
        }
    }
}

impl Column for str {
    fn index(&self, cols: &[String]) -> Option<usize> {
        cols.iter().position(|c| c == self)
    }
}

impl Column for &str {
    fn index(&self, cols: &[String]) -> Option<usize> {
        (*self).index(cols)
    }
}

impl Column for String {
    fn index(&self, cols: &[String]) -> Option<usize> {
        self.as_str().index(cols)
    }
}

impl Column for &String {
    fn index(&self, cols: &[String]) -> Option<usize> {
        self.as_str().index(cols)
    }
}

pub trait FromValue: Sized {
    fn from_value(value: &Value) -> Result<Self>;
}

fn type_error(want: &str, got: &Value) -> DbError {
    DbError::Message(format!("expected {want}, found {got:?}"))
}

impl FromValue for String {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Text(s) => Ok(s.clone()),
            other => Err(type_error("text", other)),
        }
    }
}

impl FromValue for i64 {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Integer(i) => Ok(*i),
            Value::Real(f) => Ok(*f as i64),
            other => Err(type_error("integer", other)),
        }
    }
}

impl FromValue for i32 {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(i64::from_value(value)? as i32)
    }
}

impl FromValue for usize {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(i64::from_value(value)? as usize)
    }
}

impl FromValue for bool {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(i64::from_value(value)? != 0)
    }
}

impl FromValue for Vec<u8> {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Blob(b) => Ok(b.clone()),
            other => Err(type_error("blob", other)),
        }
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Null => Ok(None),
            other => Ok(Some(T::from_value(other)?)),
        }
    }
}

impl Row {
    pub fn get<I: Column, T: FromValue>(&self, idx: I) -> Result<T> {
        let pos = idx
            .index(&self.cols)
            .ok_or_else(|| DbError::Message(format!("no such column: {:?}", self.cols)))?;
        T::from_value(&self.vals[pos])
    }
}

// ---------------------------------------------------------------------------
// Connection plumbing
// ---------------------------------------------------------------------------

pub enum Connection {
    Sqlite(rusqlite::Connection),
    Postgres(RefCell<postgres::Client>),
}

fn sqlite_values(params: &Params) -> Vec<rusqlite::types::Value> {
    params
        .values()
        .iter()
        .map(|v| match v {
            Value::Null => rusqlite::types::Value::Null,
            Value::Integer(i) => rusqlite::types::Value::Integer(*i),
            Value::Real(f) => rusqlite::types::Value::Real(*f),
            Value::Text(s) => rusqlite::types::Value::Text(s.clone()),
            Value::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
        })
        .collect()
}

/// Placeholder for a NULL whose SQL type is decided by the server.
#[derive(Debug)]
struct PgNull;

impl postgres::types::ToSql for PgNull {
    fn to_sql(
        &self,
        _ty: &postgres::types::Type,
        _out: &mut postgres::types::private::BytesMut,
    ) -> std::result::Result<postgres::types::IsNull, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(postgres::types::IsNull::Yes)
    }

    fn accepts(_ty: &postgres::types::Type) -> bool {
        true
    }

    fn to_sql_checked(
        &self,
        _ty: &postgres::types::Type,
        _out: &mut postgres::types::private::BytesMut,
    ) -> std::result::Result<postgres::types::IsNull, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(postgres::types::IsNull::Yes)
    }
}

fn pg_values(params: &Params) -> Vec<Box<dyn postgres::types::ToSql + Sync>> {
    params
        .values()
        .iter()
        .map(|v| -> Box<dyn postgres::types::ToSql + Sync> {
            match v {
                Value::Null => Box::new(PgNull),
                Value::Integer(i) => Box::new(*i),
                Value::Real(f) => Box::new(*f),
                Value::Text(s) => Box::new(s.clone()),
                Value::Blob(b) => Box::new(b.clone()),
            }
        })
        .collect()
}

/// Rewrite SQLite-flavoured SQL for PostgreSQL: `?N` → `$N`,
/// `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`.
fn pg_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut chars = sql.chars().peekable();
    let mut auto = 1usize;

    while let Some(ch) = chars.next() {
        if ch == '?' {
            match chars.peek().and_then(|c| c.to_digit(10)) {
                Some(_) => {
                    let mut n: u32 = 0;
                    while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                        n = n.saturating_mul(10).saturating_add(d);
                        chars.next();
                    }
                    out.push('$');
                    out.push_str(&n.to_string());
                }
                None => {
                    out.push('$');
                    out.push_str(&auto.to_string());
                    auto += 1;
                }
            }
        } else {
            out.push(ch);
        }
    }

    if out.contains("INSERT OR IGNORE INTO") {
        out = out.replace("INSERT OR IGNORE INTO", "INSERT INTO");
        if !out.contains("ON CONFLICT") {
            out.push_str(" ON CONFLICT DO NOTHING");
        }
    }
    out
}

/// True when an error is a unique/primary-key violation.
///
/// SQLite reports `UNIQUE constraint failed`, PostgreSQL reports
/// `duplicate key value violates unique constraint`. Relying on one message
/// silently turns a duplicate registration into a 500 on the other backend.
pub fn is_unique_violation(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(pg) = cause.downcast_ref::<postgres::Error>() {
            if pg.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                return true;
            }
        }
        let text = cause.to_string().to_ascii_lowercase();
        if text.contains("unique constraint") || text.contains("duplicate key value") {
            return true;
        }
    }
    false
}

impl Connection {
    pub fn execute(&self, sql: &str, params: Params) -> Result<usize> {
        match self {
            Connection::Sqlite(c) => {
                let mut stmt = c.prepare(sql)?;
                let values = sqlite_values(&params);
                Ok(stmt.execute(rusqlite::params_from_iter(values.iter()))?)
            }
            Connection::Postgres(c) => {
                let values = pg_values(&params);
                let refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    values.iter().map(|v| v.as_ref()).collect();
                let changed = c.borrow_mut().execute(pg_sql(sql).as_str(), &refs)?;
                Ok(changed as usize)
            }
        }
    }

    pub fn query_row<T>(
        &self,
        sql: &str,
        params: Params,
        map: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        match self {
            Connection::Sqlite(c) => {
                let mut stmt = c.prepare(sql)?;
                let cols: Vec<String> = stmt.column_names().map(str::to_owned).collect();
                let values = sqlite_values(&params);
                let mut rows = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                match rows.next()? {
                    Some(row) => map(&sqlite_row(row, &cols)?),
                    None => Err(DbError::NoRows),
                }
            }
            Connection::Postgres(c) => {
                let values = pg_values(&params);
                let refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    values.iter().map(|v| v.as_ref()).collect();
                let rows = c.borrow_mut().query(pg_sql(sql).as_str(), &refs)?;
                match rows.first() {
                    Some(row) => map(&pg_row(row)?),
                    None => Err(DbError::NoRows),
                }
            }
        }
    }

    pub fn query_all(&self, sql: &str, params: Params) -> Result<Vec<Row>> {
        match self {
            Connection::Sqlite(c) => {
                let mut stmt = c.prepare(sql)?;
                let cols: Vec<String> = stmt.column_names().map(str::to_owned).collect();
                let values = sqlite_values(&params);
                let mut rows = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                let mut out = Vec::new();
                while let Some(row) = rows.next()? {
                    out.push(sqlite_row(row, &cols)?);
                }
                Ok(out)
            }
            Connection::Postgres(c) => {
                let values = pg_values(&params);
                let refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    values.iter().map(|v| v.as_ref()).collect();
                let rows = c.borrow_mut().query(pg_sql(sql).as_str(), &refs)?;
                rows.iter().map(pg_row).collect()
            }
        }
    }

    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        match self {
            Connection::Sqlite(c) => Ok(c.execute_batch(sql)?),
            Connection::Postgres(c) => {
                let rewritten = pg_sql(sql);
                Ok(c.borrow_mut().batch_execute(&rewritten)?)
            }
        }
    }

    fn begin(&self) -> Result<()> {
        self.execute_batch("BEGIN")
    }

    fn commit(&self) -> Result<()> {
        self.execute_batch("COMMIT")
    }

    fn rollback(&self) -> Result<()> {
        self.execute_batch("ROLLBACK")
    }
}

fn sqlite_row(row: &rusqlite::Row<'_>, cols: &[String]) -> Result<Row> {
    use rusqlite::types::ValueRef;
    let mut vals = Vec::with_capacity(cols.len());
    for i in 0..cols.len() {
        let value = match row.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(i) => Value::Integer(i),
            ValueRef::Real(f) => Value::Real(f),
            ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Value::Blob(b.to_vec()),
        };
        vals.push(value);
    }
    Ok(Row {
        cols: cols.to_vec(),
        vals,
    })
}

fn pg_row(row: &postgres::Row) -> Result<Row> {
    use postgres::types::Type;
    let mut cols = Vec::with_capacity(row.columns().len());
    let mut vals = Vec::with_capacity(row.columns().len());

    for (i, col) in row.columns().iter().enumerate() {
        cols.push(col.name().to_string());
        let ty = col.type_();
        let value = if *ty == Type::BOOL {
            row.try_get::<_, Option<bool>>(i)?
                .map(|b| Value::Integer(b as i64))
                .unwrap_or(Value::Null)
        } else if *ty == Type::INT2 {
            row.try_get::<_, Option<i16>>(i)?
                .map(|v| Value::Integer(v as i64))
                .unwrap_or(Value::Null)
        } else if *ty == Type::INT4 {
            row.try_get::<_, Option<i32>>(i)?
                .map(|v| Value::Integer(v as i64))
                .unwrap_or(Value::Null)
        } else if *ty == Type::INT8 {
            row.try_get::<_, Option<i64>>(i)?
                .map(Value::Integer)
                .unwrap_or(Value::Null)
        } else if *ty == Type::FLOAT4 {
            row.try_get::<_, Option<f32>>(i)?
                .map(|v| Value::Real(v as f64))
                .unwrap_or(Value::Null)
        } else if *ty == Type::FLOAT8 {
            row.try_get::<_, Option<f64>>(i)?
                .map(Value::Real)
                .unwrap_or(Value::Null)
        } else if *ty == Type::BYTEA {
            row.try_get::<_, Option<Vec<u8>>>(i)?
                .map(Value::Blob)
                .unwrap_or(Value::Null)
        } else {
            // TEXT, VARCHAR, BPCHAR, NAME, JSON, …
            row.try_get::<_, Option<String>>(i)?
                .map(Value::Text)
                .unwrap_or(Value::Null)
        };
        vals.push(value);
    }

    Ok(Row { cols, vals })
}

/// A transaction handle. Committing/rolling back is handled by [`Db::tx`].
pub struct Tx<'a> {
    conn: &'a Connection,
}

impl Tx<'_> {
    pub fn execute(&self, sql: &str, params: Params) -> Result<usize> {
        self.conn.execute(sql, params)
    }

    pub fn query_row<T>(
        &self,
        sql: &str,
        params: Params,
        map: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        self.conn.query_row(sql, params, map)
    }
}

impl std::ops::Deref for Tx<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn
    }
}

/// Run blocking database work without blocking a tokio worker. On a
/// multi-threaded runtime this parks the worker; in a synchronous context (or a
/// current-thread runtime) it just runs inline.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::RuntimeFlavor;
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// True when every configured PostgreSQL host is explicitly loopback.
///
/// TLS is mandatory for remote hosts, but a local `postgres` started without a
/// certificate is a normal development setup. Only literal loopback addresses
/// and `localhost` qualify: an arbitrary DNS name must not be able to downgrade
/// transport security by resolving to 127.0.0.1.
fn postgres_host_is_loopback(config: &postgres::Config) -> bool {
    let hosts = config.get_hosts();
    !hosts.is_empty()
        && hosts.iter().all(|host| match host {
            postgres::config::Host::Tcp(host) => {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .map(|ip| ip.is_loopback())
                        .unwrap_or(false)
            }
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => true,
        })
}

// ---------------------------------------------------------------------------
// Db
// ---------------------------------------------------------------------------

pub struct Db {
    conn: Mutex<Connection>,
    backend: &'static str,
}

impl Db {
    /// Open the database. A `database_url` starting with `postgres://` or
    /// `postgresql://` selects PostgreSQL (e.g. Supabase); otherwise `path`
    /// is used as a SQLite file.
    pub fn open(database_url: Option<&str>, path: &str) -> anyhow::Result<Self> {
        Self::open_with_options(database_url, path, true)
    }

    /// Open storage with an explicit migration policy. Serverless instances
    /// should connect to an already-migrated database instead of racing DDL
    /// during concurrent cold starts.
    pub fn open_with_options(
        database_url: Option<&str>,
        path: &str,
        auto_migrate: bool,
    ) -> anyhow::Result<Self> {
        match database_url {
            Some(url) if url.starts_with("postgres://") || url.starts_with("postgresql://") => {
                Self::open_postgres(url, auto_migrate)
            }
            Some(url) if !url.trim().is_empty() => {
                anyhow::bail!("KAGI_DATABASE_URL must start with postgres:// or postgresql://")
            }
            _ => Self::open_sqlite(path),
        }
    }

    fn open_sqlite(path: &str) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("opening sqlite db {path}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous=NORMAL;",
        )?;
        let db = Self {
            conn: Mutex::new(Connection::Sqlite(conn)),
            backend: "sqlite",
        };
        db.migrate()?;
        Ok(db)
    }

    fn open_postgres(url: &str, auto_migrate: bool) -> anyhow::Result<Self> {
        let url = url.to_string();
        // The synchronous PostgreSQL client drives a private current-thread
        // runtime, which panics if it is created on a tokio worker thread.
        // Connecting and migrating therefore happens inside a blocking region;
        // that works from `#[tokio::main]` locally and from the Vercel runtime.
        let client = blocking(move || -> anyhow::Result<postgres::Client> {
            // Never echo the URL: it contains the database password.
            let mut config: postgres::Config = url.parse().map_err(|_| {
                anyhow::anyhow!("parsing KAGI_DATABASE_URL failed; check the URL syntax")
            })?;
            // Identity data and signing keys must never travel over plaintext TCP.
            // Remote hosts therefore require TLS even if the supplied URL omitted
            // sslmode=require. Loopback is exempt so that a local `postgres`
            // instance (and the integration test suite) can run without a
            // certificate; `Prefer` still upgrades to TLS when the server offers it.
            config.ssl_mode(if postgres_host_is_loopback(&config) {
                postgres::config::SslMode::Prefer
            } else {
                postgres::config::SslMode::Require
            });
            let tls = native_tls::TlsConnector::builder()
                .build()
                .context("building TLS connector")?;
            let mut client = config
                .connect(postgres_native_tls::MakeTlsConnector::new(tls))
                .context("connecting to postgres (check KAGI_DATABASE_URL and sslmode)")?;
            if auto_migrate {
                // `supabase/schema.sql` contains both CREATE TABLE IF NOT EXISTS and
                // forward-compatible ALTER statements, so a single batch is enough.
                client
                    .batch_execute(POSTGRES_SCHEMA)
                    .context("applying supabase/schema.sql")?;
            }
            Ok(client)
        })?;
        Ok(Self {
            conn: Mutex::new(Connection::Postgres(RefCell::new(client))),
            backend: "postgres",
        })
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let c = self.lock();
        c.execute_batch(SQLITE_SCHEMA)?;
        // SQLite has no `ADD COLUMN IF NOT EXISTS`; ignore the duplicate-column
        // error so that upgrades are idempotent.
        for (table, column, decl) in [
            ("sessions", "last_seen_at", "INTEGER NOT NULL DEFAULT 0"),
            ("sessions", "user_agent", "TEXT"),
            ("sessions", "ip", "TEXT"),
            ("access_tokens", "session_id", "TEXT"),
            ("clients", "registration_token_hash", "TEXT"),
            ("clients", "backchannel_logout_uri", "TEXT"),
            (
                "clients",
                "backchannel_logout_session_required",
                "INTEGER NOT NULL DEFAULT 0",
            ),
            ("auth_codes", "claims", "TEXT"),
            ("refresh_tokens", "claims", "TEXT"),
            ("audit_events", "seq", "INTEGER"),
            ("audit_events", "prev_hash", "TEXT"),
            ("audit_events", "hash", "TEXT"),
        ] {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {decl}");
            if let Err(e) = c.execute_batch(&sql) {
                let message = e.to_string().to_ascii_lowercase();
                if !message.contains("duplicate column") && !message.contains("already exists") {
                    return Err(e.into());
                }
            }
        }
        // Created after the column migrations: on an upgraded database the
        // column does not exist yet while the schema batch runs.
        c.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(seq)")?;
        c.execute(
            "UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at = 0",
            params![],
        )?;
        Ok(())
    }

    /// `sqlite` or `postgres`, for start-up logging.
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let run = || {
            let guard = self.lock();
            f(&guard)
        };
        // The synchronous postgres client drives its own runtime internally,
        // so it must not run on a tokio worker thread.
        if self.backend == "postgres" {
            blocking(run)
        } else {
            run()
        }
    }

    pub fn tx<T>(&self, f: impl FnOnce(&Tx<'_>) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let run = || {
            let guard = self.lock();
            guard.begin()?;
            let tx = Tx { conn: &guard };
            match f(&tx) {
                Ok(v) => {
                    guard.commit()?;
                    Ok(v)
                }
                Err(e) => {
                    let _ = guard.rollback();
                    Err(e)
                }
            }
        };
        if self.backend == "postgres" {
            blocking(run)
        } else {
            run()
        }
    }

    /// Remove expired short-lived rows. Cheap enough to run on a timer.
    /// Delete expired or one-shot state that no longer serves a purpose.
    ///
    /// `audit_retention_days == 0` keeps the audit trail indefinitely.
    pub fn sweep(&self, audit_retention_days: i64) -> anyhow::Result<()> {
        let now = crate::util::now();
        self.with(|c| {
            c.execute("DELETE FROM flows WHERE expires_at < ?1", params![now])?;
            c.execute(
                "DELETE FROM auth_codes WHERE expires_at < ?1",
                params![now - 3600],
            )?;
            c.execute(
                "DELETE FROM dpop_replay WHERE expires_at < ?1",
                params![now],
            )?;
            c.execute(
                "DELETE FROM assertion_replay WHERE expires_at < ?1",
                params![now],
            )?;
            c.execute(
                "DELETE FROM device_codes WHERE expires_at < ?1",
                params![now - 3600],
            )?;
            c.execute(
                "DELETE FROM rate_limits WHERE window_start < ?1",
                params![now - 3600],
            )?;
            // Expired browser sessions may still have live access/refresh
            // tokens. Revoke them before deleting the session rows so a
            // forgotten tab cannot keep minting tokens after the session has
            // timed out.
            c.execute(
                "UPDATE refresh_tokens SET revoked = 1
                 WHERE session_id IN (SELECT id FROM sessions WHERE expires_at < ?1)",
                params![now],
            )?;
            c.execute(
                "UPDATE access_tokens SET revoked = 1
                 WHERE session_id IN (SELECT id FROM sessions WHERE expires_at < ?1)",
                params![now],
            )?;
            c.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])?;
            c.execute(
                "DELETE FROM refresh_tokens WHERE expires_at < ?1 AND revoked = 1",
                params![now - 86400],
            )?;
            c.execute(
                "DELETE FROM access_tokens WHERE expires_at < ?1",
                params![now - 86400],
            )?;
            // Consumed recovery codes have no further use; keep a short grace
            // window so a recent recovery can still be audited from the row.
            c.execute(
                "DELETE FROM recovery_codes WHERE used_at IS NOT NULL AND used_at < ?1",
                params![now - 30 * 86400],
            )?;
            Ok(())
        })?;
        if audit_retention_days > 0 {
            // Pruning must advance the chain anchor atomically, so it runs in
            // its own transaction after the lock above has been released.
            self.prune_audit(now - audit_retention_days * 86400)?;
        }
        Ok(())
    }

    /// Append one event to the tamper-evident audit chain.
    ///
    /// The read of the current head, the insert and the head update happen in
    /// one transaction. SQLite serialises via the process mutex; PostgreSQL
    /// additionally takes a transaction-scoped advisory lock so independently
    /// scaled instances cannot fork the chain.
    pub fn append_audit(
        &self,
        user_id: Option<&str>,
        client_id: Option<&str>,
        kind: &str,
        detail: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<()> {
        let id = crate::util::new_id();
        let created_at = crate::util::now();
        self.tx(|tx| {
            if self.backend == "postgres" {
                tx.execute(
                    "SELECT pg_advisory_xact_lock(?1)",
                    params![AUDIT_CHAIN_LOCK],
                )?;
            }
            let head = tx
                .query_row(
                    "SELECT seq, hash FROM audit_head WHERE id = 'head'",
                    params![],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let (previous_seq, prev_hash) = head.unwrap_or((0, AUDIT_GENESIS_HASH.to_string()));
            let seq = previous_seq + 1;
            let hash = audit_hash(
                seq, &id, created_at, user_id, client_id, kind, detail, ip, user_agent, &prev_hash,
            );
            tx.execute(
                "INSERT INTO audit_events
                     (id, user_id, client_id, kind, detail, ip, user_agent, created_at,
                      seq, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    id, user_id, client_id, kind, detail, ip, user_agent, created_at, seq,
                    prev_hash, hash
                ],
            )?;
            tx.execute(
                "INSERT INTO audit_head (id, seq, hash, updated_at)
                 VALUES ('head', ?1, ?2, ?3)
                 ON CONFLICT (id) DO UPDATE SET seq = ?1, hash = ?2, updated_at = ?3",
                params![seq, hash, created_at],
            )?;
            Ok(())
        })
    }

    /// Delete audit events older than `cutoff`, advancing the chain anchor to
    /// the last removed event so the retained suffix still verifies.
    pub fn prune_audit(&self, cutoff: i64) -> anyhow::Result<usize> {
        self.tx(|tx| {
            let anchor = tx
                .query_row(
                    "SELECT seq, hash FROM audit_head WHERE id = 'anchor'",
                    params![],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let last_removed = tx
                .query_row(
                    "SELECT seq, hash FROM audit_events
                     WHERE created_at < ?1 AND seq IS NOT NULL
                     ORDER BY seq DESC LIMIT 1",
                    params![cutoff],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let removed = tx.execute(
                "DELETE FROM audit_events WHERE created_at < ?1",
                params![cutoff],
            )?;
            if let Some((seq, hash)) = last_removed {
                // Never move the anchor backwards if a later prune races an
                // earlier one.
                if anchor.as_ref().is_none_or(|(current, _)| seq > *current) {
                    tx.execute(
                        "INSERT INTO audit_head (id, seq, hash, updated_at)
                         VALUES ('anchor', ?1, ?2, ?3)
                         ON CONFLICT (id) DO UPDATE SET seq = ?1, hash = ?2, updated_at = ?3",
                        params![seq, hash, crate::util::now()],
                    )?;
                }
            }
            Ok(removed)
        })
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub acr: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub kind: String,
    pub detail: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    /// Chain position. `None` for events written before the chain existed.
    pub seq: Option<i64>,
    pub prev_hash: Option<String>,
    pub hash: Option<String>,
}

/// Result of re-walking the audit hash chain.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditVerification {
    pub ok: bool,
    /// Chained events that were re-hashed and matched.
    pub checked: i64,
    /// Legacy events without a chain position (informational, not a failure).
    pub unhashed: i64,
    pub anchor_seq: i64,
    pub head_seq: i64,
    pub head_hash: Option<String>,
    /// First detected problem, if any (`gap`, `broken link`, `hash mismatch`).
    pub error: Option<String>,
    pub checked_at: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Consent {
    pub client_id: String,
    pub client_name: String,
    pub scope: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Stats {
    pub users: i64,
    pub credentials: i64,
    pub sessions: i64,
    pub clients: i64,
    pub active_access_tokens: i64,
    pub active_refresh_tokens: i64,
    pub audit_events: i64,
    pub recovery_codes: i64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub auth_method: String,
    pub jwks: Option<JsonValue>,
    pub require_dpop: bool,
    pub require_par: bool,
    pub id_token_alg: String,
    pub registration_token_hash: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub name: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Flow {
    pub id: String,
    pub kind: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub payload: JsonValue,
    pub challenge: Option<String>,
    pub csrf: Option<String>,
    pub expires_at: i64,
    pub consumed: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AuthCode {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub acr: String,
    pub dpop_jkt: Option<String>,
    pub session_id: Option<String>,
    pub claims: Option<String>,
    pub expires_at: i64,
    pub consumed: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct RefreshToken {
    pub token_hash: String,
    pub family_id: String,
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub acr: String,
    pub dpop_jkt: Option<String>,
    pub session_id: Option<String>,
    pub claims: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub rotated_to: Option<String>,
    pub revoked: bool,
}

/// A pending or completed RFC 8628 device authorization grant.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DeviceCode {
    pub device_hash: String,
    pub client_id: String,
    pub scope: String,
    pub user_id: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub status: String,
    pub interval_secs: i64,
    pub last_polled_at: i64,
    pub expires_at: i64,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Row mapping helpers
// ---------------------------------------------------------------------------

fn json_strings(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

fn map_user(row: &Row) -> Result<User> {
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        display_name: row.get("display_name")?,
        email: row.get("email")?,
        email_verified: row.get::<_, i64>("email_verified")? != 0,
        created_at: row.get("created_at")?,
    })
}

fn map_client(row: &Row) -> Result<Client> {
    let jwks_raw: Option<String> = row.get("jwks")?;
    Ok(Client {
        id: row.get("id")?,
        name: row.get("name")?,
        secret_hash: row.get("secret_hash")?,
        redirect_uris: json_strings(&row.get::<_, String>("redirect_uris")?),
        post_logout_redirect_uris: json_strings(
            &row.get::<_, String>("post_logout_redirect_uris")?,
        ),
        grant_types: json_strings(&row.get::<_, String>("grant_types")?),
        scopes: json_strings(&row.get::<_, String>("scopes")?),
        auth_method: row.get("auth_method")?,
        jwks: jwks_raw.and_then(|s| serde_json::from_str(&s).ok()),
        require_dpop: row.get::<_, i64>("require_dpop")? != 0,
        require_par: row.get::<_, i64>("require_par")? != 0,
        id_token_alg: row.get("id_token_alg")?,
        registration_token_hash: row.get("registration_token_hash")?,
        backchannel_logout_uri: row.get("backchannel_logout_uri")?,
        backchannel_logout_session_required: row
            .get::<_, i64>("backchannel_logout_session_required")?
            != 0,
    })
}

fn map_credential(row: &Row) -> Result<Credential> {
    Ok(Credential {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        public_key: row.get("public_key")?,
        key_type: row.get("key_type")?,
        sign_count: row.get("sign_count")?,
        transports: json_strings(&row.get::<_, String>("transports")?),
        backup_eligible: row.get::<_, i64>("backup_eligible")? != 0,
        name: row.get("nickname")?,
        created_at: row.get("created_at")?,
    })
}

fn map_session(row: &Row) -> Result<Session> {
    Ok(Session {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        auth_time: row.get("auth_time")?,
        amr: json_strings(&row.get::<_, String>("amr")?),
        acr: row.get("acr")?,
        expires_at: row.get("expires_at")?,
        created_at: row.get("created_at")?,
        last_seen_at: row.get("last_seen_at")?,
        user_agent: row.get("user_agent")?,
        ip: row.get("ip")?,
    })
}

fn map_flow(row: &Row) -> Result<Flow> {
    Ok(Flow {
        id: row.get("id")?,
        kind: row.get("kind")?,
        user_id: row.get("user_id")?,
        client_id: row.get("client_id")?,
        payload: serde_json::from_str(&row.get::<_, String>("payload")?).unwrap_or(JsonValue::Null),
        challenge: row.get("challenge")?,
        csrf: row.get("csrf")?,
        expires_at: row.get("expires_at")?,
        consumed: row.get::<_, i64>("consumed")? != 0,
    })
}

pub fn load_user(c: &Connection, id: &str) -> anyhow::Result<Option<User>> {
    Ok(
        c.query_row("SELECT * FROM users WHERE id = ?1", params![id], map_user)
            .optional()?,
    )
}

pub fn load_user_by_name(c: &Connection, username: &str) -> anyhow::Result<Option<User>> {
    Ok(c.query_row(
        "SELECT * FROM users WHERE lower(username) = lower(?1)",
        params![username],
        map_user,
    )
    .optional()?)
}

pub fn load_client(c: &Connection, id: &str) -> anyhow::Result<Option<Client>> {
    Ok(c.query_row(
        "SELECT * FROM clients WHERE id = ?1",
        params![id],
        map_client,
    )
    .optional()?)
}

/// Clients that hold a token for this user (optionally for one browser
/// session) and have registered a back-channel logout endpoint. Used to send
/// OIDC Back-Channel Logout tokens when a session ends.
pub fn backchannel_clients_for_user(
    c: &Connection,
    user_id: &str,
    session_id: Option<&str>,
) -> anyhow::Result<Vec<Client>> {
    let rows = match session_id {
        Some(sid) => c.query_all(
            "SELECT DISTINCT cl.* FROM clients cl
             JOIN access_tokens a ON a.client_id = cl.id
             WHERE a.user_id = ?1 AND a.session_id = ?2
               AND cl.backchannel_logout_uri IS NOT NULL",
            params![user_id, sid],
        )?,
        None => c.query_all(
            "SELECT DISTINCT cl.* FROM clients cl
             JOIN access_tokens a ON a.client_id = cl.id
             WHERE a.user_id = ?1 AND cl.backchannel_logout_uri IS NOT NULL",
            params![user_id],
        )?,
    };
    rows.iter()
        .map(|row| map_client(row).map_err(|error| anyhow::anyhow!(error.to_string())))
        .collect()
}

/// Remember (or update) the scopes a user has approved for a client.
pub fn record_consent(
    c: &Connection,
    user_id: &str,
    client_id: &str,
    scope: &str,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO consents (user_id, client_id, scope, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(user_id, client_id)
         DO UPDATE SET scope = excluded.scope, created_at = excluded.created_at",
        params![user_id, client_id, scope, crate::util::now()],
    )?;
    Ok(())
}

/// True when a stored consent already covers every requested scope.
pub fn consent_covers(
    c: &Connection,
    user_id: &str,
    client_id: &str,
    scope: &str,
) -> anyhow::Result<bool> {
    let stored: Option<String> = c
        .query_row(
            "SELECT scope FROM consents WHERE user_id = ?1 AND client_id = ?2",
            params![user_id, client_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    let granted = crate::oidc::split_scope(&stored);
    Ok(crate::oidc::split_scope(scope)
        .iter()
        .all(|s| granted.iter().any(|g| g == s)))
}

pub fn load_session(c: &Connection, id_hash: &str) -> anyhow::Result<Option<Session>> {
    Ok(c.query_row(
        "SELECT * FROM sessions WHERE id = ?1 AND expires_at > ?2",
        params![id_hash, crate::util::now()],
        map_session,
    )
    .optional()?)
}

pub fn list_sessions(c: &Connection, user_id: &str) -> anyhow::Result<Vec<Session>> {
    let rows = c.query_all(
        "SELECT * FROM sessions WHERE user_id = ?1 AND expires_at > ?2
         ORDER BY last_seen_at DESC, created_at DESC",
        params![user_id, crate::util::now()],
    )?;
    rows.iter()
        .map(|row| map_session(row).map_err(|e| anyhow::anyhow!(e.to_string())))
        .collect()
}

pub fn touch_session(c: &Connection, id_hash: &str, at: i64) -> anyhow::Result<()> {
    c.execute(
        "UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2",
        params![at, id_hash],
    )?;
    Ok(())
}

pub fn delete_session(c: &Connection, id_hash: &str, user_id: &str) -> anyhow::Result<usize> {
    Ok(c.execute(
        "DELETE FROM sessions WHERE id = ?1 AND user_id = ?2",
        params![id_hash, user_id],
    )?)
}

/// Revoke every token that was issued from a browser session. Access tokens
/// are JWTs, but kagi keeps their `jti` so logout can invalidate them
/// immediately.
pub fn revoke_session_tokens(c: &Connection, session_id: &str) -> anyhow::Result<()> {
    c.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?1",
        params![session_id],
    )?;
    c.execute(
        "UPDATE access_tokens SET revoked = 1 WHERE session_id = ?1",
        params![session_id],
    )?;
    Ok(())
}

/// Revoke every token a user holds for one client. Used when the user
/// withdraws consent from the account console.
pub fn revoke_client_tokens(c: &Connection, user_id: &str, client_id: &str) -> anyhow::Result<()> {
    c.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1 AND client_id = ?2",
        params![user_id, client_id],
    )?;
    c.execute(
        "UPDATE access_tokens SET revoked = 1 WHERE user_id = ?1 AND client_id = ?2",
        params![user_id, client_id],
    )?;
    Ok(())
}

/// Effect of an administrative revocation, reported back to the operator.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct RevocationSummary {
    pub sessions: usize,
    pub refresh_tokens: usize,
    pub access_tokens: usize,
    pub device_codes: usize,
}

/// Invalidate every credential a user currently holds.
///
/// This is the storage half of the administrative incident-response endpoint:
/// browser sessions are deleted, their access and refresh tokens revoked, and
/// pending device codes denied. Rows are only counted when their state
/// actually changes, so the summary is honest about the effect and the
/// operation is idempotent.
pub fn revoke_user_access(c: &Connection, user_id: &str) -> anyhow::Result<RevocationSummary> {
    let refresh_tokens = c.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1 AND revoked = 0",
        params![user_id],
    )?;
    let access_tokens = c.execute(
        "UPDATE access_tokens SET revoked = 1 WHERE user_id = ?1 AND revoked = 0",
        params![user_id],
    )?;
    let sessions = c.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
    let device_codes = c.execute(
        "UPDATE device_codes SET status = 'denied'
         WHERE user_id = ?1 AND status = 'pending'",
        params![user_id],
    )?;
    Ok(RevocationSummary {
        sessions,
        refresh_tokens,
        access_tokens,
        device_codes,
    })
}

pub fn update_user_profile(
    c: &Connection,
    user_id: &str,
    display_name: &str,
    email: Option<&str>,
) -> anyhow::Result<()> {
    c.execute(
        "UPDATE users SET display_name = ?1, email = ?2 WHERE id = ?3",
        params![display_name, email, user_id],
    )?;
    Ok(())
}

pub fn delete_user(c: &Connection, user_id: &str) -> anyhow::Result<usize> {
    // Tokens have no foreign key: remove them explicitly before the user row.
    c.execute(
        "DELETE FROM access_tokens WHERE user_id = ?1",
        params![user_id],
    )?;
    c.execute(
        "DELETE FROM refresh_tokens WHERE user_id = ?1",
        params![user_id],
    )?;
    c.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    Ok(c.execute("DELETE FROM users WHERE id = ?1", params![user_id])?)
}

pub fn rename_credential(
    c: &Connection,
    id: &str,
    user_id: &str,
    name: &str,
) -> anyhow::Result<usize> {
    Ok(c.execute(
        "UPDATE credentials SET nickname = ?1 WHERE id = ?2 AND user_id = ?3",
        params![name, id, user_id],
    )?)
}

pub fn delete_credential(c: &Connection, id: &str, user_id: &str) -> anyhow::Result<usize> {
    Ok(c.execute(
        "DELETE FROM credentials WHERE id = ?1 AND user_id = ?2",
        params![id, user_id],
    )?)
}

pub fn count_credentials(c: &Connection, user_id: &str) -> anyhow::Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM credentials WHERE user_id = ?1",
        params![user_id],
        |r| r.get(0),
    )?)
}

pub fn list_consents(c: &Connection, user_id: &str) -> anyhow::Result<Vec<Consent>> {
    let rows = c.query_all(
        "SELECT c.client_id, COALESCE(cl.name, c.client_id) AS client_name, c.scope, c.created_at
         FROM consents c LEFT JOIN clients cl ON cl.id = c.client_id
         WHERE c.user_id = ?1 ORDER BY c.created_at DESC",
        params![user_id],
    )?;
    Ok(rows
        .iter()
        .map(|r| {
            Ok(Consent {
                client_id: r.get("client_id")?,
                client_name: r.get("client_name")?,
                scope: r.get("scope")?,
                created_at: r.get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?)
}

pub fn delete_consent(c: &Connection, user_id: &str, client_id: &str) -> anyhow::Result<usize> {
    Ok(c.execute(
        "DELETE FROM consents WHERE user_id = ?1 AND client_id = ?2",
        params![user_id, client_id],
    )?)
}

/// Canonical, unambiguous encoding of every field covered by the chain hash.
///
/// Length prefixes keep `("ab", "c")` and `("a", "bc")` distinct without
/// depending on JSON escaping details, so verification is stable across
/// backends and releases.
#[allow(clippy::too_many_arguments)]
fn audit_hash(
    seq: i64,
    id: &str,
    created_at: i64,
    user_id: Option<&str>,
    client_id: Option<&str>,
    kind: &str,
    detail: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    prev_hash: &str,
) -> String {
    use std::fmt::Write;

    let mut canonical = String::with_capacity(256);
    canonical.push_str("kagi-audit-v1\n");
    let mut field = |value: Option<&str>| {
        match value {
            Some(value) => {
                let _ = write!(canonical, "{}:", value.len());
                canonical.push_str(value);
            }
            None => canonical.push_str("-1:"),
        }
        canonical.push('\n');
    };

    field(Some(prev_hash));
    field(Some(&seq.to_string()));
    field(Some(id));
    field(Some(&created_at.to_string()));
    field(user_id);
    field(client_id);
    field(Some(kind));
    field(Some(detail));
    field(ip);
    field(user_agent);
    crate::util::sha256_hex(&canonical)
}

fn map_audit(row: &Row) -> Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        client_id: row.get("client_id")?,
        kind: row.get("kind")?,
        detail: row.get("detail").unwrap_or_default(),
        ip: row.get("ip")?,
        user_agent: row.get("user_agent")?,
        created_at: row.get("created_at")?,
        seq: row.get("seq")?,
        prev_hash: row.get("prev_hash")?,
        hash: row.get("hash")?,
    })
}

pub fn recent_audit(c: &Connection, user_id: &str, limit: i64) -> anyhow::Result<Vec<AuditEvent>> {
    let rows = c.query_all(
        "SELECT * FROM audit_events WHERE user_id = ?1
         ORDER BY created_at DESC LIMIT ?2",
        params![user_id, limit.clamp(1, 100)],
    )?;
    rows.iter()
        .map(map_audit)
        .collect::<Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Return the chained audit events after `after_seq`, oldest first.
pub fn audit_page(c: &Connection, after_seq: i64, limit: i64) -> anyhow::Result<Vec<AuditEvent>> {
    let rows = c.query_all(
        "SELECT * FROM audit_events
         WHERE seq IS NOT NULL AND seq > ?1
         ORDER BY seq ASC LIMIT ?2",
        params![after_seq, limit.clamp(1, 5000)],
    )?;
    rows.iter()
        .map(map_audit)
        .collect::<Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Current chain head as `(seq, hash)`, if anything has been chained yet.
pub fn audit_head(c: &Connection) -> anyhow::Result<Option<(i64, String)>> {
    Ok(c.query_row(
        "SELECT seq, hash FROM audit_head WHERE id = 'head'",
        params![],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()?)
}

/// Re-walk the chain from the pruning anchor and re-hash every event.
pub fn audit_verify(c: &Connection) -> anyhow::Result<AuditVerification> {
    let anchor = c
        .query_row(
            "SELECT seq, hash FROM audit_head WHERE id = 'anchor'",
            params![],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let head = audit_head(c)?;
    let (mut expected_seq, mut prev_hash) = match &anchor {
        Some((seq, hash)) => (seq + 1, hash.clone()),
        None => (1, AUDIT_GENESIS_HASH.to_string()),
    };
    let anchor_seq = anchor.map(|(seq, _)| seq).unwrap_or(0);
    let unhashed: i64 = c.query_row(
        "SELECT COUNT(*) FROM audit_events WHERE seq IS NULL",
        params![],
        |row| row.get(0),
    )?;

    let rows = c.query_all(
        "SELECT * FROM audit_events WHERE seq IS NOT NULL ORDER BY seq ASC",
        params![],
    )?;
    let mut checked = 0i64;
    let mut error = None;
    let mut last_seq = anchor_seq;
    for row in rows.iter() {
        let event = map_audit(row)?;
        let seq = event.seq.unwrap_or_default();
        if seq != expected_seq {
            error = Some(format!(
                "chain gap: expected seq {expected_seq}, found {seq}"
            ));
            break;
        }
        let prev = event.prev_hash.clone().unwrap_or_default();
        if prev != prev_hash {
            error = Some(format!("broken link at seq {seq}"));
            break;
        }
        let computed = audit_hash(
            seq,
            &event.id,
            event.created_at,
            event.user_id.as_deref(),
            event.client_id.as_deref(),
            &event.kind,
            &event.detail,
            event.ip.as_deref(),
            event.user_agent.as_deref(),
            &prev,
        );
        if event.hash.as_deref() != Some(computed.as_str()) {
            error = Some(format!("hash mismatch at seq {seq}"));
            break;
        }
        prev_hash = computed;
        expected_seq += 1;
        last_seq = seq;
        checked += 1;
    }

    // A head that does not describe the last walked event means rows were
    // removed without advancing the anchor, or the head itself was edited.
    if error.is_none() {
        match &head {
            Some((seq, hash)) if *seq == last_seq && hash == &prev_hash => {}
            Some((seq, _)) => {
                error = Some(format!(
                    "chain head mismatch: head seq {seq}, verified through {last_seq}"
                ))
            }
            None if checked == 0 => {}
            None => error = Some("chain head is missing".to_string()),
        }
    }

    Ok(AuditVerification {
        ok: error.is_none(),
        checked,
        unhashed,
        anchor_seq,
        head_seq: head.as_ref().map(|(seq, _)| *seq).unwrap_or(0),
        head_hash: head.map(|(_, hash)| hash),
        error,
        checked_at: crate::util::now(),
    })
}

/// Replace all unused recovery codes for a user. Returns nothing: callers show
/// the plaintext codes once, only hashes are persisted.
pub fn replace_recovery_codes(
    c: &Connection,
    user_id: &str,
    hashes: &[String],
    created_at: i64,
) -> anyhow::Result<()> {
    c.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
        params![user_id],
    )?;
    for hash in hashes {
        c.execute(
            "INSERT INTO recovery_codes (code_hash, user_id, created_at, used_at)
             VALUES (?1, ?2, ?3, NULL)",
            params![hash, user_id, created_at],
        )?;
    }
    Ok(())
}

pub fn count_recovery_codes(c: &Connection, user_id: &str) -> anyhow::Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
        params![user_id],
        |r| r.get(0),
    )?)
}

/// Atomically mark a recovery code as used. Returns `true` when this exact code
/// was unused and is now consumed.
pub fn consume_recovery_code(
    c: &Connection,
    user_id: &str,
    code_hash: &str,
) -> anyhow::Result<bool> {
    let changed = c.execute(
        "UPDATE recovery_codes SET used_at = ?1
         WHERE code_hash = ?2 AND user_id = ?3 AND used_at IS NULL",
        params![crate::util::now(), code_hash, user_id],
    )?;
    Ok(changed == 1)
}

/// Minimal, non-secret account state for the administrative user view.
/// Counts are of *currently usable* credentials so that an operator can tell a
/// dormant account from one with live sessions and tokens.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct UserOverview {
    pub passkeys: i64,
    pub sessions: i64,
    pub active_access_tokens: i64,
    pub active_refresh_tokens: i64,
    pub audit_events: i64,
    /// Latest session activity (0 when the account has never had a session).
    pub last_seen_at: i64,
    /// Latest issue time across access and refresh tokens.
    pub last_token_issued_at: i64,
    /// Latest passkey assertion.
    pub last_credential_used_at: i64,
    /// Latest audit event attributed to the user.
    pub last_audit_at: i64,
}

impl UserOverview {
    /// Best-effort "last activity" across every signal the operator can see.
    pub fn last_activity_at(&self) -> i64 {
        self.last_seen_at
            .max(self.last_token_issued_at)
            .max(self.last_credential_used_at)
            .max(self.last_audit_at)
    }
}

pub fn user_overview(c: &Connection, user_id: &str) -> anyhow::Result<UserOverview> {
    let now = crate::util::now();
    let count = |sql: &str| -> anyhow::Result<i64> {
        Ok(c.query_row(sql, params![user_id, now], |r| r.get(0))?)
    };
    let last = |sql: &str| -> anyhow::Result<i64> {
        Ok(c.query_row(sql, params![user_id], |r| r.get(0))?)
    };
    let refresh_issued =
        last("SELECT COALESCE(MAX(issued_at), 0) FROM refresh_tokens WHERE user_id = ?1")?;
    let access_issued =
        last("SELECT COALESCE(MAX(issued_at), 0) FROM access_tokens WHERE user_id = ?1")?;
    Ok(UserOverview {
        passkeys: last("SELECT COUNT(*) FROM credentials WHERE user_id = ?1")?,
        sessions: count("SELECT COUNT(*) FROM sessions WHERE user_id = ?1 AND expires_at > ?2")?,
        active_access_tokens: count(
            "SELECT COUNT(*) FROM access_tokens
             WHERE user_id = ?1 AND revoked = 0 AND expires_at > ?2",
        )?,
        active_refresh_tokens: count(
            "SELECT COUNT(*) FROM refresh_tokens
             WHERE user_id = ?1 AND revoked = 0 AND expires_at > ?2",
        )?,
        audit_events: last("SELECT COUNT(*) FROM audit_events WHERE user_id = ?1")?,
        last_seen_at: last(
            "SELECT COALESCE(MAX(last_seen_at), 0) FROM sessions WHERE user_id = ?1",
        )?,
        last_token_issued_at: refresh_issued.max(access_issued),
        last_credential_used_at: last(
            "SELECT COALESCE(MAX(last_used_at), 0) FROM credentials WHERE user_id = ?1",
        )?,
        last_audit_at: last(
            "SELECT COALESCE(MAX(created_at), 0) FROM audit_events WHERE user_id = ?1",
        )?,
    })
}

pub fn stats(c: &Connection) -> anyhow::Result<Stats> {
    let count =
        |sql: &str| -> anyhow::Result<i64> { Ok(c.query_row(sql, params![], |r| r.get(0))?) };
    let now = crate::util::now();
    Ok(Stats {
        users: count("SELECT COUNT(*) FROM users")?,
        credentials: count("SELECT COUNT(*) FROM credentials")?,
        sessions: c.query_row(
            "SELECT COUNT(*) FROM sessions WHERE expires_at > ?1",
            params![now],
            |r| r.get(0),
        )?,
        clients: count("SELECT COUNT(*) FROM clients")?,
        active_access_tokens: c.query_row(
            "SELECT COUNT(*) FROM access_tokens WHERE revoked = 0 AND expires_at > ?1",
            params![now],
            |r| r.get(0),
        )?,
        active_refresh_tokens: c.query_row(
            "SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0 AND expires_at > ?1",
            params![now],
            |r| r.get(0),
        )?,
        audit_events: count("SELECT COUNT(*) FROM audit_events")?,
        recovery_codes: count("SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NULL")?,
    })
}

pub fn load_flow(c: &Connection, id: &str) -> anyhow::Result<Option<Flow>> {
    Ok(c.query_row(
        "SELECT * FROM flows WHERE id = ?1 AND expires_at > ?2 AND consumed = 0",
        params![id, crate::util::now()],
        map_flow,
    )
    .optional()?)
}

pub fn load_code(c: &Connection, code_hash: &str) -> anyhow::Result<Option<AuthCode>> {
    Ok(c.query_row(
        "SELECT * FROM auth_codes WHERE code_hash = ?1",
        params![code_hash],
        |row| {
            Ok(AuthCode {
                code_hash: row.get("code_hash")?,
                client_id: row.get("client_id")?,
                user_id: row.get("user_id")?,
                redirect_uri: row.get("redirect_uri")?,
                scope: row.get("scope")?,
                nonce: row.get("nonce")?,
                code_challenge: row.get("code_challenge")?,
                auth_time: row.get("auth_time")?,
                amr: json_strings(&row.get::<_, String>("amr")?),
                acr: row.get("acr")?,
                dpop_jkt: row.get("dpop_jkt")?,
                session_id: row.get("session_id")?,
                claims: row.get("claims")?,
                expires_at: row.get("expires_at")?,
                consumed: row.get::<_, i64>("consumed")? != 0,
            })
        },
    )
    .optional()?)
}

pub fn load_refresh(c: &Connection, token_hash: &str) -> anyhow::Result<Option<RefreshToken>> {
    Ok(c.query_row(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?1",
        params![token_hash],
        |row| {
            Ok(RefreshToken {
                token_hash: row.get("token_hash")?,
                family_id: row.get("family_id")?,
                user_id: row.get("user_id")?,
                client_id: row.get("client_id")?,
                scope: row.get("scope")?,
                auth_time: row.get("auth_time")?,
                amr: json_strings(&row.get::<_, String>("amr")?),
                acr: row.get("acr")?,
                dpop_jkt: row.get("dpop_jkt")?,
                session_id: row.get("session_id")?,
                claims: row.get("claims")?,
                issued_at: row.get("issued_at")?,
                expires_at: row.get("expires_at")?,
                rotated_to: row.get("rotated_to")?,
                revoked: row.get::<_, i64>("revoked")? != 0,
            })
        },
    )
    .optional()?)
}

/// Load a device grant by the SHA-256 of its device code.
pub fn load_device(c: &Connection, device_hash: &str) -> anyhow::Result<Option<DeviceCode>> {
    Ok(c.query_row(
        "SELECT * FROM device_codes WHERE device_hash = ?1",
        params![device_hash],
        map_device,
    )
    .optional()?)
}

/// Resolve the human-entered user code. Expired grants are never returned.
pub fn load_device_by_user_code(
    c: &Connection,
    user_code_hash: &str,
) -> anyhow::Result<Option<DeviceCode>> {
    Ok(c.query_row(
        "SELECT * FROM device_codes WHERE user_code_hash = ?1 AND expires_at > ?2",
        params![user_code_hash, crate::util::now()],
        map_device,
    )
    .optional()?)
}

/// Return the authorization grant (if any) that a browser session established.
fn map_device(row: &Row) -> Result<DeviceCode> {
    Ok(DeviceCode {
        device_hash: row.get("device_hash")?,
        client_id: row.get("client_id")?,
        scope: row.get("scope")?,
        user_id: row.get("user_id")?,
        auth_time: row.get("auth_time")?,
        amr: json_strings(&row.get::<_, String>("amr")?),
        acr: row.get("acr")?,
        status: row.get("status")?,
        interval_secs: row.get("interval_secs")?,
        last_polled_at: row.get("last_polled_at")?,
        expires_at: row.get("expires_at")?,
        created_at: row.get("created_at")?,
    })
}

pub fn credentials_for_user(c: &Connection, user_id: &str) -> anyhow::Result<Vec<Credential>> {
    let rows = c.query_all(
        "SELECT id, user_id, public_key, key_type, sign_count, transports, backup_eligible, nickname, created_at
         FROM credentials WHERE user_id = ?1 ORDER BY created_at",
        params![user_id],
    )?;
    let out = rows
        .iter()
        .map(map_credential)
        .collect::<Result<Vec<_>>>()?;
    Ok(out)
}

pub fn load_credential(c: &Connection, id: &str) -> anyhow::Result<Option<Credential>> {
    Ok(c.query_row(
        "SELECT id, user_id, public_key, key_type, sign_count, transports, backup_eligible, nickname, created_at
         FROM credentials WHERE id = ?1",
        params![id],
        map_credential,
    )
    .optional()?)
}

/// Seed a public demo client so the server is usable immediately.
pub fn seed_demo_client(c: &Connection) -> anyhow::Result<()> {
    let exists: Option<String> = c
        .query_row(
            "SELECT id FROM clients WHERE id = 'demo-web'",
            params![],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_some() {
        return Ok(());
    }
    c.execute(
        "INSERT INTO clients (id, name, secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, scopes, auth_method, jwks, require_dpop, require_par, id_token_alg, created_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, NULL, 0, 0, 'ES256', ?8)",
        params![
            "demo-web",
            "kagi demo",
            serde_json::to_string(&vec![
                "http://localhost:3000/callback",
                "http://localhost:8080/demo/callback",
            ])?,
            "[]",
            serde_json::to_string(&vec![
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"
            ])?,
            serde_json::to_string(&vec!["openid", "profile", "email", "offline_access"])?,
            "none",
            crate::util::now(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod schema_regression_tests {
    #[test]
    fn postgres_schema_contains_runtime_security_tables_and_columns() {
        let schema = super::POSTGRES_SCHEMA;
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS last_seen_at"));
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS session_id"));
        assert!(schema.contains("CREATE TABLE IF NOT EXISTS audit_events"));
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS seq BIGINT"));
        assert!(schema.contains("CREATE TABLE IF NOT EXISTS audit_head"));
        assert!(schema.contains("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq"));
        assert!(schema.contains("CREATE TABLE IF NOT EXISTS recovery_codes"));
    }

    fn loopback(url: &str) -> bool {
        super::postgres_host_is_loopback(&url.parse().expect("valid postgres url"))
    }

    #[test]
    fn only_explicit_loopback_hosts_relax_tls() {
        assert!(loopback("postgresql://kagi@127.0.0.1:5432/postgres"));
        assert!(loopback("postgresql://kagi@localhost/postgres"));
        assert!(loopback("postgresql://kagi@[::1]:5432/postgres"));
        assert!(!loopback("postgresql://kagi@db.example.com/postgres"));
        assert!(!loopback("postgresql://kagi@10.0.0.5/postgres"));
    }

    #[test]
    fn invalid_database_url_error_does_not_disclose_credentials() {
        let supplied = "mysql://service-user:very-secret-password@db.example.invalid/identity";
        let error = super::Db::open_with_options(Some(supplied), ":memory:", false)
            .err()
            .expect("an unsupported database scheme must be rejected");
        let message = format!("{error:#}");

        assert!(message.contains("KAGI_DATABASE_URL"));
        assert!(!message.contains("very-secret-password"));
        assert!(!message.contains("service-user"));
    }

    #[test]
    fn malformed_postgres_url_error_does_not_disclose_credentials() {
        let supplied =
            "postgresql://service-user:very-secret-password@db.example.invalid:not-a-port/identity";
        let error = super::Db::open_with_options(Some(supplied), ":memory:", false)
            .err()
            .expect("a malformed PostgreSQL URL must be rejected");
        let message = format!("{error:#}");

        assert!(message.contains("KAGI_DATABASE_URL"));
        assert!(!message.contains("very-secret-password"));
        assert!(!message.contains("service-user"));
    }

    fn audit_db() -> super::Db {
        super::Db::open_with_options(None, ":memory:", true).expect("in-memory sqlite db")
    }

    fn append(db: &super::Db, count: usize) {
        for i in 0..count {
            db.append_audit(
                Some("user-1"),
                Some("client-1"),
                "test.event",
                &format!("detail {i}"),
                Some("127.0.0.1"),
                Some("test-agent"),
            )
            .expect("append audit");
        }
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let db = audit_db();
        append(&db, 5);

        let verification = db.with(super::audit_verify).expect("verify chain");
        assert!(verification.ok, "{:?}", verification.error);
        assert_eq!(verification.checked, 5);
        assert_eq!(verification.head_seq, 5);
        assert_eq!(verification.unhashed, 0);

        db.with(|c| {
            c.execute(
                "UPDATE audit_events SET detail = 'tampered' WHERE seq = 2",
                super::params![],
            )?;
            Ok(())
        })
        .expect("tamper");

        let verification = db.with(super::audit_verify).expect("verify chain");
        assert!(!verification.ok);
        assert!(
            verification
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("hash mismatch"),
            "{:?}",
            verification.error
        );
    }

    #[test]
    fn audit_chain_detects_a_removed_link() {
        let db = audit_db();
        append(&db, 4);

        db.with(|c| {
            c.execute("DELETE FROM audit_events WHERE seq = 2", super::params![])?;
            Ok(())
        })
        .expect("delete link");

        let verification = db.with(super::audit_verify).expect("verify chain");
        assert!(!verification.ok);
        assert!(verification
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("chain gap"));
    }

    #[test]
    fn audit_retention_advances_the_anchor_and_keeps_the_suffix_verifiable() {
        let db = audit_db();
        append(&db, 5);
        db.with(|c| {
            c.execute(
                "UPDATE audit_events SET created_at = 1 WHERE seq <= 2",
                super::params![],
            )?;
            Ok(())
        })
        .expect("age rows");

        let removed = db.prune_audit(crate::util::now()).expect("prune");
        assert_eq!(removed, 2);

        let verification = db.with(super::audit_verify).expect("verify chain");
        assert!(verification.ok, "{:?}", verification.error);
        assert_eq!(verification.anchor_seq, 2);
        assert_eq!(verification.checked, 3);
        assert_eq!(verification.head_seq, 5);
    }

    #[test]
    fn audit_chain_skips_legacy_rows_but_links_new_events() {
        let db = audit_db();
        // A pre-chain event as written by an older release.
        db.with(|c| {
            c.execute(
                "INSERT INTO audit_events (id, kind, detail, created_at) VALUES ('legacy', 'old', 'x', 1)",
                super::params![],
            )?;
            Ok(())
        })
        .expect("legacy row");
        append(&db, 2);

        let verification = db.with(super::audit_verify).expect("verify chain");
        assert!(verification.ok, "{:?}", verification.error);
        assert_eq!(verification.unhashed, 1);
        assert_eq!(verification.checked, 2);
    }

    fn seed_shared_user(db: &super::Db) {
        let now = crate::util::now();
        db.with(|c| {
            c.execute(
                "INSERT INTO users (id, username, display_name, created_at)
                 VALUES ('u1', 'u1', 'User One', ?1)",
                super::params![now],
            )?;
            c.execute(
                "INSERT INTO sessions (id, user_id, auth_time, amr, acr, expires_at, created_at)
                 VALUES ('s1', 'u1', ?1, '[]', 'urn:kagi:acr:passkey', ?2, ?1)",
                super::params![now, now + 3600],
            )?;
            c.execute(
                "INSERT INTO refresh_tokens
                     (token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr,
                      issued_at, expires_at)
                 VALUES ('rt', 'family', 'u1', 'demo-web', 'openid', ?1, '[]', 'acr', ?1, ?2)",
                super::params![now, now + 3600],
            )?;
            c.execute(
                "INSERT INTO access_tokens
                     (jti, user_id, client_id, scope, audience, subject, issued_at, expires_at)
                 VALUES ('at', 'u1', 'demo-web', 'openid', 'issuer', 'u1', ?1, ?2)",
                super::params![now, now + 300],
            )?;
            c.execute(
                "INSERT INTO device_codes
                     (device_hash, user_code_hash, client_id, scope, user_id, status,
                      interval_secs, expires_at, created_at)
                 VALUES ('dh', 'uch', 'demo-web', 'openid', 'u1', 'pending', 5, ?1, ?2)",
                super::params![now + 600, now],
            )?;
            Ok(())
        })
        .expect("seed shared user");
    }

    #[test]
    fn revoke_user_access_invalidates_every_credential_once() {
        let db = audit_db();
        seed_shared_user(&db);

        let summary = db
            .with(|c| super::revoke_user_access(c, "u1"))
            .expect("revoke user");
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.refresh_tokens, 1);
        assert_eq!(summary.access_tokens, 1);
        assert_eq!(summary.device_codes, 1);

        let (sessions, refresh_revoked, access_revoked, device_status): (i64, i64, i64, String) =
            db.with(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM sessions", super::params![], |r| {
                        r.get(0)
                    })?,
                    c.query_row(
                        "SELECT revoked FROM refresh_tokens WHERE token_hash = 'rt'",
                        super::params![],
                        |r| r.get(0),
                    )?,
                    c.query_row(
                        "SELECT revoked FROM access_tokens WHERE jti = 'at'",
                        super::params![],
                        |r| r.get(0),
                    )?,
                    c.query_row(
                        "SELECT status FROM device_codes WHERE device_hash = 'dh'",
                        super::params![],
                        |r| r.get(0),
                    )?,
                ))
            })
            .expect("inspect revocation");
        assert_eq!(sessions, 0);
        assert_eq!(refresh_revoked, 1);
        assert_eq!(access_revoked, 1);
        assert_eq!(device_status, "denied");

        // A second call reports no further changes.
        let again = db
            .with(|c| super::revoke_user_access(c, "u1"))
            .expect("revoke twice");
        assert_eq!(again.sessions, 0);
        assert_eq!(again.refresh_tokens, 0);
        assert_eq!(again.access_tokens, 0);
        assert_eq!(again.device_codes, 0);
    }

    #[test]
    fn user_overview_reports_live_state_and_drops_after_revocation() {
        let db = audit_db();
        seed_shared_user(&db);

        let overview = db
            .with(|c| super::user_overview(c, "u1"))
            .expect("user overview");
        assert_eq!(overview.sessions, 1);
        assert_eq!(overview.active_refresh_tokens, 1);
        assert_eq!(overview.active_access_tokens, 1);
        assert_eq!(overview.passkeys, 0);
        assert!(overview.last_token_issued_at > 0);
        assert!(overview.last_activity_at() >= overview.last_token_issued_at);

        db.with(|c| super::revoke_user_access(c, "u1"))
            .expect("revoke user");
        let after = db
            .with(|c| super::user_overview(c, "u1"))
            .expect("overview after revoke");
        assert_eq!(after.sessions, 0);
        assert_eq!(after.active_refresh_tokens, 0);
        assert_eq!(after.active_access_tokens, 0);
        // Historical signals survive revocation so the operator can still see
        // when the account was last active.
        assert_eq!(after.last_token_issued_at, overview.last_token_issued_at);
    }

    #[test]
    fn audit_pages_are_cursor_ordered() {
        let db = audit_db();
        append(&db, 6);
        let first = db.with(|c| super::audit_page(c, 0, 4)).expect("first page");
        assert_eq!(first.len(), 4);
        assert_eq!(first[0].seq, Some(1));
        let cursor = first.last().and_then(|event| event.seq).unwrap();
        let second = db
            .with(|c| super::audit_page(c, cursor, 4))
            .expect("second page");
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].seq, Some(5));
        assert_eq!(second[1].seq, Some(6));
    }
}
