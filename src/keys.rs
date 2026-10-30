use crate::db::Db;
use crate::jose::SigKey;
use crate::util::now;
use crate::db::params;
use anyhow::Context;
use rand::rngs::SysRng;
use serde_json::{json, Value};

/// In-memory view of the signing keys. The current key signs, older keys stay
/// published so tokens minted just before a rotation still verify.
pub struct KeyRing {
    keys: Vec<SigKey>,
    current: usize,
}

const MAX_KEYS: i64 = 3;

fn new_signing_key() -> SigKey {
    let key = p256::ecdsa::SigningKey::random(&mut SysRng);
    let kid = crate::util::random_token(9);
    SigKey { kid, key }
}

impl KeyRing {
    pub fn load(db: &Db) -> anyhow::Result<Self> {
        let raw: Vec<(String, String)> = db.with(|c| {
            let rows = c.query_all(
                "SELECT kid, private_jwk FROM signing_keys ORDER BY active DESC, created_at DESC, kid DESC",
                params![],
            )?;
            rows.iter()
                .map(|r| Ok((r.get(0)?, r.get(1)?)))
                .collect()
        })?;

        if raw.is_empty() {
            let sk = new_signing_key();
            let kid = sk.kid.clone();
            let private = serde_json::to_string(&sk.private_jwk())?;
            let public = serde_json::to_string(&sk.public_jwk())?;
            db.with(|c| {
                c.execute(
                    "INSERT INTO signing_keys (kid, private_jwk, public_jwk, created_at, active)
                     VALUES (?1, ?2, ?3, ?4, 1)",
                    params![kid, private, public, now()],
                )?;
                Ok(())
            })?;
            return Ok(Self { keys: vec![sk], current: 0 });
        }

        let mut keys = Vec::new();
        for (kid, private_jwk) in raw {
            let jwk: Value = serde_json::from_str(&private_jwk)
                .with_context(|| format!("signing key {kid} is not valid JSON"))?;
            keys.push(SigKey::from_jwk(&jwk, &kid)?);
        }
        Ok(Self { keys, current: 0 })
    }

    pub fn current(&self) -> &SigKey {
        &self.keys[self.current.min(self.keys.len() - 1)]
    }

    pub fn find(&self, kid: &str) -> Option<&SigKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    pub fn jwks(&self) -> Value {
        json!({ "keys": self.keys.iter().map(|k| k.public_jwk()).collect::<Vec<_>>() })
    }

    pub fn key_ids(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.kid.clone()).collect()
    }

    /// Create a new signing key, retire the previous one and prune old keys.
    pub fn rotate(&mut self, db: &Db) -> anyhow::Result<String> {
        let sk = new_signing_key();
        let kid = sk.kid.clone();
        let private = serde_json::to_string(&sk.private_jwk())?;
        let public = serde_json::to_string(&sk.public_jwk())?;
        db.with(|c| {
            c.execute(
                "INSERT INTO signing_keys (kid, private_jwk, public_jwk, created_at, active)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                params![kid, private, public, now()],
            )?;
            c.execute("UPDATE signing_keys SET active = 0 WHERE kid <> ?1", params![kid])?;
            c.execute(
                "DELETE FROM signing_keys WHERE kid NOT IN (
                     SELECT kid FROM signing_keys ORDER BY created_at DESC, kid DESC LIMIT ?1
                 )",
                params![MAX_KEYS],
            )?;
            Ok(())
        })?;
        *self = Self::load(db)?;
        Ok(kid)
    }
}
