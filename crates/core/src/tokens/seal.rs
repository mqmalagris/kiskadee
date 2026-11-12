//! Row seals: an HMAC over every `tokens.db` column, so a row edited or
//! forged outside the Broker is refused.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::ledger::encoding::{self, Field};

/// Domain string for row seals, so a seal can't be replayed as anything else.
const SEAL_DOMAIN: &[u8] = b"kiskadee/tokens/v2";

pub(super) const ROW_COLUMNS: &str =
    "id, hash, profile, scope, created_ms, expires_ms, revoked_ms, reads_used, seal";

/// The Broker's key for sealing `tokens.db` rows. Derived from the
/// user-presence unlock once per Broker session (ADR 0004), never stored.
pub struct TokenKey([u8; 32]);

impl TokenKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TokenKey(bytes)
    }
}

impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenKey(<redacted>)")
    }
}

/// A `tokens.db` row as stored, in [`ROW_COLUMNS`] order.
pub(super) struct Row {
    pub id: String,
    pub hash: Vec<u8>,
    pub profile: String,
    pub scope: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub revoked_ms: Option<i64>,
    /// Messages whose content the token has received (its read budget used).
    pub reads_used: i64,
    pub seal: Vec<u8>,
}

impl Row {
    pub fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Row {
            id: row.get(0)?,
            hash: row.get(1)?,
            profile: row.get(2)?,
            scope: row.get(3)?,
            created_ms: row.get(4)?,
            expires_ms: row.get(5)?,
            revoked_ms: row.get(6)?,
            reads_used: row.get(7)?,
            seal: row.get(8)?,
        })
    }

    /// The HMAC over every column but the seal itself.
    fn mac(&self, key: &TokenKey) -> Hmac<Sha256> {
        let fields = [
            Field::Text(&self.id),
            Field::Blob(&self.hash),
            Field::Text(&self.profile),
            Field::Text(&self.scope),
            Field::Int(self.created_ms),
            Field::Int(self.expires_ms),
            self.revoked_ms.map_or(Field::Null, Field::Int),
            Field::Int(self.reads_used),
        ];
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC takes any key length");
        mac.update(&encoding::encode(SEAL_DOMAIN, &fields));
        mac
    }

    pub fn sealed(mut self, key: &TokenKey) -> Self {
        self.seal = self.mac(key).finalize().into_bytes().to_vec();
        self
    }

    /// Constant-time check of the stored seal.
    pub fn intact(&self, key: &TokenKey) -> bool {
        self.mac(key).verify_slice(&self.seal).is_ok()
    }
}
