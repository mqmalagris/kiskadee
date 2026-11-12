//! Read budgets: how many messages' content a token has received. The
//! count lives in the token's sealed row, so it survives a restart and an
//! edit outside the Broker is refused like any other.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::seal::{ROW_COLUMNS, Row};
use super::{Error, Result, TokenStore};
use crate::profiles::Scope;

/// The result of [`TokenStore::charge_reads`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// The reads were charged; this many remain.
    Charged { reads_remaining: u64 },
    /// Charging would pass the budget, so nothing was charged; this many
    /// remain.
    Short { reads_remaining: u64 },
    /// The token was revoked after the call was admitted; nothing was
    /// charged.
    Revoked,
    /// The token expired after the call was admitted; nothing was charged.
    Expired,
}

impl TokenStore {
    /// Charges `reads` against token `id`'s budget, all or nothing. The
    /// check and the charge happen under one write lock, so two calls
    /// racing for the last reads can't both be charged, and a token
    /// revoked or expired while its call ran is charged nothing and gets
    /// nothing.
    pub fn charge_reads(&mut self, id: &str, reads: u64) -> Result<Charge> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                &format!("SELECT {ROW_COLUMNS} FROM tokens WHERE id = ?1"),
                [id],
                Row::read,
            )
            .optional()?
            .ok_or_else(|| Error::UnknownToken(id.to_string()))?;
        if !row.intact(&self.key) {
            return Err(Error::Tampered(id.to_string()));
        }
        if row.revoked_ms.is_some() {
            return Ok(Charge::Revoked);
        }
        if (self.clock)()? >= row.expires_ms {
            return Ok(Charge::Expired);
        }
        let scope: Scope = serde_json::from_str(&row.scope)
            .map_err(|e| Error::Corrupt(format!("token {id}: {e}")))?;
        let used = u64::try_from(row.reads_used)
            .map_err(|_| Error::Corrupt(format!("token {id}: negative reads_used")))?;
        let remaining = scope.read_budget.saturating_sub(used);
        if reads > remaining {
            return Ok(Charge::Short {
                reads_remaining: remaining,
            });
        }
        if reads > 0 {
            let reads_used = i64::try_from(used + reads)
                .map_err(|_| Error::Corrupt(format!("token {id}: reads_used overflows")))?;
            let row = Row { reads_used, ..row }.sealed(&self.key);
            tx.execute(
                "UPDATE tokens SET reads_used = ?1, seal = ?2 WHERE id = ?3",
                params![row.reads_used, row.seal, row.id],
            )?;
            tx.commit()?;
        }
        Ok(Charge::Charged {
            reads_remaining: remaining - reads,
        })
    }
}
