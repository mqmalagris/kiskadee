//! The human's side: mint, revoke and list. Each is an admin Verb, logged
//! in the Ledger whether it succeeds or not.

use std::collections::BTreeSet;
use std::fmt;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;

use super::seal::{ROW_COLUMNS, Row};
use super::{Error, Result, SECRET_BYTES, TOKEN_PREFIX, TokenStore, hash, random};
use crate::ledger::encoding;
use crate::ledger::{self, Actor, Call, Ledger, Status};
use crate::profiles::{Profile, Profiles, Scope, Selector};
use crate::verb::Verb;

const ID_BYTES: usize = 6;
const MINT_VERB: &str = "token.mint";
const REVOKE_VERB: &str = "token.revoke";
const ALREADY_REVOKED: &str = "token.already-revoked";

/// A token as handed to the human once, at mint. Never stored.
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({TOKEN_PREFIX}<redacted>)")
    }
}

#[derive(Debug)]
pub struct Minted {
    /// Public id, as the Ledger and `list` show it.
    pub id: String,
    pub secret: Secret,
    pub expires_ms: i64,
}

/// What `mint` should grant. Every `None` takes the Profile's ceiling.
#[derive(Debug, Clone, Serialize)]
pub struct MintRequest {
    pub profile: String,
    pub accounts: Option<Selector>,
    pub resources: Option<Selector>,
    pub verbs: Option<BTreeSet<Verb>>,
    pub read_budget: Option<u64>,
    pub ttl_ms: Option<i64>,
}

impl MintRequest {
    /// Everything the Profile allows.
    pub fn new(profile: &str) -> Self {
        MintRequest {
            profile: profile.to_string(),
            accounts: None,
            resources: None,
            verbs: None,
            read_budget: None,
            ttl_ms: None,
        }
    }
}

/// A stored token, without its secret or hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub id: String,
    pub profile: String,
    /// `None` when the row failed its integrity check: it was edited or
    /// forged outside the Broker, and `admit` refuses it.
    pub scope: Option<Scope>,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub revoked_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    Now,
    /// It was already revoked; nothing changed.
    Already,
}

/// A mint request checked against its Profile: exactly what will be granted.
#[derive(Serialize)]
struct Resolved {
    profile: String,
    scope: Scope,
    ttl_ms: i64,
}

impl TokenStore {
    /// Mints a token from a Profile, narrowed by `request`. Logged as
    /// `token.mint` by `by`, whether it succeeds or not; the Ledger digest
    /// covers the scope actually granted, so a widened `profiles.toml`
    /// shows there.
    pub fn mint(
        &mut self,
        ledger: &mut Ledger,
        by: Actor,
        profiles: &Profiles,
        request: &MintRequest,
    ) -> Result<Minted> {
        let id = encoding::hex(&random::<ID_BYTES>()?);
        let resolved = resolve(profiles, request);
        let args = match &resolved {
            Ok(resolved) => serde_json::to_vec(resolved),
            Err(_) => serde_json::to_vec(request),
        }
        .map_err(|e| Error::Corrupt(e.to_string()))?;
        let seq = ledger.begin(Call {
            actor: by,
            account: None,
            verb: MINT_VERB.into(),
            target: Some(id.clone()),
            args_digest: ledger::digest(&args),
        })?;
        match resolved.and_then(|resolved| self.insert(id, resolved)) {
            Ok(minted) => {
                if let Err(e) = ledger.outcome(seq, Status::Ok, None) {
                    // Nobody will get the secret, so don't leave it live.
                    let _ = self.revoke_row(&minted.id);
                    return Err(e.into());
                }
                Ok(minted)
            }
            Err(e) => {
                let (status, code) = e.outcome();
                ledger.outcome(seq, status, Some(code))?;
                Err(e)
            }
        }
    }

    fn insert(&mut self, id: String, resolved: Resolved) -> Result<Minted> {
        let created_ms = (self.clock)()?;
        let expires_ms = created_ms
            .checked_add(resolved.ttl_ms)
            .ok_or(Error::BadTtl)?;
        let secret = Secret(format!(
            "{TOKEN_PREFIX}{}",
            encoding::hex(&random::<SECRET_BYTES>()?)
        ));
        let row = Row {
            id,
            hash: hash(secret.expose()).to_vec(),
            profile: resolved.profile,
            scope: serde_json::to_string(&resolved.scope)
                .map_err(|e| Error::Corrupt(e.to_string()))?,
            created_ms,
            expires_ms,
            revoked_ms: None,
            seal: Vec::new(),
        }
        .sealed(&self.key);
        self.conn.execute(
            &format!("INSERT INTO tokens ({ROW_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
            params![
                row.id,
                row.hash,
                row.profile,
                row.scope,
                row.created_ms,
                row.expires_ms,
                row.revoked_ms,
                row.seal
            ],
        )?;
        Ok(Minted {
            id: row.id,
            secret,
            expires_ms,
        })
    }

    /// Revokes token `id`. Revoking twice is a no-op success; both are
    /// logged as `token.revoke` by `by`. If the outcome can't be logged the
    /// call fails even though the revocation stands; revoking again is
    /// safe and reports [`Revoked::Already`].
    pub fn revoke(&mut self, ledger: &mut Ledger, by: Actor, id: &str) -> Result<Revoked> {
        let seq = ledger.begin(Call {
            actor: by,
            account: None,
            verb: REVOKE_VERB.into(),
            target: Some(id.to_string()),
            args_digest: ledger::digest(id.as_bytes()),
        })?;
        let result = self.revoke_row(id);
        let (status, detail) = match &result {
            Ok(Revoked::Now) => (Status::Ok, None),
            Ok(Revoked::Already) => (Status::Ok, Some(ALREADY_REVOKED)),
            Err(e) => {
                let (status, code) = e.outcome();
                (status, Some(code))
            }
        };
        ledger.outcome(seq, status, detail)?;
        result
    }

    fn revoke_row(&mut self, id: &str) -> Result<Revoked> {
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
            return Ok(Revoked::Already);
        }
        let row = Row {
            revoked_ms: Some((self.clock)()?),
            ..row
        }
        .sealed(&self.key);
        tx.execute(
            "UPDATE tokens SET revoked_ms = ?1, seal = ?2 WHERE id = ?3",
            params![row.revoked_ms, row.seal, row.id],
        )?;
        tx.commit()?;
        Ok(Revoked::Now)
    }

    /// Every token ever minted, oldest first. A row that fails its
    /// integrity check is listed with `scope: None`.
    pub fn list(&self) -> Result<Vec<TokenInfo>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {ROW_COLUMNS} FROM tokens ORDER BY rowid"))?;
        let rows = stmt.query_map([], Row::read)?;
        let mut tokens = Vec::new();
        for row in rows {
            let row = row?;
            let scope = row
                .intact(&self.key)
                .then(|| serde_json::from_str(&row.scope).ok())
                .flatten();
            tokens.push(TokenInfo {
                id: row.id,
                profile: row.profile,
                scope,
                created_ms: row.created_ms,
                expires_ms: row.expires_ms,
                revoked_ms: row.revoked_ms,
            });
        }
        Ok(tokens)
    }
}

/// Checks a mint request against its Profile and fills in the ceiling for
/// everything left out.
fn resolve(profiles: &Profiles, request: &MintRequest) -> Result<Resolved> {
    let profile = profiles
        .get(&request.profile)
        .ok_or_else(|| Error::UnknownProfile(request.profile.clone()))?;
    let scope = resolve_scope(profile, request)?;
    let ttl_ms = request.ttl_ms.unwrap_or(profile.max_ttl_ms);
    if ttl_ms <= 0 {
        return Err(Error::BadTtl);
    }
    if ttl_ms > profile.max_ttl_ms {
        return Err(exceeds(profile, "ttl"));
    }
    Ok(Resolved {
        profile: profile.name.clone(),
        scope,
        ttl_ms,
    })
}

fn resolve_scope(profile: &Profile, request: &MintRequest) -> Result<Scope> {
    for (field, selector) in [
        ("accounts", &request.accounts),
        ("resources", &request.resources),
    ] {
        if selector.as_ref().is_some_and(|s| !s.is_valid()) {
            return Err(Error::EmptyScope { field });
        }
    }
    if request.verbs.as_ref().is_some_and(BTreeSet::is_empty) {
        return Err(Error::EmptyScope { field: "verbs" });
    }
    let ceiling = &profile.ceiling;
    let scope = Scope {
        accounts: request
            .accounts
            .clone()
            .unwrap_or_else(|| ceiling.accounts.clone()),
        resources: request
            .resources
            .clone()
            .unwrap_or_else(|| ceiling.resources.clone()),
        verbs: request
            .verbs
            .clone()
            .unwrap_or_else(|| ceiling.verbs.clone()),
        read_budget: request.read_budget.unwrap_or(ceiling.read_budget),
    };
    match scope.first_excess(ceiling) {
        Some(field) => Err(exceeds(profile, field)),
        None => Ok(scope),
    }
}

fn exceeds(profile: &Profile, field: &'static str) -> Error {
    Error::ExceedsProfile {
        profile: profile.name.clone(),
        field,
    }
}
