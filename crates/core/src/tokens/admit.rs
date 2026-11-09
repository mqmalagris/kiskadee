//! The agent's side: checking a token for one Verb call.
//!
//! [`TokenStore::admit`] is the only way to check a token, and it writes the
//! call's `begin` to the Ledger before anything else can fail; a denial or
//! an error also gets its outcome there. Token and scope denials are made
//! here. Later ones (read budget, rate limits) belong to the Verb
//! dispatcher, which writes its `denied` outcome on the same `begin_seq`.

use std::fmt;

use rusqlite::OptionalExtension;

use super::seal::{ROW_COLUMNS, Row};
use super::{
    Error, INTERNAL_ERROR, MAX_NAME_BYTES, Result, SECRET_BYTES, TOKEN_PREFIX, TokenStore, hash,
};
use crate::ledger::{Actor, Call, Ledger, Status};
use crate::profiles::Scope;
use crate::verb::Verb;

/// One Verb call an agent asks for.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub verb: Verb,
    /// `None` means every Account.
    pub account: Option<&'a str>,
    /// Folder or label; `None` means all of them.
    pub resource: Option<&'a str>,
    /// What the call acts on (a message or thread id), for the Ledger.
    pub target: Option<&'a str>,
    /// SHA-256 of the call's canonical arguments.
    pub args_digest: [u8; 32],
}

/// Proof that [`TokenStore::admit`] let a call through. Only `admit`
/// creates one.
#[derive(Debug, Clone)]
pub struct Grant {
    token_id: String,
    scope: Scope,
    expires_ms: i64,
}

impl Grant {
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn expires_ms(&self) -> i64 {
        self.expires_ms
    }
}

/// Why a call was refused. [`Denial::code`] is the stable, machine-readable
/// part, also written to the Ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// Missing, malformed, or matching no token.
    UnknownToken,
    /// The token's row was edited or forged outside the Broker.
    Tampered,
    Revoked,
    Expired,
    /// A name in the request is longer than [`MAX_NAME_BYTES`].
    BadRequest,
    Verb(Verb),
    Account,
    Resource,
}

impl Denial {
    pub fn code(&self) -> &'static str {
        match self {
            Denial::UnknownToken => "token.unknown",
            Denial::Tampered => "token.tampered",
            Denial::Revoked => "token.revoked",
            Denial::Expired => "token.expired",
            Denial::BadRequest => "request.invalid",
            Denial::Verb(_) => "scope.verb",
            Denial::Account => "scope.account",
            Denial::Resource => "scope.resource",
        }
    }

    /// Whether the request came from an identified token and is well
    /// formed, so its Account and target can go in the Ledger.
    fn trusts_request(&self) -> bool {
        !matches!(
            self,
            Denial::UnknownToken | Denial::Tampered | Denial::BadRequest
        )
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::UnknownToken => f.write_str("no valid Capability token"),
            Denial::Tampered => f.write_str("the token's record failed its integrity check"),
            Denial::Revoked => f.write_str("the token was revoked"),
            Denial::Expired => f.write_str("the token has expired"),
            Denial::BadRequest => write!(
                f,
                "a name in the request is longer than {MAX_NAME_BYTES} bytes"
            ),
            Denial::Verb(verb) => write!(f, "the token doesn't allow {verb}"),
            Denial::Account => f.write_str("the token doesn't cover this Account"),
            Denial::Resource => f.write_str("the token doesn't cover this folder or label"),
        }
    }
}

#[derive(Debug)]
pub enum Admission {
    /// The call may run; its `begin` is at `begin_seq`, and the caller
    /// writes the outcome.
    Admitted { grant: Grant, begin_seq: i64 },
    /// Refused; `begin` and `denied` outcome are both in the Ledger.
    Denied { denial: Denial, begin_seq: i64 },
}

enum Checked {
    Granted(Grant),
    /// The token's id when its row exists and is intact.
    Refused(Option<String>, Denial),
}

impl TokenStore {
    /// Checks `presented` for `request`, writing the call's `begin` to the
    /// Ledger first and, for a denial or an error, its outcome too. The
    /// Account and target are recorded only once an intact token is
    /// identified, so an unauthenticated caller can't write text into the
    /// Ledger. Expiry is checked now, so a call admitted just before its
    /// token expires still completes. Surrounding whitespace, such as the
    /// newline an environment variable picks up, is ignored.
    pub fn admit(
        &self,
        ledger: &mut Ledger,
        presented: &str,
        request: &Request<'_>,
    ) -> Result<Admission> {
        let checked = self.check(presented.trim_ascii(), request);
        let (actor, trusted) = match &checked {
            Ok(Checked::Granted(grant)) => (Actor::Token(grant.token_id.clone()), true),
            Ok(Checked::Refused(Some(id), denial)) => {
                (Actor::Token(id.clone()), denial.trusts_request())
            }
            Ok(Checked::Refused(None, _)) | Err(_) => (Actor::UnknownToken, false),
        };
        let recorded = |name: Option<&str>| name.filter(|_| trusted).map(str::to_string);
        let begin_seq = ledger.begin(Call {
            actor,
            account: recorded(request.account),
            verb: request.verb.as_str().into(),
            target: recorded(request.target),
            args_digest: request.args_digest,
        })?;
        match checked {
            Ok(Checked::Granted(grant)) => Ok(Admission::Admitted { grant, begin_seq }),
            Ok(Checked::Refused(_, denial)) => {
                ledger.outcome(begin_seq, Status::Denied, Some(denial.code()))?;
                Ok(Admission::Denied { denial, begin_seq })
            }
            Err(e) => {
                ledger.outcome(begin_seq, Status::Error, Some(INTERNAL_ERROR))?;
                Err(e)
            }
        }
    }

    /// Refusals in order: unknown, tampered, revoked, expired, an oversized
    /// request, then scope (Verb, Account, folder).
    fn check(&self, presented: &str, request: &Request<'_>) -> Result<Checked> {
        if !well_formed(presented) {
            return Ok(Checked::Refused(None, Denial::UnknownToken));
        }
        let row = self
            .conn
            .query_row(
                &format!("SELECT {ROW_COLUMNS} FROM tokens WHERE hash = ?1"),
                [hash(presented).to_vec()],
                Row::read,
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(Checked::Refused(None, Denial::UnknownToken));
        };
        if !row.intact(&self.key) {
            // The id is in a forged or edited row, so it isn't trusted either.
            return Ok(Checked::Refused(None, Denial::Tampered));
        }
        let refuse = |denial| Ok(Checked::Refused(Some(row.id.clone()), denial));
        if row.revoked_ms.is_some() {
            return refuse(Denial::Revoked);
        }
        if (self.clock)()? >= row.expires_ms {
            return refuse(Denial::Expired);
        }
        let names = [request.account, request.resource, request.target];
        if names
            .into_iter()
            .flatten()
            .any(|name| name.len() > MAX_NAME_BYTES)
        {
            return refuse(Denial::BadRequest);
        }
        let scope: Scope = serde_json::from_str(&row.scope)
            .map_err(|e| Error::Corrupt(format!("token {}: {e}", row.id)))?;
        if !scope.verbs.contains(&request.verb) {
            return refuse(Denial::Verb(request.verb));
        }
        if !scope.accounts.allows(request.account) {
            return refuse(Denial::Account);
        }
        if !scope.resources.allows(request.resource) {
            return refuse(Denial::Resource);
        }
        Ok(Checked::Granted(Grant {
            token_id: row.id,
            scope,
            expires_ms: row.expires_ms,
        }))
    }
}

fn well_formed(presented: &str) -> bool {
    presented.strip_prefix(TOKEN_PREFIX).is_some_and(|rest| {
        rest.len() == SECRET_BYTES * 2
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
