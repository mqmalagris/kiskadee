//! Capability tokens: scoped, expiring, revocable grants minted from a
//! Profile (PRD glossary), kept in `tokens.db`.
//!
//! A token is `ksk_` followed by 64 hex characters (256 random bits). Only
//! its SHA-256 is stored, and the Ledger records a separate public id,
//! never the token. A slow password hash isn't needed: 256 random bits
//! can't be guessed, and lookup is by hash, so timing reveals nothing.
//!
//! Agents run as the same OS user as the Broker (ADR 0004), so they can
//! write `tokens.db`. Every row is sealed with an HMAC under the Broker's
//! [`TokenKey`], and a row whose seal doesn't verify is refused: a forged
//! token, a widened scope, a later expiry or a cleared revocation all fail.
//! What a seal can't stop is restoring an older copy of the whole file,
//! which brings back a revoked token; only isolated mode (ADR 0004)
//! closes that.
//!
//! Two sides share the store: the human's admin Verbs (`admin`: mint,
//! revoke, list) and every agent call (`admit`). Minting and revoking need
//! confirmed user presence (ADR 0004) before they're called.

mod admin;
mod admit;
mod budget;
mod seal;

use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::db::{self, FileKind, SetupError};
use crate::ledger::{self, Status};

pub use admin::{MintRequest, Minted, Revoked, Secret, TokenInfo};
pub use admit::{Admission, Denial, Grant, Request};
pub use budget::Charge;
pub use seal::TokenKey;

/// Start of every token, so a leaked one is easy for secret scanners to spot.
pub const TOKEN_PREFIX: &str = "ksk_";

/// Longest Account, folder or target name a call may carry. A longer one
/// is denied before it reaches the Ledger, so callers can't grow it with
/// text.
pub const MAX_NAME_BYTES: usize = 256;

const SECRET_BYTES: usize = 32;
const INTERNAL_ERROR: &str = "internal";

/// Schema version stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = r"
CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    hash       BLOB NOT NULL UNIQUE CHECK (length(hash) = 32),
    profile    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK (expires_ms > created_ms),
    revoked_ms INTEGER,
    reads_used INTEGER NOT NULL DEFAULT 0 CHECK (reads_used >= 0),
    seal       BLOB NOT NULL CHECK (length(seal) = 32)
);
";

/// A token store file. Its `application_id` spells "kTok".
const FILE: FileKind = FileKind {
    application_id: 0x6B54_6F6B,
    schema: SCHEMA,
    version: SCHEMA_VERSION,
};

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    Ledger(ledger::Error),
    NoWal(String),
    NewerSchema(i64),
    /// The file was made by a pre-release kiskadee whose tokens can't be
    /// carried over.
    OldSchema(i64),
    /// The file is some other kind of database.
    WrongFile(PathBuf),
    Clock,
    /// The OS random number generator failed.
    Random,
    UnknownProfile(String),
    UnknownToken(String),
    /// Token `id`'s row was edited or forged outside the Broker.
    Tampered(String),
    /// A mint asked for more than the Profile allows.
    ExceedsProfile {
        profile: String,
        field: &'static str,
    },
    /// A mint named no Accounts, folders or Verbs, or an empty name.
    EmptyScope {
        field: &'static str,
    },
    /// A TTL of zero or less, or one that overflows the clock.
    BadTtl,
    Corrupt(String),
}

impl Error {
    /// How a failed admin Verb is recorded in the Ledger.
    fn outcome(&self) -> (Status, &'static str) {
        match self {
            Error::UnknownProfile(_) => (Status::Denied, "profile.unknown"),
            Error::ExceedsProfile { .. } => (Status::Denied, "profile.exceeded"),
            Error::EmptyScope { .. } => (Status::Denied, "scope.empty"),
            Error::BadTtl => (Status::Denied, "ttl.invalid"),
            Error::UnknownToken(_) => (Status::Denied, Denial::UnknownToken.code()),
            Error::Tampered(_) => (Status::Denied, Denial::Tampered.code()),
            _ => (Status::Error, INTERNAL_ERROR),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sqlite(e) => write!(f, "token database: {e}"),
            Error::Ledger(e) => write!(f, "{e}"),
            Error::NoWal(mode) => write!(
                f,
                "token database needs WAL journaling, but SQLite is using {mode:?}"
            ),
            Error::NewerSchema(v) => write!(
                f,
                "token database schema v{v} is newer than this kiskadee (v{SCHEMA_VERSION}); upgrade kiskadee"
            ),
            Error::OldSchema(v) => write!(
                f,
                "token database schema v{v} is from a pre-release kiskadee and can't be upgraded; delete tokens.db and mint new tokens"
            ),
            Error::WrongFile(path) => {
                write!(f, "{} is not a kiskadee token database", path.display())
            }
            Error::Clock => write!(f, "system clock is before 1970"),
            Error::Random => write!(f, "the OS random number generator failed"),
            Error::UnknownProfile(name) => write!(f, "no profile named {name:?}"),
            Error::UnknownToken(id) => write!(f, "no token with id {id:?}"),
            Error::Tampered(id) => write!(
                f,
                "token {id:?} was changed outside kiskadee; its record can't be trusted"
            ),
            Error::ExceedsProfile { profile, field } => {
                write!(f, "{field} goes beyond what profile {profile:?} allows")
            }
            Error::EmptyScope { field } => {
                write!(
                    f,
                    "{field} names nothing; leave it out to take the Profile's"
                )
            }
            Error::BadTtl => write!(f, "the TTL must be a positive duration"),
            Error::Corrupt(why) => write!(f, "token database row unreadable: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Sqlite(e) => Some(e),
            Error::Ledger(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

impl From<ledger::Error> for Error {
    fn from(e: ledger::Error) -> Self {
        Error::Ledger(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Milliseconds since the Unix epoch. A closure, so a test can move it.
pub type Clock = Box<dyn Fn() -> Result<i64> + Send + Sync>;

pub struct TokenStore {
    conn: Connection,
    key: TokenKey,
    clock: Clock,
}

impl TokenStore {
    /// Opens `tokens.db` at `path`, creating it if needed. Rows are sealed
    /// and checked with `key`.
    pub fn open(path: &Path, key: TokenKey) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        db::prepare(&mut conn, &FILE).map_err(|e| match e {
            SetupError::Sqlite(e) => Error::Sqlite(e),
            SetupError::NoWal(mode) => Error::NoWal(mode),
            SetupError::Newer(version) => Error::NewerSchema(version),
            SetupError::Older(version) => Error::OldSchema(version),
            SetupError::WrongKind => Error::WrongFile(path.to_path_buf()),
        })?;
        Ok(TokenStore {
            conn,
            key,
            clock: Box::new(now_ms),
        })
    }

    /// Replaces the wall clock. For tests.
    pub fn with_clock(mut self, clock: impl Fn() -> Result<i64> + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }
}

fn hash(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

fn now_ms() -> Result<i64> {
    crate::time::now_ms().ok_or(Error::Clock)
}
