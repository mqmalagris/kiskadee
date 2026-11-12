//! The Ledger: an append-only, hash-chained record of every Verb call, kept in
//! its own SQLite file (`ledger.db`), separate from the rebuildable cache
//! (ADR 0003).
//!
//! Every call appends a `begin` row before it executes and an `outcome` row
//! after. No row is ever updated or deleted: triggers reject both, and the
//! hash chain (see [`encoding`]) makes an edited, removed or reordered row
//! visible to [`Ledger::verify`], even when the triggers were dropped first.
//! A crash between the two leaves a `begin` with no `outcome`, which `verify`
//! reports as an orphan, not as damage.
//!
//! Tamper-evident, not tamper-proof. The chain alone can't show that rows
//! were cut off the end, and someone with write access to the file can
//! rebuild the whole chain. Catching either needs the head hash kept
//! somewhere else (an ADR 0003 follow-up).
//!
//! Rows hold ids, Verb names and digests only. Never put sender-controlled
//! text (subjects, bodies, display names) in `target` or `detail`.

pub(crate) mod encoding;

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;

use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::db::{self, FileKind, SetupError};
pub use encoding::GENESIS;
use encoding::{COLUMNS, FIELD_COUNT, Field};

/// Schema version stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;

/// A Ledger file. Its `application_id` spells "kLdg".
const FILE: FileKind = FileKind {
    application_id: 0x6B4C_6467,
    schema: SCHEMA,
    version: SCHEMA_VERSION,
};

const DAY_MS: i64 = 86_400_000;

const SCHEMA: &str = r"
CREATE TABLE entries (
    seq         INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('begin', 'outcome')),
    actor       TEXT,
    account     TEXT,
    verb        TEXT,
    target      TEXT,
    args_digest BLOB,
    begin_seq   INTEGER,
    status      TEXT,
    detail      TEXT,
    prev_hash   BLOB NOT NULL,
    hash        BLOB NOT NULL,
    CHECK (kind <> 'begin' OR (actor IS NOT NULL AND verb IS NOT NULL
        AND args_digest IS NOT NULL AND begin_seq IS NULL AND status IS NULL)),
    CHECK (kind <> 'outcome' OR (begin_seq IS NOT NULL
        AND status IN ('ok', 'denied', 'error', 'conflict')
        AND actor IS NULL AND account IS NULL AND verb IS NULL
        AND target IS NULL AND args_digest IS NULL))
);
CREATE UNIQUE INDEX entries_one_outcome ON entries (begin_seq) WHERE kind = 'outcome';
CREATE INDEX entries_ts ON entries (ts_ms);
CREATE INDEX entries_actor ON entries (actor);
CREATE INDEX entries_account ON entries (account);
CREATE TRIGGER entries_no_update BEFORE UPDATE ON entries
    BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER entries_no_delete BEFORE DELETE ON entries
    BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
";

/// Positions in a `SELECT {COLUMNS}, prev_hash, hash` row.
mod col {
    pub const SEQ: usize = 0;
    pub const TS_MS: usize = 1;
    pub const KIND: usize = 2;
    pub const ACTOR: usize = 3;
    pub const ACCOUNT: usize = 4;
    pub const VERB: usize = 5;
    pub const TARGET: usize = 6;
    pub const ARGS_DIGEST: usize = 7;
    pub const BEGIN_SEQ: usize = 8;
    pub const STATUS: usize = 9;
    pub const DETAIL: usize = 10;
    pub const PREV_HASH: usize = 11;
    pub const HASH: usize = 12;
}

static INSERT: LazyLock<String> = LazyLock::new(|| {
    let placeholders: Vec<String> = (1..=FIELD_COUNT + 2).map(|i| format!("?{i}")).collect();
    format!(
        "INSERT INTO entries ({COLUMNS}, prev_hash, hash) VALUES ({})",
        placeholders.join(", ")
    )
});

fn column_name(index: usize) -> &'static str {
    COLUMNS.split(", ").nth(index).unwrap_or("?")
}

/// Who made a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// An agent, by Capability token id (never the token itself).
    Token(String),
    /// An agent whose token matched none. What it presented is never
    /// recorded.
    UnknownToken,
    /// The human, by session id.
    Human(String),
}

/// How [`Actor::UnknownToken`] is written; token ids are hex, so it can't
/// collide with one.
const UNKNOWN_TOKEN: &str = "unknown";

/// A `begin` (aliased `e`) by an agent that wasn't refused. Denied calls,
/// including every unknown token, aren't use and stay out of [`Stats`].
const AGENT_USE: &str = "substr(e.actor, 1, 6) = 'token:'
    AND NOT EXISTS (SELECT 1 FROM entries o
        WHERE o.kind = 'outcome' AND o.begin_seq = e.seq AND o.status = 'denied')";

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Actor::Token(id) => write!(f, "token:{id}"),
            Actor::UnknownToken => write!(f, "token:{UNKNOWN_TOKEN}"),
            Actor::Human(id) => write!(f, "human:{id}"),
        }
    }
}

impl FromStr for Actor {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s.split_once(':') {
            Some(("token", UNKNOWN_TOKEN)) => Ok(Actor::UnknownToken),
            Some(("token", id)) => Ok(Actor::Token(id.into())),
            Some(("human", id)) => Ok(Actor::Human(id.into())),
            _ => Err(Error::Corrupt(format!("unknown actor {s:?}"))),
        }
    }
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Denied,
    Error,
    /// A sync replay found the server state had moved on.
    Conflict,
}

impl Status {
    pub const ALL: [Status; 4] = [Status::Ok, Status::Denied, Status::Error, Status::Conflict];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Denied => "denied",
            Status::Error => "error",
            Status::Conflict => "conflict",
        }
    }
}

impl FromStr for Status {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Status::ALL
            .into_iter()
            .find(|status| status.as_str() == s)
            .ok_or_else(|| Error::Corrupt(format!("unknown status {s:?}")))
    }
}

/// A Verb call as recorded in its `begin` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub actor: Actor,
    pub account: Option<String>,
    pub verb: String,
    /// What the call acts on (a message or thread id), if anything.
    pub target: Option<String>,
    /// SHA-256 of the call's canonical arguments; see [`digest`].
    pub args_digest: [u8; 32],
}

/// One Ledger row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: i64,
    /// Milliseconds since the Unix epoch, UTC. Never earlier than the
    /// previous entry's, even if the clock stepped back.
    pub ts_ms: i64,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Begin(Call),
    Outcome {
        begin_seq: i64,
        status: Status,
        detail: Option<String>,
    },
}

impl Entry {
    fn kind(&self) -> &'static str {
        match self.body {
            Body::Begin(_) => "begin",
            Body::Outcome { .. } => "outcome",
        }
    }

    /// The row's column values in canonical order (see [`encoding`]).
    /// `actor` is the rendered [`Actor`] of a `begin`; ignored for an `outcome`.
    fn fields<'a>(&'a self, actor: &'a str) -> [Field<'a>; FIELD_COUNT] {
        let (seq, ts, kind) = (
            Field::Int(self.seq),
            Field::Int(self.ts_ms),
            Field::Text(self.kind()),
        );
        match &self.body {
            Body::Begin(call) => [
                seq,
                ts,
                kind,
                Field::Text(actor),
                Field::text(call.account.as_deref()),
                Field::Text(&call.verb),
                Field::text(call.target.as_deref()),
                Field::Blob(&call.args_digest),
                Field::Null,
                Field::Null,
                Field::Null,
            ],
            Body::Outcome {
                begin_seq,
                status,
                detail,
            } => [
                seq,
                ts,
                kind,
                Field::Null,
                Field::Null,
                Field::Null,
                Field::Null,
                Field::Null,
                Field::Int(*begin_seq),
                Field::Text(status.as_str()),
                Field::text(detail.as_deref()),
            ],
        }
    }
}

/// SHA-256 of a call's canonical argument bytes, for [`Call::args_digest`].
pub fn digest(args: &[u8]) -> [u8; 32] {
    Sha256::digest(args).into()
}

/// Result of [`Ledger::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub entries: u64,
    /// Hash of the last row (GENESIS for an empty Ledger).
    pub head: [u8; 32],
    /// `begin` rows with no `outcome`: calls in flight, or interrupted by a crash.
    pub orphans: Vec<i64>,
    /// The first problem found, if the chain is broken. Checking stops there.
    pub problem: Option<Problem>,
}

impl Verification {
    pub fn is_intact(&self) -> bool {
        self.problem.is_none()
    }
    pub fn head_hex(&self) -> String {
        encoding::hex(&self.head)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub seq: i64,
    pub kind: ProblemKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProblemKind {
    /// Rows are missing: the previous row was `expected - 1`.
    Gap { expected: i64 },
    /// `prev_hash` doesn't match the previous row's hash.
    BrokenLink,
    /// The row's content doesn't match its stored hash.
    HashMismatch,
    /// An `outcome` points at a row that isn't an earlier `begin`, or that already has an outcome.
    BadOutcome { begin_seq: i64 },
    /// A column holds a value the encoding or the row's kind doesn't allow.
    BadValue { column: &'static str },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seq = self.seq;
        match &self.kind {
            ProblemKind::Gap { expected } => {
                write!(f, "entry #{seq}: expected #{expected}, rows are missing")
            }
            ProblemKind::BrokenLink => {
                write!(
                    f,
                    "entry #{seq}: prev_hash doesn't match entry #{}",
                    seq - 1
                )
            }
            ProblemKind::HashMismatch => write!(f, "entry #{seq}: content doesn't match its hash"),
            ProblemKind::BadOutcome { begin_seq } => write!(
                f,
                "entry #{seq}: outcome for #{begin_seq}, which isn't an open begin"
            ),
            ProblemKind::BadValue { column } => {
                write!(f, "entry #{seq}: column {column} holds an invalid value")
            }
        }
    }
}

/// Totals for [`Ledger::stats`], all read from one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub entries: u64,
    pub begins: u64,
    /// Outcome counts in [`Status::ALL`] order.
    pub outcomes: [u64; Status::ALL.len()],
    pub orphans: u64,
    /// Distinct Capability tokens that made at least one call that wasn't
    /// denied.
    pub tokens: u64,
    pub first_ts_ms: Option<i64>,
    pub last_ts_ms: Option<i64>,
    /// Calls per UTC day, oldest first. Days without calls are left out.
    pub days: Vec<Day>,
}

/// One UTC day of [`Stats::days`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Day {
    /// Start of the day, milliseconds since the Unix epoch.
    pub start_ms: i64,
    /// Verb calls (`begin` rows), by anyone.
    pub calls: u64,
    /// Calls made by agents and not denied. Agents can only read in 0.1, so
    /// these are the 0.1 gate's "agent reads".
    pub agent_calls: u64,
    /// Distinct tokens that made calls that day, not counting denied ones.
    pub tokens: u64,
}

impl Stats {
    /// Days with at least one agent call.
    pub fn agent_days(&self) -> u64 {
        self.days.iter().filter(|day| day.agent_calls > 0).count() as u64
    }

    /// Consecutive days with agent calls, ending at the latest such day.
    pub fn agent_streak(&self) -> u64 {
        let mut streak = 0;
        let mut later: Option<i64> = None;
        for day in self.days.iter().rev().filter(|day| day.agent_calls > 0) {
            if later.is_some_and(|start| day.start_ms != start - DAY_MS) {
                break;
            }
            streak += 1;
            later = Some(day.start_ms);
        }
        streak
    }
}

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    /// No Ledger file at the given path.
    Missing(PathBuf),
    /// The file exists but holds no Ledger (empty, or some other database).
    NotALedger(PathBuf),
    /// The file was written by a newer kiskadee.
    NewerSchema(i64),
    /// SQLite refused WAL mode; it reported this journal mode instead.
    NoWal(String),
    /// The system clock is before the Unix epoch, so a call can't be timestamped.
    Clock,
    /// An outcome for a row that isn't an open `begin`.
    NotOpen(i64),
    /// A stored row couldn't be read back.
    Corrupt(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sqlite(e) => write!(f, "ledger database: {e}"),
            Error::Missing(path) => write!(f, "no ledger at {}", path.display()),
            Error::NotALedger(path) => write!(f, "{} is not a kiskadee ledger", path.display()),
            Error::NewerSchema(v) => write!(
                f,
                "ledger schema v{v} is newer than this kiskadee (v{SCHEMA_VERSION}); upgrade kiskadee"
            ),
            Error::NoWal(mode) => write!(
                f,
                "ledger needs WAL journaling, but SQLite is using {mode:?}"
            ),
            Error::Clock => write!(f, "system clock is before 1970; can't timestamp the call"),
            Error::NotOpen(seq) => write!(f, "entry #{seq} is not a begin without an outcome"),
            Error::Corrupt(why) => write!(f, "ledger row unreadable: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Milliseconds since the Unix epoch. A closure, so a test can move it.
pub type Clock = Box<dyn Fn() -> Result<i64> + Send + Sync>;

pub struct Ledger {
    conn: Connection,
    clock: Clock,
}

impl Ledger {
    /// Opens the Ledger at `path` for writing, creating it if needed.
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        db::prepare(&mut conn, &FILE).map_err(|e| setup_error(e, path))?;
        Ok(Ledger {
            conn,
            clock: Box::new(now_ms),
        })
    }

    /// Opens an existing Ledger for reading. Never creates, migrates or
    /// otherwise writes the file; [`Ledger::begin`] and
    /// [`Ledger::outcome`] fail on it.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::Missing(path.to_path_buf()));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        match db::identify(&conn, &FILE).map_err(|e| setup_error(e, path))? {
            SCHEMA_VERSION => Ok(Ledger {
                conn,
                clock: Box::new(now_ms),
            }),
            0 => Err(Error::NotALedger(path.to_path_buf())),
            newer => Err(Error::NewerSchema(newer)),
        }
    }

    /// Replaces the wall clock. For tests and replay.
    pub fn with_clock(mut self, clock: impl Fn() -> Result<i64> + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Records a call before it executes. Returns the `begin` row's seq,
    /// which [`Ledger::outcome`] takes.
    pub fn begin(&mut self, call: Call) -> Result<i64> {
        self.append(|seq, ts_ms| Entry {
            seq,
            ts_ms,
            body: Body::Begin(call),
        })
    }

    /// Records how the call started by `begin_seq` ended.
    pub fn outcome(&mut self, begin_seq: i64, status: Status, detail: Option<&str>) -> Result<i64> {
        self.append(|seq, ts_ms| Entry {
            seq,
            ts_ms,
            body: Body::Outcome {
                begin_seq,
                status,
                detail: detail.map(str::to_string),
            },
        })
    }

    fn append(&mut self, build: impl FnOnce(i64, i64) -> Entry) -> Result<i64> {
        // IMMEDIATE: take the write lock before reading the head or the
        // clock, so two writers never chain onto the same row and seq order
        // is also timestamp order.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (last_seq, last_ts_ms, prev_hash) = tx
            .query_row(
                "SELECT seq, ts_ms, hash FROM entries ORDER BY seq DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
            .unwrap_or((0, i64::MIN, GENESIS.to_vec()));
        let prev_hash: [u8; 32] = prev_hash
            .try_into()
            .map_err(|_| Error::Corrupt(format!("entry #{last_seq} has a malformed hash")))?;
        // A clock stepping back must not let `--since` skip a newer row.
        let ts_ms = (self.clock)()?.max(last_ts_ms);
        let entry = build(last_seq + 1, ts_ms);

        if let Body::Outcome { begin_seq, .. } = entry.body {
            let open: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM entries b WHERE b.seq = ?1 AND b.kind = 'begin'
                    AND NOT EXISTS (SELECT 1 FROM entries o
                        WHERE o.kind = 'outcome' AND o.begin_seq = b.seq))",
                [begin_seq],
                |row| row.get(0),
            )?;
            if !open {
                return Err(Error::NotOpen(begin_seq));
            }
        }

        let actor = match &entry.body {
            Body::Begin(call) => call.actor.to_string(),
            Body::Outcome { .. } => String::new(),
        };
        let fields = entry.fields(&actor);
        let hash = encoding::chain(&prev_hash, &encoding::canonical(&fields));
        let values = fields
            .iter()
            .map(to_value)
            .chain([Value::Blob(prev_hash.to_vec()), Value::Blob(hash.to_vec())]);
        tx.execute(&INSERT, rusqlite::params_from_iter(values))?;
        tx.commit()?;
        Ok(entry.seq)
    }

    /// Walks the whole chain from the first row, recomputing every hash from
    /// the stored column values.
    pub fn verify(&self) -> Result<Verification> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS}, prev_hash, hash FROM entries ORDER BY seq"
        ))?;
        let mut rows = stmt.query([])?;
        let mut report = Verification {
            entries: 0,
            head: GENESIS,
            orphans: Vec::new(),
            problem: None,
        };
        let mut open = std::collections::BTreeSet::new();
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(col::SEQ)?;
            let expected = report.entries as i64 + 1;
            let fail = |kind| Some(Problem { seq, kind });
            let bad = |index| {
                fail(ProblemKind::BadValue {
                    column: column_name(index),
                })
            };
            if seq != expected {
                report.problem = fail(ProblemKind::Gap { expected });
                break;
            }
            let mut fields = Vec::with_capacity(FIELD_COUNT);
            for index in 0..FIELD_COUNT {
                match field_of(row.get_ref(index)?) {
                    Some(field) => fields.push(field),
                    None => break,
                }
            }
            if fields.len() < FIELD_COUNT {
                report.problem = bad(fields.len());
                break;
            }
            let prev_hash = row.get_ref(col::PREV_HASH)?.as_blob().unwrap_or_default();
            if prev_hash != report.head {
                report.problem = fail(ProblemKind::BrokenLink);
                break;
            }
            let computed = encoding::chain(&report.head, &encoding::canonical(&fields));
            if row.get_ref(col::HASH)?.as_blob().unwrap_or_default() != computed {
                report.problem = fail(ProblemKind::HashMismatch);
                break;
            }
            match (fields[col::KIND], fields[col::BEGIN_SEQ]) {
                (Field::Text("begin"), _) => {
                    open.insert(seq);
                }
                (Field::Text("outcome"), Field::Int(begin_seq)) => {
                    if !open.remove(&begin_seq) {
                        report.problem = fail(ProblemKind::BadOutcome { begin_seq });
                        break;
                    }
                }
                (Field::Text("outcome"), _) => {
                    report.problem = bad(col::BEGIN_SEQ);
                    break;
                }
                _ => {
                    report.problem = bad(col::KIND);
                    break;
                }
            }
            report.head = computed;
            report.entries += 1;
        }
        report.orphans = open.into_iter().collect();
        Ok(report)
    }

    /// Entries at or after `ts_ms`, oldest first.
    pub fn since(&self, ts_ms: i64) -> Result<Vec<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM entries WHERE ts_ms >= ?1 ORDER BY seq"
        ))?;
        let mut rows = stmt.query([ts_ms])?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(col::SEQ)?;
            let corrupt = |what: &str| Error::Corrupt(format!("entry #{seq}: {what}"));
            let kind: String = row.get(col::KIND)?;
            let body = match kind.as_str() {
                "begin" => Body::Begin(Call {
                    actor: row
                        .get::<_, Option<String>>(col::ACTOR)?
                        .ok_or_else(|| corrupt("begin without actor"))?
                        .parse()?,
                    account: row.get(col::ACCOUNT)?,
                    verb: row
                        .get::<_, Option<String>>(col::VERB)?
                        .ok_or_else(|| corrupt("begin without verb"))?,
                    target: row.get(col::TARGET)?,
                    args_digest: row
                        .get::<_, Option<Vec<u8>>>(col::ARGS_DIGEST)?
                        .and_then(|d| d.try_into().ok())
                        .ok_or_else(|| corrupt("bad args digest"))?,
                }),
                "outcome" => Body::Outcome {
                    begin_seq: row
                        .get::<_, Option<i64>>(col::BEGIN_SEQ)?
                        .ok_or_else(|| corrupt("outcome without begin"))?,
                    status: row
                        .get::<_, Option<String>>(col::STATUS)?
                        .ok_or_else(|| corrupt("outcome without status"))?
                        .parse()?,
                    detail: row.get(col::DETAIL)?,
                },
                other => return Err(corrupt(&format!("unknown kind {other:?}"))),
            };
            entries.push(Entry {
                seq,
                ts_ms: row.get(col::TS_MS)?,
                body,
            });
        }
        Ok(entries)
    }

    pub fn stats(&self) -> Result<Stats> {
        // One read transaction, so a call committed between two of these
        // queries can't make the figures disagree.
        let tx = self.conn.unchecked_transaction()?;
        let mut stats = tx.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(kind = 'begin'), 0), MIN(ts_ms), MAX(ts_ms),
                    COUNT(DISTINCT CASE WHEN kind = 'begin' AND {AGENT_USE} THEN actor END)
                 FROM entries e"
            ),
            [],
            |row| {
                Ok(Stats {
                    entries: count(row.get(0)?),
                    begins: count(row.get(1)?),
                    first_ts_ms: row.get(2)?,
                    last_ts_ms: row.get(3)?,
                    tokens: count(row.get(4)?),
                    ..Stats::default()
                })
            },
        )?;

        let mut by_status = tx.prepare(
            "SELECT status, COUNT(*) FROM entries WHERE kind = 'outcome' GROUP BY status",
        )?;
        let mut rows = by_status.query([])?;
        while let Some(row) = rows.next()? {
            let status: Status = row.get::<_, String>(0)?.parse()?;
            let index = Status::ALL
                .iter()
                .position(|s| *s == status)
                .unwrap_or_default();
            stats.outcomes[index] = count(row.get(1)?);
        }
        stats.orphans = stats
            .begins
            .saturating_sub(stats.outcomes.iter().sum::<u64>());

        let mut by_day = tx.prepare(&format!(
            "SELECT ts_ms / ?1 AS day, COUNT(*),
                COALESCE(SUM({AGENT_USE}), 0),
                COUNT(DISTINCT CASE WHEN {AGENT_USE} THEN actor END)
             FROM entries e WHERE kind = 'begin' GROUP BY day ORDER BY day"
        ))?;
        let mut rows = by_day.query([DAY_MS])?;
        while let Some(row) = rows.next()? {
            stats.days.push(Day {
                start_ms: row.get::<_, i64>(0)? * DAY_MS,
                calls: count(row.get(1)?),
                agent_calls: count(row.get(2)?),
                tokens: count(row.get(3)?),
            });
        }
        Ok(stats)
    }
}

fn setup_error(e: SetupError, path: &Path) -> Error {
    match e {
        SetupError::Sqlite(e) => Error::Sqlite(e),
        SetupError::NoWal(mode) => Error::NoWal(mode),
        SetupError::Newer(version) => Error::NewerSchema(version),
        // v1 is the first Ledger schema, so no file is older.
        SetupError::Older(version) => Error::Corrupt(format!("unknown schema v{version}")),
        SetupError::WrongKind => Error::NotALedger(path.to_path_buf()),
    }
}

fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn to_value(field: &Field<'_>) -> Value {
    match *field {
        Field::Null => Value::Null,
        Field::Int(v) => Value::Integer(v),
        Field::Text(v) => Value::Text(v.to_string()),
        Field::Blob(v) => Value::Blob(v.to_vec()),
    }
}

fn field_of(value: ValueRef<'_>) -> Option<Field<'_>> {
    match value {
        ValueRef::Null => Some(Field::Null),
        ValueRef::Integer(v) => Some(Field::Int(v)),
        ValueRef::Text(v) => std::str::from_utf8(v).ok().map(Field::Text),
        ValueRef::Blob(v) => Some(Field::Blob(v)),
        ValueRef::Real(_) => None,
    }
}

fn now_ms() -> Result<i64> {
    crate::time::now_ms().ok_or(Error::Clock)
}
