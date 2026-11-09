//! Durable SQLite setup shared by the Broker's own files (`ledger.db`,
//! `tokens.db`).

use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, TransactionBehavior};

/// How long a write waits for another connection's. Writers queue behind
/// each other's `synchronous=FULL` commits, which take tens of milliseconds
/// each on a slow disk, and every Verb call waits on its `begin` row, so
/// waiting beats refusing the call. rusqlite's 5 s default ran out with 4
/// writers on a Windows CI runner.
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const WAL_RETRY_FOR: Duration = BUSY_TIMEOUT;
const WAL_RETRY_EVERY: Duration = Duration::from_millis(10);

/// One kind of Broker file. `application_id` tells the kinds apart, so
/// opening `tokens.db` as a Ledger (or any other SQLite file as either)
/// fails at open instead of on the first query.
pub(crate) struct FileKind {
    pub application_id: i32,
    pub schema: &'static str,
    pub version: i64,
}

#[derive(Debug)]
pub(crate) enum SetupError {
    Sqlite(rusqlite::Error),
    /// SQLite refused WAL; it reported this journal mode instead.
    NoWal(String),
    /// The file was written by a newer kiskadee.
    Newer(i64),
    /// The file is some other kind of database.
    WrongKind,
}

impl From<rusqlite::Error> for SetupError {
    fn from(e: rusqlite::Error) -> Self {
        SetupError::Sqlite(e)
    }
}

/// Readies `conn` for durable writes: WAL journaling, `synchronous=FULL`,
/// and the schema created if the file is new.
pub(crate) fn prepare(conn: &mut Connection, kind: &FileKind) -> Result<(), SetupError> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let mode = enable_wal(conn)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(SetupError::NoWal(mode));
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    // IMMEDIATE: two processes opening a new file at once both see version
    // 0 unless the check runs under the write lock. The second waits here,
    // then finds the schema the first created.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    match identify(&tx, kind)? {
        0 => {
            let tables: i64 =
                tx.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
            if tables > 0 {
                return Err(SetupError::WrongKind);
            }
            tx.execute_batch(kind.schema)?;
            tx.pragma_update(None, "application_id", kind.application_id)?;
            tx.pragma_update(None, "user_version", kind.version)?;
        }
        found if found == kind.version => {}
        newer => return Err(SetupError::Newer(newer)),
    }
    tx.commit()?;
    Ok(())
}

/// The file's schema version, after checking it's `kind`. 0 means a new,
/// unstamped file.
pub(crate) fn identify(conn: &Connection, kind: &FileKind) -> Result<i64, SetupError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    match (version, application_id) {
        (0, 0) => Ok(0),
        (_, id) if id == kind.application_id => Ok(version),
        _ => Err(SetupError::WrongKind),
    }
}

/// Switching a new file to WAL needs an exclusive lock, and when two
/// connections race for it SQLite answers BUSY at once instead of waiting
/// out the busy timeout (waiting could deadlock). Retry for as long as the
/// timeout would have waited. Returns the journal mode SQLite reports.
fn enable_wal(conn: &Connection) -> rusqlite::Result<String> {
    let deadline = Instant::now() + WAL_RETRY_FOR;
    loop {
        match conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0)) {
            Err(e)
                if e.sqlite_error_code() == Some(ErrorCode::DatabaseBusy)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(WAL_RETRY_EVERY);
            }
            other => return other,
        }
    }
}
