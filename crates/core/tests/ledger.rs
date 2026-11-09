//! Ledger behavior against a real SQLite file (ADR 0003).

use std::path::Path;
use std::process::Command;
use std::sync::Barrier;

use kiskadee_core::ledger::{
    Actor, Body, Call, Error, GENESIS, Ledger, ProblemKind, Status, digest,
};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

const DAY_MS: i64 = 86_400_000;

fn call(verb: &str) -> Call {
    Call {
        actor: Actor::Token("t1".into()),
        account: Some("work".into()),
        verb: verb.into(),
        target: Some("msg-42".into()),
        args_digest: digest(br#"{"limit":20}"#),
    }
}

fn human(verb: &str) -> Call {
    Call {
        actor: Actor::Human("s9".into()),
        account: None,
        target: None,
        ..call(verb)
    }
}

fn token(id: &str, verb: &str) -> Call {
    Call {
        actor: Actor::Token(id.into()),
        ..call(verb)
    }
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).expect("raw connection")
}

/// begin(#1) outcome(#2, denied) begin(#3), then the connection is closed.
fn three_entries(path: &Path) {
    let mut ledger = Ledger::open(path).unwrap();
    let seq = ledger.begin(call("mail.list")).unwrap();
    ledger.outcome(seq, Status::Denied, None).unwrap();
    ledger.begin(call("mail.read")).unwrap();
}

/// Runs `sql` with the triggers dropped, then verifies with a fresh handle.
fn tamper(sql: &str) -> kiskadee_core::ledger::Problem {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    let conn = raw(&path);
    conn.execute_batch("DROP TRIGGER entries_no_update; DROP TRIGGER entries_no_delete;")
        .unwrap();
    conn.execute_batch(sql).unwrap();
    drop(conn);
    let report = Ledger::open(&path).unwrap().verify().unwrap();
    report.problem.expect("tampering must be detected")
}

/// What someone with write access can do: rewrite rows, then recompute the
/// whole chain. Re-implements the frozen v1 encoding from its spec in
/// `encoding.rs`, independently of the crate's code.
fn forge(path: &Path, sql: &str) {
    let conn = raw(path);
    conn.execute_batch("DROP TRIGGER entries_no_update; DROP TRIGGER entries_no_delete;")
        .unwrap();
    conn.execute_batch(sql).unwrap();
    let columns =
        "seq, ts_ms, kind, actor, account, verb, target, args_digest, begin_seq, status, detail";
    let rows: Vec<Vec<Value>> = conn
        .prepare(&format!("SELECT {columns} FROM entries ORDER BY seq"))
        .unwrap()
        .query_map([], |row| (0..11).map(|i| row.get::<_, Value>(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut prev = GENESIS;
    for row in rows {
        let mut canonical = b"kiskadee/ledger/v1".to_vec();
        for value in &row {
            match value {
                Value::Null => canonical.push(0x00),
                Value::Integer(v) => {
                    canonical.push(0x01);
                    canonical.extend_from_slice(&v.to_be_bytes());
                }
                Value::Text(v) => {
                    canonical.push(0x02);
                    canonical.extend_from_slice(&(v.len() as u32).to_be_bytes());
                    canonical.extend_from_slice(v.as_bytes());
                }
                Value::Blob(v) => {
                    canonical.push(0x03);
                    canonical.extend_from_slice(&(v.len() as u32).to_be_bytes());
                    canonical.extend_from_slice(v);
                }
                Value::Real(_) => panic!("forge: real values aren't encodable"),
            }
        }
        let hash: [u8; 32] = Sha256::new()
            .chain_update(prev)
            .chain_update(&canonical)
            .finalize()
            .into();
        let Value::Integer(seq) = row[0] else {
            panic!("seq is an integer")
        };
        conn.execute(
            "UPDATE entries SET prev_hash = ?1, hash = ?2 WHERE seq = ?3",
            rusqlite::params![prev.to_vec(), hash.to_vec(), seq],
        )
        .unwrap();
        prev = hash;
    }
}

#[test]
fn empty_ledger_verifies_with_genesis_head() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(&dir.path().join("ledger.db")).unwrap();
    let report = ledger.verify().unwrap();
    assert!(report.is_intact());
    assert_eq!((report.entries, report.head), (0, GENESIS));
}

#[test]
fn begin_and_outcome_chain_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut ledger = Ledger::open(&path).unwrap();
    let first = ledger.begin(call("mail.list")).unwrap();
    ledger.outcome(first, Status::Ok, None).unwrap();
    let second = ledger.begin(call("mail.read")).unwrap();
    ledger
        .outcome(second, Status::Denied, Some("out of scope"))
        .unwrap();

    let report = ledger.verify().unwrap();
    assert!(report.is_intact(), "{:?}", report.problem);
    assert_eq!(report.entries, 4);
    assert!(report.orphans.is_empty());
}

#[test]
fn reopening_continues_the_same_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    let mut ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.begin(call("mail.search")).unwrap(), 4);
    let report = ledger.verify().unwrap();
    assert!(report.is_intact());
    assert_eq!(report.orphans, vec![3, 4]);
}

#[test]
fn outcome_needs_an_open_begin() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::open(&dir.path().join("ledger.db")).unwrap();
    assert!(matches!(
        ledger.outcome(1, Status::Ok, None),
        Err(Error::NotOpen(1))
    ));
    let seq = ledger.begin(call("mail.list")).unwrap();
    let outcome = ledger.outcome(seq, Status::Ok, None).unwrap();
    assert!(matches!(
        ledger.outcome(seq, Status::Error, None),
        Err(Error::NotOpen(_))
    ));
    assert!(matches!(
        ledger.outcome(outcome, Status::Ok, None),
        Err(Error::NotOpen(_))
    ));
    assert!(ledger.verify().unwrap().is_intact());
}

#[test]
fn update_and_delete_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut ledger = Ledger::open(&path).unwrap();
    ledger.begin(call("mail.list")).unwrap();
    drop(ledger);

    let conn = raw(&path);
    for sql in [
        "UPDATE entries SET verb = 'mail.delete' WHERE seq = 1",
        "DELETE FROM entries WHERE seq = 1",
        "DELETE FROM entries",
    ] {
        let error = conn.execute(sql, []).unwrap_err();
        assert!(
            error.to_string().contains("append-only"),
            "{sql}: unexpected error {error}"
        );
    }
    drop(conn);
    assert!(Ledger::open(&path).unwrap().verify().unwrap().is_intact());
}

#[test]
fn verify_catches_an_edited_status() {
    let problem = tamper("UPDATE entries SET status = 'ok' WHERE seq = 2");
    assert_eq!((problem.seq, problem.kind), (2, ProblemKind::HashMismatch));
}

#[test]
fn verify_catches_an_edited_timestamp() {
    let problem = tamper("UPDATE entries SET ts_ms = ts_ms + 1 WHERE seq = 1");
    assert_eq!((problem.seq, problem.kind), (1, ProblemKind::HashMismatch));
}

#[test]
fn verify_catches_a_replaced_hash() {
    let problem = tamper("UPDATE entries SET hash = zeroblob(32) WHERE seq = 1");
    assert_eq!((problem.seq, problem.kind), (1, ProblemKind::HashMismatch));
}

#[test]
fn verify_catches_a_deleted_middle_row() {
    let problem = tamper("DELETE FROM entries WHERE seq = 2");
    assert_eq!(
        (problem.seq, problem.kind),
        (3, ProblemKind::Gap { expected: 2 })
    );
}

#[test]
fn verify_catches_a_broken_link() {
    let problem = tamper("UPDATE entries SET prev_hash = zeroblob(32) WHERE seq = 2");
    assert_eq!((problem.seq, problem.kind), (2, ProblemKind::BrokenLink));
}

#[test]
fn verify_catches_reordered_rows() {
    let problem = tamper(
        "UPDATE entries SET seq = 99 WHERE seq = 2;
         UPDATE entries SET seq = 2 WHERE seq = 3;
         UPDATE entries SET seq = 3 WHERE seq = 99;",
    );
    assert_eq!((problem.seq, problem.kind), (2, ProblemKind::BrokenLink));
}

#[test]
fn verify_rejects_a_value_the_encoding_cannot_represent() {
    // TEXT columns coerce a float to text (a plain HashMismatch); a BLOB
    // column keeps the float.
    let problem = tamper("UPDATE entries SET args_digest = 1.5 WHERE seq = 1");
    assert_eq!(
        (problem.seq, problem.kind),
        (
            1,
            ProblemKind::BadValue {
                column: "args_digest"
            }
        )
    );
}

#[test]
fn verify_rejects_a_forged_outcome_for_a_missing_begin() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    forge(
        &path,
        "INSERT INTO entries VALUES (4, 0, 'outcome', NULL, NULL, NULL, NULL, NULL,
            99, 'ok', NULL, zeroblob(32), zeroblob(32))",
    );
    let problem = Ledger::open(&path).unwrap().verify().unwrap().problem;
    assert_eq!(
        problem.map(|p| (p.seq, p.kind)),
        Some((4, ProblemKind::BadOutcome { begin_seq: 99 }))
    );
}

#[test]
fn verify_names_a_non_integer_begin_seq() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    forge(&path, "UPDATE entries SET begin_seq = 'one' WHERE seq = 2");
    let problem = Ledger::open(&path).unwrap().verify().unwrap().problem;
    assert_eq!(
        problem.map(|p| (p.seq, p.kind)),
        Some((
            2,
            ProblemKind::BadValue {
                column: "begin_seq"
            }
        ))
    );
}

/// Known limit (ADR 0003, tamper-evident not tamper-proof): a rewrite that
/// recomputes the whole chain verifies. Only an exported head would differ.
#[test]
fn a_fully_rebuilt_chain_is_not_detectable_from_the_chain_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    let honest = Ledger::open(&path).unwrap().verify().unwrap().head;
    forge(&path, "UPDATE entries SET status = 'ok' WHERE seq = 2");
    let report = Ledger::open(&path).unwrap().verify().unwrap();
    assert!(report.is_intact());
    assert_ne!(report.head, honest);
}

/// Known limit: truncating the tail leaves a valid shorter chain.
#[test]
fn truncating_the_tail_is_not_detectable_from_the_chain_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut ledger = Ledger::open(&path).unwrap();
    ledger.begin(call("mail.list")).unwrap();
    let head_after_one = ledger.verify().unwrap().head;
    ledger.begin(call("mail.read")).unwrap();
    drop(ledger);
    let conn = raw(&path);
    conn.execute_batch("DROP TRIGGER entries_no_delete; DELETE FROM entries WHERE seq = 2;")
        .unwrap();
    drop(conn);
    let report = Ledger::open(&path).unwrap().verify().unwrap();
    assert!(report.is_intact());
    assert_eq!(
        report.head, head_after_one,
        "only an exported head would differ"
    );
}

/// ADR 0003: a crash between `begin` and execution leaves an orphan `begin`
/// and an intact chain. The child process aborts (no destructors, no
/// rollback) right after `begin` returns.
#[test]
fn crash_after_begin_leaves_an_orphan_and_verify_passes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut ledger = Ledger::open(&path).unwrap();
    let seq = ledger.begin(call("mail.list")).unwrap();
    ledger.outcome(seq, Status::Ok, None).unwrap();
    drop(ledger);

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
        .env("KISKADEE_CRASH_LEDGER", &path)
        .status()
        .unwrap();
    assert!(!status.success(), "the child must die, not exit cleanly");

    let ledger = Ledger::open(&path).unwrap();
    let report = ledger.verify().unwrap();
    assert!(report.is_intact(), "{:?}", report.problem);
    assert_eq!(report.entries, 3);
    assert_eq!(report.orphans, vec![3]);
    assert_eq!(ledger.stats().unwrap().orphans, 1);
}

/// Not a test on its own: the crashing half of the test above.
#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("KISKADEE_CRASH_LEDGER") else {
        return;
    };
    let mut ledger = Ledger::open(Path::new(&path)).unwrap();
    ledger.begin(call("mail.delete")).unwrap();
    std::process::abort();
}

/// Several processes may open a brand-new ledger.db at once (the CLI
/// auto-starting the Broker): one creates the schema, all share one chain.
#[test]
fn concurrent_writers_on_a_new_file_share_one_intact_chain() {
    const WRITERS: usize = 4;
    const CALLS: usize = 20;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let barrier = Barrier::new(WRITERS);
    std::thread::scope(|scope| {
        for writer in 0..WRITERS {
            let (path, barrier) = (&path, &barrier);
            scope.spawn(move || {
                barrier.wait();
                let mut ledger = Ledger::open(path).unwrap();
                for _ in 0..CALLS {
                    let seq = ledger
                        .begin(token(&format!("w{writer}"), "mail.list"))
                        .unwrap();
                    ledger.outcome(seq, Status::Ok, None).unwrap();
                }
            });
        }
    });

    let ledger = Ledger::open(&path).unwrap();
    let report = ledger.verify().unwrap();
    assert!(report.is_intact(), "{:?}", report.problem);
    assert_eq!(report.entries, (WRITERS * CALLS * 2) as u64);
    assert!(report.orphans.is_empty());
    let entries = ledger.since(0).unwrap();
    assert!(
        entries
            .windows(2)
            .all(|pair| pair[0].ts_ms <= pair[1].ts_ms),
        "timestamps must follow seq order"
    );
    assert_eq!(ledger.stats().unwrap().tokens, WRITERS as u64);
}

#[test]
fn a_clock_stepping_back_never_moves_an_entry_before_the_previous_one() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(&dir.path().join("ledger.db")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(2_000));
    ledger.begin(call("mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(1_000));
    ledger.begin(call("mail.read")).unwrap();
    let entries = ledger.since(2_000).unwrap();
    assert_eq!(
        entries.iter().map(|e| e.ts_ms).collect::<Vec<_>>(),
        [2_000, 2_000]
    );
}

#[test]
fn a_clock_that_fails_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(&dir.path().join("ledger.db")).unwrap();
    let mut ledger = ledger.with_clock(|| Err(Error::Clock));
    assert!(matches!(ledger.begin(call("mail.list")), Err(Error::Clock)));
    assert_eq!(ledger.verify().unwrap().entries, 0);
}

#[test]
fn since_filters_by_time_and_round_trips_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut ledger = Ledger::open(&path).unwrap().with_clock(|| Ok(1_000));
    let old = ledger.begin(call("mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(2_000));
    ledger.outcome(old, Status::Ok, None).unwrap();
    ledger.begin(human("token.mint")).unwrap();

    let entries = ledger.since(2_000).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 2);
    assert_eq!(
        entries[0].body,
        Body::Outcome {
            begin_seq: 1,
            status: Status::Ok,
            detail: None
        }
    );
    assert_eq!(
        (entries[1].ts_ms, &entries[1].body),
        (2_000, &Body::Begin(human("token.mint")))
    );
    assert_eq!(ledger.since(0).unwrap().len(), 3);
    assert!(ledger.since(2_001).unwrap().is_empty());
}

#[test]
fn stats_counts_outcomes_and_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::open(&dir.path().join("ledger.db"))
        .unwrap()
        .with_clock(|| Ok(5));
    for status in [Status::Ok, Status::Ok, Status::Denied, Status::Conflict] {
        let seq = ledger.begin(call("mail.list")).unwrap();
        ledger.outcome(seq, status, None).unwrap();
    }
    ledger.begin(call("mail.read")).unwrap();

    let stats = ledger.stats().unwrap();
    assert_eq!(stats.entries, 9);
    assert_eq!(stats.begins, 5);
    assert_eq!(stats.outcomes, [2, 1, 0, 1]);
    assert_eq!(stats.orphans, 1);
    assert_eq!((stats.first_ts_ms, stats.last_ts_ms), (Some(5), Some(5)));
}

#[test]
fn stats_of_an_empty_ledger_are_zero() {
    let dir = tempfile::tempdir().unwrap();
    let stats = Ledger::open(&dir.path().join("ledger.db"))
        .unwrap()
        .stats()
        .unwrap();
    assert_eq!((stats.entries, stats.orphans, stats.tokens), (0, 0, 0));
    assert_eq!((stats.first_ts_ms, stats.last_ts_ms), (None, None));
    assert!(stats.days.is_empty());
    assert_eq!((stats.agent_days(), stats.agent_streak()), (0, 0));
}

/// The 0.1 gate's measurement: days with agent reads, distinct tokens,
/// Verbs per day.
#[test]
fn stats_report_agent_days_tokens_and_calls_per_day() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(&dir.path().join("ledger.db")).unwrap();
    // Day 0: two calls by t1, one by the human. Day 1: t2. Day 2: nothing.
    // Days 3 and 4: t1. Day 5: the human only.
    let mut ledger = ledger.with_clock(|| Ok(10));
    ledger.begin(token("t1", "mail.list")).unwrap();
    ledger.begin(token("t1", "mail.read")).unwrap();
    ledger.begin(human("mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(DAY_MS + 10));
    ledger.begin(token("t2", "mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(3 * DAY_MS));
    ledger.begin(token("t1", "mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(4 * DAY_MS + 1));
    ledger.begin(token("t1", "mail.list")).unwrap();
    let mut ledger = ledger.with_clock(|| Ok(5 * DAY_MS));
    ledger.begin(human("mail.list")).unwrap();

    let stats = ledger.stats().unwrap();
    assert_eq!(stats.tokens, 2);
    assert_eq!(
        stats
            .days
            .iter()
            .map(|d| (d.start_ms / DAY_MS, d.calls, d.agent_calls, d.tokens))
            .collect::<Vec<_>>(),
        [
            (0, 3, 2, 1),
            (1, 1, 1, 1),
            (3, 1, 1, 1),
            (4, 1, 1, 1),
            (5, 1, 0, 0)
        ]
    );
    assert_eq!(stats.agent_days(), 4);
    assert_eq!(
        stats.agent_streak(),
        2,
        "days 3 and 4; day 2 had no agent calls"
    );
}

#[test]
fn journal_uses_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    drop(Ledger::open(&path).unwrap());
    let mode: String = raw(&path)
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    // WAL is stored in the file; synchronous=FULL is per connection and set
    // on every writable open.
    assert_eq!(mode, "wal");
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    drop(Ledger::open(&path).unwrap());
    raw(&path).pragma_update(None, "user_version", 2).unwrap();
    assert!(matches!(Ledger::open(&path), Err(Error::NewerSchema(2))));
    assert!(matches!(
        Ledger::open_read_only(&path),
        Err(Error::NewerSchema(2))
    ));
}

#[test]
fn read_only_open_of_a_missing_file_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    assert!(matches!(
        Ledger::open_read_only(&path),
        Err(Error::Missing(_))
    ));
    assert!(!path.exists());
}

#[test]
fn read_only_open_leaves_an_empty_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(
        Ledger::open_read_only(&path),
        Err(Error::NotALedger(_))
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert!(!dir.path().join("ledger.db-wal").exists());
}

#[test]
fn read_only_ledger_reads_but_refuses_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    three_entries(&path);
    let mut reader = Ledger::open_read_only(&path).unwrap();
    assert_eq!(reader.verify().unwrap().entries, 3);
    assert!(matches!(
        reader.begin(call("mail.list")),
        Err(Error::Sqlite(_))
    ));
    assert_eq!(reader.verify().unwrap().entries, 3);
}
