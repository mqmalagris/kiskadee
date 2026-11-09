//! `kiskadee ledger` end to end: a real binary against a real ledger.db.

use std::path::Path;
use std::process::{Command, Output};

use kiskadee_core::ledger::{Actor, Call, Ledger, Status, digest};

fn kiskadee(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kiskadee"))
        .args(args)
        .env("KISKADEE_HOME", home)
        .output()
        .expect("run kiskadee")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn seed(home: &Path) {
    let mut ledger = Ledger::open(&home.join("ledger.db")).unwrap();
    let seq = ledger
        .begin(Call {
            actor: Actor::Token("t1".into()),
            account: Some("work".into()),
            verb: "mail.list".into(),
            target: Some("inbox\u{1b}[2J".into()),
            args_digest: digest(b"{}"),
        })
        .unwrap();
    ledger.outcome(seq, Status::Ok, None).unwrap();
    ledger
        .begin(Call {
            actor: Actor::Token("t1".into()),
            account: Some("work".into()),
            verb: "mail.read".into(),
            target: None,
            args_digest: digest(b"{}"),
        })
        .unwrap();
}

#[test]
fn missing_ledger_fails_without_creating_one() {
    let home = tempfile::tempdir().unwrap();
    let output = kiskadee(home.path(), &["ledger", "verify"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no ledger at"));
    assert!(!home.path().join("ledger.db").exists());
}

#[test]
fn an_empty_file_is_reported_and_left_untouched() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("ledger.db");
    std::fs::write(&path, b"").unwrap();
    let output = kiskadee(home.path(), &["ledger", "verify"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not a kiskadee ledger"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn verify_reports_an_intact_chain_and_orphans() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let output = kiskadee(home.path(), &["ledger", "verify"]);
    assert!(output.status.success(), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("ok: 3 entries, chain intact"), "{text}");
    assert!(
        text.contains("without an outcome") && text.contains("#3"),
        "{text}"
    );
}

#[test]
fn stats_report_totals_and_the_gate_metrics() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let text = stdout(&kiskadee(home.path(), &["ledger", "stats"]));
    for expected in [
        "entries     3",
        "no outcome 1",
        "tokens      1",
        "agent days  1 (latest streak 1)",
        "day (UTC)   calls  agent  tokens",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    let today = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
        .to_string();
    assert!(
        text.lines()
            .any(|line| line.starts_with(&today) && line.ends_with("2      2       1")),
        "{text}"
    );
}

#[test]
fn list_shows_recent_entries_with_control_characters_replaced() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let text = stdout(&kiskadee(home.path(), &["ledger", "--since", "1h"]));
    assert_eq!(text.lines().count(), 3, "{text}");
    assert!(
        text.contains("token:t1  work  mail.list inbox?[2J"),
        "{text}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "control characters must not reach the terminal"
    );
    assert!(text.contains("outcome  #1 ok"), "{text}");
}

#[test]
fn list_says_so_when_nothing_is_recent() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let text = stdout(&kiskadee(
        home.path(),
        &["ledger", "--since", "2099-01-01T00:00:00Z"],
    ));
    assert!(text.contains("no entries since"), "{text}");
}

#[test]
fn verify_exits_nonzero_on_tampering() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let conn = rusqlite::Connection::open(home.path().join("ledger.db")).unwrap();
    conn.execute_batch(
        "DROP TRIGGER entries_no_update; UPDATE entries SET status = 'denied' WHERE seq = 2;",
    )
    .unwrap();
    drop(conn);

    let output = kiskadee(home.path(), &["ledger", "verify"]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("BROKEN: entry #2"), "{text}");
    assert!(text.contains("1 entries verified before it"), "{text}");
}

#[test]
fn bad_since_is_a_usage_error() {
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let output = kiskadee(home.path(), &["ledger", "--since", "yesterday"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("use a duration like"));
}
