//! The Verb dispatcher against real `tokens.db` and `ledger.db` files and a
//! fake mail backend.
//!
//! Plan Phase 1, "Verb dispatcher + budgets + rate limits": a call over
//! budget is denied and logged; there is no code path that forwards raw
//! protocol commands. Design: `docs/intent/0003-verb-dispatcher.md`.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Barrier;

use kiskadee_core::dispatch::{
    BackendError, Dispatcher, Error, Executor, Invocation, Location, MAX_PER_CALL, Output,
    RATE_LIMIT, RATE_WINDOW_MS, Refusal, Reply, Response, VerbCall,
};
use kiskadee_core::ledger::{Actor, Body, Entry, Ledger, Status};
use kiskadee_core::profiles::{Profiles, Selector};
use kiskadee_core::tokens::{Charge, Denial, MintRequest, TokenKey, TokenStore};
use kiskadee_core::verb::Verb;

const NOW: i64 = 1_800_000_000_000;
const KEY: [u8; 32] = [7; 32];

/// One Account, `work`, with folders `INBOX`, `Archive`, `Work` and
/// `Work/Clients`.
const WORK: &str = r#"
[reader]
verbs = ["list", "read", "search", "attachment.extract"]
accounts = ["work"]
resources = ["INBOX", "Archive"]
read_budget = 10
max_ttl = "1h"

[nested]
verbs = ["read"]
accounts = ["work"]
resources = ["Work"]
read_budget = 10
max_ttl = "1h"

[both]
verbs = ["read"]
accounts = ["work", "home"]
resources = ["INBOX"]
read_budget = 10
max_ttl = "1h"

[roomy]
verbs = ["read"]
accounts = ["work"]
resources = ["INBOX"]
read_budget = 50
max_ttl = "1h"
"#;

/// A mail backend that serves threads from memory and records every run.
#[derive(Default)]
struct FakeMail {
    /// Thread id to where it lives (a thread can span folders) and how
    /// many messages it holds.
    threads: BTreeMap<String, (Vec<Location>, u64)>,
    runs: RefCell<Vec<(Verb, u32, Option<String>)>>,
    fail: Cell<bool>,
    locate_fails: Cell<bool>,
    unsupported: Cell<bool>,
    /// Reports this many messages instead of the thread's real count, as a
    /// backend that breaks its contract would.
    misreport: Cell<Option<u64>>,
    /// Runs once while the next Verb is being fetched.
    during_run: RefCell<Option<Box<dyn FnOnce()>>>,
}

fn location(account: &str, folder: &str) -> Location {
    Location {
        account: account.into(),
        folder: folder.into(),
    }
}

impl FakeMail {
    fn with(threads: &[(&str, &str, &str, u64)]) -> Self {
        FakeMail {
            threads: threads
                .iter()
                .map(|&(id, account, folder, messages)| {
                    (id.to_string(), (vec![location(account, folder)], messages))
                })
                .collect(),
            ..FakeMail::default()
        }
    }

    /// Thread `id` also has messages in `folder` of the same Account.
    fn spanning(mut self, id: &str, folder: &str) -> Self {
        let (locations, _) = self.threads.get_mut(id).unwrap();
        let account = locations[0].account.clone();
        locations.push(location(&account, folder));
        self
    }
}

/// The dispatcher owns its executor; the test keeps a handle to inspect it.
struct Shared(Rc<FakeMail>);

impl Executor for Shared {
    fn locate(&self, target: &str) -> Result<Vec<Location>, BackendError> {
        if self.0.locate_fails.get() {
            return Err(BackendError::Failed("connection reset".into()));
        }
        Ok(self
            .0
            .threads
            .get(target)
            .map(|(locations, _)| locations.clone())
            .unwrap_or_default())
    }

    fn run(&self, invocation: &Invocation<'_>) -> Result<Output, BackendError> {
        self.0.runs.borrow_mut().push((
            invocation.verb,
            invocation.limit,
            invocation.cursor.map(str::to_string),
        ));
        if let Some(during) = self.0.during_run.borrow_mut().take() {
            during();
        }
        if self.0.fail.get() {
            return Err(BackendError::Failed("connection reset".into()));
        }
        if self.0.unsupported.get() {
            return Err(BackendError::Unsupported);
        }
        let messages = if let Some(misreported) = self.0.misreport.get() {
            misreported
        } else if invocation.verb.returns_content() {
            let target = invocation.target.expect("content Verbs name a target");
            self.0.threads[target].1
        } else {
            0
        };
        Ok(Output {
            body: format!("{} ok", invocation.verb).into_bytes(),
            messages,
            cursor: (!invocation.verb.returns_content()).then(|| "page-2".to_string()),
        })
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    mail: Rc<FakeMail>,
    clock: Rc<Cell<i64>>,
    dispatcher: Dispatcher<Shared>,
}

fn open(dir: &Path, mail: &Rc<FakeMail>, clock: &Rc<Cell<i64>>) -> Dispatcher<Shared> {
    let tokens = TokenStore::open(&dir.join("tokens.db"), TokenKey::from_bytes(KEY))
        .unwrap()
        .with_clock(|| Ok(NOW));
    let ledger = Ledger::open(&dir.join("ledger.db"))
        .unwrap()
        .with_clock(|| Ok(NOW));
    let clock = Rc::clone(clock);
    Dispatcher::new(tokens, ledger, Shared(Rc::clone(mail))).with_clock(move || Some(clock.get()))
}

fn fixture(mail: FakeMail) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let mail = Rc::new(mail);
    let clock = Rc::new(Cell::new(NOW));
    Fixture {
        dispatcher: open(&path, &mail, &clock),
        mail,
        clock,
        _dir: dir,
        dir: path,
    }
}

/// Threads in `work`: 4, 6 and 7 messages in INBOX, 1 in each other folder.
fn work_mail() -> FakeMail {
    FakeMail::with(&[
        ("t4", "work", "INBOX", 4),
        ("t6", "work", "INBOX", 6),
        ("t7", "work", "INBOX", 7),
        ("t-archive", "work", "Archive", 1),
        ("t-sent", "work", "Sent", 1),
        ("t-lower", "work", "inbox", 1),
        ("t-work", "work", "Work", 1),
        ("t-clients", "work", "Work/Clients", 1),
    ])
}

fn human() -> Actor {
    Actor::Human("session-1".into())
}

/// A `read` of `target` that names INBOX, as an agent working in the inbox
/// would; where the thread really lives is for the dispatcher to check.
fn read(target: &str) -> VerbCall<'_> {
    VerbCall {
        resource: Some("INBOX"),
        ..read_in(None, target)
    }
}

fn read_in<'a>(folder: Option<&'a str>, target: &'a str) -> VerbCall<'a> {
    VerbCall {
        verb: Verb::Read,
        account: Some("work"),
        resource: folder,
        target: Some(target),
        limit: None,
        cursor: None,
        args: serde_json::Value::Null,
    }
}

fn list() -> VerbCall<'static> {
    VerbCall {
        verb: Verb::List,
        account: Some("work"),
        resource: Some("INBOX"),
        target: None,
        limit: None,
        cursor: None,
        args: serde_json::Value::Null,
    }
}

impl Fixture {
    /// Mints a token from `profile` in [`WORK`]; returns its secret.
    fn mint(&mut self, profile: &str) -> String {
        let profiles = Profiles::parse(WORK).unwrap();
        let (tokens, ledger) = self.dispatcher.stores();
        tokens
            .mint(ledger, human(), &profiles, &MintRequest::new(profile))
            .unwrap()
            .secret
            .expose()
            .to_string()
    }

    fn call(&mut self, secret: &str, call: &VerbCall<'_>) -> Response {
        self.dispatcher.call(secret, call).unwrap()
    }

    fn entries(&self) -> Vec<Entry> {
        self.dispatcher.ledger().since(0).unwrap()
    }

    fn reopen(&mut self) {
        self.dispatcher = open(&self.dir, &self.mail, &self.clock);
    }

    fn runs(&self) -> usize {
        self.mail.runs.borrow().len()
    }
}

fn reply(response: Response) -> Reply {
    match response {
        Response::Reply(reply) => reply,
        Response::Refused(refusal) => panic!("expected a reply, got {refusal:?}"),
    }
}

fn refusal(response: Response) -> Refusal {
    match response {
        Response::Refused(refusal) => refusal,
        Response::Reply(_) => panic!("expected a refusal"),
    }
}

/// The last two Ledger rows: the call's `begin` verb and its outcome.
fn last_outcome(entries: &[Entry]) -> (String, Status, Option<String>) {
    let [.., begin, outcome] = entries else {
        panic!("expected a begin and an outcome, got {entries:?}")
    };
    let Body::Begin(call) = &begin.body else {
        panic!("expected a begin, got {begin:?}")
    };
    let Body::Outcome { status, detail, .. } = &outcome.body else {
        panic!("expected an outcome, got {outcome:?}")
    };
    (call.verb.clone(), *status, detail.clone())
}

fn denied(code: &str) -> (String, Status, Option<String>) {
    ("read".into(), Status::Denied, Some(code.into()))
}

/// AC-1a: a token with a budget of 10 that has used 4 reads a 7-message
/// thread. 11 > 10, so the whole call is denied with 6 reads remaining, no
/// content is returned, and the Ledger has its begin and denied outcome.
#[test]
fn ac_1a_a_thread_over_the_remaining_budget_is_denied_whole_and_logged() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    assert_eq!(reply(f.call(&secret, &read("t4"))).reads_remaining, 6);

    let refused = refusal(f.call(&secret, &read("t7")));

    assert_eq!(refused, Refusal::BudgetExhausted { reads_remaining: 6 });
    assert_eq!(refused.code(), "budget.exhausted");
    assert_eq!(last_outcome(&f.entries()), denied("budget.exhausted"));
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 6);
}

/// AC-1b: the same token, 4 used, reads a 6-message thread. 10 fits
/// exactly, so it succeeds with 0 left; the next `read` is denied while
/// `list` and `search` still work.
#[test]
fn ac_1b_a_thread_that_fits_exactly_succeeds_and_only_reads_stop_after_it() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    reply(f.call(&secret, &read("t4")));

    let fits = reply(f.call(&secret, &read("t6")));

    assert_eq!((fits.reads_used, fits.reads_remaining), (Some(6), 0));
    assert_eq!(fits.body, b"read ok");
    assert_eq!(
        last_outcome(&f.entries()),
        ("read".into(), Status::Ok, Some("reads=6".into()))
    );
    assert_eq!(
        refusal(f.call(&secret, &read("t-archive"))),
        Refusal::BudgetExhausted { reads_remaining: 0 }
    );
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 0);
    let search = VerbCall {
        verb: Verb::Search,
        ..list()
    };
    assert_eq!(reply(f.call(&secret, &search)).reads_remaining, 0);
}

#[test]
fn metadata_verbs_cost_no_reads_and_log_no_read_count() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let listed = reply(f.call(&secret, &list()));
    assert_eq!((listed.reads_used, listed.reads_remaining), (None, 10));
    assert_eq!(listed.cursor.as_deref(), Some("page-2"));
    assert_eq!(
        last_outcome(&f.entries()),
        ("list".into(), Status::Ok, None)
    );
}

#[test]
fn every_content_verb_is_charged_per_message() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let extract = VerbCall {
        verb: Verb::AttachmentExtract,
        ..read("t4")
    };
    assert_eq!(reply(f.call(&secret, &extract)).reads_remaining, 6);
}

#[test]
fn a_token_with_no_reads_left_is_denied_before_the_backend_runs() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    reply(f.call(&secret, &read("t4")));
    reply(f.call(&secret, &read("t6")));
    let runs = f.runs();
    refusal(f.call(&secret, &read("t4")));
    assert_eq!(f.runs(), runs);
}

#[test]
fn a_backend_failure_charges_nothing_and_is_logged_as_an_error() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    f.mail.fail.set(true);
    assert!(f.dispatcher.call(&secret, &read("t4")).is_err());
    assert_eq!(
        last_outcome(&f.entries()),
        ("read".into(), Status::Error, Some("backend".into()))
    );
    f.mail.fail.set(false);
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 10);
}

#[test]
fn reads_used_survive_a_broker_restart() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    reply(f.call(&secret, &read("t4")));
    f.reopen();
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 6);
}

#[test]
fn editing_reads_used_outside_kiskadee_is_refused_as_tampered() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    reply(f.call(&secret, &read("t4")));
    let conn = rusqlite::Connection::open(f.dir.join("tokens.db")).unwrap();
    conn.execute_batch("UPDATE tokens SET reads_used = 0")
        .unwrap();
    assert_eq!(
        refusal(f.call(&secret, &list())),
        Refusal::Token(Denial::Tampered)
    );
}

/// Two calls that each fit the budget but not together: both may run, but
/// only one charge can commit.
#[test]
fn racing_charges_on_one_token_never_overspend_the_budget() {
    let f = fixture(work_mail());
    let mut f = f;
    f.mint("reader");
    let id = f.dispatcher.stores().0.list().unwrap()[0].id.clone();
    let barrier = Barrier::new(2);
    let results: Vec<Charge> = std::thread::scope(|s| {
        let racers: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    let mut tokens =
                        TokenStore::open(&f.dir.join("tokens.db"), TokenKey::from_bytes(KEY))
                            .unwrap();
                    barrier.wait();
                    tokens.charge_reads(&id, 6).unwrap()
                })
            })
            .collect();
        racers.into_iter().map(|r| r.join().unwrap()).collect()
    });
    let charged = results
        .iter()
        .filter(|c| matches!(c, Charge::Charged { .. }))
        .count();
    assert_eq!(charged, 1, "{results:?}");
    assert!(results.contains(&Charge::Short { reads_remaining: 4 }));
}

#[test]
fn a_list_asking_for_more_than_the_cap_gets_the_cap_and_a_cursor() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for limit in [None, Some(500), Some(MAX_PER_CALL)] {
        let call = VerbCall { limit, ..list() };
        assert_eq!(
            reply(f.call(&secret, &call)).cursor.as_deref(),
            Some("page-2")
        );
    }
    let next = VerbCall {
        limit: Some(10),
        cursor: Some("page-2"),
        ..list()
    };
    reply(f.call(&secret, &next));
    let limits: Vec<_> = f
        .mail
        .runs
        .borrow()
        .iter()
        .map(|(_, limit, cursor)| (*limit, cursor.clone()))
        .collect();
    assert_eq!(
        limits,
        [
            (MAX_PER_CALL, None),
            (MAX_PER_CALL, None),
            (MAX_PER_CALL, None),
            (10, Some("page-2".into()))
        ]
    );
}

#[test]
fn a_target_out_of_scope_and_a_missing_target_look_the_same_to_the_agent() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for (target, reason) in [
        ("t-sent", "scope.resource"),
        ("no-such-id", "target.missing"),
    ] {
        let refused = refusal(f.call(&secret, &read(target)));
        assert_eq!(
            (&refused, refused.code()),
            (&Refusal::TargetUnavailable, "target.unavailable"),
            "{target}"
        );
        assert_eq!(last_outcome(&f.entries()), denied(reason), "{target}");
    }
    assert_eq!(f.runs(), 0);
}

#[test]
fn a_target_in_another_account_is_unavailable_and_logged_as_scope_account() {
    let mut f = fixture(FakeMail::with(&[("t-home", "home", "INBOX", 1)]));
    let secret = f.mint("reader");
    assert_eq!(
        refusal(f.call(&secret, &read("t-home"))),
        Refusal::TargetUnavailable
    );
    assert_eq!(last_outcome(&f.entries()), denied("scope.account"));
}

#[test]
fn inbox_matches_in_any_case_and_other_folders_match_exactly() {
    let mut f = fixture(work_mail());
    let reader = f.mint("reader");
    reply(f.call(&reader, &read("t-lower")));
    let nested = f.mint("nested");
    reply(f.call(&nested, &read_in(Some("Work"), "t-work")));
    assert_eq!(
        refusal(f.call(&nested, &read_in(Some("Work"), "t-clients"))),
        Refusal::TargetUnavailable
    );
    let lower = VerbCall {
        resource: Some("inbox"),
        ..list()
    };
    reply(f.call(&reader, &lower));
    let archive = VerbCall {
        resource: Some("archive"),
        ..list()
    };
    assert_eq!(
        refusal(f.call(&reader, &archive)),
        Refusal::Token(Denial::Resource)
    );
}

#[test]
fn call_61_in_a_minute_is_rate_limited_with_a_retry_after() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for _ in 0..RATE_LIMIT {
        reply(f.call(&secret, &list()));
    }
    f.clock.set(NOW + 15_000);
    assert_eq!(
        refusal(f.call(&secret, &list())),
        Refusal::RateLimited { retry_after_s: 45 }
    );
    f.clock.set(NOW + RATE_WINDOW_MS);
    reply(f.call(&secret, &list()));
}

#[test]
fn denied_calls_count_toward_the_rate_limit() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let out_of_scope = VerbCall {
        resource: Some("Sent"),
        ..list()
    };
    for _ in 0..RATE_LIMIT {
        refusal(f.call(&secret, &out_of_scope));
    }
    assert!(matches!(
        refusal(f.call(&secret, &list())),
        Refusal::RateLimited { .. }
    ));
}

#[test]
fn only_the_first_rate_limited_call_of_a_window_is_logged() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for _ in 0..RATE_LIMIT {
        reply(f.call(&secret, &list()));
    }
    let before = f.entries().len();
    for _ in 0..5 {
        refusal(f.call(&secret, &list()));
    }
    let entries = f.entries();
    assert_eq!(entries.len(), before + 2);
    assert_eq!(
        last_outcome(&entries),
        ("list".into(), Status::Denied, Some("rate.limited".into()))
    );
    assert_eq!(f.dispatcher.rate_limited_unlogged(), 4);
}

#[test]
fn unidentified_callers_share_one_bucket_that_spares_real_tokens() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for i in 0..RATE_LIMIT {
        let bogus = format!("ksk_{i:064x}");
        assert_eq!(
            refusal(f.call(&bogus, &list())),
            Refusal::Token(Denial::UnknownToken)
        );
    }
    assert!(matches!(
        refusal(f.call("not-a-token", &list())),
        Refusal::RateLimited { .. }
    ));
    reply(f.call(&secret, &list()));
}

/// The minted scope's Selector, read back, still allows `INBOX` exactly.
#[test]
fn a_selector_folds_case_only_for_inbox() {
    let only = Selector::only(["INBOX", "Work"]);
    assert!(only.allows_folder(Some("inbox")) && only.allows_folder(Some("Inbox")));
    assert!(only.allows_folder(Some("Work")));
    assert!(!only.allows_folder(Some("work")) && !only.allows_folder(Some("Work/Clients")));
}

#[test]
fn a_content_verb_naming_no_target_is_unavailable_and_never_runs() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let no_target = VerbCall {
        target: None,
        ..read("t4")
    };
    assert_eq!(
        refusal(f.call(&secret, &no_target)),
        Refusal::TargetUnavailable
    );
    assert_eq!(last_outcome(&f.entries()), denied("target.missing"));
    assert_eq!(f.runs(), 0);
}

/// A token covering `work` and `home` reads a `home` thread while naming
/// `work`: refused, so the backend and the Ledger never act on an Account
/// the thread isn't in.
#[test]
fn a_target_in_another_account_than_the_call_names_is_unavailable() {
    let mut f = fixture(FakeMail::with(&[("t-home", "home", "INBOX", 1)]));
    let secret = f.mint("both");
    assert_eq!(
        refusal(f.call(&secret, &read("t-home"))),
        Refusal::TargetUnavailable
    );
    assert_eq!(last_outcome(&f.entries()), denied("target.account"));
    let named = VerbCall {
        account: Some("home"),
        ..read("t-home")
    };
    reply(f.call(&secret, &named));
}

#[test]
fn a_thread_with_one_message_outside_the_scope_is_unavailable() {
    let mut f = fixture(work_mail().spanning("t4", "Sent"));
    let secret = f.mint("reader");
    assert_eq!(
        refusal(f.call(&secret, &read("t4"))),
        Refusal::TargetUnavailable
    );
    assert_eq!(last_outcome(&f.entries()), denied("scope.resource"));
    assert_eq!(f.runs(), 0);
}

#[test]
fn a_token_revoked_while_its_call_runs_gets_nothing_and_is_not_charged() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let id = f.dispatcher.stores().0.list().unwrap()[0].id.clone();
    let dir = f.dir.clone();
    *f.mail.during_run.borrow_mut() = Some(Box::new(move || {
        let mut tokens = TokenStore::open(&dir.join("tokens.db"), TokenKey::from_bytes(KEY))
            .unwrap()
            .with_clock(|| Ok(NOW));
        let mut ledger = Ledger::open(&dir.join("ledger.db"))
            .unwrap()
            .with_clock(|| Ok(NOW));
        tokens.revoke(&mut ledger, human(), &id).unwrap();
    }));

    assert_eq!(
        refusal(f.call(&secret, &read("t4"))),
        Refusal::Token(Denial::Revoked)
    );
    // The revoke's own rows land between the read's begin and outcome.
    let entries = f.entries();
    let Body::Outcome { status, detail, .. } = &entries.last().unwrap().body else {
        panic!("expected the read's outcome last, got {entries:?}")
    };
    assert_eq!(
        (*status, detail.as_deref()),
        (Status::Denied, Some("token.revoked"))
    );
    assert_eq!(f.dispatcher.stores().0.list().unwrap()[0].reads_used, 0);
}

#[test]
fn a_token_that_expired_after_admission_is_not_charged() {
    let mut f = fixture(work_mail());
    f.mint("reader");
    let id = f.dispatcher.stores().0.list().unwrap()[0].id.clone();
    let mut later = TokenStore::open(&f.dir.join("tokens.db"), TokenKey::from_bytes(KEY))
        .unwrap()
        .with_clock(|| Ok(NOW + 2 * 3_600_000));
    assert_eq!(later.charge_reads(&id, 4).unwrap(), Charge::Expired);
    assert_eq!(f.dispatcher.stores().0.list().unwrap()[0].reads_used, 0);
}

/// A backend that reports a count outside the contract releases nothing:
/// no messages for a content Verb (content for free), more than the cap,
/// or any for a metadata Verb.
#[test]
fn a_backend_that_breaks_the_message_contract_is_an_error_and_releases_nothing() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for (misreported, call) in [
        (0, read("t4")),
        (u64::from(MAX_PER_CALL) + 1, read("t4")),
        (3, list()),
    ] {
        f.mail.misreport.set(Some(misreported));
        assert!(
            matches!(f.dispatcher.call(&secret, &call), Err(Error::Backend(_))),
            "{misreported}"
        );
        assert_eq!(last_outcome(&f.entries()).1, Status::Error, "{misreported}");
    }
    f.mail.misreport.set(None);
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 10);
}

#[test]
fn a_thread_of_exactly_the_cap_is_released_and_charged_in_full() {
    let cap = u64::from(MAX_PER_CALL);
    let mut f = fixture(FakeMail::with(&[("t-big", "work", "INBOX", cap)]));
    let secret = f.mint("roomy");
    let big = reply(f.call(&secret, &read("t-big")));
    assert_eq!((big.reads_used, big.reads_remaining), (Some(cap), 0));
}

#[test]
fn a_verb_the_backend_does_not_support_yet_is_refused_and_logged() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    f.mail.unsupported.set(true);
    let refused = refusal(f.call(&secret, &read("t4")));
    assert_eq!(
        (&refused, refused.code()),
        (&Refusal::Unsupported, "verb.unsupported")
    );
    assert_eq!(last_outcome(&f.entries()), denied("verb.unsupported"));
    f.mail.unsupported.set(false);
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 10);
}

#[test]
fn a_backend_that_cannot_locate_targets_fails_the_call_as_a_backend_error() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    f.mail.locate_fails.set(true);
    assert!(f.dispatcher.call(&secret, &read("t4")).is_err());
    assert_eq!(
        last_outcome(&f.entries()),
        ("read".into(), Status::Error, Some("backend".into()))
    );
    assert_eq!(f.runs(), 0);
}

#[test]
fn a_limit_of_zero_asks_the_backend_for_one_result() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let zero = VerbCall {
        limit: Some(0),
        ..list()
    };
    reply(f.call(&secret, &zero));
    assert_eq!(f.mail.runs.borrow()[0].1, 1);
}

/// The window rolls: calls drop out one by one as they age past 60 s, not
/// all at once, so a fixed one-minute window would fail this.
#[test]
fn the_rate_window_rolls_call_by_call() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let half = RATE_LIMIT / 2;
    for at in [NOW, NOW + RATE_WINDOW_MS / 2, NOW + RATE_WINDOW_MS] {
        f.clock.set(at);
        for _ in 0..half {
            reply(f.call(&secret, &list()));
        }
    }
    assert_eq!(
        refusal(f.call(&secret, &list())),
        Refusal::RateLimited { retry_after_s: 30 }
    );
}

#[test]
fn each_token_has_its_own_rate_limit() {
    let mut f = fixture(work_mail());
    let busy = f.mint("reader");
    let quiet = f.mint("reader");
    for _ in 0..RATE_LIMIT {
        reply(f.call(&busy, &list()));
    }
    refusal(f.call(&busy, &list()));
    reply(f.call(&quiet, &list()));
}

#[test]
fn a_rate_limited_call_is_logged_again_in_the_next_window() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    for at in [NOW, NOW + RATE_WINDOW_MS] {
        f.clock.set(at);
        for _ in 0..RATE_LIMIT {
            reply(f.call(&secret, &list()));
        }
        let before = f.entries().len();
        refusal(f.call(&secret, &list()));
        assert_eq!(f.entries().len(), before + 2, "{at}");
    }
    assert_eq!(f.dispatcher.rate_limited_unlogged(), 0);
}

#[test]
fn a_tampered_token_is_rate_limited_with_the_unidentified_callers() {
    let mut f = fixture(work_mail());
    let tampered = f.mint("reader");
    let conn = rusqlite::Connection::open(f.dir.join("tokens.db")).unwrap();
    conn.execute_batch("UPDATE tokens SET reads_used = 1")
        .unwrap();
    for _ in 0..RATE_LIMIT {
        assert_eq!(
            refusal(f.call(&tampered, &list())),
            Refusal::Token(Denial::Tampered)
        );
    }
    assert!(matches!(
        refusal(f.call("not-a-token", &list())),
        Refusal::RateLimited { .. }
    ));
}

/// Known limit (ADR 0004, plan Edge Cases rollback row, `won't`): putting
/// back an older sealed copy of a token's row passes the seal, so it also
/// refunds the reads spent since. Writing tokens.db already allows this.
#[test]
fn restoring_an_older_sealed_row_refunds_the_reads_spent_since() {
    let mut f = fixture(work_mail());
    let secret = f.mint("reader");
    let conn = rusqlite::Connection::open(f.dir.join("tokens.db")).unwrap();
    let (used, seal): (i64, Vec<u8>) = conn
        .query_row("SELECT reads_used, seal FROM tokens", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(reply(f.call(&secret, &read("t4"))).reads_remaining, 6);
    conn.execute(
        "UPDATE tokens SET reads_used = ?1, seal = ?2",
        rusqlite::params![used, seal],
    )
    .unwrap();
    assert_eq!(reply(f.call(&secret, &list())).reads_remaining, 10);
}
