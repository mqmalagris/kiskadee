//! Capability tokens against real `tokens.db` and `ledger.db` files.
//!
//! Plan Phase 1, "Capability tokens + Profiles": out-of-scope, expired and
//! revoked tokens are denied with a structured denial and a Ledger entry.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Barrier;

use kiskadee_core::ledger::{Actor, Body, Call, Entry, Ledger, Status, digest};
use kiskadee_core::profiles::{Profiles, Selector};
use kiskadee_core::tokens::{
    Admission, Denial, Error, MAX_NAME_BYTES, MintRequest, Minted, Request, Revoked, TOKEN_PREFIX,
    TokenKey, TokenStore,
};
use kiskadee_core::verb::Verb;

const HOUR_MS: i64 = 3_600_000;
/// Every test runs at this wall-clock time unless it moves the clock.
const NOW: i64 = 1_800_000_000_000;
/// Test-only sealing key; the Broker derives the real one from user presence.
const KEY: [u8; 32] = [7; 32];

/// Narrow Profiles for scope tests: one Account, one folder.
const WORK_ONLY: &str = r#"
[work-inbox]
verbs = ["list", "read"]
accounts = ["work"]
resources = ["INBOX"]
read_budget = 50
max_ttl = "1h"
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    ledger: Ledger,
    tokens: TokenStore,
}

fn open_tokens(dir: &Path) -> TokenStore {
    TokenStore::open(&dir.join("tokens.db"), TokenKey::from_bytes(KEY))
        .unwrap()
        .with_clock(|| Ok(NOW))
}

fn open_ledger(dir: &Path) -> Ledger {
    Ledger::open(&dir.join("ledger.db"))
        .unwrap()
        .with_clock(|| Ok(NOW))
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    Fixture {
        ledger: open_ledger(&path),
        tokens: open_tokens(&path),
        _dir: dir,
        dir: path,
    }
}

fn human() -> Actor {
    Actor::Human("session-1".into())
}

fn request<'a>(verb: Verb, account: Option<&'a str>, resource: Option<&'a str>) -> Request<'a> {
    Request {
        verb,
        account,
        resource,
        target: Some("msg-1"),
        args_digest: digest(b"{}"),
    }
}

impl Fixture {
    fn mint(&mut self, profiles: &Profiles, request: MintRequest) -> Minted {
        self.tokens
            .mint(&mut self.ledger, human(), profiles, &request)
            .unwrap()
    }

    fn call(
        &mut self,
        secret: &str,
        verb: Verb,
        account: Option<&str>,
        resource: Option<&str>,
    ) -> Admission {
        self.tokens
            .admit(&mut self.ledger, secret, &request(verb, account, resource))
            .unwrap()
    }

    fn entries(&self) -> Vec<Entry> {
        self.ledger.since(0).unwrap()
    }

    /// Runs `sql` straight against `tokens.db`, as a same-user process could.
    fn tamper(&self, sql: &str) {
        let conn = rusqlite::Connection::open(self.dir.join("tokens.db")).unwrap();
        conn.execute_batch(sql).unwrap();
    }
}

/// The last two Ledger rows are a call's `begin` and its outcome.
fn last_call(entries: &[Entry]) -> (Call, Body) {
    let [.., begin, outcome] = entries else {
        panic!("expected a begin and an outcome, got {entries:?}")
    };
    let Body::Begin(call) = &begin.body else {
        panic!("expected a begin, got {begin:?}")
    };
    (call.clone(), outcome.body.clone())
}

/// The last two Ledger rows are this call's `begin` and its `denied` outcome.
fn assert_denial_logged(entries: &[Entry], actor: &str, verb: &str, code: &str) {
    let (call, outcome) = last_call(entries);
    assert_eq!(
        (call.actor.to_string().as_str(), call.verb.as_str()),
        (actor, verb)
    );
    assert!(
        matches!(&outcome, Body::Outcome { status: Status::Denied, detail: Some(d), .. } if d == code),
        "expected a denied outcome {code:?}, got {outcome:?}"
    );
}

fn denial(admission: Admission) -> Denial {
    match admission {
        Admission::Denied { denial, .. } => denial,
        Admission::Admitted { .. } => panic!("expected a denial"),
    }
}

fn admitted(admission: &Admission) -> bool {
    matches!(admission, Admission::Admitted { .. })
}

#[test]
fn a_minted_token_admits_a_call_in_scope_and_logs_its_begin() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    assert!(minted.secret.expose().starts_with(TOKEN_PREFIX));

    let Admission::Admitted { grant, begin_seq } = f.call(
        minted.secret.expose(),
        Verb::Read,
        Some("work"),
        Some("INBOX"),
    ) else {
        panic!("a call in scope must be admitted")
    };
    assert_eq!(grant.token_id(), minted.id);

    // The begin is written before the call runs; the caller writes the outcome.
    let entries = f.entries();
    let begin = entries.last().unwrap();
    assert_eq!(begin.seq, begin_seq);
    let Body::Begin(call) = &begin.body else {
        panic!("expected a begin")
    };
    assert_eq!(call.actor, Actor::Token(minted.id.clone()));
    assert_eq!(call.verb, "read");
    assert_eq!(call.account.as_deref(), Some("work"));
    assert_eq!(call.target.as_deref(), Some("msg-1"));
    assert_eq!(f.ledger.verify().unwrap().orphans, vec![begin_seq]);
}

#[test]
fn a_successful_mint_is_logged_with_the_new_token_id() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let (call, outcome) = last_call(&f.entries());
    assert_eq!(call.actor, human());
    assert_eq!(call.verb, "token.mint");
    assert_eq!(call.target.as_deref(), Some(minted.id.as_str()));
    assert!(
        matches!(
            outcome,
            Body::Outcome {
                status: Status::Ok,
                detail: None,
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[test]
fn a_narrowed_token_admits_a_call_inside_its_scope() {
    let mut f = fixture();
    let profiles = Profiles::parse(WORK_ONLY).unwrap();
    let minted = f.mint(&profiles, MintRequest::new("work-inbox"));
    assert!(admitted(&f.call(
        minted.secret.expose(),
        Verb::Read,
        Some("work"),
        Some("INBOX")
    )));
}

#[test]
fn a_verb_outside_the_token_is_denied_and_logged() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let denied = denial(f.call(
        minted.secret.expose(),
        Verb::SendRequest,
        Some("work"),
        None,
    ));
    assert_eq!(denied, Denial::Verb(Verb::SendRequest));
    assert_eq!(denied.code(), "scope.verb");
    assert_denial_logged(
        &f.entries(),
        &format!("token:{}", minted.id),
        "send-request",
        "scope.verb",
    );
}

#[test]
fn an_account_outside_the_token_is_denied_and_logged() {
    let mut f = fixture();
    let profiles = Profiles::parse(WORK_ONLY).unwrap();
    let minted = f.mint(&profiles, MintRequest::new("work-inbox"));
    let secret = minted.secret.expose();
    assert_eq!(
        denial(f.call(secret, Verb::List, Some("home"), Some("INBOX"))),
        Denial::Account
    );
    assert_denial_logged(
        &f.entries(),
        &format!("token:{}", minted.id),
        "list",
        "scope.account",
    );
    // Naming no Account means all of them, which this token doesn't cover.
    assert_eq!(
        denial(f.call(secret, Verb::List, None, Some("INBOX"))),
        Denial::Account
    );
}

#[test]
fn a_folder_outside_the_token_is_denied_and_logged() {
    let mut f = fixture();
    let profiles = Profiles::parse(WORK_ONLY).unwrap();
    let minted = f.mint(&profiles, MintRequest::new("work-inbox"));
    let secret = minted.secret.expose();
    assert_eq!(
        denial(f.call(secret, Verb::List, Some("work"), Some("Archive"))),
        Denial::Resource
    );
    assert_denial_logged(
        &f.entries(),
        &format!("token:{}", minted.id),
        "list",
        "scope.resource",
    );
    assert_eq!(
        denial(f.call(secret, Verb::List, Some("work"), None)),
        Denial::Resource
    );
}

/// Edge case: a token expires exactly at its TTL. Checked at `begin`; the
/// last admitted millisecond is one before expiry.
#[test]
fn an_expired_token_is_denied_and_logged_from_the_exact_expiry_time() {
    let mut f = fixture();
    let mut request = MintRequest::new("readonly");
    request.ttl_ms = Some(HOUR_MS);
    let minted = f.mint(&Profiles::built_in(), request);
    assert_eq!(minted.expires_ms, NOW + HOUR_MS);
    let secret = minted.secret.expose().to_string();

    f.tokens = f.tokens.with_clock(|| Ok(NOW + HOUR_MS - 1));
    assert!(admitted(&f.call(
        &secret,
        Verb::Read,
        Some("work"),
        Some("INBOX")
    )));
    f.tokens = f.tokens.with_clock(|| Ok(NOW + HOUR_MS));
    let denied = denial(f.call(&secret, Verb::Read, Some("work"), Some("INBOX")));
    assert_eq!((denied.code(), denied), ("token.expired", Denial::Expired));
    assert_denial_logged(
        &f.entries(),
        &format!("token:{}", minted.id),
        "read",
        "token.expired",
    );
}

/// Edge case: revoke a token, then the agent retries.
#[test]
fn a_revoked_token_is_denied_on_the_very_next_call() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let secret = minted.secret.expose().to_string();
    assert!(admitted(&f.call(&secret, Verb::Read, Some("work"), None)));
    assert_eq!(
        f.tokens.revoke(&mut f.ledger, human(), &minted.id).unwrap(),
        Revoked::Now
    );
    let denied = denial(f.call(&secret, Verb::Read, Some("work"), None));
    assert_eq!((denied.code(), denied), ("token.revoked", Denial::Revoked));
    assert_denial_logged(
        &f.entries(),
        &format!("token:{}", minted.id),
        "read",
        "token.revoked",
    );
    assert!(f.ledger.verify().unwrap().is_intact());
}

/// The real shape: the human revokes through one connection while the
/// Broker admits through another.
#[test]
fn a_revocation_through_another_connection_denies_the_next_call() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let mut other = open_tokens(&f.dir);
    let mut other_ledger = open_ledger(&f.dir);
    other
        .revoke(&mut other_ledger, human(), &minted.id)
        .unwrap();
    assert_eq!(
        denial(f.call(minted.secret.expose(), Verb::List, Some("work"), None)),
        Denial::Revoked
    );
}

#[test]
fn missing_malformed_and_unknown_tokens_are_denied_and_logged_without_the_secret() {
    let mut f = fixture();
    let never_minted = format!("{TOKEN_PREFIX}{}", "ab".repeat(32));
    for presented in ["", "not-a-token", "ksk_short", never_minted.as_str()] {
        let denied = denial(f.call(presented, Verb::List, Some("work"), None));
        assert_eq!(
            (denied.code(), denied),
            ("token.unknown", Denial::UnknownToken)
        );
        assert_denial_logged(&f.entries(), "token:unknown", "list", "token.unknown");
    }
    drop(f.ledger);
    assert!(!file_contains(&f.dir, "ledger.db", never_minted.as_bytes()));
}

/// An unauthenticated caller can't write text into the append-only Ledger.
#[test]
fn an_unknown_token_has_its_account_and_target_left_out_of_the_ledger() {
    let mut f = fixture();
    let call = Request {
        target: Some("chosen-by-the-caller"),
        ..request(Verb::Read, Some("attacker-text"), None)
    };
    f.tokens.admit(&mut f.ledger, "garbage", &call).unwrap();
    let (logged, _) = last_call(&f.entries());
    assert_eq!(logged.actor, Actor::UnknownToken);
    assert_eq!(
        (logged.account.as_deref(), logged.target.as_deref()),
        (None, None)
    );
}

#[test]
fn a_name_longer_than_the_limit_is_denied_and_not_recorded() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let long = "x".repeat(MAX_NAME_BYTES + 1);
    let at_limit = "x".repeat(MAX_NAME_BYTES);
    assert!(admitted(&f.call(
        minted.secret.expose(),
        Verb::List,
        Some(&at_limit),
        None
    )));
    let denied = denial(f.call(minted.secret.expose(), Verb::List, Some(&long), None));
    assert_eq!(
        (denied.code(), denied),
        ("request.invalid", Denial::BadRequest)
    );
    let (logged, _) = last_call(&f.entries());
    assert_eq!(logged.actor, Actor::Token(minted.id.clone()));
    assert_eq!(logged.account, None);
}

#[test]
fn a_token_presented_with_surrounding_whitespace_is_accepted() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let from_env = format!(" {}\r\n", minted.secret.expose());
    assert!(admitted(&f.call(&from_env, Verb::List, Some("work"), None)));
}

#[test]
fn an_uppercased_or_unprefixed_token_is_unknown() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let hex_part = &minted.secret.expose()[TOKEN_PREFIX.len()..];
    let upper = format!("{TOKEN_PREFIX}{}", hex_part.to_uppercase());
    for presented in [upper.as_str(), hex_part] {
        assert_eq!(
            denial(f.call(presented, Verb::List, Some("work"), None)),
            Denial::UnknownToken
        );
    }
}

/// Denials are reported in a fixed order: revoked, expired, then scope
/// (Verb, Account, folder).
#[test]
fn when_several_rules_fail_the_first_in_order_is_reported() {
    let mut f = fixture();
    let profiles = Profiles::parse(WORK_ONLY).unwrap();
    let wrong_everything = |f: &mut Fixture, secret: &str| {
        denial(f.call(secret, Verb::Draft, Some("home"), Some("Archive")))
    };
    let live = f.mint(&profiles, MintRequest::new("work-inbox"));
    assert_eq!(
        wrong_everything(&mut f, live.secret.expose()),
        Denial::Verb(Verb::Draft)
    );
    assert_eq!(
        denial(f.call(
            live.secret.expose(),
            Verb::List,
            Some("home"),
            Some("Archive")
        )),
        Denial::Account
    );
    f.tokens = f.tokens.with_clock(|| Ok(NOW + HOUR_MS));
    assert_eq!(
        wrong_everything(&mut f, live.secret.expose()),
        Denial::Expired
    );
    f.tokens.revoke(&mut f.ledger, human(), &live.id).unwrap();
    assert_eq!(
        wrong_everything(&mut f, live.secret.expose()),
        Denial::Revoked
    );
}

/// Edge case: mint the same token twice. Minting always creates a new one.
#[test]
fn minting_twice_creates_two_independent_tokens() {
    let mut f = fixture();
    let first = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let second = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    assert_ne!(first.id, second.id);
    assert_ne!(first.secret.expose(), second.secret.expose());
    f.tokens.revoke(&mut f.ledger, human(), &first.id).unwrap();
    assert!(admitted(&f.call(
        second.secret.expose(),
        Verb::List,
        Some("work"),
        None
    )));
}

/// Edge case: revoke twice. The second is a no-op success, and logged.
#[test]
fn revoking_twice_is_a_logged_no_op() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    assert_eq!(
        f.tokens.revoke(&mut f.ledger, human(), &minted.id).unwrap(),
        Revoked::Now
    );
    let (_, first) = last_call(&f.entries());
    assert!(matches!(
        first,
        Body::Outcome {
            status: Status::Ok,
            detail: None,
            ..
        }
    ));
    f.tokens = f.tokens.with_clock(|| Ok(NOW + 5));
    assert_eq!(
        f.tokens.revoke(&mut f.ledger, human(), &minted.id).unwrap(),
        Revoked::Already
    );
    let (call, second) = last_call(&f.entries());
    assert_eq!(call.verb, "token.revoke");
    assert!(
        matches!(&second, Body::Outcome { status: Status::Ok, detail: Some(d), .. } if d == "token.already-revoked"),
        "{second:?}"
    );
    let listed = f.tokens.list().unwrap();
    assert_eq!(
        listed[0].revoked_ms,
        Some(NOW),
        "the first revocation time is kept"
    );
    let report = f.ledger.verify().unwrap();
    assert!(report.is_intact() && report.orphans.is_empty());
}

#[test]
fn two_racing_revokes_record_exactly_one_revocation() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let barrier = Barrier::new(2);
    let results: Vec<Revoked> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (dir, id, barrier) = (&f.dir, &minted.id, &barrier);
                scope.spawn(move || {
                    let mut tokens = open_tokens(dir);
                    let mut ledger = open_ledger(dir);
                    barrier.wait();
                    tokens.revoke(&mut ledger, human(), id).unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut sorted = results.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>();
    sorted.sort();
    assert_eq!(sorted, ["Already", "Now"]);
    assert!(f.ledger.verify().unwrap().is_intact());
}

/// Several processes may open a brand-new tokens.db at once.
#[test]
fn concurrent_first_opens_of_tokens_db_share_one_store() {
    const OPENERS: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let barrier = Barrier::new(OPENERS);
    std::thread::scope(|scope| {
        for _ in 0..OPENERS {
            let (dir, barrier) = (dir.path(), &barrier);
            scope.spawn(move || {
                barrier.wait();
                let mut tokens = open_tokens(dir);
                let mut ledger = open_ledger(dir);
                tokens
                    .mint(
                        &mut ledger,
                        human(),
                        &Profiles::built_in(),
                        &MintRequest::new("readonly"),
                    )
                    .unwrap();
            });
        }
    });
    assert_eq!(open_tokens(dir.path()).list().unwrap().len(), OPENERS);
}

#[test]
fn revoking_an_unknown_id_is_an_error_and_is_logged() {
    let mut f = fixture();
    let result = f.tokens.revoke(&mut f.ledger, human(), "000000000000");
    assert!(matches!(result, Err(Error::UnknownToken(_))), "{result:?}");
    assert_denial_logged(
        &f.entries(),
        "human:session-1",
        "token.revoke",
        "token.unknown",
    );
}

#[test]
fn mint_can_narrow_the_profile_in_every_dimension() {
    let mut f = fixture();
    let mut request = MintRequest::new("triage");
    request.accounts = Some(Selector::only(["work"]));
    request.resources = Some(Selector::only(["INBOX"]));
    request.verbs = Some(BTreeSet::from([Verb::List]));
    request.read_budget = Some(10);
    request.ttl_ms = Some(HOUR_MS);
    let minted = f.mint(&Profiles::built_in(), request);
    let listed = f.tokens.list().unwrap();
    let scope = listed[0].scope.as_ref().unwrap();
    assert_eq!(scope.accounts, Selector::only(["work"]));
    assert_eq!(scope.resources, Selector::only(["INBOX"]));
    assert_eq!(scope.verbs, BTreeSet::from([Verb::List]));
    assert_eq!(scope.read_budget, 10);
    assert_eq!(listed[0].expires_ms, NOW + HOUR_MS);
    assert_eq!(
        denial(f.call(
            minted.secret.expose(),
            Verb::Read,
            Some("work"),
            Some("INBOX")
        )),
        Denial::Verb(Verb::Read)
    );
}

/// Changes one field of a mint so it reaches past the Profile.
type Change = fn(&mut MintRequest);

#[test]
fn mint_never_widens_the_profile() {
    let profiles = Profiles::parse(WORK_ONLY).unwrap();
    let widen: [(&str, Change); 5] = [
        ("accounts", |r| r.accounts = Some(Selector::All)),
        ("resources", |r| {
            r.resources = Some(Selector::only(["INBOX", "Archive"]))
        }),
        ("verbs", |r| {
            r.verbs = Some(BTreeSet::from([Verb::List, Verb::Draft]))
        }),
        ("read_budget", |r| r.read_budget = Some(51)),
        ("ttl", |r| r.ttl_ms = Some(HOUR_MS + 1)),
    ];
    for (field, change) in widen {
        let mut f = fixture();
        let mut request = MintRequest::new("work-inbox");
        change(&mut request);
        let result = f.tokens.mint(&mut f.ledger, human(), &profiles, &request);
        match result {
            Err(Error::ExceedsProfile { field: got, .. }) => assert_eq!(got, field),
            other => panic!("{field}: expected ExceedsProfile, got {other:?}"),
        }
        assert!(
            f.tokens.list().unwrap().is_empty(),
            "{field}: nothing is stored"
        );
        assert_denial_logged(
            &f.entries(),
            "human:session-1",
            "token.mint",
            "profile.exceeded",
        );
    }
}

/// A mint that names nothing would store a scope that can never be used.
#[test]
fn mint_refuses_a_scope_that_names_nothing() {
    let empty: [(&str, Change); 3] = [
        ("accounts", |r| {
            r.accounts = Some(Selector::only(Vec::<&str>::new()))
        }),
        ("resources", |r| r.resources = Some(Selector::only([""]))),
        ("verbs", |r| r.verbs = Some(BTreeSet::new())),
    ];
    for (field, change) in empty {
        let mut f = fixture();
        let mut request = MintRequest::new("readonly");
        change(&mut request);
        let result = f
            .tokens
            .mint(&mut f.ledger, human(), &Profiles::built_in(), &request);
        assert!(
            matches!(result, Err(Error::EmptyScope { field: got }) if got == field),
            "{field}: {result:?}"
        );
        assert!(
            f.tokens.list().unwrap().is_empty(),
            "{field}: nothing is stored"
        );
        assert_denial_logged(&f.entries(), "human:session-1", "token.mint", "scope.empty");
    }
}

#[test]
fn a_bad_ttl_and_an_unknown_profile_cannot_be_minted() {
    let mut f = fixture();
    for ttl in [0, -1] {
        let mut bad = MintRequest::new("readonly");
        bad.ttl_ms = Some(ttl);
        assert!(matches!(
            f.tokens
                .mint(&mut f.ledger, human(), &Profiles::built_in(), &bad),
            Err(Error::BadTtl)
        ));
    }
    assert!(matches!(
        f.tokens.mint(
            &mut f.ledger,
            human(),
            &Profiles::built_in(),
            &MintRequest::new("admin")
        ),
        Err(Error::UnknownProfile(name)) if name == "admin"
    ));
    assert_denial_logged(
        &f.entries(),
        "human:session-1",
        "token.mint",
        "profile.unknown",
    );
    assert!(f.tokens.list().unwrap().is_empty());
}

/// A same-user process writes a row for a token it made up (ADR 0004: agents
/// run as the user). The seal it can't compute gives it away.
#[test]
fn a_forged_row_is_refused_as_tampered() {
    let mut f = fixture();
    let forged = format!("{TOKEN_PREFIX}{}", "cd".repeat(32));
    let hash = sha256_hex(forged.as_bytes());
    f.tamper(&format!(
        "INSERT INTO tokens VALUES ('feedfacecafe', x'{hash}', 'readonly',
            '{{\"accounts\":\"*\",\"resources\":\"*\",\"verbs\":[\"send-request\"],\"read_budget\":1}}',
            0, 9000000000000, NULL, zeroblob(32))"
    ));
    let denied = denial(f.call(&forged, Verb::SendRequest, Some("work"), None));
    assert_eq!(
        (denied.code(), denied),
        ("token.tampered", Denial::Tampered)
    );
    // The forged id is attacker-chosen text, so it isn't recorded either.
    assert_denial_logged(
        &f.entries(),
        "token:unknown",
        "send-request",
        "token.tampered",
    );
    let listed = f.tokens.list().unwrap();
    assert_eq!(
        (listed[0].id.as_str(), &listed[0].scope),
        ("feedfacecafe", &None)
    );
}

#[test]
fn editing_a_real_row_outside_kiskadee_is_refused_as_tampered() {
    for edit in [
        // Widen the scope.
        r#"UPDATE tokens SET scope = replace(scope, '"list"', '"send-request"')"#,
        // Push the expiry out.
        "UPDATE tokens SET expires_ms = expires_ms + 86400000",
        // Clear a revocation.
        "UPDATE tokens SET revoked_ms = NULL",
    ] {
        let mut f = fixture();
        let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
        if edit.contains("revoked_ms") {
            f.tokens.revoke(&mut f.ledger, human(), &minted.id).unwrap();
        }
        f.tamper(edit);
        assert_eq!(
            denial(f.call(minted.secret.expose(), Verb::List, Some("work"), None)),
            Denial::Tampered,
            "{edit}"
        );
        let revoked = f.tokens.revoke(&mut f.ledger, human(), &minted.id);
        assert!(
            matches!(revoked, Err(Error::Tampered(_))),
            "{edit}: {revoked:?}"
        );
    }
}

#[test]
fn a_store_opened_with_another_key_trusts_none_of_its_rows() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    f.tokens = TokenStore::open(&f.dir.join("tokens.db"), TokenKey::from_bytes([8; 32]))
        .unwrap()
        .with_clock(|| Ok(NOW));
    assert_eq!(
        denial(f.call(minted.secret.expose(), Verb::List, Some("work"), None)),
        Denial::Tampered
    );
}

/// Known limit (ADR 0004): sealed rows can't be edited, but restoring an
/// older copy of the whole file brings back a revoked token. Only isolated
/// mode prevents it.
#[test]
fn restoring_an_old_copy_of_tokens_db_brings_back_a_revoked_token() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    drop(f.tokens);
    let backup = f.dir.join("tokens.backup");
    std::fs::copy(f.dir.join("tokens.db"), &backup).unwrap();

    let mut tokens = open_tokens(&f.dir);
    tokens.revoke(&mut f.ledger, human(), &minted.id).unwrap();
    drop(tokens);
    std::fs::copy(&backup, f.dir.join("tokens.db")).unwrap();

    f.tokens = open_tokens(&f.dir);
    assert!(admitted(&f.call(
        minted.secret.expose(),
        Verb::List,
        Some("work"),
        None
    )));
}

/// If the Ledger can't record a mint's outcome, the caller never gets the
/// secret, so the token mustn't stay live.
#[test]
fn a_mint_whose_outcome_cannot_be_logged_leaves_no_live_token() {
    let mut f = fixture();
    let conn = rusqlite::Connection::open(f.dir.join("ledger.db")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER block_outcomes BEFORE INSERT ON entries WHEN NEW.kind = 'outcome'
            BEGIN SELECT RAISE(ABORT, 'outcome blocked'); END;",
    )
    .unwrap();
    drop(conn);
    let result = f.tokens.mint(
        &mut f.ledger,
        human(),
        &Profiles::built_in(),
        &MintRequest::new("readonly"),
    );
    assert!(matches!(result, Err(Error::Ledger(_))), "{result:?}");
    let listed = f.tokens.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(
        listed[0].revoked_ms.is_some(),
        "the unreachable token is revoked"
    );
}

/// When the check itself fails, the attempt is still in the Ledger.
#[test]
fn an_error_while_checking_is_logged_before_it_is_returned() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    f.tokens = f.tokens.with_clock(|| Err(Error::Clock));
    let result = f.tokens.admit(
        &mut f.ledger,
        minted.secret.expose(),
        &request(Verb::List, Some("work"), None),
    );
    assert!(matches!(result, Err(Error::Clock)), "{result:?}");
    let (call, outcome) = last_call(&f.entries());
    assert_eq!(
        (call.actor.clone(), call.verb.as_str()),
        (Actor::UnknownToken, "list")
    );
    assert!(
        matches!(&outcome, Body::Outcome { status: Status::Error, detail: Some(d), .. } if d == "internal"),
        "{outcome:?}"
    );
}

#[test]
fn the_secret_is_never_written_to_disk() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let secret = minted.secret.expose().to_string();
    f.call(&secret, Verb::List, Some("work"), None);
    drop(f.tokens);
    drop(f.ledger);
    for file in ["tokens.db", "ledger.db"] {
        assert!(
            !file_contains(&f.dir, file, secret.as_bytes()),
            "{file} holds the secret"
        );
        let hex_part = &secret[TOKEN_PREFIX.len()..];
        assert!(
            !file_contains(&f.dir, file, hex_part.as_bytes()),
            "{file} holds the secret"
        );
    }
}

#[test]
fn tokens_and_revocations_survive_a_reopen() {
    let mut f = fixture();
    let kept = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let revoked = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    f.tokens
        .revoke(&mut f.ledger, human(), &revoked.id)
        .unwrap();
    f.tokens = open_tokens(&f.dir);
    assert!(admitted(&f.call(
        kept.secret.expose(),
        Verb::List,
        Some("work"),
        None
    )));
    assert_eq!(
        denial(f.call(revoked.secret.expose(), Verb::List, Some("work"), None)),
        Denial::Revoked
    );
}

#[test]
fn ledger_and_token_files_cannot_be_opened_as_each_other() {
    let f = fixture();
    let as_tokens = TokenStore::open(&f.dir.join("ledger.db"), TokenKey::from_bytes(KEY));
    assert!(
        matches!(as_tokens, Err(Error::WrongFile(_))),
        "{:?}",
        as_tokens.err()
    );
    let as_ledger = Ledger::open(&f.dir.join("tokens.db"));
    assert!(
        matches!(as_ledger, Err(kiskadee_core::ledger::Error::NotALedger(_))),
        "{:?}",
        as_ledger.err()
    );
}

#[test]
fn a_tokens_db_from_a_newer_kiskadee_is_refused() {
    let f = fixture();
    drop(f.tokens);
    let conn = rusqlite::Connection::open(f.dir.join("tokens.db")).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    assert!(matches!(
        TokenStore::open(&f.dir.join("tokens.db"), TokenKey::from_bytes(KEY)),
        Err(Error::NewerSchema(2))
    ));
}

#[test]
fn list_reports_tokens_by_id_without_secrets() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("drafter"));
    let listed = f.tokens.list().unwrap();
    assert_eq!(listed.len(), 1);
    let info = &listed[0];
    assert_eq!(
        (info.id.as_str(), info.profile.as_str()),
        (minted.id.as_str(), "drafter")
    );
    assert_eq!((info.created_ms, info.revoked_ms), (NOW, None));
    assert!(!format!("{info:?}").contains(minted.secret.expose()));
}

#[test]
fn secrets_and_keys_are_redacted_in_debug_output() {
    let mut f = fixture();
    let minted = f.mint(&Profiles::built_in(), MintRequest::new("readonly"));
    let shown = format!("{minted:?}");
    assert!(!shown.contains(minted.secret.expose()), "{shown}");
    assert!(shown.contains(&minted.id));
    assert!(!format!("{:?}", TokenKey::from_bytes(KEY)).contains("7"));
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn file_contains(dir: &Path, name: &str, needle: &[u8]) -> bool {
    [name.to_string(), format!("{name}-wal")]
        .iter()
        .any(|file| {
            std::fs::read(dir.join(file))
                .map(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
                .unwrap_or(false)
        })
}
