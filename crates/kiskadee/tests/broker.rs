//! The Broker over its real transport: auto-start, one Broker per
//! endpoint, idle exit, and Verb calls reaching the dispatcher.
//!
//! Plan Phase 1, "IPC transport + auto-start": two Clients starting at once
//! produce one Broker, and the Broker exits after the idle timeout. Design:
//! `docs/intent/0004-ipc-transport.md`.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kiskadee::broker::client::{self, Client};
use kiskadee::broker::protocol::{Call, Outcome, Pong, Request};
use kiskadee::broker::{self, Broker, Config, Exit};
use kiskadee_core::ledger::{Body, Entry, Ledger, Status};
use kiskadee_core::profiles::Profiles;
use kiskadee_core::tokens::{MintRequest, TokenKey, TokenStore};
use kiskadee_platform::ipc::Endpoint;
use kiskadee_platform::ipc::peer::Identity;
use kiskadee_platform::lock::FileLock;

const KEY: [u8; 32] = [7; 32];

/// A data directory for one test, and every Broker it started, killed on
/// drop so a failed test leaves nothing running.
struct Home {
    dir: tempfile::TempDir,
    started: Mutex<Vec<u32>>,
}

impl Home {
    fn new() -> Home {
        Home {
            dir: tempfile::tempdir().unwrap(),
            started: Mutex::new(Vec::new()),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::for_home(self.path())
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kiskadee"));
        command
            .args(args)
            .env("KISKADEE_HOME", self.path())
            .env_remove("KISKADEE_TOKEN");
        command
    }

    /// Runs `kiskadee ping`, which starts a Broker if none answers. Reads
    /// only its one line of output and waits for the process, never for
    /// end of file, which an inherited handle could hold open.
    fn ping(&self) -> Pong {
        let mut child = self
            .command(&["ping"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let status = wait(&mut child, Duration::from_secs(10)).expect("ping must finish");
        assert!(status.success(), "ping failed: {line}");
        let pong: Pong = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        self.started.lock().unwrap().push(pong.pid);
        pong
    }

    /// `kiskadee broker --idle-timeout <secs>` in the foreground.
    fn broker(&self, idle_secs: u64) -> Child {
        let child = self
            .command(&["broker", "--idle-timeout", &idle_secs.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.started.lock().unwrap().push(child.id());
        child
    }

    fn broker_lock_is_free(&self) -> bool {
        FileLock::try_exclusive(&self.endpoint().broker_lock())
            .unwrap()
            .is_some()
    }

    fn entries(&self) -> Vec<Entry> {
        Ledger::open_read_only(&self.path().join("ledger.db"))
            .unwrap()
            .since(0)
            .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        for pid in self.started.lock().unwrap().drain(..) {
            kill(pid);
        }
    }
}

fn kill(pid: u32) {
    let pid = pid.to_string();
    let mut command = if cfg!(windows) {
        let mut command = Command::new("taskkill");
        command.args(["/F", "/PID", &pid]);
        command
    } else {
        let mut command = Command::new("kill");
        command.args(["-9", &pid]);
        command
    };
    let _ = command.stdout(Stdio::null()).stderr(Stdio::null()).status();
}

fn wait(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Connects to a Broker that's starting up.
fn connect(endpoint: &Endpoint) -> Client {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match Client::connect(endpoint) {
            Ok(client) => return client,
            Err(e) if Instant::now() > deadline => panic!("no Broker answered: {e}"),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn socket_exists(endpoint: &Endpoint) -> bool {
    cfg!(unix) && Path::new(endpoint.address()).exists()
}

/// Runs a Broker in this process, so it can hold a test key or expect a
/// stranger. It's listening when this returns.
fn in_process(
    home: &Home,
    key: Option<TokenKey>,
    expected_peer: Identity,
) -> thread::JoinHandle<Exit> {
    let config = Config {
        endpoint: home.endpoint(),
        ledger: home.path().join("ledger.db"),
        tokens: home.path().join("tokens.db"),
        key,
        idle_timeout: Duration::from_millis(500),
        expected_peer,
    };
    let bound = Broker::bind(config).unwrap().expect("no other Broker");
    thread::spawn(move || Exit::Idle(bound.run()))
}

fn mint_readonly(home: &Home) -> String {
    let mut tokens =
        TokenStore::open(&home.path().join("tokens.db"), TokenKey::from_bytes(KEY)).unwrap();
    let mut ledger = Ledger::open(&home.path().join("ledger.db")).unwrap();
    tokens
        .mint(
            &mut ledger,
            kiskadee_core::ledger::Actor::Human("test".into()),
            &Profiles::built_in(),
            &MintRequest::new("readonly"),
        )
        .unwrap()
        .secret
        .expose()
        .to_string()
}

fn begin_and_outcome(entries: &[Entry], verb: &str) -> (Option<u32>, Status, Option<String>) {
    let begin = entries
        .iter()
        .find(|entry| matches!(&entry.body, Body::Begin(call) if call.verb == verb))
        .unwrap_or_else(|| panic!("no {verb} begin in {entries:?}"));
    let Body::Begin(call) = &begin.body else {
        unreachable!()
    };
    let outcome = entries
        .iter()
        .find_map(|entry| match &entry.body {
            Body::Outcome {
                begin_seq,
                status,
                detail,
            } if *begin_seq == begin.seq => Some((*status, detail.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no outcome for #{}", begin.seq));
    (call.peer_pid, outcome.0, outcome.1)
}

/// AC-2a: no Broker running, four Clients ping at the same instant. All
/// four get an answer from the same Broker, which holds `broker.lock`;
/// only one was ever spawned, since a second spawn would have rotated its
/// log to `broker.log.1`.
#[test]
fn ac_2a_four_clients_starting_at_once_produce_one_broker() {
    let home = Arc::new(Home::new());
    let barrier = Arc::new(Barrier::new(4));
    let pids: Vec<u32> = (0..4)
        .map(|_| {
            let (home, barrier) = (Arc::clone(&home), Arc::clone(&barrier));
            thread::spawn(move || {
                barrier.wait();
                home.ping().pid
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();

    assert!(pids.iter().all(|&pid| pid == pids[0]), "{pids:?}");
    assert!(!home.broker_lock_is_free());
    assert!(home.path().join("broker.log").exists());
    assert!(
        !home.path().join("broker.log.1").exists(),
        "a second Broker was spawned"
    );
}

/// AC-2b: a crashed Broker left its lock file, and on Unix its socket,
/// behind. Neither blocks a new Broker, and neither is taken for a live
/// one: the next ping starts a Broker that answers.
#[test]
fn ac_2b_a_crashed_brokers_leftovers_neither_block_nor_fool_a_new_one() {
    let home = Home::new();
    let endpoint = home.endpoint();
    endpoint.prepare().unwrap();
    std::fs::write(endpoint.broker_lock(), b"").unwrap();
    #[cfg(unix)]
    drop(std::os::unix::net::UnixListener::bind(endpoint.address()).unwrap());
    assert_eq!(socket_exists(&endpoint), cfg!(unix));

    let pong = home.ping();

    assert_ne!(pong.pid, std::process::id());
    assert!(!home.broker_lock_is_free());
    assert_eq!(connect(&endpoint).ping().unwrap(), pong);
}

/// AC-3a: a Broker with a 1 s idle timeout exits about a second after its
/// last Client disconnects, removing its socket and freeing its lock; the
/// next ping starts a new Broker.
#[test]
fn ac_3a_the_broker_exits_after_the_idle_timeout_and_the_next_ping_restarts_it() {
    let home = Home::new();
    let mut broker = home.broker(1);
    let first = connect(&home.endpoint()).ping().unwrap();
    assert_eq!(first.pid, broker.id());

    let status = wait(&mut broker, Duration::from_secs(5)).expect("the Broker must exit");

    assert!(status.success(), "{status}");
    assert!(!socket_exists(&home.endpoint()));
    assert!(home.broker_lock_is_free());
    assert_ne!(home.ping().pid, first.pid);
}

/// AC-3b: an open connection counts as activity even when it's silent, so
/// the Broker outlives three timeouts while a Client holds one, and exits
/// once that Client lets go.
#[test]
fn ac_3b_a_silent_open_connection_keeps_the_broker_alive() {
    let home = Home::new();
    let mut broker = home.broker(1);
    let mut client = connect(&home.endpoint());
    client.ping().unwrap();

    thread::sleep(Duration::from_secs(3));
    assert!(
        broker.try_wait().unwrap().is_none(),
        "exited with a connection open"
    );

    drop(client);
    let status = wait(&mut broker, Duration::from_secs(5)).expect("the Broker must exit");
    assert!(status.success(), "{status}");
}

/// AC-4: with a key, a Verb call over the pipe reaches the dispatcher: a
/// `list` with a `readonly` token answers `ok` with the reads remaining,
/// and the Ledger has its `begin` and `ok` with the caller's pid.
#[test]
fn ac_4_a_verb_call_over_the_transport_is_dispatched_and_logged_with_the_peer_pid() {
    let home = Home::new();
    let token = mint_readonly(&home);
    let broker = in_process(
        &home,
        Some(TokenKey::from_bytes(KEY)),
        Identity::current().unwrap(),
    );

    let mut client = connect(&home.endpoint());
    let response = client
        .request(&Request::Call(Call {
            token,
            verb: "list".into(),
            ..Call::default()
        }))
        .unwrap();
    let Outcome::Ok(reply) = response.outcome else {
        panic!("expected ok, got {response:?}")
    };
    assert_eq!(reply["reads_remaining"], 500);
    drop(client);
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));

    let (pid, status, _) = begin_and_outcome(&home.entries(), "list");
    assert_eq!((pid, status), (Some(std::process::id()), Status::Ok));
}

/// AC-5: the real binary starts locked. Its ping says so, and a `read`
/// with any token is refused `broker.locked` and logged as an unidentified
/// caller with the caller's pid.
#[test]
fn ac_5_a_locked_broker_reports_it_and_refuses_verb_calls_logged() {
    let home = Home::new();
    assert!(home.ping().locked);

    let mut client = connect(&home.endpoint());
    let response = client
        .request(&Request::Call(Call {
            token: "anything".into(),
            verb: "read".into(),
            target: Some("t1".into()),
            ..Call::default()
        }))
        .unwrap();
    let Outcome::Denied(problem) = response.outcome else {
        panic!("expected a refusal, got {response:?}")
    };
    assert_eq!(problem.code, "broker.locked");
    assert_eq!(
        problem.message,
        "kiskadee is locked; ask the user to unlock it"
    );

    let entries = home.entries();
    let (pid, status, detail) = begin_and_outcome(&entries, "read");
    assert_eq!(
        (pid, status, detail.as_deref()),
        (
            Some(std::process::id()),
            Status::Denied,
            Some("broker.locked")
        )
    );
    let Body::Begin(call) = &entries[0].body else {
        panic!("expected a begin")
    };
    assert_eq!(call.actor, kiskadee_core::ledger::Actor::UnknownToken);
}

/// AC-6: a peer that isn't the expected user is closed with no reply and
/// no Ledger row, and only counted.
#[test]
fn ac_6_a_peer_of_another_user_is_closed_unanswered_and_only_counted() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::nobody());

    let error = connect(&home.endpoint()).ping().unwrap_err();

    assert!(
        matches!(error, client::Error::NoReply | client::Error::Frame(_)),
        "{error}"
    );
    let Exit::Idle(report) = broker.join().unwrap() else {
        panic!("expected an idle exit")
    };
    assert_eq!(report.refused_peers, 1);
    assert!(home.entries().is_empty());
}

/// An agent's shell reads a command's output to end of file. The Broker a
/// `ping` starts must not hold the Client's stdout open, or that read waits
/// for the Broker's idle exit.
#[test]
fn the_output_of_a_ping_that_starts_a_broker_ends_with_the_ping() {
    let home = Home::new();
    let mut child = home
        .command(&["ping"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut text).map(|_| text)
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !reader.is_finished() {
        assert!(
            Instant::now() < deadline,
            "stdout still open: the Broker inherited it"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let text = reader.join().unwrap().unwrap();
    let pong: Pong = serde_json::from_str(text.trim()).unwrap();
    home.started.lock().unwrap().push(pong.pid);
    assert!(wait(&mut child, Duration::from_secs(5)).unwrap().success());
}

#[test]
fn a_second_broker_on_the_same_endpoint_exits_quietly() {
    let home = Home::new();
    let first = home.ping();
    let mut second = home.broker(1);
    let status = wait(&mut second, Duration::from_secs(5)).expect("the second Broker must exit");
    assert!(status.success(), "{status}");
    assert_eq!(connect(&home.endpoint()).ping().unwrap().pid, first.pid);
}

fn raw_frame(endpoint: &Endpoint, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    use kiskadee_platform::ipc::frame::Conn;
    use std::io::Write;
    let stream = endpoint.connect().map_err(|e| e.to_string())?;
    (&stream).write_all(bytes).map_err(|e| e.to_string())?;
    let mut conn = Conn::new(stream).map_err(|e| e.to_string())?;
    conn.read_frame(None).map_err(|e| e.to_string())
}

#[test]
fn an_oversize_or_non_json_frame_closes_the_connection_unanswered() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());
    let endpoint = home.endpoint();

    let oversize = (2u32 << 20).to_be_bytes();
    assert!(!matches!(raw_frame(&endpoint, &oversize), Ok(Some(_))));
    let mut garbage = 3u32.to_be_bytes().to_vec();
    garbage.extend_from_slice(b"\xff\xfe\xfd");
    assert!(!matches!(raw_frame(&endpoint, &garbage), Ok(Some(_))));

    // The Broker is still serving.
    assert!(connect(&endpoint).ping().unwrap().locked);
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));
}

#[test]
fn a_frame_that_stalls_partway_is_dropped_after_the_frame_timeout() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());
    let endpoint = home.endpoint();
    let started = Instant::now();

    // A header promising 10 bytes, then nothing.
    let result = raw_frame(&endpoint, &10u32.to_be_bytes());

    assert!(!matches!(result, Ok(Some(_))), "{result:?}");
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(5), "{waited:?}");
    assert!(waited < Duration::from_secs(9), "{waited:?}");
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));
}

#[test]
fn an_unknown_op_is_refused_and_the_connection_stays_usable() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());
    let mut client = connect(&home.endpoint());
    let raw = br#"{"v":1,"op":"exec","cmd":"UID FETCH 1:* BODY[]"}"#;
    let response = {
        use kiskadee_platform::ipc::frame::Conn;
        let stream = home.endpoint().connect().unwrap();
        let mut conn = Conn::new(stream).unwrap();
        conn.write_frame(raw).unwrap();
        conn.read_frame(None).unwrap().expect("a reply")
    };
    let response: kiskadee::broker::protocol::Response = serde_json::from_slice(&response).unwrap();
    let Outcome::Denied(problem) = response.outcome else {
        panic!("expected a refusal")
    };
    assert_eq!(problem.code, "request.invalid");
    assert!(client.ping().unwrap().locked);
    drop(client);
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));
}

/// The Client checks the server before sending: on Windows another user
/// could create the Broker's pipe name first. CI has one OS user, so the
/// stranger is the expected identity, as in AC-6.
#[test]
fn a_client_sends_nothing_to_an_endpoint_served_by_another_user() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());

    let refused = Client::connect_expecting(&home.endpoint(), &Identity::nobody());

    assert!(
        matches!(refused, Err(client::Error::Stranger(_))),
        "{:?}",
        refused.err()
    );
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));
    assert!(home.entries().is_empty(), "the Broker got a request");
}

#[test]
fn a_broker_that_never_comes_up_is_reported_with_its_log_after_the_start_timeout() {
    let home = Home::new();
    let log = home.path().join("broker.log");
    let started = Instant::now();

    let result = Client::connect_or_start(&home.endpoint(), &log, &|| Ok(()));

    let Err(error @ client::Error::DidNotStart { .. }) = result else {
        panic!("expected DidNotStart, got {:?}", result.err())
    };
    assert!(
        error.to_string().contains(&log.display().to_string()),
        "{error}"
    );
    assert!(started.elapsed() >= client::START_TIMEOUT);
}

#[test]
fn the_connection_past_the_limit_is_closed_unanswered_and_counted() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());
    let endpoint = home.endpoint();
    let mut open: Vec<Client> = (0..broker::MAX_CONNECTIONS)
        .map(|_| connect(&endpoint))
        .collect();
    // Every slot is taken once each answers.
    for client in &mut open {
        client.ping().unwrap();
    }

    let extra = Client::connect(&endpoint).and_then(|mut client| client.ping());

    assert!(extra.is_err(), "the connection past the limit was served");
    drop(open);
    let Exit::Idle(report) = broker.join().unwrap() else {
        panic!("expected an idle exit")
    };
    assert_eq!(report.over_limit, 1);
}

/// A crashed Broker's output survives the next auto-start as broker.log.1.
#[test]
fn a_second_auto_start_keeps_the_previous_brokers_log() {
    let home = Home::new();
    let first = home.ping();
    kill(first.pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !home.broker_lock_is_free() {
        assert!(Instant::now() < deadline, "the killed Broker kept its lock");
        thread::sleep(Duration::from_millis(20));
    }

    let second = home.ping();

    assert_ne!(second.pid, first.pid);
    let previous = std::fs::read_to_string(home.path().join("broker.log.1")).unwrap();
    assert!(
        previous.contains(&format!("pid {}", first.pid)),
        "{previous}"
    );
}

#[test]
fn a_call_naming_no_kiskadee_verb_is_refused_and_not_logged() {
    let home = Home::new();
    let broker = in_process(&home, None, Identity::current().unwrap());
    let mut client = connect(&home.endpoint());

    let response = client
        .request(&Request::Call(Call {
            token: "anything".into(),
            verb: "uid-fetch".into(),
            ..Call::default()
        }))
        .unwrap();

    let Outcome::Denied(problem) = response.outcome else {
        panic!("expected a refusal")
    };
    assert_eq!(problem.code, "request.invalid");
    drop(client);
    assert!(matches!(broker.join().unwrap(), Exit::Idle(_)));
    assert!(home.entries().is_empty());
}
