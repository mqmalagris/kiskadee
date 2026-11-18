//! The Broker process: listens on the local endpoint, checks every peer is
//! the same OS user, and answers framed requests (ADR 0004). `ping` needs
//! no token; a Verb call goes through the Verb dispatcher, or, while the
//! Broker is locked, is refused and logged.
//!
//! One thread per connection and one dispatcher behind a mutex: calls run
//! one at a time, which the stub backend makes free. `broker.lock`, held
//! for the Broker's whole life, makes sure only one runs per endpoint; it
//! exits once no connection has been open for the idle timeout.

pub mod client;
pub mod protocol;
mod spawn;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use kiskadee_core::dispatch::{
    self, BackendError, Dispatcher, Executor, Invocation, Location, Locked, Output, Refusal,
    VerbCall,
};
use kiskadee_core::ledger::{self, Ledger};
use kiskadee_core::tokens::{self, TokenKey, TokenStore};
use kiskadee_core::verb::Verb;
use kiskadee_platform::ipc::frame::Conn;
use kiskadee_platform::ipc::peer::{self, Identity, Peer};
use kiskadee_platform::ipc::prelude::*;
use kiskadee_platform::ipc::{Endpoint, Listener, Stream};
use kiskadee_platform::lock::FileLock;

pub use spawn::spawn_detached;

use protocol::{Parsed, Problem, Request, Response};

/// How long an auto-started Broker waits with no connection open.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Most connections open at once; past it a new one is closed unanswered.
pub const MAX_CONNECTIONS: usize = 64;

/// How often the accept loop wakes to look at the idle timer.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

pub struct Config {
    pub endpoint: Endpoint,
    pub ledger: PathBuf,
    pub tokens: PathBuf,
    /// `None` until the presence unlock exists (Phase 2): the Broker is
    /// locked and refuses every Verb call.
    pub key: Option<TokenKey>,
    pub idle_timeout: Duration,
    /// Who may connect: this user, unless a test needs a stranger.
    pub expected_peer: Identity,
}

/// Why [`serve`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// Another Broker holds `broker.lock`.
    AlreadyRunning,
    /// No connection was open for the idle timeout.
    Idle(Report),
}

/// What the Broker counted but didn't log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Connections from another user, or with unreadable credentials.
    pub refused_peers: u64,
    /// Connections closed for being over [`MAX_CONNECTIONS`].
    pub over_limit: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Ledger(ledger::Error),
    Tokens(tokens::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Ledger(e) => write!(f, "{e}"),
            Error::Tokens(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Runs the Broker until it's idle. Returns at once with
/// [`Exit::AlreadyRunning`] if another Broker has the endpoint.
pub fn serve(config: Config) -> Result<Exit, Error> {
    match Broker::bind(config)? {
        Some(broker) => Ok(Exit::Idle(broker.run())),
        None => Ok(Exit::AlreadyRunning),
    }
}

/// A Broker that holds the endpoint and is listening.
pub struct Broker {
    // Field order is drop order: the listener (and its socket file) goes
    // before the lock, so a new Broker never finds a live socket it may
    // delete.
    listener: Listener,
    _lock: FileLock,
    shared: Arc<Shared>,
    idle_timeout: Duration,
}

impl Broker {
    /// Takes `broker.lock` and starts listening, or returns `None` if
    /// another Broker holds the lock.
    pub fn bind(config: Config) -> Result<Option<Broker>, Error> {
        config.endpoint.prepare()?;
        let Some(lock) = FileLock::try_exclusive(&config.endpoint.broker_lock())? else {
            return Ok(None);
        };
        bind_locked(config, lock).map(Some)
    }

    /// Serves until no connection has been open for the idle timeout.
    pub fn run(self) -> Report {
        loop {
            match self.listener.accept() {
                Ok(stream) => admit(&self.shared, stream),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let open = self.shared.open();
                    if open.count == 0 && open.idle_since.elapsed() >= self.idle_timeout {
                        break;
                    }
                    drop(open);
                    thread::sleep(ACCEPT_POLL);
                }
                Err(e) => {
                    eprintln!("kiskadee broker: accept failed: {e}");
                    thread::sleep(ACCEPT_POLL);
                }
            }
        }
        eprintln!("kiskadee broker: idle, exiting");
        Report {
            refused_peers: self.shared.refused_peers.load(Ordering::Relaxed),
            over_limit: self.shared.over_limit.load(Ordering::Relaxed),
        }
    }
}

fn bind_locked(config: Config, lock: FileLock) -> Result<Broker, Error> {
    // Holding the lock: any socket still there is a dead Broker's.
    config.endpoint.remove_stale()?;
    let ledger = Ledger::open(&config.ledger).map_err(Error::Ledger)?;
    let engine = match config.key {
        Some(key) => {
            let tokens = TokenStore::open(&config.tokens, key).map_err(Error::Tokens)?;
            Engine::Open(Dispatcher::new(tokens, ledger, NoAccounts))
        }
        None => Engine::Locked(Locked::new(ledger)),
    };
    let listener = config.endpoint.listen()?;
    let shared = Arc::new(Shared {
        locked: matches!(engine, Engine::Locked(_)),
        engine: Mutex::new(engine),
        open: Mutex::new(Open {
            count: 0,
            idle_since: Instant::now(),
        }),
        expected_peer: config.expected_peer,
        refused_peers: AtomicU64::new(0),
        over_limit: AtomicU64::new(0),
    });
    eprintln!(
        "kiskadee broker {} (pid {}) listening on {}{}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        config.endpoint.address(),
        if shared.locked { ", locked" } else { "" }
    );
    Ok(Broker {
        listener,
        _lock: lock,
        shared,
        idle_timeout: config.idle_timeout,
    })
}

enum Engine {
    Open(Dispatcher<NoAccounts>),
    Locked(Locked),
}

struct Open {
    count: usize,
    /// When the last connection closed, or the Broker started.
    idle_since: Instant,
}

struct Shared {
    engine: Mutex<Engine>,
    locked: bool,
    open: Mutex<Open>,
    expected_peer: Identity,
    refused_peers: AtomicU64,
    over_limit: AtomicU64,
}

impl Shared {
    fn open(&self) -> MutexGuard<'_, Open> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn admit(shared: &Arc<Shared>, stream: Stream) {
    let mut open = shared.open();
    if open.count >= MAX_CONNECTIONS {
        drop(open);
        shared.over_limit.fetch_add(1, Ordering::Relaxed);
        eprintln!("kiskadee broker: over {MAX_CONNECTIONS} connections, closing one");
        return;
    }
    open.count += 1;
    drop(open);
    // The slot is given back however the thread ends, panics included, and
    // also if it never starts: the closure, and the slot with it, is dropped.
    let slot = Slot(Arc::clone(shared));
    let spawned = thread::Builder::new()
        .name("kiskadee-conn".into())
        .spawn(move || serve_connection(&slot.0, stream));
    if let Err(e) = spawned {
        eprintln!("kiskadee broker: no thread for a connection: {e}");
    }
}

/// One counted connection; dropping it gives the count back and, for the
/// last one, starts the idle clock.
struct Slot(Arc<Shared>);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.0.open();
        open.count -= 1;
        if open.count == 0 {
            open.idle_since = Instant::now();
        }
    }
}

fn serve_connection(shared: &Shared, stream: Stream) {
    // A stranger gets no reply and no Ledger row: it isn't a kiskadee
    // caller, and logging it would let anything grow ledger.db.
    let peer = match peer::check(&stream, &shared.expected_peer) {
        Ok(peer) => peer,
        Err(why) => {
            shared.refused_peers.fetch_add(1, Ordering::Relaxed);
            eprintln!("kiskadee broker: connection refused: {why}");
            return;
        }
    };
    let mut conn = match Conn::new(stream) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("kiskadee broker: {e}");
            return;
        }
    };
    loop {
        let frame = match conn.read_frame(None) {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(e) => {
                eprintln!("kiskadee broker: closing a connection: {e}");
                return;
            }
        };
        let response = match protocol::parse(&frame) {
            Parsed::Request(request) => answer(shared, peer, request),
            Parsed::Refuse(problem) => Response::denied(problem),
            Parsed::Garbage => {
                eprintln!("kiskadee broker: closing a connection: frame is not a JSON object");
                return;
            }
        };
        if let Err(e) = conn.write_frame(&response.to_bytes()) {
            eprintln!("kiskadee broker: closing a connection: {e}");
            return;
        }
    }
}

fn answer(shared: &Shared, peer: Peer, request: Request) -> Response {
    let call = match request {
        Request::Ping {} => {
            // Answered without the dispatcher lock, so a probe never waits
            // behind a call.
            return Response::ok(protocol::Pong {
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").into(),
                locked: shared.locked,
            });
        }
        Request::Call(call) => call,
    };
    let Ok(verb) = call.verb.parse::<Verb>() else {
        return Response::denied(Problem::new(
            protocol::REQUEST_INVALID,
            format!("{:?} is not a kiskadee Verb", call.verb),
        ));
    };
    let verb_call = VerbCall {
        verb,
        account: call.account.as_deref(),
        resource: call.resource.as_deref(),
        target: call.target.as_deref(),
        limit: call.limit,
        cursor: call.cursor.as_deref(),
        args: call.args.clone(),
        peer_pid: peer.pid,
    };
    let mut engine = shared.engine.lock().unwrap_or_else(PoisonError::into_inner);
    let result = match &mut *engine {
        Engine::Open(dispatcher) => dispatcher.call(&call.token, &verb_call),
        Engine::Locked(locked) => locked.call(&verb_call),
    };
    drop(engine);
    match result {
        Ok(dispatch::Response::Reply(reply)) => match serde_json::from_slice(&reply.body) {
            Ok(body) => Response::ok(protocol::Reply {
                body,
                cursor: reply.cursor,
                reads_used: reply.reads_used,
                reads_remaining: reply.reads_remaining,
            }),
            Err(e) => {
                eprintln!("kiskadee broker: backend body is not JSON: {e}");
                Response::error(Problem::new(protocol::BACKEND, "the mail backend failed"))
            }
        },
        Ok(dispatch::Response::Refused(refusal)) => Response::denied(refusal_problem(&refusal)),
        Err(e) => {
            // The detail stays in the Broker's log; the agent gets the code.
            eprintln!("kiskadee broker: {verb} failed: {e}");
            let code = match e {
                dispatch::Error::Backend(_) => protocol::BACKEND,
                _ => protocol::INTERNAL,
            };
            Response::error(Problem::new(code, "the call failed inside kiskadee"))
        }
    }
}

fn refusal_problem(refusal: &Refusal) -> Problem {
    let mut problem = Problem::new(refusal.code(), refusal.to_string());
    match refusal {
        Refusal::BudgetExhausted { reads_remaining } => {
            problem.reads_remaining = Some(*reads_remaining);
        }
        Refusal::RateLimited { retry_after_s } => problem.retry_after_s = Some(*retry_after_s),
        _ => {}
    }
    problem
}

/// The backend until the mail layer exists (Phase 3): no Accounts, so every
/// target is missing and `list` and `search` find nothing.
pub struct NoAccounts;

impl Executor for NoAccounts {
    fn locate(&self, _target: &str) -> Result<Vec<Location>, BackendError> {
        Ok(Vec::new())
    }

    fn run(&self, invocation: &Invocation<'_>) -> Result<Output, BackendError> {
        if invocation.verb.returns_content() {
            // Unreachable: a content Verb's target is always missing here.
            return Err(BackendError::Unsupported);
        }
        Ok(Output {
            body: br#"{"results":[]}"#.to_vec(),
            messages: 0,
            cursor: None,
        })
    }
}
