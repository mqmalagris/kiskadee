//! The Client side: connect to the Broker, starting one if none answers
//! (ADR 0004 point 6), and exchange one frame per request.
//!
//! Before sending anything, a Client checks the endpoint is served by its
//! own OS user: on Windows pipe names are machine-wide and predictable, so
//! another user could create the Broker's pipe first and collect tokens.
//!
//! Starting is serialized by `start.lock`: a Client takes it, tries once
//! more to connect (another Client may have just started a Broker), and
//! only then spawns one and waits for it to answer. Should two Brokers
//! start anyway, `broker.lock` lets only one of them run.

use std::fmt;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use kiskadee_platform::ipc::Endpoint;
use kiskadee_platform::ipc::frame::{Conn, FrameError};
use kiskadee_platform::ipc::peer::{self, Identity, Refused};
use kiskadee_platform::lock::FileLock;

use super::protocol::{self, Pong, Request, Response};

/// How long a Client waits for a Broker it started to answer.
pub const START_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a Client waits for the answer to one request. Local reads come
/// from the Broker's cache, so this is generous.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Backoff while a started Broker comes up.
const START_POLL_MIN: Duration = Duration::from_millis(5);
const START_POLL_MAX: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Frame(FrameError),
    /// The endpoint is served by another OS user, or by a process whose
    /// user can't be read. Nothing was sent to it.
    Stranger(Refused),
    /// The Broker hung up without answering.
    NoReply,
    /// The Broker answered with something that isn't a response.
    BadReply(String),
    /// A spawned Broker never answered.
    DidNotStart {
        log: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Frame(e) => write!(f, "{e}"),
            Error::Stranger(why) => write!(
                f,
                "the Broker's endpoint isn't served by you ({why}); nothing was sent to it"
            ),
            Error::NoReply => f.write_str("the Broker closed the connection without answering"),
            Error::BadReply(why) => write!(f, "unreadable answer from the Broker: {why}"),
            Error::DidNotStart { log } => write!(
                f,
                "the Broker didn't start within {}s; see {log}",
                START_TIMEOUT.as_secs()
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Error::Frame(e)
    }
}

impl Error {
    /// No Broker listens: the endpoint doesn't exist or refuses outright.
    /// Only this starts a Broker; any other failure is reported as is.
    fn no_broker(&self) -> bool {
        matches!(self, Error::Io(e) if matches!(
            e.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ))
    }

    /// The Broker exists but every pipe instance is taken for a moment.
    fn busy(&self) -> bool {
        const ERROR_PIPE_BUSY: i32 = 231;
        matches!(self, Error::Io(e) if cfg!(windows) && e.raw_os_error() == Some(ERROR_PIPE_BUSY))
    }

    /// The Broker went away mid-exchange, as one exiting for idleness does.
    fn hung_up(&self) -> bool {
        match self {
            Error::NoReply | Error::Frame(FrameError::Truncated) => true,
            Error::Frame(FrameError::Io(e)) => matches!(
                e.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }
}

/// A connection to a Broker of this OS user.
pub struct Client {
    conn: Conn,
}

impl Client {
    /// Connects to a running Broker served by this user.
    pub fn connect(endpoint: &Endpoint) -> Result<Client, Error> {
        Client::connect_expecting(endpoint, &Identity::current()?)
    }

    /// Connects, refusing an endpoint not served by `server`. A test can
    /// pass a stranger's identity, since CI has only one OS user.
    pub fn connect_expecting(endpoint: &Endpoint, server: &Identity) -> Result<Client, Error> {
        let conn = Conn::new(endpoint.connect()?)?;
        peer::check_server(&conn, server).map_err(Error::Stranger)?;
        Ok(Client { conn })
    }

    /// Connects, calling `start` to launch a Broker if none listens, then
    /// waiting up to [`START_TIMEOUT`] for it. `log` is named in the error.
    pub fn connect_or_start(
        endpoint: &Endpoint,
        log: &Path,
        start: &dyn Fn() -> io::Result<()>,
    ) -> Result<Client, Error> {
        match Client::connect_patiently(endpoint) {
            Err(e) if e.no_broker() => {}
            other => return other,
        }
        endpoint.prepare()?;
        let _starting = FileLock::exclusive(&endpoint.start_lock())?;
        match Client::connect_patiently(endpoint) {
            Err(e) if e.no_broker() => {}
            other => return other,
        }
        start()?;
        let deadline = Instant::now() + START_TIMEOUT;
        let mut poll = START_POLL_MIN;
        loop {
            match Client::connect(endpoint) {
                Err(e) if e.no_broker() || e.busy() => {}
                other => return other,
            }
            if Instant::now() >= deadline {
                return Err(Error::DidNotStart {
                    log: log.display().to_string(),
                });
            }
            thread::sleep(poll);
            poll = (poll * 2).min(START_POLL_MAX);
        }
    }

    /// [`Client::connect`], waiting out a moment when every pipe instance
    /// is busy.
    fn connect_patiently(endpoint: &Endpoint) -> Result<Client, Error> {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            match Client::connect(endpoint) {
                Err(e) if e.busy() && Instant::now() < deadline => {
                    thread::sleep(START_POLL_MIN);
                }
                other => return other,
            }
        }
    }

    /// Sends `request` and waits up to [`REPLY_TIMEOUT`] for the response.
    pub fn request(&mut self, request: &Request) -> Result<Response, Error> {
        self.conn.write_frame(&protocol::encode(request))?;
        let frame = self
            .conn
            .read_frame(Some(REPLY_TIMEOUT))?
            .ok_or(Error::NoReply)?;
        serde_json::from_slice(&frame).map_err(|e| Error::BadReply(e.to_string()))
    }

    pub fn ping(&mut self) -> Result<Pong, Error> {
        let value = self
            .request(&Request::Ping {})?
            .outcome
            .into_ok()
            .map_err(|problem| Error::BadReply(format!("{}: {}", problem.code, problem.message)))?;
        serde_json::from_value(value).map_err(|e| Error::BadReply(e.to_string()))
    }
}

/// Pings the Broker for `endpoint`, starting one if needed. A Broker that
/// was shutting down for idleness may hang up on the first try, so a
/// hang-up is retried once; a `ping` is safe to repeat, a Verb call isn't.
pub fn ping_or_start(
    endpoint: &Endpoint,
    log: &Path,
    start: &dyn Fn() -> io::Result<()>,
) -> Result<Pong, Error> {
    let attempt = || Client::connect_or_start(endpoint, log, start)?.ping();
    match attempt() {
        Err(e) if e.hung_up() => attempt(),
        other => other,
    }
}
