//! The Verb dispatcher: the one path from an agent's call to the mail
//! backend.
//!
//! For each call, in order: the rate limit; the token and its scope
//! ([`TokenStore::admit`], which writes the call's `begin`); the target's
//! real Account and folder, re-checked against the scope; for content
//! Verbs, the read budget. Then the Verb runs, its reads are charged, and
//! only then is the content released. Every refusal and error after the
//! `begin` gets its outcome in the Ledger.
//!
//! There is no passthrough: the backend is an [`Executor`], which only
//! ever receives a [`Verb`] from the fixed set, never a protocol command.

mod rate;

use std::fmt;

use rate::{RateLimiter, Verdict};

use crate::ledger::{self, Actor, Ledger, Status};
use crate::profiles::Scope;
use crate::tokens::{self, Admission, Charge, Denial, Grant, Request, TokenStore};
use crate::verb::Verb;

/// Most results one `list` or `search` returns, and most messages one
/// content Verb returns. Asking for more gets this many and a cursor.
pub const MAX_PER_CALL: u32 = 50;

/// Most calls one token may make in [`RATE_WINDOW_MS`], denied ones
/// included.
pub const RATE_LIMIT: usize = 60;

/// The rolling window [`RATE_LIMIT`] counts over.
pub const RATE_WINDOW_MS: i64 = 60_000;

/// Ledger outcome details for the dispatcher's own refusals.
const BUDGET_EXHAUSTED: &str = "budget.exhausted";
const RATE_LIMITED: &str = "rate.limited";
const TARGET_UNAVAILABLE: &str = "target.unavailable";
const TARGET_MISSING: &str = "target.missing";
const TARGET_ACCOUNT: &str = "target.account";
const VERB_UNSUPPORTED: &str = "verb.unsupported";
const BACKEND_ERROR: &str = "backend";
const INTERNAL_ERROR: &str = "internal";

/// One Verb call as an agent sends it.
#[derive(Debug, Clone)]
pub struct VerbCall<'a> {
    pub verb: Verb,
    /// `None` means every Account.
    pub account: Option<&'a str>,
    /// Folder or label; `None` means all of them.
    pub resource: Option<&'a str>,
    /// The message or thread id the call acts on.
    pub target: Option<&'a str>,
    /// How many results the agent wants; capped at [`MAX_PER_CALL`].
    pub limit: Option<u32>,
    /// A cursor from an earlier reply, to fetch the next page.
    pub cursor: Option<&'a str>,
    /// The Verb's own arguments (a search query, say), passed to the
    /// backend as they are.
    pub args: serde_json::Value,
}

/// Where a message lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub account: String,
    pub folder: String,
}

/// What the backend is asked to run: a checked [`VerbCall`].
#[derive(Debug)]
pub struct Invocation<'a> {
    pub verb: Verb,
    pub account: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub target: Option<&'a str>,
    /// Never more than [`MAX_PER_CALL`].
    pub limit: u32,
    pub cursor: Option<&'a str>,
    pub args: &'a serde_json::Value,
}

/// What the backend returns. The dispatcher never looks inside `body`, so
/// core stays free of email types (ADR 0002).
#[derive(Debug)]
pub struct Output {
    pub body: Vec<u8>,
    /// Messages whose content `body` carries: what the call costs. Zero
    /// for a Verb that doesn't return content.
    pub messages: u64,
    /// Set when there are more results.
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// This backend doesn't implement the Verb yet.
    Unsupported,
    /// The backend failed. The text is for the Broker's own log, never the
    /// Ledger.
    Failed(String),
}

/// The mail side of the dispatcher, implemented by the mail layer.
pub trait Executor {
    /// Where the message or thread `target` lives; empty if it doesn't
    /// exist. A thread can span folders, so it may be several places.
    fn locate(&self, target: &str) -> Result<Vec<Location>, BackendError>;

    /// Runs one checked Verb.
    fn run(&self, invocation: &Invocation<'_>) -> Result<Output, BackendError>;
}

/// Why the dispatcher refused a call. [`Refusal::code`] is what the agent
/// sees; the Ledger may record a more specific reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The token or its scope refused the call.
    Token(Denial),
    /// The target doesn't exist or is outside the token's scope; the agent
    /// isn't told which, so it can't probe for messages it can't read.
    TargetUnavailable,
    /// The call needs more reads than remain; nothing was returned.
    BudgetExhausted {
        reads_remaining: u64,
    },
    RateLimited {
        retry_after_s: u64,
    },
    /// The backend doesn't support this Verb yet.
    Unsupported,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Token(denial) => denial.code(),
            Refusal::TargetUnavailable => TARGET_UNAVAILABLE,
            Refusal::BudgetExhausted { .. } => BUDGET_EXHAUSTED,
            Refusal::RateLimited { .. } => RATE_LIMITED,
            Refusal::Unsupported => VERB_UNSUPPORTED,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Token(denial) => write!(f, "{denial}"),
            Refusal::TargetUnavailable => {
                f.write_str("the target doesn't exist or isn't covered by the token")
            }
            Refusal::BudgetExhausted { reads_remaining } => write!(
                f,
                "the call needs more reads than the token has left ({reads_remaining})"
            ),
            Refusal::RateLimited { retry_after_s } => {
                write!(f, "too many calls; retry in {retry_after_s}s")
            }
            Refusal::Unsupported => f.write_str("this Verb isn't available yet"),
        }
    }
}

/// A call that ran.
#[derive(Debug)]
pub struct Reply {
    pub body: Vec<u8>,
    pub cursor: Option<String>,
    /// Reads this call cost; `None` for a Verb that returns no content.
    pub reads_used: Option<u64>,
    pub reads_remaining: u64,
}

#[derive(Debug)]
pub enum Response {
    Reply(Reply),
    Refused(Refusal),
}

#[derive(Debug)]
pub enum Error {
    Tokens(tokens::Error),
    Ledger(ledger::Error),
    /// The backend failed, or broke its contract.
    Backend(String),
    Clock,
    /// The call's arguments couldn't be encoded for their digest.
    Args(String),
}

impl Error {
    fn code(&self) -> &'static str {
        match self {
            Error::Backend(_) => BACKEND_ERROR,
            _ => INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tokens(e) => write!(f, "{e}"),
            Error::Ledger(e) => write!(f, "{e}"),
            Error::Backend(why) => write!(f, "mail backend: {why}"),
            Error::Clock => f.write_str("system clock is before 1970"),
            Error::Args(why) => write!(f, "call arguments: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tokens(e) => Some(e),
            Error::Ledger(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tokens::Error> for Error {
    fn from(e: tokens::Error) -> Self {
        Error::Tokens(e)
    }
}

impl From<ledger::Error> for Error {
    fn from(e: ledger::Error) -> Self {
        Error::Ledger(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Milliseconds since the Unix epoch; `None` before 1970. A closure, so a
/// test can move it.
pub type Clock = Box<dyn Fn() -> Option<i64>>;

/// How an admitted call ended: the Ledger outcome and what the agent gets.
struct Finished {
    status: Status,
    detail: Option<String>,
    response: Response,
}

impl Finished {
    fn refused(detail: &str, refusal: Refusal) -> Self {
        Finished {
            status: Status::Denied,
            detail: Some(detail.to_string()),
            response: Response::Refused(refusal),
        }
    }
}

pub struct Dispatcher<E> {
    tokens: TokenStore,
    ledger: Ledger,
    executor: E,
    limiter: RateLimiter,
    clock: Clock,
}

impl<E: Executor> Dispatcher<E> {
    pub fn new(tokens: TokenStore, ledger: Ledger, executor: E) -> Self {
        Dispatcher {
            tokens,
            ledger,
            executor,
            limiter: RateLimiter::default(),
            clock: Box::new(crate::time::now_ms),
        }
    }

    /// Replaces the wall clock the rate limits use. For tests.
    pub fn with_clock(mut self, clock: impl Fn() -> Option<i64> + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The token store and the Ledger, for the human's admin Verbs.
    pub fn stores(&mut self) -> (&mut TokenStore, &mut Ledger) {
        (&mut self.tokens, &mut self.ledger)
    }

    /// Rate-limited calls left out of the Ledger since the Broker started.
    pub fn rate_limited_unlogged(&self) -> u64 {
        self.limiter.unlogged()
    }

    /// Runs `call` for the agent presenting `presented`. A refusal is a
    /// [`Response::Refused`]; an `Err` is a failure, already in the Ledger
    /// when the call got that far.
    pub fn call(&mut self, presented: &str, call: &VerbCall<'_>) -> Result<Response> {
        let now_ms = (self.clock)().ok_or(Error::Clock)?;
        let args_digest = args_digest(call)?;
        let caller = self.tokens.identify(presented)?;
        if let Verdict::Limited { retry_after_s, log } =
            self.limiter.check(caller.as_deref(), now_ms)
        {
            if log {
                // Nothing the caller sent goes in but the Verb: a flood
                // can't write text into the Ledger.
                let seq = self.ledger.begin(ledger::Call {
                    actor: caller.map_or(Actor::UnknownToken, Actor::Token),
                    account: None,
                    verb: call.verb.as_str().into(),
                    target: None,
                    args_digest,
                })?;
                self.ledger
                    .outcome(seq, Status::Denied, Some(RATE_LIMITED))?;
            }
            return Ok(Response::Refused(Refusal::RateLimited { retry_after_s }));
        }
        let request = Request {
            verb: call.verb,
            account: call.account,
            resource: call.resource,
            target: call.target,
            args_digest,
        };
        let (grant, begin_seq) = match self.tokens.admit(&mut self.ledger, presented, &request)? {
            Admission::Admitted { grant, begin_seq } => (grant, begin_seq),
            Admission::Denied { denial, .. } => {
                return Ok(Response::Refused(Refusal::Token(denial)));
            }
        };
        match self.run(&grant, call) {
            Ok(finished) => {
                self.ledger
                    .outcome(begin_seq, finished.status, finished.detail.as_deref())?;
                Ok(finished.response)
            }
            Err(e) => {
                self.ledger
                    .outcome(begin_seq, Status::Error, Some(e.code()))?;
                Err(e)
            }
        }
    }

    /// Everything after admission: target, budget, the Verb itself, the
    /// charge.
    fn run(&mut self, grant: &Grant, call: &VerbCall<'_>) -> Result<Finished> {
        let content = call.verb.returns_content();
        match call.target {
            Some(target) => {
                let locations = self.executor.locate(target).map_err(backend)?;
                if let Some(reason) = out_of_reach(grant.scope(), call.account, &locations) {
                    return Ok(Finished::refused(reason, Refusal::TargetUnavailable));
                }
            }
            // Content always comes from a target, and only a located
            // target's real place is checked against the scope.
            None if content => {
                return Ok(Finished::refused(
                    TARGET_MISSING,
                    Refusal::TargetUnavailable,
                ));
            }
            None => {}
        }
        if content && grant.reads_remaining() == 0 {
            let refusal = Refusal::BudgetExhausted { reads_remaining: 0 };
            return Ok(Finished::refused(BUDGET_EXHAUSTED, refusal));
        }
        let invocation = Invocation {
            verb: call.verb,
            account: call.account,
            resource: call.resource,
            target: call.target,
            limit: call.limit.unwrap_or(MAX_PER_CALL).clamp(1, MAX_PER_CALL),
            cursor: call.cursor,
            args: &call.args,
        };
        let output = match self.executor.run(&invocation) {
            Ok(output) => output,
            Err(BackendError::Unsupported) => {
                return Ok(Finished::refused(VERB_UNSUPPORTED, Refusal::Unsupported));
            }
            Err(e) => return Err(backend(e)),
        };
        // A content Verb's target exists, so it returns at least one
        // message; anything else would release content for free.
        let in_contract = if content {
            (1..=u64::from(MAX_PER_CALL)).contains(&output.messages)
        } else {
            output.messages == 0
        };
        if !in_contract {
            return Err(Error::Backend(format!(
                "{} returned {} messages' content",
                call.verb, output.messages
            )));
        }
        if !content {
            return Ok(Finished {
                status: Status::Ok,
                detail: None,
                response: Response::Reply(Reply {
                    body: output.body,
                    cursor: output.cursor,
                    reads_used: None,
                    reads_remaining: grant.reads_remaining(),
                }),
            });
        }
        // The content is released only once it's paid for; a call that
        // lost a race for the last reads is refused and its content dropped.
        let reads = output.messages;
        match self.tokens.charge_reads(grant.token_id(), reads)? {
            Charge::Charged { reads_remaining } => Ok(Finished {
                status: Status::Ok,
                detail: Some(format!("reads={reads}")),
                response: Response::Reply(Reply {
                    body: output.body,
                    cursor: output.cursor,
                    reads_used: Some(reads),
                    reads_remaining,
                }),
            }),
            Charge::Short { reads_remaining } => Ok(Finished::refused(
                BUDGET_EXHAUSTED,
                Refusal::BudgetExhausted { reads_remaining },
            )),
            Charge::Revoked => Ok(token_refused(Denial::Revoked)),
            Charge::Expired => Ok(token_refused(Denial::Expired)),
        }
    }
}

fn token_refused(denial: Denial) -> Finished {
    Finished::refused(denial.code(), Refusal::Token(denial))
}

/// Why `locations` aren't all within `scope`, as a Ledger detail, or
/// `None` if they are. A target in another Account than the one the call
/// names is refused too, so the backend and the Ledger never act on a
/// claimed Account that isn't the real one.
fn out_of_reach(
    scope: &Scope,
    claimed_account: Option<&str>,
    locations: &[Location],
) -> Option<&'static str> {
    if locations.is_empty() {
        return Some(TARGET_MISSING);
    }
    locations.iter().find_map(|location| {
        if !scope.accounts.allows(Some(&location.account)) {
            Some(Denial::Account.code())
        } else if claimed_account.is_some_and(|claimed| claimed != location.account) {
            Some(TARGET_ACCOUNT)
        } else if !scope.resources.allows_folder(Some(&location.folder)) {
            Some(Denial::Resource.code())
        } else {
            None
        }
    })
}

/// The digest of everything in the call the `begin` row doesn't hold
/// itself, so the Ledger pins the exact call.
fn args_digest(call: &VerbCall<'_>) -> Result<[u8; 32]> {
    let canonical = serde_json::json!({
        "resource": call.resource,
        "limit": call.limit,
        "cursor": call.cursor,
        "args": call.args,
    });
    let bytes = serde_json::to_vec(&canonical).map_err(|e| Error::Args(e.to_string()))?;
    Ok(ledger::digest(&bytes))
}

fn backend(e: BackendError) -> Error {
    match e {
        BackendError::Unsupported => Error::Backend("unsupported".into()),
        BackendError::Failed(why) => Error::Backend(why),
    }
}
