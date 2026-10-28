//! Phase 0 spike: initial sync of a large Gmail INBOX with async-imap, then
//! incremental resync with CONDSTORE (Gmail has no QRESYNC).
//!
//! Env: KISKADEE_GOOGLE_CLIENT_JSON, KISKADEE_GMAIL_USER (as in gmail_xoauth2_spike;
//! run that first so a refresh token is in the keychain).
//! Modes (first arg):
//!   initial  header sync (UID, FLAGS, MODSEQ, size, ENVELOPE), newest first, in
//!            batches; resumable: re-running skips UIDs already cached
//!   resync   CHANGEDSINCE delta for flags and new mail, UID SEARCH diff for expunges
//! Read-only (EXAMINE, no bodies). Prints counts and bytes, never message content.
//! Cache: ~/.kiskadee-dev/gmail-sync-state.json. Throwaway: the real engine lands in Phase 3.

use std::collections::{BTreeMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use async_imap::Authenticator;
use futures_util::TryStreamExt;
use oauth2::basic::BasicClient;
use oauth2::{ClientId, ClientSecret, RefreshToken, TokenResponse, TokenUrl, reqwest};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Error = Box<dyn std::error::Error>;
type Session = async_imap::Session<Counting<async_native_tls::TlsStream<tokio::net::TcpStream>>>;

const KEYCHAIN_KEY: &str = "spike-gmail-refresh-token";
const BATCH: usize = 2000;
const QUERY: &str = "(UID FLAGS MODSEQ RFC822.SIZE ENVELOPE)";

#[derive(Default, Serialize, Deserialize)]
struct State {
    uid_validity: u32,
    /// HIGHESTMODSEQ to resync from: taken when the cache was first created, so
    /// a resumed initial sync never skips changes made between its runs.
    modseq: u64,
    complete: bool,
    messages: BTreeMap<u32, Message>,
}

#[derive(Serialize, Deserialize)]
struct Message {
    modseq: u64,
    flags: Vec<String>,
    size: u32,
    from: String,
    subject: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "initial".into());
    let path = state_path()?;
    let mut state: State = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(_) => State::default(),
    };

    let received = Arc::new(AtomicU64::new(0));
    let mut session = connect(received.clone()).await?;
    let inbox = session.examine("INBOX").await?;
    let uid_validity = inbox.uid_validity.ok_or("no UIDVALIDITY")?;
    let highest = inbox
        .highest_modseq
        .ok_or("no HIGHESTMODSEQ (CONDSTORE off?)")?;
    println!(
        "INBOX: {} messages, highestmodseq {highest}; cache: {} messages, modseq {}",
        inbox.exists,
        state.messages.len(),
        state.modseq
    );
    if state.uid_validity != uid_validity {
        if state.uid_validity != 0 {
            println!("UIDVALIDITY changed: dropping the cache, full resync");
        }
        state = State {
            uid_validity,
            modseq: highest,
            ..State::default()
        };
    }
    let baseline = received.load(Ordering::Relaxed);
    let started = Instant::now();

    match mode.as_str() {
        "initial" => initial(&mut session, &mut state, &path, &received).await?,
        "resync" if !state.complete => {
            return Err("initial sync not complete; run `initial`".into());
        }
        "resync" => resync(&mut session, &mut state, highest, inbox.exists).await?,
        other => return Err(format!("unknown mode {other}").into()),
    }
    save(&path, &state)?;
    session.logout().await?;

    println!(
        "done in {:.1}s, {} bytes received from the server (after EXAMINE); cache now {} messages",
        started.elapsed().as_secs_f64(),
        received.load(Ordering::Relaxed) - baseline,
        state.messages.len()
    );
    Ok(())
}

async fn initial(
    session: &mut Session,
    state: &mut State,
    path: &std::path::Path,
    received: &AtomicU64,
) -> Result<(), Error> {
    let all = session.uid_search("ALL").await?;
    let mut missing: Vec<u32> = all
        .into_iter()
        .filter(|uid| !state.messages.contains_key(uid))
        .collect();
    // Newest first, so the top of the INBOX is usable after the first batch.
    missing.sort_unstable_by(|a, b| b.cmp(a));
    println!("{} UIDs to fetch", missing.len());
    let started = Instant::now();
    for (index, chunk) in missing.chunks(BATCH).enumerate() {
        let fetched = fetch_into(session, &uid_set(chunk), QUERY, state).await?;
        save(path, state)?;
        println!(
            "  batch {}: {fetched} messages, total {} cached, {:.1}s, {:.1} MB received",
            index + 1,
            state.messages.len(),
            started.elapsed().as_secs_f64(),
            received.load(Ordering::Relaxed) as f64 / 1e6
        );
    }
    state.complete = true;
    Ok(())
}

async fn resync(
    session: &mut Session,
    state: &mut State,
    highest: u64,
    exists: u32,
) -> Result<(), Error> {
    if highest == state.modseq && exists as usize == state.messages.len() {
        println!("nothing changed (same HIGHESTMODSEQ and count): no FETCH sent");
        return Ok(());
    }

    // Flag changes and new mail: only messages whose MODSEQ moved past ours.
    let query = format!("(UID FLAGS MODSEQ) (CHANGEDSINCE {})", state.modseq);
    let mut changed = Vec::new();
    {
        let mut stream = session.uid_fetch("1:*", &query).await?;
        while let Some(fetch) = stream.try_next().await? {
            let uid = fetch.uid.ok_or("FETCH without UID")?;
            let flags = flags_of(&fetch);
            match state.messages.get_mut(&uid) {
                Some(message) => {
                    message.flags = flags;
                    message.modseq = fetch.modseq.unwrap_or(message.modseq);
                    changed.push(uid);
                }
                None => changed.push(uid),
            }
        }
    }
    let new: Vec<u32> = changed
        .iter()
        .copied()
        .filter(|uid| !state.messages.contains_key(uid))
        .collect();
    if !new.is_empty() {
        fetch_into(session, &uid_set(&new), QUERY, state).await?;
    }
    println!(
        "CHANGEDSINCE: {} flag updates, {} new messages",
        changed.len() - new.len(),
        new.len()
    );

    // Expunges: without QRESYNC there is no VANISHED, so diff the UID set,
    // but only when the counts say something is gone.
    if exists as usize != state.messages.len() {
        let live: HashSet<u32> = session.uid_search("ALL").await?;
        let gone: Vec<u32> = state
            .messages
            .keys()
            .copied()
            .filter(|uid| !live.contains(uid))
            .collect();
        for uid in &gone {
            state.messages.remove(uid);
        }
        println!("UID SEARCH diff: {} expunged", gone.len());
    } else {
        println!("counts match: no UID SEARCH needed");
    }
    state.modseq = highest;
    Ok(())
}

async fn fetch_into(
    session: &mut Session,
    set: &str,
    query: &str,
    state: &mut State,
) -> Result<usize, Error> {
    let mut stream = session.uid_fetch(set, query).await?;
    let mut count = 0;
    while let Some(fetch) = stream.try_next().await? {
        let uid = fetch.uid.ok_or("FETCH without UID")?;
        let envelope = fetch.envelope();
        let text =
            |bytes: Option<&[u8]>| String::from_utf8_lossy(bytes.unwrap_or_default()).into_owned();
        let from = envelope
            .and_then(|e| e.from.as_ref())
            .and_then(|list| list.first())
            .map(|a| format!("{}@{}", text(a.mailbox.as_deref()), text(a.host.as_deref())))
            .unwrap_or_default();
        state.messages.insert(
            uid,
            Message {
                modseq: fetch.modseq.unwrap_or_default(),
                flags: flags_of(&fetch),
                size: fetch.size.unwrap_or_default(),
                from,
                subject: text(envelope.and_then(|e| e.subject.as_deref())),
            },
        );
        count += 1;
    }
    Ok(count)
}

fn flags_of(fetch: &async_imap::types::Fetch) -> Vec<String> {
    fetch.flags().map(|flag| format!("{flag:?}")).collect()
}

/// Compresses UIDs into an IMAP sequence set ("5,7:9,12").
fn uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    let mut parts = Vec::new();
    let mut iter = sorted.into_iter().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end = iter.next().unwrap_or(end);
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
    }
    parts.join(",")
}

async fn connect(received: Arc<AtomicU64>) -> Result<Session, Error> {
    let user = env("KISKADEE_GMAIL_USER")?;
    let access = access_token().await?;
    let tcp = tokio::net::TcpStream::connect(("imap.gmail.com", 993)).await?;
    let tls = async_native_tls::TlsConnector::new()
        .connect("imap.gmail.com", tcp)
        .await?;
    let mut client = async_imap::Client::new(Counting {
        inner: tls,
        received,
    });
    client.read_response().await?;
    let session = client
        .authenticate(
            "XOAUTH2",
            XOAuth2 {
                user: &user,
                token: &access,
            },
        )
        .await
        .map_err(|(error, _)| error)?;
    Ok(session)
}

async fn access_token() -> Result<String, Error> {
    kiskadee_platform::keychain::init()?;
    let refresh = kiskadee_platform::keychain::get(KEYCHAIN_KEY)?
        .ok_or("no refresh token; run gmail_xoauth2_spike first")?;
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(env(
        "KISKADEE_GOOGLE_CLIENT_JSON",
    )?)?)?;
    let field = |name: &str| {
        json["installed"][name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("client JSON has no installed.{name}"))
    };
    let oauth = BasicClient::new(ClientId::new(field("client_id")?))
        .set_client_secret(ClientSecret::new(field("client_secret")?))
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".into())?);
    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let tokens = oauth
        .exchange_refresh_token(&RefreshToken::new(String::from_utf8(refresh)?))
        .request_async(&http)
        .await?;
    Ok(tokens.access_token().secret().clone())
}

struct XOAuth2<'a> {
    user: &'a str,
    token: &'a str,
}

impl Authenticator for XOAuth2<'_> {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

/// Counts bytes read from the server, to prove a resync transfers only the delta.
#[derive(Debug)]
struct Counting<S> {
    inner: S,
    received: Arc<AtomicU64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        self.received.fetch_add(read, Ordering::Relaxed);
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn state_path() -> Result<std::path::PathBuf, Error> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"))?;
    Ok(std::path::Path::new(&home).join(".kiskadee-dev/gmail-sync-state.json"))
}

fn save(path: &std::path::Path, state: &State) -> Result<(), Error> {
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec(state)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn env(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| format!("{key} not set").into())
}
