//! Phase 0 spike: JMAP initial sync + `Email/changes` delta loop with
//! jmap-client against a local Stalwart (scripts/test-server.sh).
//!
//! Run: `eval "$(scripts/test-server.sh up)"` then
//! `cargo run -p kiskadee-mail --example jmap_sync_spike`.
//! Throwaway code: the real `Jmap` backend lands in Phase 3.

use jmap_client::client::{Client, Credentials};
use jmap_client::mailbox::{Role, query::Filter};

type Error = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let url = env("KISKADEE_TEST_JMAP_URL")?;
    let user = env("KISKADEE_TEST_USER")?;
    let pass = env("KISKADEE_TEST_PASS")?;

    // The local test server uses a self-signed cert; real servers never get this.
    let client = Client::new()
        .credentials(Credentials::basic(&user, &pass))
        .accept_invalid_certs(true)
        .follow_redirects(["localhost"])
        .connect(&url)
        .await?;
    println!("connected: api_url = {}", client.session().api_url());

    let inbox_id = client
        .mailbox_query(Filter::role(Role::Inbox).into(), None::<Vec<_>>)
        .await?
        .take_ids()
        .pop()
        .ok_or("no Inbox")?;
    println!("inbox id = {inbox_id}");

    // Initial sync: fetch every Email id plus the state to resume from.
    let mut request = client.build();
    request.get_email();
    let initial = request.send_get_email().await?;
    let mut state = initial.state().to_string();
    println!(
        "initial sync: {} emails, state = {state}",
        initial.list().len()
    );

    // Something arrives on the server.
    let raw = b"From: bob@localhost\r\nTo: alice@localhost\r\nSubject: spike delta\r\n\
Message-ID: <spike-1@localhost>\r\nDate: Mon, 6 Oct 2026 12:00:00 +0000\r\n\r\nhello from the spike\r\n";
    let imported = client
        .email_import(raw.to_vec(), [inbox_id.as_str()], None::<Vec<&str>>, None)
        .await?;
    let new_id = imported.id().ok_or("import returned no id")?.to_string();
    println!("imported {new_id}");

    // Delta 1: only the new message, not a full rescan.
    let changes = client.email_changes(&state, None).await?;
    println!(
        "delta 1: created {:?}, updated {:?}, destroyed {:?}",
        changes.created(),
        changes.updated(),
        changes.destroyed()
    );
    assert_eq!(
        changes.created(),
        std::slice::from_ref(&new_id),
        "delta must contain exactly the new email"
    );
    state = changes.new_state().to_string();

    // Delta 2: deletion shows up as destroyed.
    client.email_destroy(&new_id).await?;
    let changes = client.email_changes(&state, None).await?;
    println!("delta 2: destroyed {:?}", changes.destroyed());
    assert_eq!(changes.destroyed(), std::slice::from_ref(&new_id));
    state = changes.new_state().to_string();

    // Delta 3: nothing changed, nothing returned.
    let changes = client.email_changes(&state, None).await?;
    assert!(
        changes.created().is_empty()
            && changes.updated().is_empty()
            && changes.destroyed().is_empty()
    );
    println!("delta 3: empty, as expected. SPIKE PASSED");
    Ok(())
}

fn env(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| format!("{key} not set; run scripts/test-server.sh up").into())
}
