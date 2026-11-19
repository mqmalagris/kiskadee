//! `kiskadee broker` and `kiskadee ping`.

use std::error::Error;
use std::process::ExitCode;
use std::time::Duration;

use kiskadee::broker::{self, Config, Exit, client};
use kiskadee_platform::ipc::Endpoint;
use kiskadee_platform::ipc::peer::Identity;
use kiskadee_platform::paths;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const NO_DATA_DIR: &str = "can't find a data directory; set KISKADEE_HOME";

#[derive(clap::Args)]
pub struct BrokerArgs {
    /// Exit after this many seconds with no connection open.
    #[arg(long, value_name = "SECS", default_value_t = broker::DEFAULT_IDLE_TIMEOUT.as_secs())]
    idle_timeout: u64,
}

/// Runs the Broker in the foreground. It starts locked: the unlock that
/// supplies its token key comes with Phase 2.
pub fn broker(args: BrokerArgs) -> Result<ExitCode> {
    let config = Config {
        endpoint: Endpoint::resolve()?,
        ledger: paths::ledger_db().ok_or(NO_DATA_DIR)?,
        tokens: paths::tokens_db().ok_or(NO_DATA_DIR)?,
        key: None,
        idle_timeout: Duration::from_secs(args.idle_timeout),
        expected_peer: Identity::current()?,
    };
    match broker::serve(config)? {
        // Another Broker won the race; it serves everyone.
        Exit::AlreadyRunning => {}
        // Counted, never logged to the Ledger: leave a trace in broker.log.
        Exit::Idle(report) => eprintln!(
            "kiskadee broker: refused {} connection(s) from other users, closed {} over the limit",
            report.refused_peers, report.over_limit
        ),
    }
    Ok(ExitCode::SUCCESS)
}

/// Checks the Broker answers, starting one if none runs, and prints its
/// `ping` answer as JSON.
pub fn ping() -> Result<ExitCode> {
    let endpoint = Endpoint::resolve()?;
    let log = paths::broker_log().ok_or(NO_DATA_DIR)?;
    let pong = client::ping_or_start(&endpoint, &log, &|| broker::spawn_detached(&log))?;
    println!("{}", serde_json::to_string(&pong)?);
    Ok(ExitCode::SUCCESS)
}
