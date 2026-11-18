//! Starting `kiskadee broker` detached from the Client that needed it.

use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// The agent's token: a long-lived Broker has no use for it, so it never
/// sits in the Broker's environment.
const TOKEN_ENV: &str = "KISKADEE_TOKEN";

/// Spawns this binary as `kiskadee broker`, detached, with its output in
/// `log`. The previous log is kept as `broker.log.1`, so the last crash
/// survives one restart. Called under `start.lock`, so nothing else
/// rotates the log meanwhile. The child isn't waited on: it outlives the
/// Client.
pub fn spawn_detached(log: &Path) -> io::Result<()> {
    if let Some(dir) = log.parent() {
        fs::create_dir_all(dir)?;
    }
    match fs::rename(log, log.with_extension("log.1")) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    // Or the Broker would hold the Client's stdout open on Windows.
    kiskadee_platform::process::keep_std_handles_from_children()?;
    let out = File::create(log)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("broker")
        .env_remove(TOKEN_ENV)
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out);
    spawn(&mut command)
}

/// No console and its own process group, and out of the caller's job
/// object when the job allows it, so closing the agent's terminal or job
/// doesn't take the Broker down. A job that forbids breakaway fails that
/// spawn, so it's retried without.
#[cfg(windows)]
fn spawn(command: &mut Command) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let detached = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    command.creation_flags(detached | CREATE_BREAKAWAY_FROM_JOB);
    if command.spawn().is_ok() {
        return Ok(());
    }
    command.creation_flags(detached);
    command.spawn().map(drop)
}

/// Its own process group, so a hang-up on the agent's terminal doesn't
/// reach it.
#[cfg(unix)]
fn spawn(command: &mut Command) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    command.process_group(0).spawn().map(drop)
}
