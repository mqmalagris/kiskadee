//! Where kiskadee keeps its files.

use std::path::PathBuf;

/// The data directory: `KISKADEE_HOME` if set, else the OS local data dir
/// (`%LOCALAPPDATA%\kiskadee`, `~/Library/Application Support/kiskadee`,
/// `$XDG_DATA_HOME/kiskadee`).
pub fn data_dir() -> Option<PathBuf> {
    match std::env::var_os("KISKADEE_HOME") {
        Some(home) if !home.is_empty() => Some(PathBuf::from(home)),
        _ => dirs::data_local_dir().map(|dir| dir.join("kiskadee")),
    }
}

/// `ledger.db`, kept apart from the rebuildable cache (ADR 0003).
pub fn ledger_db() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join("ledger.db"))
}

/// `tokens.db`, the Capability token store (ADR 0004).
pub fn tokens_db() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join("tokens.db"))
}

/// Where an auto-started Broker writes its output.
pub fn broker_log() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join("broker.log"))
}
