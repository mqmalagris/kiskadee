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
