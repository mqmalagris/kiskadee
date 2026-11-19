//! Process hygiene for starting a long-lived child.

/// Stops this process's stdin, stdout and stderr from being inherited by
/// children it spawns from now on.
///
/// On Windows a child inherits every inheritable handle, not just the
/// three it's given. A detached Broker would then hold its Client's stdout
/// pipe open, and anything reading that output to the end, as agent shells
/// do, would wait for the Broker to exit. A no-op on Unix, where the child's
/// standard descriptors are replaced and every other one is close-on-exec.
pub fn keep_std_handles_from_children() -> std::io::Result<()> {
    #[cfg(windows)]
    return crate::windows_pipe::keep_std_handles_from_children();
    #[cfg(not(windows))]
    Ok(())
}
