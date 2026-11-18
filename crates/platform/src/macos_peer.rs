//! The pid on the other end of a Unix socket, on macOS.
//!
//! `getpeereid`, which the peer credentials come from on macOS, gives a
//! uid and gid but no pid, and the Ledger records the caller's pid for
//! every call. `LOCAL_PEERPID` gives it; neither std nor rustix wraps it.
#![allow(unsafe_code, reason = "getsockopt(SOL_LOCAL, LOCAL_PEERPID)")]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// The pid of the process that connected the socket `fd`, as it was at
/// connect time.
pub fn peer_pid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket for the call; `pid` and `len` are
    // valid places to write, and `len` holds the size of `pid`.
    let status = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(pid).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative peer pid"))
}
