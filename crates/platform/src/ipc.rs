//! The Broker's local transport: a named pipe on Windows, a Unix socket
//! elsewhere (ADR 0004). On Windows the pipe's DACL grants access to the
//! current user's SID only, so other users can't even open it.

use std::io;

use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::prelude::*;

pub use interprocess::local_socket::{Listener, Stream};

/// Creates a listener reachable only by the current OS user.
pub fn listen(name: &str) -> io::Result<Listener> {
    #[cfg(windows)]
    {
        let sid = crate::windows_sid::current_user_sid()?;
        // Protected DACL with a single allow ACE: generic-all for this user.
        listen_with_sddl(name, &format!("D:P(A;;GA;;;{sid})"))
    }
    #[cfg(not(windows))]
    {
        // Unix socket permissions arrive with the macOS/Linux spike.
        let _ = name;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix transport not built yet",
        ))
    }
}

#[cfg(windows)]
fn listen_with_sddl(name: &str, sddl: &str) -> io::Result<Listener> {
    use interprocess::local_socket::ListenerOptions;
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let sddl = widestring::U16CString::from_str(sddl)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SDDL contains NUL"))?;
    let descriptor = SecurityDescriptor::deserialize(&sddl)?;
    ListenerOptions::new()
        .name(name.to_ns_name::<GenericNamespaced>()?)
        .security_descriptor(descriptor)
        .create_sync()
}

/// Connects to the Broker listening on `name`.
pub fn connect(name: &str) -> io::Result<Stream> {
    Stream::connect(name.to_ns_name::<GenericNamespaced>()?)
}

/// The connecting process's id, recorded in the Ledger for every call.
pub fn peer_pid(stream: &Stream) -> io::Result<Option<u32>> {
    let pid = stream.peer_creds()?.pid();
    // Unix reports `pid_t` (i32); Windows already reports u32.
    #[cfg(unix)]
    let pid = pid.and_then(|pid| u32::try_from(pid).ok());
    Ok(pid)
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::thread;

    use super::*;

    fn unique_name() -> String {
        format!("kiskadee-test-{}", rand::random::<u64>())
    }

    #[test]
    fn the_current_user_round_trips_and_the_peer_pid_is_ours() {
        let name = unique_name();
        let listener = listen(&name).expect("listen");

        let server = thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            let pid = peer_pid(&conn).unwrap();
            let mut reader = BufReader::new(&conn);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            (&conn).write_all(b"pong\n").unwrap();
            (line, pid)
        });

        let client = connect(&name).expect("same user must be able to connect");
        (&client).write_all(b"ping\n").unwrap();
        let mut reply = String::new();
        BufReader::new(&client).read_line(&mut reply).unwrap();

        let (received, pid) = server.join().unwrap();
        assert_eq!(received, "ping\n");
        assert_eq!(reply, "pong\n");
        assert_eq!(pid, Some(std::process::id()));
    }

    #[test]
    fn a_principal_outside_the_dacl_is_refused() {
        // Proxy for "another Windows user": a protected DACL that grants only
        // LocalSystem leaves the current user outside it. Real two-user
        // testing is a manual step.
        let name = unique_name();
        let _listener = listen_with_sddl(&name, "D:P(A;;GA;;;SY)").expect("listen");

        let error = connect(&name).expect_err("must be refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }
}
