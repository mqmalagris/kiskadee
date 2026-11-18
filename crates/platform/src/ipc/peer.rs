//! The same-user check the Broker runs on every connection (ADR 0004). The
//! OS access list should already keep other users out; this check holds
//! even if the socket directory or pipe ended up wider than intended.

use std::fmt;
use std::io;

use interprocess::local_socket::Stream;

use super::frame::Conn;
use interprocess::local_socket::prelude::*;

/// An OS user: the effective uid on Unix, the user SID on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity(Inner);

#[cfg(unix)]
type Inner = u32;
#[cfg(windows)]
type Inner = String;

impl Identity {
    /// The user this process runs as.
    pub fn current() -> io::Result<Identity> {
        #[cfg(unix)]
        return Ok(Identity(rustix::process::geteuid().as_raw()));
        #[cfg(windows)]
        return crate::windows_sid::current_user_sid().map(Identity);
    }

    /// An identity no process runs as, for testing the refusal without a
    /// second OS user: uid `-1` is invalid on Unix, and the Null SID owns no
    /// processes on Windows.
    pub fn nobody() -> Identity {
        #[cfg(unix)]
        return Identity(u32::MAX);
        #[cfg(windows)]
        return Identity("S-1-0-0".into());
    }
}

/// A connected process that passed the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: Option<u32>,
}

/// Why a peer was turned away.
#[derive(Debug)]
pub enum Refused {
    /// The peer runs as another user.
    OtherUser,
    /// The OS wouldn't say who the peer is, so it's treated as a stranger.
    Unreadable(io::Error),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::OtherUser => f.write_str("peer runs as another user"),
            Refused::Unreadable(e) => write!(f, "peer credentials unreadable: {e}"),
        }
    }
}

/// Checks that the process on the other end of `stream` runs as `expected`.
pub fn check(stream: &Stream, expected: &Identity) -> Result<Peer, Refused> {
    let creds = stream.peer_creds().map_err(Refused::Unreadable)?;
    let pid = creds.pid();
    #[cfg(unix)]
    let (pid, actual) = {
        let pid = pid.and_then(|pid| u32::try_from(pid).ok());
        let euid = creds.euid().ok_or_else(|| {
            Refused::Unreadable(io::Error::new(io::ErrorKind::Unsupported, "no peer euid"))
        })?;
        (pid, Identity(euid))
    };
    #[cfg(windows)]
    let actual = {
        let pid = pid.ok_or_else(|| {
            Refused::Unreadable(io::Error::new(io::ErrorKind::Unsupported, "no peer pid"))
        })?;
        Identity(crate::windows_sid::process_user_sid(pid).map_err(Refused::Unreadable)?)
    };
    matches(pid, &actual, expected)
}

/// Checks that the process serving the connection `conn` runs as
/// `expected`. A Client runs this before sending anything: pipe names are
/// machine-wide and predictable on Windows, so another user could create
/// the Broker's pipe first and collect what Clients send it.
pub fn check_server(conn: &Conn, expected: &Identity) -> Result<Peer, Refused> {
    #[cfg(unix)]
    let (pid, actual) = {
        let creds = conn.socket().peer_creds().map_err(Refused::Unreadable)?;
        let pid = creds.pid().and_then(|pid| u32::try_from(pid).ok());
        let euid = creds.euid().ok_or_else(|| {
            Refused::Unreadable(io::Error::new(io::ErrorKind::Unsupported, "no server euid"))
        })?;
        (pid, Identity(euid))
    };
    #[cfg(windows)]
    let (pid, actual) = {
        let pid =
            crate::windows_pipe::server_process_id(conn.pipe()).map_err(Refused::Unreadable)?;
        let sid = crate::windows_sid::process_user_sid(pid).map_err(Refused::Unreadable)?;
        (Some(pid), Identity(sid))
    };
    matches(pid, &actual, expected)
}

fn matches(pid: Option<u32>, actual: &Identity, expected: &Identity) -> Result<Peer, Refused> {
    if actual == expected {
        Ok(Peer { pid })
    } else {
        Err(Refused::OtherUser)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::ipc::Endpoint;

    /// A connected pair: the Broker's accepted stream and a Client's
    /// connection.
    fn pair(dir: &std::path::Path) -> (Stream, Conn) {
        let endpoint = Endpoint::in_dir(dir);
        endpoint.prepare().unwrap();
        let listener = endpoint.listen().unwrap();
        let client = Conn::new(endpoint.connect().unwrap()).unwrap();
        loop {
            match listener.accept() {
                Ok(server) => return (server, client),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }

    #[test]
    fn the_same_user_passes_both_ways_with_our_pid_and_frames_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (server, mut client) = pair(dir.path());
        let me = Identity::current().unwrap();
        let ours = Peer {
            pid: Some(std::process::id()),
        };

        assert_eq!(check(&server, &me).unwrap(), ours);
        assert_eq!(check_server(&client, &me).unwrap(), ours);

        let mut server = Conn::new(server).unwrap();
        client.write_frame(b"ping").unwrap();
        assert_eq!(
            server.read_frame(None).unwrap().as_deref(),
            Some(&b"ping"[..])
        );
        server.write_frame(b"pong").unwrap();
        assert_eq!(
            client.read_frame(None).unwrap().as_deref(),
            Some(&b"pong"[..])
        );
    }

    #[test]
    fn a_stranger_is_refused_in_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let (server, client) = pair(dir.path());
        let stranger = Identity::nobody();
        assert!(matches!(check(&server, &stranger), Err(Refused::OtherUser)));
        assert!(matches!(
            check_server(&client, &stranger),
            Err(Refused::OtherUser)
        ));
    }
}
