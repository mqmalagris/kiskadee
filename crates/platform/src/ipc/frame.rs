//! Length-prefixed frames: a 4-byte big-endian length, then that many
//! bytes, at most [`MAX_FRAME`].
//!
//! Pipes and sockets here have no portable read timeout, so reads are
//! polled: a nonblocking socket on Unix, a blocking pipe read only as far as
//! `PeekNamedPipe` reports on Windows. Once a frame's first byte arrives
//! the rest must follow within [`FRAME_TIMEOUT`], so a stalled peer can't
//! pin a Broker thread; on Unix a write has the same deadline. Between
//! frames there is no deadline: an idle MCP connection is legitimate.

use std::fmt;
use std::io::{self, Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::Stream;
use interprocess::local_socket::prelude::*;

/// The largest frame either side accepts.
pub const MAX_FRAME: usize = 1 << 20;

/// How long the rest of a frame may take once it has started.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

const MIN_POLL: Duration = Duration::from_millis(1);
const MAX_POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// The peer announced a frame over [`MAX_FRAME`].
    TooLarge(usize),
    /// A started frame, or a write, didn't finish in [`FRAME_TIMEOUT`], or
    /// no frame started within the wait given to [`Conn::read_frame`].
    Timeout,
    /// The peer hung up partway through a frame.
    Truncated,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "{e}"),
            FrameError::TooLarge(len) => {
                write!(f, "frame of {len} bytes is over the {MAX_FRAME}-byte limit")
            }
            FrameError::Timeout => write!(f, "frame not finished within {FRAME_TIMEOUT:?}"),
            FrameError::Truncated => f.write_str("peer hung up partway through a frame"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// A connection that sends and receives frames. Run the peer check on the
/// stream first: this takes it over.
pub struct Conn {
    io: Io,
}

/// A nonblocking socket on Unix, where `Ok(0)` is end of file and an empty
/// socket is `WouldBlock`.
#[cfg(unix)]
struct Io(Stream);

/// A blocking pipe on Windows, read only as far as `PeekNamedPipe` says is
/// there: a nonblocking pipe reads `Ok(0)` both when empty and after a
/// hang-up, so it can't be told apart.
#[cfg(windows)]
struct Io(std::fs::File);

impl Conn {
    pub fn new(stream: Stream) -> io::Result<Conn> {
        #[cfg(unix)]
        {
            stream.set_nonblocking(true)?;
            Ok(Conn { io: Io(stream) })
        }
        #[cfg(windows)]
        {
            stream.set_nonblocking(false)?;
            let Stream::NamedPipe(pipe) = stream;
            let handle: std::os::windows::io::OwnedHandle = pipe.into();
            Ok(Conn {
                io: Io(handle.into()),
            })
        }
    }

    /// The next frame, or `Ok(None)` when the peer hung up between frames.
    /// `wait` bounds how long to wait for a frame to start: `None` waits as
    /// long as the peer keeps the connection open, which is right for the
    /// Broker; a Client awaiting a reply passes a limit, and gets
    /// [`FrameError::Timeout`] past it.
    pub fn read_frame(&mut self, wait: Option<Duration>) -> Result<Option<Vec<u8>>, FrameError> {
        let mut header = [0; 4];
        let waiting = Instant::now();
        let Some(started) = self.fill(&mut header, None, &|| {
            wait.is_some_and(|wait| waiting.elapsed() > wait)
        })?
        else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge(len));
        }
        let mut body = vec![0; len];
        self.fill(&mut body, Some(started), &|| false)?;
        Ok(Some(body))
    }

    /// The socket, for checking who is on the other end.
    #[cfg(unix)]
    pub(crate) fn socket(&self) -> &Stream {
        &self.io.0
    }

    /// The pipe, for checking who is on the other end.
    #[cfg(windows)]
    pub(crate) fn pipe(&self) -> &std::fs::File {
        &self.io.0
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<(), FrameError> {
        if payload.len() > MAX_FRAME {
            return Err(FrameError::TooLarge(payload.len()));
        }
        let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(payload);

        self.io.write_all(&bytes)
    }

    /// Fills `buf`. `started` is when the frame began, if it has; returns
    /// when it began, or `None` for a hang-up before any byte. `gave_up`
    /// says when to stop waiting for that first byte.
    fn fill(
        &mut self,
        buf: &mut [u8],
        mut started: Option<Instant>,
        gave_up: &dyn Fn() -> bool,
    ) -> Result<Option<Instant>, FrameError> {
        let mut filled = 0;
        let mut poll = MIN_POLL;
        while filled < buf.len() {
            match self.io.try_read(&mut buf[filled..]) {
                Ok(0) => return closed(started),
                Ok(n) => {
                    started.get_or_insert_with(Instant::now);
                    filled += n;
                    poll = MIN_POLL;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match started {
                        None if gave_up() => return Err(FrameError::Timeout),
                        Some(at) if at.elapsed() > FRAME_TIMEOUT => {
                            return Err(FrameError::Timeout);
                        }
                        _ => {}
                    }
                    poll = sleep(poll);
                }
                Err(e) if hung_up(&e) => return closed(started),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(started)
    }
}

fn closed(started: Option<Instant>) -> Result<Option<Instant>, FrameError> {
    match started {
        None => Ok(None),
        Some(_) => Err(FrameError::Truncated),
    }
}

impl Io {
    /// Reads what's there, or fails with `WouldBlock` if nothing is.
    #[cfg(unix)]
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }

    #[cfg(windows)]
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match crate::windows_pipe::available(&self.0)? {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            available => {
                let end = buf.len().min(available);
                self.0.read(&mut buf[..end])
            }
        }
    }

    /// Writes all of `bytes` within [`FRAME_TIMEOUT`].
    #[cfg(unix)]
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        let started = Instant::now();
        let mut written = 0;
        let mut poll = MIN_POLL;
        while written < bytes.len() {
            match (&self.0).write(&bytes[written..]) {
                Ok(0) => return Err(FrameError::Io(io::ErrorKind::WriteZero.into())),
                Ok(n) => {
                    written += n;
                    poll = MIN_POLL;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if started.elapsed() > FRAME_TIMEOUT {
                        return Err(FrameError::Timeout);
                    }
                    poll = sleep(poll);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Writes all of `bytes`. A blocking pipe write has no deadline: a
    /// same-user peer that stops reading holds its thread, one of the
    /// Broker's capped connections, until it hangs up.
    #[cfg(windows)]
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        self.0.write_all(bytes).map_err(FrameError::Io)
    }
}

/// A Windows pipe reports a hang-up as an error, not as end of file.
fn hung_up(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

/// Sleeps `poll`, returning the next, longer, interval.
fn sleep(poll: Duration) -> Duration {
    thread::sleep(poll);
    (poll * 2).min(MAX_POLL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::Endpoint;

    /// The Broker's end and a Client's end of one connection.
    fn pair(dir: &std::path::Path) -> (Conn, Conn) {
        let endpoint = Endpoint::in_dir(dir);
        endpoint.prepare().unwrap();
        let listener = endpoint.listen().unwrap();
        let client = Conn::new(endpoint.connect().unwrap()).unwrap();
        loop {
            match listener.accept() {
                Ok(server) => return (Conn::new(server).unwrap(), client),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }

    /// Writes raw bytes, around the framing, from the client end.
    fn raw(conn: &mut Conn, bytes: &[u8]) {
        conn.io.write_all(bytes).unwrap();
    }

    #[test]
    fn a_frame_of_exactly_the_limit_round_trips_and_one_byte_more_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut server, mut client) = pair(dir.path());
        let largest = vec![b'x'; MAX_FRAME];
        let writer = thread::spawn(move || {
            client.write_frame(&largest).unwrap();
            client
        });
        assert_eq!(
            server.read_frame(None).unwrap().map(|f| f.len()),
            Some(MAX_FRAME)
        );
        let mut client = writer.join().unwrap();

        assert!(matches!(
            client.write_frame(&vec![0; MAX_FRAME + 1]),
            Err(FrameError::TooLarge(_))
        ));
        raw(
            &mut client,
            &u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes(),
        );
        assert!(matches!(
            server.read_frame(None),
            Err(FrameError::TooLarge(len)) if len == MAX_FRAME + 1
        ));
    }

    #[test]
    fn an_empty_frame_and_two_frames_sent_together_both_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let (mut server, mut client) = pair(dir.path());
        let mut both = 0u32.to_be_bytes().to_vec();
        both.extend_from_slice(&2u32.to_be_bytes());
        both.extend_from_slice(b"hi");
        raw(&mut client, &both);
        assert_eq!(server.read_frame(None).unwrap(), Some(Vec::new()));
        assert_eq!(server.read_frame(None).unwrap(), Some(b"hi".to_vec()));
    }

    #[test]
    fn a_hang_up_between_frames_is_a_clean_close_and_mid_frame_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let (mut server, client) = pair(dir.path());
        drop(client);
        assert!(matches!(server.read_frame(None), Ok(None)));

        let (mut server, mut client) = pair(&dir.path().join("second"));
        raw(&mut client, &10u32.to_be_bytes());
        raw(&mut client, b"abc");
        drop(client);
        assert!(matches!(
            server.read_frame(None),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn a_reply_that_never_starts_times_out_after_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (_server, mut client) = pair(dir.path());
        let started = std::time::Instant::now();
        assert!(matches!(
            client.read_frame(Some(Duration::from_millis(200))),
            Err(FrameError::Timeout)
        ));
        assert!(started.elapsed() >= Duration::from_millis(200));
    }
}
