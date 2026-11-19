//! The Broker's local transport (ADR 0004): a named pipe on Windows whose
//! DACL grants only the current user's SID, and a Unix socket in a `0700`
//! directory elsewhere. On top of the OS access list, the Broker checks
//! every peer's identity itself ([`peer`]) and frames messages with a size
//! and time bound ([`frame`]).

pub mod frame;
pub mod peer;

use std::io;
use std::path::{Path, PathBuf};

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerNonblockingMode, ListenerOptions};

pub use interprocess::local_socket::{Listener, Stream};

/// The traits that give [`Listener`] and [`Stream`] their methods.
pub mod prelude {
    pub use interprocess::local_socket::prelude::*;
}

/// Where the Broker listens, and the directory holding its lock files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    dir: PathBuf,
    /// The pipe name on Windows; the socket path elsewhere.
    address: String,
}

impl Endpoint {
    /// The endpoint for this user, or for `KISKADEE_HOME` when it's set, so
    /// a test's Broker never meets the real one.
    pub fn resolve() -> io::Result<Endpoint> {
        let home = std::env::var_os("KISKADEE_HOME").filter(|home| !home.is_empty());
        let data = crate::paths::data_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no data directory"))?;
        Ok(Endpoint::in_dir(&run_dir(home.is_some(), &data)))
    }

    /// The endpoint [`Endpoint::resolve`] gives with `KISKADEE_HOME` set to
    /// `home`, for tests that can't set the variable process-wide.
    pub fn for_home(home: &Path) -> Endpoint {
        Endpoint::in_dir(&run_dir(true, home))
    }

    /// The endpoint whose lock files live in `dir`.
    pub fn in_dir(dir: &Path) -> Endpoint {
        #[cfg(windows)]
        let address = pipe_name(dir);
        #[cfg(not(windows))]
        let address = dir.join("broker.sock").to_string_lossy().into_owned();
        Endpoint {
            dir: dir.to_path_buf(),
            address,
        }
    }

    /// The directory for [`Endpoint::broker_lock`] and [`Endpoint::start_lock`].
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Held by the Broker for its whole life: one Broker per endpoint.
    pub fn broker_lock(&self) -> PathBuf {
        self.dir.join("broker.lock")
    }

    /// Held by a Client while it starts a Broker.
    pub fn start_lock(&self) -> PathBuf {
        self.dir.join("start.lock")
    }

    /// The pipe name or socket path, for messages.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Creates the directory if needed. On Unix it must be a real
    /// directory owned by this user with mode `0700`: a wrong mode on our
    /// own directory is fixed, anything else is refused.
    pub fn prepare(&self) -> io::Result<()> {
        prepare_dir(&self.dir)
    }

    /// Removes a socket left behind by a Broker that crashed. Only the
    /// holder of `broker.lock` may call this: a live Broker's socket would
    /// otherwise be deleted from under it. A no-op on Windows, where a pipe
    /// dies with its server.
    pub fn remove_stale(&self) -> io::Result<()> {
        #[cfg(unix)]
        match std::fs::remove_file(&self.address) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        Ok(())
    }

    /// Starts listening with a nonblocking accept, so the Broker can watch
    /// its idle timer. [`frame::Conn`] sets each stream's own mode.
    pub fn listen(&self) -> io::Result<Listener> {
        let listener = listen_options(self)?.create_sync()?;
        listener.set_nonblocking(ListenerNonblockingMode::Accept)?;
        Ok(listener)
    }

    pub fn connect(&self) -> io::Result<Stream> {
        #[cfg(windows)]
        let name = {
            use interprocess::local_socket::GenericNamespaced;
            self.address.as_str().to_ns_name::<GenericNamespaced>()?
        };
        #[cfg(not(windows))]
        let name = {
            use interprocess::local_socket::GenericFilePath;
            self.address.as_str().to_fs_name::<GenericFilePath>()?
        };
        Stream::connect(name)
    }
}

/// Linux: `$XDG_RUNTIME_DIR/kiskadee`. macOS: `$TMPDIR/kiskadee`, since a
/// socket path is limited to 104 bytes there. Otherwise, and whenever
/// `KISKADEE_HOME` is set: `<data dir>/run`. Windows keeps the locks in the
/// data directory itself.
fn run_dir(home_set: bool, data: &Path) -> PathBuf {
    if cfg!(windows) {
        return data.to_path_buf();
    }
    let runtime_var = if cfg!(target_os = "macos") {
        "TMPDIR"
    } else {
        "XDG_RUNTIME_DIR"
    };
    unix_run_dir(home_set, data, std::env::var_os(runtime_var))
}

/// [`run_dir`] on Unix, given the runtime directory variable's value.
fn unix_run_dir(home_set: bool, data: &Path, runtime: Option<std::ffi::OsString>) -> PathBuf {
    match runtime.filter(|dir| !home_set && !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir).join("kiskadee"),
        None => data.join("run"),
    }
}

/// `kiskadee-` and 16 hex digits of SHA-256 over the directory, so each
/// data directory gets its own pipe. The path is made absolute and folded
/// to one spelling first, since `broker.lock` lives on a case-insensitive
/// file system: two spellings of one directory must find one pipe. (8.3
/// short names and junctions aren't resolved; set `KISKADEE_HOME` to one
/// spelling.)
#[cfg(windows)]
fn pipe_name(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(normalized(dir).as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("kiskadee-{hex}")
}

#[cfg(windows)]
fn normalized(dir: &Path) -> String {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    absolute
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

#[cfg(windows)]
fn listen_options(endpoint: &Endpoint) -> io::Result<ListenerOptions<'_>> {
    let sid = crate::windows_sid::current_user_sid()?;
    // Protected DACL with a single allow ACE: generic-all for this user.
    options_with_sddl(&endpoint.address, &format!("D:P(A;;GA;;;{sid})"))
}

#[cfg(windows)]
fn options_with_sddl<'a>(name: &'a str, sddl: &str) -> io::Result<ListenerOptions<'a>> {
    use interprocess::local_socket::GenericNamespaced;
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let sddl = widestring::U16CString::from_str(sddl)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SDDL contains NUL"))?;
    let descriptor = SecurityDescriptor::deserialize(&sddl)?;
    Ok(ListenerOptions::new()
        .name(name.to_ns_name::<GenericNamespaced>()?)
        .security_descriptor(descriptor))
}

#[cfg(not(windows))]
fn listen_options(endpoint: &Endpoint) -> io::Result<ListenerOptions<'_>> {
    use interprocess::local_socket::GenericFilePath;
    Ok(ListenerOptions::new().name(endpoint.address.as_str().to_fs_name::<GenericFilePath>()?))
}

#[cfg(windows)]
fn prepare_dir(dir: &Path) -> io::Result<()> {
    // The data directory sits in the user's profile, whose ACL already
    // keeps other users out; the pipe's own DACL is the boundary.
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn prepare_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: {why}", dir.display()),
        )
    };
    // symlink_metadata: a symlink planted in a shared tmp dir must not lead
    // the Broker somewhere else.
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(refuse("is a symlink; refusing to use it"));
    }
    if !meta.is_dir() {
        return Err(refuse("is not a directory"));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(refuse("is owned by another user"));
    }
    if meta.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_principal_outside_the_dacl_is_refused() {
        // Proxy for "another Windows user": a protected DACL that grants only
        // LocalSystem leaves the current user outside it. Real two-user
        // testing is a manual step.
        let name = format!("kiskadee-test-{}", rand::random::<u64>());
        let _listener = options_with_sddl(&name, "D:P(A;;GA;;;SY)")
            .and_then(|options| options.create_sync())
            .expect("listen");
        let endpoint = Endpoint {
            dir: PathBuf::new(),
            address: name,
        };

        let error = endpoint.connect().expect_err("must be refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }

    #[test]
    fn each_data_directory_gets_its_own_pipe() {
        let a = Endpoint::in_dir(Path::new(r"C:\Users\a\kiskadee"));
        let b = Endpoint::in_dir(Path::new(r"C:\Users\b\kiskadee"));
        assert_ne!(a.address(), b.address());
        assert!(a.address().starts_with("kiskadee-"));
        assert_eq!(a, Endpoint::in_dir(Path::new(r"C:\Users\a\kiskadee")));
    }

    /// The lock file doesn't care how the directory is spelled, so the pipe
    /// mustn't either, or a second Client misses a live Broker.
    #[test]
    fn spellings_of_one_directory_find_one_pipe() {
        let pipe = |dir: &str| Endpoint::in_dir(Path::new(dir)).address().to_string();
        let canonical = pipe(r"C:\Data\kiskadee");
        for spelling in [
            r"c:\data\KISKADEE",
            r"C:\Data\kiskadee\",
            "C:/Data/kiskadee",
        ] {
            assert_eq!(pipe(spelling), canonical, "{spelling}");
        }
    }
}

#[cfg(test)]
mod run_dir_tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn the_runtime_directory_is_used_unless_kiskadee_home_is_set_or_it_is_empty() {
        let data = Path::new("/home/a/.local/share/kiskadee");
        let runtime = || Some(OsString::from("/run/user/1000"));
        assert_eq!(
            unix_run_dir(false, data, runtime()),
            Path::new("/run/user/1000/kiskadee")
        );
        assert_eq!(unix_run_dir(true, data, runtime()), data.join("run"));
        assert_eq!(unix_run_dir(false, data, None), data.join("run"));
        assert_eq!(
            unix_run_dir(false, data, Some(OsString::new())),
            data.join("run")
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn the_socket_directory_is_made_private_and_a_wrong_mode_is_fixed() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("run");
        let endpoint = Endpoint::in_dir(&dir);
        endpoint.prepare().unwrap();
        let mode = |dir: &Path| std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        endpoint.prepare().unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn a_symlinked_socket_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let dir = root.path().join("run");
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();

        let error = Endpoint::in_dir(&dir).prepare().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }
}
