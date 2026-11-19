//! Exclusive OS file locks (std `File::lock`). The OS drops a lock when its
//! process dies, so a crash never leaves a stale lock to judge by pid or
//! age: the file existing means nothing, only holding it does.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;

/// Held until dropped.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Takes the lock on `path`, creating the file, or returns `None` if
    /// another process holds it.
    pub fn try_exclusive(path: &Path) -> io::Result<Option<FileLock>> {
        let file = open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(FileLock { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }

    /// Takes the lock on `path`, waiting for whoever holds it.
    pub fn exclusive(path: &Path) -> io::Result<FileLock> {
        let file = open(path)?;
        file.lock()?;
        Ok(FileLock { _file: file })
    }
}

fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_is_refused_and_freed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.lock");
        let held = FileLock::try_exclusive(&path).unwrap().expect("free");
        assert!(FileLock::try_exclusive(&path).unwrap().is_none());
        drop(held);
        assert!(FileLock::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    fn a_blocking_lock_waits_for_the_holder_then_takes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("start.lock");
        let held = FileLock::exclusive(&path).unwrap();
        let waiter = std::thread::spawn({
            let path = path.clone();
            move || FileLock::exclusive(&path).map(drop)
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!waiter.is_finished(), "took a lock that was held");
        drop(held);
        waiter.join().unwrap().unwrap();
    }
}
