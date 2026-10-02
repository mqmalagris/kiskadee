//! The OS keychain, through keyring-core and one native store per OS.
//!
//! keyring v4 asks applications to depend on keyring-core plus the specific
//! store crates rather than on `keyring` itself, which pulls in every store.

use keyring_core::{Entry, Error};

const SERVICE: &str = "kiskadee";

/// Installs the native credential store for this OS. Call once at startup.
pub fn init() -> Result<(), Error> {
    #[cfg(windows)]
    keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
    #[cfg(not(windows))]
    return Err(Error::NoDefaultStore);
    #[cfg(windows)]
    Ok(())
}

/// Stores `secret` under `key` (e.g. an Account id), replacing any previous value.
pub fn put(key: &str, secret: &[u8]) -> Result<(), Error> {
    Entry::new(SERVICE, key)?.set_secret(secret)
}

/// Reads the secret stored under `key`. Returns `Ok(None)` when there is none.
pub fn get(key: &str) -> Result<Option<Vec<u8>>, Error> {
    match Entry::new(SERVICE, key)?.get_secret() {
        Ok(secret) => Ok(Some(secret)),
        Err(Error::NoEntry) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Deletes the secret under `key`. Deleting a missing secret succeeds.
pub fn delete(key: &str) -> Result<(), Error> {
    match Entry::new(SERVICE, key)?.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(other) => Err(other),
    }
}
