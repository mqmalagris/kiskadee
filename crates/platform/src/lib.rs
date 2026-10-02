//! kiskadee OS integration: keychain access, credential encryption, user
//! presence (Windows Hello, LocalAuthentication, polkit), the IPC transport
//! (named pipes, Unix sockets) and service install (ADR 0004).

pub mod ipc;
pub mod keychain;
#[cfg(windows)]
mod windows_sid;
