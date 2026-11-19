//! User SIDs from process tokens: this process's, for the named pipe DACL,
//! and a connecting peer's, for the same-user check (ADR 0004).
//!
//! Win32 has no safe API for reading a process token, so this file holds
//! kiskadee's `unsafe`. Every block below has a SAFETY note.
#![allow(unsafe_code, reason = "Win32 FFI: reading a process token's user SID")]

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::core::PWSTR;

/// Returns the SID of the user running this process, e.g. `S-1-5-21-...`.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
    let process = unsafe { GetCurrentProcess() };
    user_sid(process)
}

/// Returns the SID of the user running process `pid`.
pub fn process_user_sid(pid: u32) -> io::Result<String> {
    // SAFETY: OpenProcess has no preconditions; a null result is an error,
    // and a real handle is owned by `Owned` and closed once.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Owned(process);
    user_sid(process.0)
}

fn user_sid(process: HANDLE) -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid process handle for this call; `token`
    // receives a handle we own and close through `Owned`.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Owned(token);

    let mut needed = 0u32;
    // SAFETY: a size query with a null buffer; Windows writes only `needed`.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    // u64 storage keeps the buffer aligned for TOKEN_USER.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buffer` is writable, aligned and at least `needed` bytes long.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation(TokenUser) filled `buffer` with a TOKEN_USER.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut wide: PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` points into `buffer`, which outlives this call; Windows
    // allocates `wide` with LocalAlloc, freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string from Windows.
    let text = unsafe { widestring::U16CStr::from_ptr_str(wide) }.to_string_lossy();
    // SAFETY: `wide` was allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe { LocalFree(wide.cast()) };
    Ok(text)
}

/// A process or token handle closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle opened above and closed once.
        unsafe { CloseHandle(self.0) };
    }
}
