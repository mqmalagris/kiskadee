//! The current user's SID as a string, for the named pipe DACL.
//!
//! This is the only `unsafe` in kiskadee so far: Win32 has no safe API for
//! reading the process token. Every block below has a SAFETY note.
#![allow(
    unsafe_code,
    reason = "Win32 FFI: reading the process token's user SID"
)]

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::PWSTR;

/// Returns the SID of the user running this process, e.g. `S-1-5-21-...`.
pub fn current_user_sid() -> io::Result<String> {
    let token = ProcessToken::open()?;

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

struct ProcessToken(HANDLE);

impl ProcessToken {
    fn open() -> io::Result<Self> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `handle` receives a token handle we own and close in Drop.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a token handle opened above and closed once.
        unsafe { CloseHandle(self.0) };
    }
}
