//! Pipe and handle calls Win32 has no safe API for.
//!
//! A nonblocking pipe can't tell "no data yet" from "the peer hung up" (both
//! read as `Ok(0)`), so frames keep pipes blocking and look before each
//! read: `PeekNamedPipe` reports the bytes available, and fails with
//! `ERROR_BROKEN_PIPE` once the other end is gone.
#![allow(unsafe_code, reason = "Win32 FFI: PeekNamedPipe, SetHandleInformation")]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, PeekNamedPipe};

/// The pid of the process serving the pipe `pipe` is connected to.
pub fn server_process_id(pipe: &File) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` owns a valid pipe handle for the call, and `pid` is a
    // valid place for Windows to write the id.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// See [`crate::process::keep_std_handles_from_children`].
pub fn keep_std_handles_from_children() -> io::Result<()> {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle has no preconditions; it may return null (no
        // handle) or INVALID_HANDLE_VALUE, both skipped below.
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // SAFETY: `handle` is this process's own standard handle, valid for
        // the call; only its inherit flag is cleared.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            let error = io::Error::last_os_error();
            // A console handle isn't a kernel object and can't be flagged;
            // it isn't what holds a pipe open anyway.
            const ERROR_INVALID_HANDLE: i32 = 6;
            if error.raw_os_error() != Some(ERROR_INVALID_HANDLE) {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Bytes readable from `pipe` right now without blocking.
pub fn available(pipe: &File) -> io::Result<usize> {
    let mut available = 0u32;
    // SAFETY: `pipe` owns a valid pipe handle for the duration of the call;
    // a null buffer with size 0 asks only for the counts, and `available`
    // is a valid place for Windows to write one.
    let ok = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(available as usize)
}
