//! Page locking for secret memory.
//!
//! # What locking achieves, and what it does not
//!
//! `mlock` and `VirtualLock` keep pages resident, which prevents a secret
//! being written to the swap file. That is the whole of the benefit.
//!
//! It does **not** protect against hibernation, which writes all of RAM to
//! disk regardless of locking. It does not prevent a core dump from containing
//! the secret unless dumps are separately disabled. It does not survive a
//! hypervisor snapshot of the guest. And on Linux the amount a process may
//! lock is bounded by `RLIMIT_MEMLOCK`, which commonly defaults to 8 MiB and
//! has historically been as low as 64 KiB.
//!
//! Locking therefore fails routinely and unremarkably. A failure must not be
//! an error: refusing to open a vault because the OS declined to lock 32 bytes
//! would trade a real capability for a marginal one. The outcome is recorded
//! and reported instead.
//!
//! # Why secrets are heap allocated
//!
//! Locking works on pages, not objects. Locking a secret that lives on the
//! stack locks the whole surrounding page, and unlocking it when the value is
//! dropped would unlock that page for every other live secret sharing it. A
//! moved value would also leave its locked page behind while the data now
//! lives somewhere unlocked.
//!
//! Secrets are therefore boxed, so each has a stable address for its lifetime
//! and a move relocates only the pointer.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicU8, Ordering};

/// What locking actually did on this system, observed rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// No attempt has been made yet.
    Untried,
    /// Every attempt so far succeeded.
    Locked,
    /// At least one attempt was refused, usually by `RLIMIT_MEMLOCK`.
    Refused,
    /// This build has no locking implementation for the platform.
    Unsupported,
}

const UNTRIED: u8 = 0;
const LOCKED: u8 = 1;
const REFUSED: u8 = 2;
const UNSUPPORTED: u8 = 3;

static OUTCOME: AtomicU8 = AtomicU8::new(UNTRIED);

fn record(success: bool) {
    // Once anything has been refused, that stays the reported answer: a later
    // success does not undo a secret that reached swap earlier.
    let want = if success { LOCKED } else { REFUSED };
    let _ = OUTCOME.compare_exchange(UNTRIED, want, Ordering::Relaxed, Ordering::Relaxed);
    if !success {
        OUTCOME.store(REFUSED, Ordering::Relaxed);
    }
}

pub fn outcome() -> LockOutcome {
    match OUTCOME.load(Ordering::Relaxed) {
        LOCKED => LockOutcome::Locked,
        REFUSED => LockOutcome::Refused,
        UNSUPPORTED => LockOutcome::Unsupported,
        _ => LockOutcome::Untried,
    }
}

/// Attempts to keep `len` bytes at `ptr` out of swap. Returns whether it worked.
pub fn lock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        // SAFETY: `ptr` points to `len` bytes owned by the caller and live for
        // the duration of this call. mlock does not read or write the region;
        // it only changes its paging attributes. A failure is reported through
        // the return value and never left as a silent success.
        let ok = unsafe { libc::mlock(ptr as *const libc::c_void, len) } == 0;
        record(ok);
        ok
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualLock;
        // SAFETY: as above. VirtualLock only alters paging behavior for a
        // region the caller owns and keeps alive across the call.
        let ok = unsafe { VirtualLock(ptr as *mut core::ffi::c_void, len) } != 0;
        record(ok);
        ok
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        OUTCOME.store(UNSUPPORTED, Ordering::Relaxed);
        false
    }
}

/// Releases a lock taken by [`lock`]. Failures are ignored: the memory is
/// being freed regardless, and there is nothing useful to do about it.
pub fn unlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: the region was locked by `lock` and is still owned and live.
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        // SAFETY: as above.
        unsafe {
            VirtualUnlock(ptr as *mut core::ffi::c_void, len);
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_recorded_rather_than_ignored() {
        // The path that matters in practice: RLIMIT_MEMLOCK is commonly small,
        // so locking fails routinely and the status must say so rather than
        // continuing to report success.
        //
        // A privileged container bypasses the limit, so the failure is
        // provoked with an address the kernel will reject instead. The pointer
        // is never dereferenced; mlock only inspects the address range and
        // returns ENOMEM.
        let bogus = (usize::MAX / 2) as *const u8;
        let refused = !lock(bogus, 4096);

        if refused {
            assert_eq!(
                outcome(),
                LockOutcome::Refused,
                "a failed lock must move the reported outcome to Refused"
            );
            // And a later success must not erase it: a secret that already
            // reached swap is not un-reached.
            let buf = vec![0u8; 64];
            lock(buf.as_ptr(), buf.len());
            assert_eq!(outcome(), LockOutcome::Refused);
            unlock(buf.as_ptr(), buf.len());
        } else {
            // Some platforms accept anything here; the test then proves only
            // that locking does not panic.
            unlock(bogus, 4096);
        }
    }

    #[test]
    fn locking_an_empty_region_is_a_no_op() {
        assert!(lock(std::ptr::null(), 0));
        unlock(std::ptr::null(), 0);
    }
}
