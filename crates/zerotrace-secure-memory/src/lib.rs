//! Handling for values that must not outlive their use.
//!
//! What this crate promises is narrow and worth stating plainly: secrets are
//! zeroed when dropped, they cannot be printed or serialized by accident,
//! comparisons are constant-time, and their pages are locked out of swap where
//! the operating system permits it.
//!
//! What it still cannot promise is that no copy ever reached a core dump, a
//! hibernation image or a hypervisor snapshot. Locking addresses swap and
//! nothing else. See [`lock`] for the details, and
//! [`memory_protection_status`] for what actually happened on this machine
//! rather than what was intended.

#![deny(unsafe_code)]

pub mod lock;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A fixed-size secret, zeroed on drop.
///
/// `Debug` prints a placeholder and there is no `Serialize`, so a secret
/// cannot leak into a log line or an audit record by accident.
/// A fixed-size secret with a stable heap address.
///
/// Boxed rather than inline so the bytes can be page-locked: see [`lock`] for
/// why a stack-resident secret cannot be locked safely.
pub struct SecretBytes<const N: usize> {
    bytes: Box<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        let boxed = Box::new(bytes);
        lock::lock(boxed.as_ptr(), N);
        Self { bytes: boxed }
    }

    pub fn zeroed() -> Self {
        Self::new([0u8; N])
    }

    /// Exposes the raw bytes. Named to make review easy to grep for.
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Clone for SecretBytes<N> {
    /// A clone gets its own locked allocation rather than sharing one.
    fn clone(&self) -> Self {
        Self::new(*self.bytes)
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        lock::unlock(self.bytes.as_ptr(), N);
    }
}

impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes<{N}>(redacted)")
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    /// Constant-time, so comparing a secret cannot be turned into an oracle.
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice()).into()
    }
}
impl<const N: usize> Eq for SecretBytes<N> {}

/// A 256-bit symmetric key.
pub type Key256 = SecretBytes<32>;

/// A variable-length secret such as a password or a decrypted buffer.
/// A variable-length secret such as a password or a decrypted buffer.
///
/// The locked region covers the allocation present when the buffer was built.
/// A `Vec` that grows reallocates, and the old allocation is freed without
/// being locked or zeroed by this type, so callers that will append should
/// reserve capacity up front. This is a real limitation of wrapping `Vec` and
/// is stated rather than papered over.
#[derive(Clone)]
pub struct SecureBuffer {
    bytes: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        lock::lock(bytes.as_ptr(), bytes.capacity());
        Self { bytes }
    }

    pub fn with_capacity(n: usize) -> Self {
        let bytes = Vec::with_capacity(n);
        lock::lock(bytes.as_ptr(), bytes.capacity());
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn expose_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the buffer, zeroing it, and yields nothing. Used to make key
    /// destruction explicit at call sites rather than implicit in scope exit.
    pub fn destroy(self) {
        drop(self);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        let (ptr, cap) = (self.bytes.as_ptr(), self.bytes.capacity());
        self.bytes.zeroize();
        lock::unlock(ptr, cap);
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer({} bytes, redacted)", self.bytes.len())
    }
}

/// What this platform actually does for secret memory, reported honestly.
/// Allocates and frees one secret so the status reflects what this machine can
/// do, rather than reporting "not attempted" to anyone who asks before a vault
/// has been opened.
pub fn probe_memory_protection() -> (zerotrace_core::Assurance, &'static str) {
    let _ = SecretBytes::<32>::zeroed();
    memory_protection_status()
}

pub fn memory_protection_status() -> (zerotrace_core::Assurance, &'static str) {
    use zerotrace_core::Assurance;
    match lock::outcome() {
        lock::LockOutcome::Locked => (
            Assurance::BestEffort,
            "Secrets are zeroed on drop and their pages are locked out of swap. Locking \
             does not cover hibernation images, core dumps or hypervisor snapshots, so \
             this is best effort rather than verified.",
        ),
        lock::LockOutcome::Refused => (
            Assurance::Failed,
            "Secrets are zeroed on drop, but the operating system refused to lock their \
             pages, usually because of RLIMIT_MEMLOCK. Secrets may reach swap.",
        ),
        lock::LockOutcome::Unsupported => (
            Assurance::NotSupported,
            "Secrets are zeroed on drop. This platform has no memory locking \
             implementation in this build.",
        ),
        lock::LockOutcome::Untried => (
            Assurance::NotAttempted,
            "No secret has been allocated yet, so no locking has been attempted.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_secret() {
        let k = Key256::new([0xAB; 32]);
        let shown = format!("{k:?}");
        assert!(!shown.contains("ab"), "{shown}");
        assert!(!shown.contains("171"), "{shown}");
        assert!(shown.contains("redacted"));

        let b = SecureBuffer::new(b"hunter2".to_vec());
        let shown = format!("{b:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn equality_is_value_based_and_constant_time() {
        let a = Key256::new([1u8; 32]);
        let b = Key256::new([1u8; 32]);
        let c = Key256::new([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn locking_is_attempted_and_its_outcome_is_reported_truthfully() {
        // Allocating a secret must move the status off Untried, and the status
        // must never claim more than what happened.
        let _k = Key256::new([1u8; 32]);
        let (assurance, note) = memory_protection_status();
        assert_ne!(assurance, zerotrace_core::Assurance::NotAttempted);
        assert_ne!(
            assurance,
            zerotrace_core::Assurance::Verified,
            "locking can never be Verified: it does not cover hibernation or snapshots"
        );
        assert!(note.contains("zeroed on drop"), "{note}");
        match lock::outcome() {
            lock::LockOutcome::Locked => assert!(note.contains("swap")),
            lock::LockOutcome::Refused => assert!(note.contains("refused")),
            _ => {}
        }
    }

    #[test]
    fn a_clone_gets_its_own_allocation() {
        let a = Key256::new([9u8; 32]);
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a.expose().as_ptr(), b.expose().as_ptr(), "clone must not alias");
    }

    #[test]
    fn secrets_survive_being_moved() {
        // Boxing means a move relocates the pointer, not the bytes, so the
        // locked page still holds the live secret.
        let a = Key256::new([3u8; 32]);
        let addr = a.expose().as_ptr();
        let moved = a;
        assert_eq!(moved.expose().as_ptr(), addr);
        assert_eq!(moved.expose(), &[3u8; 32]);
    }

    #[test]
    fn destroy_consumes_the_buffer() {
        let b = SecureBuffer::new(vec![1, 2, 3]);
        b.destroy();
        // Nothing to assert on afterwards by design: the value is gone. The
        // test exists to pin the API shape so `destroy` stays explicit.
    }
}
