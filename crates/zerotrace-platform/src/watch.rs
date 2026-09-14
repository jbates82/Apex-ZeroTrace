//! Tracking which vaults have a running watcher.
//!
//! The lock lives beside the vault it watches, so every vault is tracked
//! independently and nothing can act on the wrong one: a caller that knows a
//! vault path knows exactly one lock path.
//!
//! # Liveness without asking the operating system
//!
//! A watcher refreshes a timestamp in its own lock file on every tick. A lock
//! whose timestamp has stopped moving belongs to a watcher that is no longer
//! running.
//!
//! The obvious alternative, asking the operating system whether a process id
//! still exists, needs different APIs on every platform and cannot be tested
//! from one of them. It is also weaker: a process id can be recycled, making a
//! dead watcher look alive, and a process that is alive but wedged looks
//! healthy while watching nothing. A heartbeat catches both.
//!
//! # Stopping without killing
//!
//! Stopping is a request, not a signal. The caller writes a small file and the
//! service notices it on its next tick, releases its own lock and exits.
//!
//! Terminating the process would be faster and worse. It needs different APIs
//! on every platform, it can strand a lock file if the kill succeeds but the
//! cleanup never runs, and it could interrupt a destruction midway. A service
//! that decides for itself when to stop always leaves things tidy.

use std::path::{Path, PathBuf};

use zerotrace_core::{Error, Result};

/// Where a vault's watcher records itself.
pub fn lock_path(vault: &Path) -> PathBuf {
    PathBuf::from(format!("{}.watch", vault.display()))
}

/// Where a stop request is left for that watcher.
pub fn stop_path(vault: &Path) -> PathBuf {
    PathBuf::from(format!("{}.watch.stop", vault.display()))
}

/// What a running watcher recorded about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchLock {
    /// Recorded for display only. Nothing depends on it.
    pub pid: u32,
    pub started_at: i64,
    /// Refreshed on every tick. This is what liveness is judged by.
    pub heartbeat_at: i64,
    pub interval_seconds: u64,
    /// Whether this watcher is permitted to destroy the vault.
    pub allow_destruction: bool,
}

impl WatchLock {
    fn encode(&self) -> String {
        format!(
            "pid={}\nstarted_at={}\nheartbeat_at={}\ninterval_seconds={}\nallow_destruction={}\n",
            self.pid,
            self.started_at,
            self.heartbeat_at,
            self.interval_seconds,
            self.allow_destruction
        )
    }

    fn decode(text: &str) -> Result<Self> {
        let mut pid = None;
        let mut started_at = 0i64;
        let mut heartbeat_at = 0i64;
        let mut interval_seconds = 0u64;
        let mut allow_destruction = false;
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "pid" => pid = v.trim().parse().ok(),
                "started_at" => started_at = v.trim().parse().unwrap_or(0),
                "heartbeat_at" => heartbeat_at = v.trim().parse().unwrap_or(0),
                "interval_seconds" => interval_seconds = v.trim().parse().unwrap_or(0),
                "allow_destruction" => allow_destruction = v.trim() == "true",
                _ => {}
            }
        }
        Ok(WatchLock {
            pid: pid.ok_or_else(|| Error::Format("watch lock has no pid".into()))?,
            started_at,
            heartbeat_at,
            interval_seconds,
            allow_destruction,
        })
    }
}

/// How long a lock may go unrefreshed before it is considered abandoned.
///
/// Three intervals plus a margin, so an ordinary slow tick or a briefly
/// suspended machine does not make a healthy watcher look dead.
pub fn staleness_limit(interval_seconds: u64) -> u64 {
    interval_seconds.saturating_mul(3).saturating_add(30)
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What is watching a vault, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchStatus {
    /// No watcher has registered.
    NotRunning,
    /// A watcher is registered and its process is alive.
    Running(WatchLock),
    /// A lock exists but its process is gone, so the vault is unwatched.
    Stale(WatchLock),
}

impl WatchStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, WatchStatus::Running(_))
    }
}

/// Reads the watch state for one vault.
pub fn status(vault: &Path) -> WatchStatus {
    let path = lock_path(vault);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return WatchStatus::NotRunning;
    };
    let Ok(lock) = WatchLock::decode(&text) else {
        // An unreadable lock is not evidence of a watcher.
        return WatchStatus::NotRunning;
    };
    // Judged by whether the lock is still being refreshed, not by asking the
    // operating system about a process id.
    let age = now_seconds().saturating_sub(lock.heartbeat_at);
    if age >= 0 && (age as u64) <= staleness_limit(lock.interval_seconds) {
        WatchStatus::Running(lock)
    } else {
        WatchStatus::Stale(lock)
    }
}

/// Registers this process as the watcher for a vault.
///
/// Refuses when a live watcher is already registered: two services on one
/// vault would race on the journal, and the second would be invisible to
/// anyone who later tried to stop the first.
pub fn acquire(vault: &Path, interval_seconds: u64, allow_destruction: bool) -> Result<WatchLock> {
    match status(vault) {
        WatchStatus::Running(existing) => {
            return Err(Error::Other(format!(
                "a watcher is already running for this vault as process {}. Stop it before \
                 starting another; two watchers would race on the same journal",
                existing.pid
            )))
        }
        WatchStatus::Stale(old) => {
            // The previous watcher died without cleaning up. Taking over is
            // correct, and worth saying so.
            eprintln!(
                "note: clearing a stale watch lock from process {}, which is no longer running",
                old.pid
            );
        }
        WatchStatus::NotRunning => {}
    }

    // A stop request left over from a previous run must not stop this one.
    let _ = std::fs::remove_file(stop_path(vault));

    let now = now_seconds();
    let lock = WatchLock {
        pid: std::process::id(),
        started_at: now,
        heartbeat_at: now,
        interval_seconds,
        allow_destruction,
    };
    std::fs::write(lock_path(vault), lock.encode())?;
    Ok(lock)
}

/// Refreshes this watcher's timestamp. Called on every tick.
///
/// Without this the lock goes stale and another watcher may take over, so a
/// service that stops calling it correctly stops being counted as the watcher.
pub fn heartbeat(vault: &Path) -> Result<()> {
    let path = lock_path(vault);
    let text = std::fs::read_to_string(&path)
        .map_err(|_| Error::Other("this vault's watch lock has gone".into()))?;
    let mut lock = WatchLock::decode(&text)?;
    if lock.pid != std::process::id() {
        // Another watcher took over. Refreshing would falsely claim its lock.
        return Err(Error::Other(
            "another watcher has taken over this vault".into(),
        ));
    }
    lock.heartbeat_at = now_seconds();
    std::fs::write(&path, lock.encode())?;
    Ok(())
}

/// Removes this process's registration.
pub fn release(vault: &Path) {
    if let WatchStatus::Running(lock) | WatchStatus::Stale(lock) = status(vault) {
        // Only remove our own lock, so a crashed run cannot delete the
        // registration of the watcher that replaced it.
        if lock.pid == std::process::id() {
            let _ = std::fs::remove_file(lock_path(vault));
        }
    }
    let _ = std::fs::remove_file(stop_path(vault));
}

/// Asks the watcher for a vault to stop.
pub fn request_stop(vault: &Path) -> Result<()> {
    match status(vault) {
        WatchStatus::NotRunning => {
            Err(Error::Other("no watcher is running for this vault".into()))
        }
        WatchStatus::Stale(_) => {
            // Nothing to ask; just tidy up.
            let _ = std::fs::remove_file(lock_path(vault));
            Ok(())
        }
        WatchStatus::Running(_) => {
            std::fs::write(stop_path(vault), b"stop\n")?;
            Ok(())
        }
    }
}

/// Whether a stop has been requested of this process.
pub fn stop_requested(vault: &Path) -> bool {
    stop_path(vault).exists()
}

/// Removes a lock whose process is gone.
pub fn clear_stale(vault: &Path) -> Result<()> {
    match status(vault) {
        WatchStatus::Stale(_) => {
            std::fs::remove_file(lock_path(vault))?;
            let _ = std::fs::remove_file(stop_path(vault));
            Ok(())
        }
        WatchStatus::Running(l) => Err(Error::Other(format!(
            "the watcher for this vault is still running as process {}",
            l.pid
        ))),
        WatchStatus::NotRunning => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ztwatch_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("v.azv")
    }

    #[test]
    fn an_unwatched_vault_reports_not_running() {
        let v = tmp("none");
        assert_eq!(status(&v), WatchStatus::NotRunning);
        assert!(request_stop(&v).is_err());
    }

    #[test]
    fn acquiring_registers_this_process_and_releasing_clears_it() {
        let v = tmp("acquire");
        let lock = acquire(&v, 300, true).unwrap();
        assert_eq!(lock.pid, std::process::id());
        assert!(lock.allow_destruction);

        match status(&v) {
            WatchStatus::Running(l) => {
                assert_eq!(l.pid, std::process::id());
                assert_eq!(l.interval_seconds, 300);
            }
            other => panic!("expected Running, got {other:?}"),
        }

        release(&v);
        assert_eq!(status(&v), WatchStatus::NotRunning);
    }

    #[test]
    fn a_second_watcher_is_refused() {
        // Two services on one vault would race on the journal, and the second
        // would be invisible to anyone trying to stop the first.
        let v = tmp("double");
        acquire(&v, 60, false).unwrap();
        let err = acquire(&v, 60, false).unwrap_err();
        assert!(format!("{err}").contains("already running"), "{err}");
        release(&v);
    }

    #[test]
    fn a_lock_that_stopped_being_refreshed_is_stale_not_running() {
        let v = tmp("stale");
        // A lock last refreshed long ago belongs to a watcher that is gone,
        // whatever its process id says.
        let abandoned = WatchLock {
            pid: std::process::id(),
            started_at: 1,
            heartbeat_at: 1,
            interval_seconds: 60,
            allow_destruction: false,
        };
        std::fs::write(lock_path(&v), abandoned.encode()).unwrap();
        assert!(matches!(status(&v), WatchStatus::Stale(_)));
        assert!(!status(&v).is_running());

        // Taking over from an abandoned lock is allowed.
        acquire(&v, 60, false).unwrap();
        assert!(status(&v).is_running());
        release(&v);
    }

    #[test]
    fn a_refreshed_lock_stays_live() {
        let v = tmp("beat");
        acquire(&v, 60, false).unwrap();
        heartbeat(&v).unwrap();
        assert!(status(&v).is_running());
        release(&v);
    }

    #[test]
    fn a_watcher_cannot_refresh_a_lock_another_took_over() {
        let v = tmp("takeover");
        // A lock owned by a different process id.
        let other = WatchLock {
            pid: std::process::id() + 1,
            started_at: now_seconds(),
            heartbeat_at: now_seconds(),
            interval_seconds: 60,
            allow_destruction: false,
        };
        std::fs::write(lock_path(&v), other.encode()).unwrap();
        let err = heartbeat(&v).unwrap_err();
        assert!(format!("{err}").contains("taken over"), "{err}");
    }

    #[test]
    fn the_staleness_limit_allows_for_a_slow_tick() {
        // Three intervals plus a margin, so an ordinary delay does not make a
        // healthy watcher look dead.
        assert!(staleness_limit(60) >= 180);
        assert!(staleness_limit(300) >= 900);
        // And a zero interval still leaves a usable window.
        assert!(staleness_limit(0) >= 30);
    }

    #[test]
    fn stopping_is_a_request_the_watcher_sees() {
        let v = tmp("stop");
        acquire(&v, 60, true).unwrap();
        assert!(!stop_requested(&v));
        request_stop(&v).unwrap();
        assert!(stop_requested(&v), "the watcher must be able to see the request");
        release(&v);
        assert!(!stop_requested(&v), "releasing clears the request too");
    }

    #[test]
    fn a_leftover_stop_request_does_not_stop_the_next_watcher() {
        let v = tmp("leftover");
        std::fs::write(stop_path(&v), b"stop\n").unwrap();
        acquire(&v, 60, false).unwrap();
        assert!(!stop_requested(&v), "a stale request must be cleared on acquire");
        release(&v);
    }

    #[test]
    fn each_vault_is_tracked_separately() {
        // Starting a watcher for one vault must say nothing about another.
        let a = tmp("sep_a");
        let b = a.with_file_name("other.azv");
        acquire(&a, 60, true).unwrap();
        assert!(status(&a).is_running());
        assert_eq!(status(&b), WatchStatus::NotRunning);
        assert!(request_stop(&b).is_err());
        release(&a);
    }

    #[test]
    fn an_unreadable_lock_is_not_treated_as_a_watcher() {
        let v = tmp("junk");
        std::fs::write(lock_path(&v), b"this is not a lock file").unwrap();
        assert_eq!(status(&v), WatchStatus::NotRunning);
    }
}
