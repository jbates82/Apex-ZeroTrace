//! The command surface the GUI talks to.
//!
//! # Why this crate exists
//!
//! The GUI must not contain cryptography or deadman logic. If it did, the
//! security boundary would run through interface code, and any defect there
//! could bypass the policy. So the front end is a client: it sends a request,
//! receives a plain data structure, and renders it.
//!
//! Three rules are enforced here rather than trusted to the caller.
//!
//! No response ever carries key material, a password, or plaintext file
//! contents. The types simply have nowhere to put them.
//!
//! The GUI cannot weaken policy (INV-8). Policy changes go through
//! `DeadmanPolicy::validate`, which refuses the dangerous shapes, and there is
//! no request that disarms a committed destruction.
//!
//! Destruction requires a confirmation token that the caller must echo back
//! exactly. A single mis-routed message cannot destroy a vault.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zerotrace_audit::{AuditLog, ChainStatus};
use zerotrace_auth::audit_events as ev;
use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::{self, TimeAnchor};
use zerotrace_core::{Assurance, Error, Result, VaultId};
use zerotrace_destroy::{authorize_explicit, execute, needs_resume, simulate, Trigger};
use zerotrace_journal::{AuditAnchor, AuditAnchorStatus, JournalStatus, StateJournal};
use zerotrace_policy::DeadmanPolicy;
use zerotrace_presence::{PresenceConfig, PresenceEngine, SignalKind};
use zerotrace_sanitize::SanitizationProfile;
use zerotrace_split::providers::ComponentProvider;
use zerotrace_split::{assess, ComponentKind, RecoveryToken, SplitBundle, UserProvider};
use zerotrace_vault::{Vault, VaultOptions};

/// The exact word a caller must send to confirm destruction.
pub const DESTROY_CONFIRMATION: &str = "DESTROY";

// ---------------------------------------------------------------------------
// Response types. None of these can carry a secret.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSummary {
    pub vault_id: String,
    pub format_version: u16,
    pub crypto_suite: String,
    pub compression: String,
    pub kdf_memory_kib: u32,
    pub kdf_time_cost: u32,
    pub factors: String,
    pub entry_count: usize,
    pub plaintext_bytes: u64,
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntrySummary {
    pub index: usize,
    pub path: String,
    pub size: u64,
    pub chunks: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadmanStatus {
    pub enabled: bool,
    pub state: String,
    pub recorded_state: String,
    pub confidence: u32,
    pub required_confidence: u32,
    pub seconds_since_strong: Option<u64>,
    pub seconds_remaining: Option<u64>,
    pub committed: bool,
    pub terminal: bool,
    pub needs_resume: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityStatus {
    pub header: String,
    pub manifest: String,
    pub integrity_root: String,
    pub chunks_checked: usize,
    pub chunks_failed: usize,
    pub intact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainStatusView {
    pub audit_records: u64,
    pub audit_chain: String,
    pub journal_records: u64,
    pub journal_chain: String,
    pub audit_anchor: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence: u64,
    pub event: String,
    pub timestamp: i64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRow {
    pub name: String,
    pub assurance: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DryRunStep {
    pub stage: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A GUI session bound to one vault path.
///
/// The session deliberately does not hold an unlocked [`Vault`] between
/// requests. Each operation unlocks, acts, and drops the keys, which keeps key
/// lifetime tied to a single operation rather than to how long a window
/// happens to be open.
pub struct Session {
    vault_path: PathBuf,
    /// Token files supplied for a split-protected vault. Paths only: the
    /// secrets are read when needed and dropped immediately after.
    tokens: Vec<PathBuf>,
    /// False when the password is the component that was lost.
    use_password: bool,
}

/// What split-key protection looks like for a vault, for display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitStatusView {
    pub enrolled: bool,
    pub threshold: u8,
    pub components: Vec<String>,
    pub resists_drive_theft: bool,
    pub tolerates_one_loss: bool,
    pub notes: Vec<String>,
}

impl Session {
    pub fn new<P: AsRef<Path>>(vault_path: P) -> Self {
        Self {
            vault_path: vault_path.as_ref().to_path_buf(),
            tokens: Vec::new(),
            use_password: true,
        }
    }

    /// Supplies token files for a split-protected vault.
    pub fn with_tokens(mut self, tokens: Vec<PathBuf>) -> Self {
        self.tokens = tokens;
        self
    }

    /// Opens using tokens alone, for when the password is what was lost.
    pub fn without_password(mut self) -> Self {
        self.use_password = false;
        self
    }

    pub fn tokens(&self) -> &[PathBuf] {
        &self.tokens
    }

    /// Where this vault records which custodian holds a component.
    ///
    /// A path, not a secret. Anyone reading it learns where to ask, and asking
    /// without a password-signed request gets them nothing.
    fn custodian_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.custodian", self.vault_path.display()))
    }

    /// The custodian directory for this vault, if one was established.
    pub fn custodian_dir(&self) -> Option<PathBuf> {
        std::fs::read_to_string(self.custodian_path())
            .ok()
            .map(|t| PathBuf::from(t.trim()))
            .filter(|p| !p.as_os_str().is_empty())
    }

    fn split_path(&self) -> PathBuf {
        zerotrace_vault::split_bundle_path(&self.vault_path)
    }

    /// Whether this vault requires a quorum of key components.
    pub fn is_split_protected(&self) -> bool {
        use std::io::Read;
        let Ok(mut f) = std::fs::File::open(&self.vault_path) else { return false };
        let mut hb = [0u8; zerotrace_format::HEADER_LEN];
        if f.read_exact(&mut hb).is_err() {
            return false;
        }
        zerotrace_format::Header::from_bytes(&hb)
            .map(|h| h.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0)
            .unwrap_or(false)
    }

    /// The single place a vault is opened, so the split path can never be
    /// bypassed by a caller that forgot about it.
    fn open_vault(&self, password: &str) -> Result<Vault> {
        if !self.is_split_protected() {
            return Vault::open(&self.vault_path, password.as_bytes());
        }

        // A split-protected vault reaches the duress identity too, and it has
        // to be tried before the components are gathered. Under coercion the
        // person may well have a token attached, and a duress password that
        // only worked on unprotected vaults would silently do nothing on
        // exactly the vaults most likely to need it.
        if self.use_password {
            if let Some(v) = Vault::try_duress_open(&self.vault_path, password.as_bytes())? {
                return Ok(v);
            }
        }
        // A custodian is a component too, so an empty token list is only a
        // problem when there is no custodian to ask either.
        if self.tokens.is_empty() && self.custodian_dir().is_none() {
            return Err(Error::Other(
                "this vault is split protected and needs a key component as well as its \
                 password. Add a recovery token."
                    .into(),
            ));
        }

        let mut components = Vec::new();
        if self.use_password {
            let salt_params = self.header_kdf()?;
            components.push((
                ComponentKind::User,
                UserProvider::from_password(password.as_bytes(), &salt_params.0, salt_params.1)?
                    .key()?,
            ));
        }
        for t in &self.tokens {
            // A file that is not a token contributes nothing, exactly like a
            // component that was never supplied. Failing the whole attempt
            // instead would let one stale or mistaken path block every valid
            // component beside it.
            let Ok(text) = std::fs::read_to_string(t) else { continue };
            let Ok(token) = RecoveryToken::decode(&text) else { continue };
            // A token file may be either share; the slot that does not match
            // simply yields nothing.
            components.push((ComponentKind::Remote, token.key()?));
            components.push((ComponentKind::Custodian, token.key()?));
        }

        // A custodian is asked last, so a vault that opens from local
        // components alone never needs it to be reachable.
        //
        // An expiry is remembered rather than raised. A vault whose remaining
        // components still reach the threshold must still open: telling
        // somebody their vault is lost when it is not would be worse than any
        // of the failures this reports.
        let mut expiry_note: Option<String> = None;
        if self.use_password {
            match self.fetch_custodian_component(password) {
                Ok(Some(key)) => components.push((ComponentKind::Custodian, key)),
                Ok(None) => {}
                Err(e) => expiry_note = Some(e.to_string()),
            }
        }

        match Vault::open_with_components(&self.vault_path, &components) {
            Ok(v) => Ok(v),
            // Only now does the expiry matter, because only now is it the
            // reason the vault did not open.
            Err(e) => match expiry_note {
                Some(note) => Err(Error::Other(note)),
                None => Err(e),
            },
        }
    }

    fn header_kdf(&self) -> Result<([u8; 32], zerotrace_kdf::KdfParams)> {
        use std::io::Read;
        let mut f = std::fs::File::open(&self.vault_path)?;
        let mut hb = [0u8; zerotrace_format::HEADER_LEN];
        f.read_exact(&mut hb)
            .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
        let h = zerotrace_format::Header::from_bytes(&hb)?;
        Ok((h.kdf_salt, h.kdf_params))
    }

    /// Reports the watcher for this vault, if any.
    pub fn watch_status(&self) -> WatchView {
        use zerotrace_platform::watch::{status, WatchStatus};
        match status(&self.vault_path) {
            WatchStatus::NotRunning => WatchView {
                running: false,
                stale: false,
                pid: 0,
                interval_seconds: 0,
                allow_destruction: false,
            },
            WatchStatus::Running(l) => WatchView {
                running: true,
                stale: false,
                pid: l.pid,
                interval_seconds: l.interval_seconds,
                allow_destruction: l.allow_destruction,
            },
            WatchStatus::Stale(l) => WatchView {
                running: false,
                stale: true,
                pid: l.pid,
                interval_seconds: l.interval_seconds,
                allow_destruction: l.allow_destruction,
            },
        }
    }

    /// Asks this vault's watcher to stop. Only ever this vault's.
    pub fn stop_watch(&self) -> Result<()> {
        zerotrace_platform::watch::request_stop(&self.vault_path)
    }

    pub fn clear_stale_watch(&self) -> Result<()> {
        zerotrace_platform::watch::clear_stale(&self.vault_path)
    }

    /// Launches a watcher in its own console, detached from this process.
    ///
    /// Detached on purpose: the point is that closing or crashing the window
    /// leaves the service running. It still dies at logout or reboot, which is
    /// what the generated service unit is for, and the window says so rather
    /// than implying otherwise.
    pub fn start_watch(&self, interval_seconds: u64, allow_destruction: bool) -> Result<()> {
        use std::process::Command;

        if self.watch_status().running {
            return Err(Error::Other(
                "a watcher is already running for this vault".into(),
            ));
        }

        // Found beside this executable rather than on PATH: nothing in this
        // project installs itself, so PATH is the wrong assumption.
        let ztd = self.service_program()?;
        let vault = self.vault_path.display().to_string();
        let interval = interval_seconds.to_string();

        let spawned = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", "start", "Apex ZeroTrace service"]);
            c.arg(&ztd).arg("watch").arg(&vault).arg("--interval").arg(&interval);
            if allow_destruction {
                c.arg("--allow-destruction");
            }
            c.spawn()
        } else {
            let mut c = Command::new(&ztd);
            c.arg("watch").arg(&vault).arg("--interval").arg(&interval);
            if allow_destruction {
                c.arg("--allow-destruction");
            }
            c.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            c.spawn()
        };

        spawned.map_err(|e| Error::Other(format!("could not start the service: {e}")))?;
        Ok(())
    }

    /// Consecutive failed password attempts since the last success.
    ///
    /// Counted from the audit log rather than a separate tally, so clearing it
    /// means editing a hash chain that `zt audit verify` then reports.
    pub fn consecutive_failures(&self) -> u32 {
        let Ok(log) = AuditLog::open(self.audit_path(), VaultId::nil()) else {
            return 0;
        };
        let Ok(records) = log.records() else { return 0 };
        let mut count = 0u32;
        for r in records.iter().rev() {
            match r.event.as_str() {
                ev::AUTH_FAILURE => count += 1,
                ev::AUTH_SUCCESS => break,
                _ => {}
            }
        }
        count
    }

    /// How long the caller must wait before trying again.
    pub fn attempt_delay(&self) -> u64 {
        backoff_seconds(self.consecutive_failures())
    }

    /// Whether the newest watcher event was an unexpected stop.
    ///
    /// Cannot be prevented, so it is reported. An attacker who kills a watcher
    /// cannot also make the record of it disappear without breaking the audit
    /// chain, which `zt audit verify` would then report.
    pub fn watcher_was_interrupted(&self) -> bool {
        let Ok(log) = AuditLog::open(self.audit_path(), VaultId::nil()) else {
            return false;
        };
        let Ok(records) = log.records() else { return false };
        records
            .iter()
            .rev()
            .find(|r| r.event.starts_with("WATCH_"))
            .map(|r| r.event == ev::WATCH_INTERRUPTED)
            .unwrap_or(false)
    }

    /// Summarizes this vault without needing a password.
    pub fn overview(&self) -> VaultOverview {
        let status = self.deadman_status().ok();
        let watch = self.watch_status();
        let policy = self.load_policy();
        VaultOverview {
            path: self.vault_path.display().to_string(),
            name: self
                .vault_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            state: status
                .as_ref()
                .map(|s| if s.terminal { "DESTROYED".into() } else { s.state.clone() })
                .unwrap_or_else(|| "?".into()),
            watched: watch.running,
            armed: watch.allow_destruction && watch.running,
            seconds_remaining: status.as_ref().and_then(|s| s.seconds_remaining),
            policy_enabled: policy.enabled,
            interrupted: self.watcher_was_interrupted(),
        }
    }

    /// Asks this vault's custodian for the component it holds.
    ///
    /// Returns `None` when there is no custodian, or when it cannot be
    /// reached: an unreachable custodian must not stop a vault that can open
    /// from the components already to hand. An expired one is different, and
    /// is reported, because that is permanent and the owner needs to know why
    /// the vault will not open rather than being told the password is wrong.
    fn fetch_custodian_component(
        &self,
        password: &str,
    ) -> Result<Option<zerotrace_secure_memory::Key256>> {
        use zerotrace_remote::custodian::{Custodian, DirectoryCustodian};
        use zerotrace_remote::{signing_identity, Intent, Request, Verdict};

        let Some(dir) = self.custodian_dir() else { return Ok(None) };
        if !dir.exists() {
            return Ok(None);
        }
        let Some(vault_id) = self.header_vault_id() else { return Ok(None) };
        let (salt, params) = self.header_kdf()?;
        let key = signing_identity(password.as_bytes(), &salt, params)?;

        let now = self.now().wall;
        let request = Request::sign(&key, vault_id, Intent::Release, now);
        let custodian = DirectoryCustodian::new(&dir);

        match custodian.handle(&request, now)? {
            Verdict::Released(bytes) => {
                if bytes.len() != 32 {
                    return Ok(None);
                }
                let mut k = zerotrace_secure_memory::Key256::zeroed();
                k.expose_mut().copy_from_slice(&bytes);
                Ok(Some(k))
            }
            Verdict::Expired { expired_at } => Err(Error::Other(format!(
                "this vault's custodian expired at {expired_at} and destroyed the component \
                 it held. That component cannot be recovered. The vault opens only if its \
                 remaining components still reach the threshold"
            ))),
            // A refusal here is not fatal: the other components may suffice.
            _ => Ok(None),
        }
    }

    /// Sets a duress password and the files it reveals.
    ///
    /// The real password opens the vault so the decoy can be written into the
    /// same container; the duress password is what will later open it into
    /// those files, destroying the real contents as it does.
    pub fn set_duress_password(
        &self,
        password: &str,
        duress_password: &str,
        decoy_files: &[PathBuf],
    ) -> Result<()> {
        self.set_duress_password_with_progress(password, duress_password, decoy_files, |_, _| {})
    }

    /// Sets a duress password, reporting progress as the decoy is built.
    pub fn set_duress_password_with_progress(
        &self,
        password: &str,
        duress_password: &str,
        decoy_files: &[PathBuf],
        progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        if decoy_files.is_empty() {
            return Err(Error::Other(
                "a duress password needs something to show. An empty vault under coercion \
                 invites the question of what else there is"
                    .into(),
            ));
        }
        zerotrace_kdf::strength::require_acceptable(duress_password)?;
        if duress_password == password {
            return Err(Error::Other(
                "the duress password must be different from the real one".into(),
            ));
        }

        let files: Vec<(PathBuf, String)> = decoy_files
            .iter()
            .map(|p| {
                let n = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".into());
                (p.clone(), n)
            })
            .collect();

        let mut v = self.open_vault(password)?;
        let id = v.vault_id();
        v.set_duress_password_with_progress(
            password.as_bytes(),
            duress_password.as_bytes(),
            &files,
            progress,
        )?;
        v.close();
        self.record(id, "DURESS_CONFIGURED", "");
        Ok(())
    }

    /// Reports this vault's custody arrangement without needing a password.
    pub fn custody_status(&self) -> CustodyView {
        use zerotrace_remote::custodian::{Custodian, DirectoryCustodian};

        let Some(dir) = self.custodian_dir() else {
            return CustodyView {
                established: false,
                directory: String::new(),
                reachable: false,
                expired: false,
                seconds_remaining: None,
            };
        };
        let directory = dir.display().to_string();
        let Some(vault_id) = self.header_vault_id() else {
            return CustodyView {
                established: true,
                directory,
                reachable: false,
                expired: false,
                seconds_remaining: None,
            };
        };
        let now = self.now().wall;
        match DirectoryCustodian::new(&dir).status(vault_id, now) {
            Ok(Some((deadline, expired))) => CustodyView {
                established: true,
                directory,
                reachable: true,
                expired,
                seconds_remaining: if expired {
                    None
                } else {
                    Some((deadline - now).max(0) as u64)
                },
            },
            // Not reachable, or holds nothing for this vault. Either way the
            // component cannot be fetched, and saying so is more use than
            // showing a stale figure.
            _ => CustodyView {
                established: true,
                directory,
                reachable: false,
                expired: false,
                seconds_remaining: None,
            },
        }
    }

    /// Checks in with this vault's custodian.
    pub fn custodian_check_in(&self, password: &str) -> Result<i64> {
        use zerotrace_remote::custodian::{Custodian, DirectoryCustodian};
        use zerotrace_remote::{signing_identity, Intent, Request, Verdict};

        let dir = self
            .custodian_dir()
            .ok_or_else(|| Error::Other("no custodian is set for this vault".into()))?;
        let vault_id = self
            .header_vault_id()
            .ok_or_else(|| Error::Other("this vault's header could not be read".into()))?;
        let (salt, params) = self.header_kdf()?;
        let key = signing_identity(password.as_bytes(), &salt, params)?;

        let now = self.now().wall;
        let request = Request::sign(&key, vault_id, Intent::CheckIn, now);
        match DirectoryCustodian::new(&dir).handle(&request, now)? {
            Verdict::CheckedIn { deadline } => {
                self.record(vault_id, "CUSTODY_CHECK_IN", "");
                Ok(deadline)
            }
            Verdict::Expired { expired_at } => Err(Error::Other(format!(
                "this vault's custodian expired at {expired_at}; the component it held is gone"
            ))),
            other => Err(Error::Other(format!(
                "the custodian refused: {}",
                other.label()
            ))),
        }
    }

    /// Establishes custody, handing a component key to a custodian.
    pub fn establish_custody(
        &self,
        password: &str,
        dir: &Path,
        component_token: &Path,
        timeout_seconds: u64,
    ) -> Result<()> {
        use zerotrace_remote::custodian::{Custodian, DirectoryCustodian, HeldShare};
        use zerotrace_remote::verifying_key;

        if timeout_seconds < 3600 {
            return Err(Error::Other("a custody timeout below an hour is refused".into()));
        }
        let vault_id = self
            .header_vault_id()
            .ok_or_else(|| Error::Other("this vault's header could not be read".into()))?;
        let token = RecoveryToken::decode(&std::fs::read_to_string(component_token)?)?;
        let (salt, params) = self.header_kdf()?;
        let owner_key = verifying_key(password.as_bytes(), &salt, params)?;

        DirectoryCustodian::new(dir).enroll(&HeldShare::new(
            vault_id,
            token.key()?.expose().to_vec(),
            owner_key,
            timeout_seconds,
            self.now().wall,
        ))?;
        self.set_custodian(dir)
    }

    /// Records where this vault's custodian is.
    pub fn set_custodian(&self, dir: &Path) -> Result<()> {
        std::fs::write(self.custodian_path(), format!("{}\n", dir.display()))?;
        let _ = zerotrace_core::restrict_permissions(&self.custodian_path());
        self.record(VaultId::nil(), "CUSTODY_ESTABLISHED", "");
        Ok(())
    }

    /// Reports whether this vault's watcher restarts at login.
    pub fn autostart_status(&self) -> AutostartView {
        use zerotrace_platform::autostart;
        let installed = autostart::installed(&self.vault_path);
        AutostartView {
            installed: installed.is_some(),
            allows_destruction: autostart::installed_allows_destruction(&self.vault_path),
            location: installed
                .map(|p| p.display().to_string())
                .or_else(|| autostart::entry_path(&self.vault_path).ok().map(|p| p.display().to_string()))
                .unwrap_or_default(),
            description: autostart::description().to_string(),
        }
    }

    /// Registers the watcher to start when this user logs in.
    ///
    /// Writes only to the current user's own startup location, so nothing is
    /// elevated and nothing is installed for other accounts.
    pub fn install_autostart(
        &self,
        interval_seconds: u64,
        allow_destruction: bool,
    ) -> Result<String> {
        use zerotrace_platform::autostart::{install, AutostartPlan};
        let ztd = self.service_program()?;
        let mut plan = AutostartPlan::new(&ztd, &self.vault_path);
        plan.interval_seconds = interval_seconds;
        plan.allow_destruction = allow_destruction;
        let path = install(&plan)?;
        self.record(VaultId::nil(), "AUTOSTART_INSTALLED", "");
        Ok(path.display().to_string())
    }

    pub fn remove_autostart(&self) -> Result<()> {
        zerotrace_platform::autostart::remove(&self.vault_path)?;
        self.record(VaultId::nil(), "AUTOSTART_REMOVED", "");
        Ok(())
    }

    /// Locates the service program beside this one.
    fn service_program(&self) -> Result<PathBuf> {
        let exe = std::env::current_exe()
            .map_err(|e| Error::Other(format!("could not locate this program: {e}")))?;
        let dir = exe.parent().ok_or_else(|| Error::Other("no program directory".into()))?;
        let ztd = dir.join(if cfg!(windows) { "ztd.exe" } else { "ztd" });
        if !ztd.exists() {
            return Err(Error::Other(format!(
                "the service program was not found at {}. Build it with `cargo build \
                 --release` and try again",
                ztd.display()
            )));
        }
        Ok(ztd)
    }

    /// Reports split protection for display.
    pub fn split_status(&self) -> Result<SplitStatusView> {
        let path = self.split_path();
        if !path.exists() {
            return Ok(SplitStatusView {
                enrolled: false,
                threshold: 0,
                components: Vec::new(),
                resists_drive_theft: false,
                tolerates_one_loss: false,
                notes: vec![
                    "This vault is protected by its password alone. Someone who removes the \
                     drive and copies the vault needs only to guess that password, offline, \
                     for as long as they like."
                        .into(),
                ],
            });
        }
        let bundle = SplitBundle::decode(&std::fs::read(&path)?)?;
        let a = assess(&bundle);
        Ok(SplitStatusView {
            enrolled: true,
            threshold: a.threshold,
            components: a.enrolled.iter().map(|k| k.label().to_string()).collect(),
            resists_drive_theft: a.resists_drive_theft,
            tolerates_one_loss: a.tolerates_one_loss,
            notes: a.notes,
        })
    }

    /// Enrols split protection, writing both token files.
    ///
    /// Only the wrapped key is rewritten; nothing stored is re-encrypted.
    pub fn enroll_split(
        &self,
        password: &str,
        token_path: &Path,
        custodian_path: Option<&Path>,
    ) -> Result<SplitStatusView> {
        for p in [Some(token_path), custodian_path].into_iter().flatten() {
            if p.exists() {
                return Err(Error::Other(format!(
                    "{} already exists; refusing to overwrite a recovery token",
                    p.display()
                )));
            }
        }

        let mut v = self.open_vault(password)?;
        let id = v.vault_id();
        let (salt, params) = self.header_kdf()?;
        let user = UserProvider::from_password(password.as_bytes(), &salt, params)?.key()?;

        let token = RecoveryToken::generate();
        let custodian = custodian_path.map(|_| RecoveryToken::generate());

        let mut components = vec![(ComponentKind::User, user), (ComponentKind::Remote, token.key()?)];
        if let Some(c) = &custodian {
            components.push((ComponentKind::Custodian, c.key()?));
        }

        v.enroll_split(&components)?;
        v.close();

        std::fs::write(token_path, format!("{}\n", token.encode()))?;
        let _ = zerotrace_core::restrict_permissions(token_path);
        if let (Some(p), Some(c)) = (custodian_path, &custodian) {
            std::fs::write(p, format!("{}\n", c.encode()))?;
            let _ = zerotrace_core::restrict_permissions(p);
        }
        self.record(id, "SPLIT_ENROLLED", "");
        self.split_status()
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    fn audit_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.audit", self.vault_path.display()))
    }
    fn journal_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.journal", self.vault_path.display()))
    }
    fn policy_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.policy", self.vault_path.display()))
    }

    fn record(&self, id: VaultId, event: &str, detail: &str) {
        if let Ok(mut log) = AuditLog::open(self.audit_path(), id) {
            let _ = log.append(event, detail);
        }
    }

    /// The current time, never earlier than something already recorded.
    ///
    /// Monotonic time is process-local, so across a restart it says nothing
    /// and the wall clock is all that is left. Setting the monotonic field
    /// from the wall clock, as this used to, made the two agree by
    /// construction and disabled the rollback check entirely: shutting down,
    /// winding the clock back and starting again bought unlimited time.
    ///
    /// What survives a restart is what was written down. The audit log and
    /// journal are append-only and timestamped, so their newest record is a
    /// time known to have happened, and the clock is not trusted below it.
    ///
    /// This does not stop somebody editing those files. That is rollback
    /// resistance, which needs an anchor they do not control and is reported
    /// as NOT IMPLEMENTED.
    fn now(&self) -> TimeAnchor {
        let raw = time::now(std::time::Instant::now());
        let (corrected, _) = time::not_before(raw, self.latest_recorded_time());
        corrected
    }

    /// The newest timestamp in anything written beside this vault.
    fn latest_recorded_time(&self) -> i64 {
        let mut newest = 0i64;
        if let Ok(log) = AuditLog::open(self.audit_path(), VaultId::nil()) {
            if let Ok(records) = log.records() {
                if let Some(r) = records.last() {
                    newest = newest.max(r.timestamp);
                }
            }
        }
        if let Ok(journal) = StateJournal::open(self.journal_path(), VaultId::nil()) {
            if let Ok(records) = journal.records() {
                if let Some(r) = records.last() {
                    newest = newest.max(r.observed.wall);
                }
            }
        }
        newest
    }

    // ---- vault ----

    pub fn create(&self, password: &str, opts: &VaultOptions) -> Result<VaultSummary> {
        if password.is_empty() {
            return Err(Error::Other("a password is required".into()));
        }
        // The only moment a password can be chosen, so the only moment the
        // floor can be applied. Opening an older vault never checks this.
        zerotrace_kdf::strength::require_acceptable(password)?;
        let v = Vault::create(&self.vault_path, password.as_bytes(), opts)?;
        let id = v.vault_id();
        let summary = summarize(&v);
        v.close();
        self.record(id, ev::VAULT_CREATED, "");
        Ok(summary)
    }

    pub fn unlock(&self, password: &str) -> Result<VaultSummary> {
        match self.open_vault(password) {
            Ok(v) => {
                let id = v.vault_id();
                let s = summarize(&v);
                v.close();
                self.record(id, ev::AUTH_SUCCESS, "gui");
                self.record(id, ev::VAULT_OPENED, "");
                Ok(s)
            }
            Err(e) => {
                self.record(VaultId::nil(), ev::AUTH_FAILURE, "gui");

                // Destruction after repeated failures is opt-in and off by
                // default. When it is on, it fires here, on the vault's own
                // policy, and the audit log carries the reason.
                let policy = self.load_policy();
                if policy.destroy_after_failures > 0
                    && self.consecutive_failures() >= policy.destroy_after_failures
                {
                    self.record(
                        VaultId::nil(),
                        "DESTRUCTION_AUTHORIZED",
                        "repeated password failures",
                    );
                    if let Err(inner) = self.destroy_after_failed_attempts() {
                        return Err(Error::Other(format!(
                            "{e}. The failure limit was reached but destruction did not \
                             complete: {inner}"
                        )));
                    }
                    return Err(Error::Other(format!(
                        "{e}. The failure limit set on this vault was reached and the vault \
                         has been destroyed."
                    )));
                }
                Err(e)
            }
        }
    }

    /// Destroys a vault because its failure limit was reached.
    ///
    /// Separate from `panic_destroy` because there is no password to open it
    /// with: the whole reason this runs is that nobody supplied a correct one.
    /// It goes through the same journal authorization so the record is the
    /// same shape as any other destruction.
    fn destroy_after_failed_attempts(&self) -> Result<()> {
        let log = AuditLog::open(self.audit_path(), VaultId::nil())?;
        let records = log.records()?;
        let id = records.first().map(|r| r.vault_id).unwrap_or_else(VaultId::nil);
        let anchor = AuditAnchor {
            records: records.len() as u64,
            last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
        };
        let now = self.now();
        let mut journal = StateJournal::open(self.journal_path(), id)?;
        authorize_explicit(&mut journal, id, now, anchor)?;
        execute(
            &self.vault_path,
            &mut journal,
            SanitizationProfile::Enhanced,
            Trigger::PanicDestroy,
            now,
        )?;
        Ok(())
    }

    pub fn list(&self, password: &str) -> Result<Vec<EntrySummary>> {
        let v = self.open_vault(password)?;
        let out = v
            .entries()
            .iter()
            .enumerate()
            .map(|(i, e)| EntrySummary {
                index: i,
                path: e.path.clone(),
                size: e.size,
                chunks: e.chunks.len(),
            })
            .collect();
        v.close();
        Ok(out)
    }

    pub fn import(&self, password: &str, source: &Path, stored_as: &str) -> Result<()> {
        self.import_with_progress(password, source, stored_as, |_, _| {})
    }

    /// Imports a file, reporting bytes done and total as it goes.
    pub fn import_with_progress(
        &self,
        password: &str,
        source: &Path,
        stored_as: &str,
        progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        let mut v = self.open_vault(password)?;
        let id = v.vault_id();
        v.import_with_progress(source, stored_as, progress)?;
        v.close();
        // The stored name is not recorded: it is exactly the metadata the
        // vault exists to hide.
        self.record(id, ev::FILE_IMPORTED, "");
        Ok(())
    }

    pub fn export(&self, password: &str, index: usize, dest_dir: &Path) -> Result<String> {
        self.export_with_progress(password, index, dest_dir, |_, _| {})
    }

    /// Exports an entry, reporting bytes done and total as it goes.
    pub fn export_with_progress(
        &self,
        password: &str,
        index: usize,
        dest_dir: &Path,
        progress: impl FnMut(u64, u64),
    ) -> Result<String> {
        let v = self.open_vault(password)?;
        let id = v.vault_id();
        // Noted before the handle is consumed. Extraction under duress hands
        // over the decoy and then leaves nothing behind: the container holds
        // only unreadable bytes and a decoy by this point, and a large
        // container with two small files in it invites the question the decoy
        // exists to prevent.
        let under_duress = v.opened_as() == zerotrace_vault::Identity::Decoy;
        let p = v.export_with_progress(index, dest_dir, progress)?;
        v.close();

        if under_duress {
            let failed = Vault::purge_all(&self.vault_path);
            if !failed.is_empty() {
                // Reported rather than swallowed. A file that survived is
                // worth knowing about, and this is the only place it can be
                // said.
                return Err(Error::Other(format!(
                    "extracted, but these could not be removed: {}",
                    failed.join(", ")
                )));
            }
            // Deliberately no audit record. The log is about to be deleted,
            // and writing to it first would recreate the file.
            return Ok(p.to_string_lossy().into_owned());
        }

        self.record(id, ev::FILE_EXPORTED, "");
        Ok(p.to_string_lossy().into_owned())
    }

    pub fn verify(&self, password: &str) -> Result<IntegrityStatus> {
        let v = self.open_vault(password)?;
        let id = v.vault_id();
        let r = v.verify()?;
        v.close();
        self.record(
            id,
            if r.is_intact() { ev::INTEGRITY_VERIFIED } else { ev::INTEGRITY_FAILED },
            "",
        );
        Ok(IntegrityStatus {
            header: r.header_authentic.label().into(),
            manifest: r.manifest_authentic.label().into(),
            integrity_root: r.integrity_root_matches.label().into(),
            chunks_checked: r.chunks_checked,
            chunks_failed: r.chunks_failed,
            intact: r.is_intact(),
        })
    }

    // ---- deadman ----

    pub fn load_policy(&self) -> DeadmanPolicy {
        let Ok(text) = std::fs::read_to_string(self.policy_path()) else {
            return DeadmanPolicy::default();
        };
        let mut p = DeadmanPolicy::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "enabled" => p.enabled = v == "true",
                "timeout_seconds" => p.timeout_seconds = v.parse().unwrap_or(p.timeout_seconds),
                "heartbeat_seconds" => {
                    p.heartbeat_seconds = v.parse().unwrap_or(p.heartbeat_seconds)
                }
                "required_confidence" => {
                    p.required_confidence = v.parse().unwrap_or(p.required_confidence)
                }
                "warning_threshold" => {
                    p.warning_threshold = v.parse().unwrap_or(p.warning_threshold)
                }
                "critical_threshold" => {
                    p.critical_threshold = v.parse().unwrap_or(p.critical_threshold)
                }
                "destroy_after_failures" => {
                    p.destroy_after_failures = v.parse().unwrap_or(p.destroy_after_failures)
                }
                _ => {}
            }
        }
        if p.validate().is_err() {
            return DeadmanPolicy::default();
        }
        p
    }

    /// Saves a policy. Invalid shapes are refused, so the GUI cannot weaken
    /// the vault by sending an unchecked structure (INV-8).
    pub fn save_policy(&self, policy: &DeadmanPolicy) -> Result<()> {
        policy.validate()?;
        let text = format!(
            "enabled = {}\ntimeout_seconds = {}\nheartbeat_seconds = {}\nrequired_confidence = {}\nwarning_threshold = {}\ncritical_threshold = {}\ndestroy_after_failures = {}\n",
            policy.enabled,
            policy.timeout_seconds,
            policy.heartbeat_seconds,
            policy.required_confidence,
            policy.warning_threshold,
            policy.critical_threshold,
            policy.destroy_after_failures
        );
        std::fs::write(self.policy_path(), text)?;
        self.record(VaultId::nil(), ev::POLICY_CHANGED, "");
        Ok(())
    }

    fn presence(&self) -> Result<(u32, Option<u64>)> {
        let log = AuditLog::open(self.audit_path(), VaultId::nil())?;
        // Scoring follows the vault's own policy, so the heartbeat setting
        // actually governs how long a check-in stays fully credited.
        let policy = self.load_policy();
        let mut engine = PresenceEngine::new(PresenceConfig::from_policy(
            policy.heartbeat_seconds,
            policy.timeout_seconds,
        ));
        for r in log.records()? {
            let kind = match r.event.as_str() {
                ev::AUTH_SUCCESS => SignalKind::PasswordAuth,
                "DEADMAN_CHECKIN" => SignalKind::ExplicitCheckIn,
                ev::FILE_IMPORTED | ev::FILE_EXPORTED | ev::VAULT_OPENED => {
                    SignalKind::VaultOperation
                }
                _ => continue,
            };
            engine.observe(
                kind,
                TimeAnchor { wall: r.timestamp, monotonic: r.timestamp.max(0) as u64 },
            );
        }
        let a = engine.assess(self.now());
        Ok((a.confidence, a.last_strong_age))
    }

    /// The vault's own identifier, read from its header.
    ///
    /// Unauthenticated, and used only to tell one vault from another at the
    /// same path. Nothing is trusted on the strength of it.
    fn header_vault_id(&self) -> Option<VaultId> {
        use std::io::Read;
        let mut f = std::fs::File::open(&self.vault_path).ok()?;
        let mut hb = [0u8; zerotrace_format::HEADER_LEN];
        f.read_exact(&mut hb).ok()?;
        zerotrace_format::Header::from_bytes(&hb).ok().map(|h| h.vault_id)
    }

    /// Whether the journal beside this vault actually describes it.
    ///
    /// Destroying a vault leaves its journal behind on purpose: it is the
    /// record of what happened. Creating a new vault with the same name would
    /// otherwise inherit that record and be reported as destroyed before it
    /// had been used.
    fn journal_describes_this_vault(&self, journal: &StateJournal) -> bool {
        let Some(recorded) = journal.records().ok().and_then(|r| r.last().map(|x| x.vault_id))
        else {
            return true; // no records yet, so nothing to disagree with
        };
        match self.header_vault_id() {
            Some(actual) => recorded == actual,
            // No readable header: the container is gone, so the journal is the
            // only account of it and is taken at its word.
            None => true,
        }
    }

    pub fn deadman_status(&self) -> Result<DeadmanStatus> {
        let (confidence, since) = self.presence()?;
        let policy = self.load_policy();
        let since_strong = since.unwrap_or(u64::MAX);
        let computed = policy.evaluate(confidence, since_strong);
        let journal = StateJournal::open(self.journal_path(), VaultId::nil())?;
        if !self.journal_describes_this_vault(&journal) {
            // A leftover journal from a different vault at this path says
            // nothing about this one.
            return Ok(DeadmanStatus {
                enabled: policy.enabled,
                state: computed.label().into(),
                recorded_state: zerotrace_core::state::DeadmanState::Normal.label().into(),
                confidence,
                required_confidence: policy.required_confidence,
                seconds_since_strong: since,
                seconds_remaining: policy.remaining(since_strong),
                committed: false,
                terminal: false,
                needs_resume: false,
            });
        }

        Ok(DeadmanStatus {
            enabled: policy.enabled,
            state: computed.label().into(),
            recorded_state: journal.state().label().into(),
            confidence,
            required_confidence: policy.required_confidence,
            seconds_since_strong: since,
            seconds_remaining: policy.remaining(since_strong),
            committed: journal.state().is_committed(),
            terminal: journal.state().is_terminal(),
            needs_resume: needs_resume(&journal),
        })
    }

    /// A check-in requires the password: it is a strong signal, so it has to
    /// cost a credential or the presence model is decorative.
    pub fn check_in(&self, password: &str) -> Result<DeadmanStatus> {
        let v = self.open_vault(password)?;
        let id = v.vault_id();
        v.close();
        self.record(id, "DEADMAN_CHECKIN", "gui");

        // Anchor the audit log in the state journal. Without this the audit
        // chain cannot be checked for a removed tail, because a prefix of a
        // valid chain is itself valid.
        let (confidence, since) = self.presence()?;
        let policy = self.load_policy();
        let computed = policy.evaluate(confidence, since.unwrap_or(u64::MAX));
        let log = AuditLog::open(self.audit_path(), id)?;
        let records = log.records()?;
        let anchor = AuditAnchor {
            records: records.len() as u64,
            last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
        };
        let now = self.now();
        let deadline = if policy.enabled { now.wall + policy.timeout_seconds as i64 } else { 0 };

        let mut journal = StateJournal::open(self.journal_path(), id)?;
        // Recording is best effort: a journal failure must be visible without
        // making a successful check-in look like a failure.
        if journal.state() != computed {
            let _ = journal.record(computed, now, deadline, confidence, anchor);
        } else {
            let _ = journal.record(computed, now, deadline, confidence, anchor);
        }

        self.deadman_status()
    }

    // ---- integrity of the records themselves ----

    pub fn chain_status(&self) -> Result<ChainStatusView> {
        let log = AuditLog::open(self.audit_path(), VaultId::nil())?;
        let audit_records = log.records()?;
        let journal = StateJournal::open(self.journal_path(), VaultId::nil())?;

        let audit_chain = match log.verify()? {
            ChainStatus::Intact { .. } => Assurance::Verified,
            ChainStatus::Broken { .. } => Assurance::Failed,
        };
        let (journal_chain, journal_records) = match journal.verify()? {
            JournalStatus::Intact { records, .. } => (Assurance::Verified, records),
            JournalStatus::Broken { .. } => (Assurance::Failed, 0),
        };

        let lookup = |i: u64| audit_records.get(i as usize).map(|r| r.hash);
        let (anchor, detail) =
            match journal.check_audit_anchor(audit_records.len() as u64, lookup)? {
                AuditAnchorStatus::Consistent => (Assurance::Verified, String::new()),
                AuditAnchorStatus::NoAnchor => (
                    Assurance::NotAttempted,
                    "No check-in has anchored the audit log yet.".into(),
                ),
                AuditAnchorStatus::Truncated { expected, found } => (
                    Assurance::Failed,
                    format!("Audit log holds {found} records; the journal recorded {expected}."),
                ),
                AuditAnchorStatus::Diverged { at } => (
                    Assurance::Failed,
                    format!("Audit record {at} no longer matches the anchored hash."),
                ),
            };

        Ok(ChainStatusView {
            audit_records: audit_records.len() as u64,
            audit_chain: audit_chain.label().into(),
            journal_records,
            journal_chain: journal_chain.label().into(),
            audit_anchor: anchor.label().into(),
            detail,
        })
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let log = AuditLog::open(self.audit_path(), VaultId::nil())?;
        let mut recs = log.records()?;
        if recs.len() > limit {
            recs.drain(..recs.len() - limit);
        }
        Ok(recs
            .into_iter()
            .map(|r| AuditEntry {
                sequence: r.sequence,
                event: r.event,
                timestamp: r.timestamp,
                detail: r.detail,
            })
            .collect())
    }

    // ---- destruction ----

    pub fn dry_run(&self) -> Vec<DryRunStep> {
        simulate(&self.vault_path, SanitizationProfile::Enhanced)
            .into_iter()
            .map(|(stage, detail)| DryRunStep { stage, detail })
            .collect()
    }

    /// PANIC LOCK. Never destroys anything.
    ///
    /// Because a session holds no keys between requests, there is nothing
    /// resident to tear down, and this reports that rather than implying it
    /// closed something.
    pub fn panic_lock(&self) -> Vec<CapabilityRow> {
        vec![
            CapabilityRow {
                name: "Vault contents".into(),
                assurance: "UNTOUCHED".into(),
                note: "Panic lock never destroys data.".into(),
            },
            CapabilityRow {
                name: "Resident keys".into(),
                assurance: Assurance::Verified.label().into(),
                note: "No key material is held between requests; each operation unlocks, \
                       acts and zeroes."
                    .into(),
            },
            CapabilityRow {
                name: "Resident sessions".into(),
                assurance: Assurance::NotImplemented.label().into(),
                note: "There is no long-lived unlocked session to terminate.".into(),
            },
        ]
    }

    /// PANIC DESTROY. Irreversible.
    ///
    /// Requires the vault password and an exact confirmation string. Both are
    /// checked before anything is written, so a stray message cannot reach the
    /// destruction path.
    pub fn panic_destroy(&self, password: &str, confirmation: &str) -> Result<String> {
        if confirmation != DESTROY_CONFIRMATION {
            return Err(Error::Other(format!(
                "destruction requires the exact confirmation {DESTROY_CONFIRMATION}; nothing \
                 was changed"
            )));
        }
        let v = self.open_vault(password)?;
        let id = v.vault_id();
        v.close();

        let log = AuditLog::open(self.audit_path(), id)?;
        let records = log.records()?;
        let anchor = AuditAnchor {
            records: records.len() as u64,
            last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
        };
        let now = self.now();

        let mut journal = StateJournal::open(self.journal_path(), id)?;
        self.record(id, "DESTRUCTION_AUTHORIZED", "gui panic destroy");
        authorize_explicit(&mut journal, id, now, anchor)?;
        let report = execute(
            &self.vault_path,
            &mut journal,
            SanitizationProfile::Enhanced,
            Trigger::PanicDestroy,
            now,
        )?;
        self.record(id, "DESTRUCTION_VERIFIED", "");
        Ok(report.render())
    }

    /// Finishes a destruction that was interrupted.
    pub fn resume_destruction(&self) -> Result<Option<String>> {
        let mut journal = StateJournal::open(self.journal_path(), VaultId::nil())?;
        if !needs_resume(&journal) {
            return Ok(None);
        }
        let report = execute(
            &self.vault_path,
            &mut journal,
            SanitizationProfile::Enhanced,
            Trigger::DeadlineExpired,
            self.now(),
        )?;
        Ok(Some(report.render()))
    }
}

fn summarize(v: &Vault) -> VaultSummary {
    VaultSummary {
        vault_id: v.vault_id().to_string(),
        format_version: v.format_version(),
        crypto_suite: v.crypto_suite().label().into(),
        compression: v.compress_suite().label().into(),
        kdf_memory_kib: v.kdf_params().memory_kib,
        kdf_time_cost: v.kdf_params().time_cost,
        factors: if v.factors().count() > 1 { "password + FIDO2".into() } else { "password".into() },
        entry_count: v.entries().len(),
        plaintext_bytes: v.entries().iter().map(|e| e.size).sum(),
        stored_bytes: v.entries().iter().flat_map(|e| e.chunks.iter()).map(|c| c.ciphertext_len as u64).sum(),
    }
}

/// What this build actually enforces, for the dashboard.
///
/// Generated from code so the GUI cannot display capabilities the binary does
/// not have.
pub fn capabilities() -> Vec<CapabilityRow> {
    let row = |name: &str, a: Assurance, note: &str| CapabilityRow {
        name: name.into(),
        assurance: a.label().into(),
        note: note.into(),
    };
    let (mem, mem_note) = zerotrace_secure_memory_status();
    vec![
        row("Authenticated encryption", Assurance::Verified, "XChaCha20-Poly1305 or AES-256-GCM"),
        row("Header authentication", Assurance::Verified, "KDF parameters cannot be downgraded"),
        row("Encrypted metadata", Assurance::Verified, "filenames, paths, sizes, timestamps"),
        row("Chunk integrity", Assurance::Verified, "per-chunk AEAD plus a Merkle root"),
        row("Multi-factor composition", Assurance::Verified, "all required factors are needed"),
        row("Tamper-evident audit", Assurance::Verified, "hash chained"),
        row("State journal", Assurance::Verified, "anchors the audit log"),
        row("Presence engine", Assurance::Verified, "ambient signals cannot satisfy a policy"),
        row("Cryptographic erasure", Assurance::Verified, "verified by read-back"),
        row("Container overwrite", Assurance::BestEffort, "the storage stack cannot be observed"),
        row("Memory locking", mem, mem_note),
        row("FIDO2 transport", Assurance::NotImplemented, "no hardware support in this build"),
        row("Snapshot handling", Assurance::NotImplemented, "no platform provider"),
        row("Free-space sanitization", Assurance::NotSupported, "not portable"),
        row("OS service supervision", Assurance::NotImplemented, "nothing restarts the service"),
    ]
}

/// Reported from the secure-memory crate so the window cannot show a
/// capability the binary does not actually have.
fn zerotrace_secure_memory_status() -> (Assurance, &'static str) {
    zerotrace_secure_memory::probe_memory_protection()
}

/// What the window needs to know about a vault's watcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchView {
    pub running: bool,
    pub stale: bool,
    pub pid: u32,
    pub interval_seconds: u64,
    pub allow_destruction: bool,
}

/// A vault in the recent list, summarized without opening it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultOverview {
    pub path: String,
    pub name: String,
    pub state: String,
    pub watched: bool,
    pub armed: bool,
    pub seconds_remaining: Option<u64>,
    pub policy_enabled: bool,
    /// A watcher stopped without shutting down since the last clean start.
    pub interrupted: bool,
}

/// What a vault's custodian is doing, for display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyView {
    pub established: bool,
    pub directory: String,
    pub reachable: bool,
    pub expired: bool,
    pub seconds_remaining: Option<u64>,
}

/// Whether the watcher restarts when this user logs in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutostartView {
    pub installed: bool,
    pub allows_destruction: bool,
    pub location: String,
    pub description: String,
}

/// Whether a file is a usable ZeroTrace token.
///
/// Front ends call this when a file is chosen, so a mistake is reported at the
/// moment it is made rather than as a failure several steps later.
pub fn validate_token_file(path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("could not read {}: {e}", path.display())))?;
    RecoveryToken::decode(&text).map(|_| ())
}

/// How long to wait before a further attempt, after `failures` in a row.
///
/// The default protection against guessing at the keyboard, and unlike a
/// destruction counter it costs nothing when it fires on an honest mistake.
/// Four seconds, then sixteen, then a minute, and so on to a five minute cap:
/// unnoticeable once, unusable as an attack.
pub fn backoff_seconds(failures: u32) -> u64 {
    match failures {
        0 => 0,
        1 => 0,
        2 => 4,
        3 => 16,
        4 => 60,
        _ => 300,
    }
}

/// Summarizes every remembered vault, for an overview that needs no passwords.
pub fn remembered_vaults() -> Vec<VaultOverview> {
    zerotrace_platform::recent::load()
        .into_iter()
        .map(|p| Session::new(p).overview())
        .collect()
}

/// Records a vault as recently used.
pub fn remember_vault(path: &Path) {
    let _ = zerotrace_platform::recent::remember(path);
}

/// Drops a vault from the remembered list, once it no longer exists.
pub fn forget_vault(path: &Path) {
    let _ = zerotrace_platform::recent::forget(path);
}

/// A convenience for front ends: the state's severity, for color selection.
pub fn severity(state: &str) -> &'static str {
    match state {
        "NORMAL" => "ok",
        "WARNING" => "warn",
        "CRITICAL" | "ARMED" => "alert",
        "DESTROYED" => "terminal",
        _ => "busy",
    }
}

pub fn state_from_label(s: &str) -> Option<DeadmanState> {
    use DeadmanState::*;
    Some(match s {
        "NORMAL" => Normal,
        "WARNING" => Warning,
        "CRITICAL" => Critical,
        "ARMED" => Armed,
        "DESTROYED" => Destroyed,
        _ => return None,
    })
}


