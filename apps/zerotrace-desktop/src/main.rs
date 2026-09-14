//! Apex ZeroTrace desktop window.
//!
//! A native front end over `zerotrace-ipc`. It contains no cryptography, no
//! policy evaluation and no destruction logic: every decision is made by the
//! core and arrives here as plain data.
//!
//! Passwords are held in a `String` only while a prompt is open, cleared the
//! moment the operation completes, and never stored between operations. That
//! is weaker than the core's `SecretBytes`, because egui needs an editable
//! `String` to render a text field, and it is stated plainly rather than
//! implied otherwise.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod guide;
mod theme;
mod widgets;

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use zeroize::Zeroize;

use theme::*;
use widgets::*;
use zerotrace_ipc::{
    capabilities, AuditEntry, CapabilityRow, ChainStatusView, DeadmanStatus, DryRunStep,
    EntrySummary, Session, VaultSummary, DESTROY_CONFIRMATION,
};
use zerotrace_policy::DeadmanPolicy;
use zerotrace_vault::VaultOptions;

/// What a password prompt is being collected for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Unlock,
    CheckIn,
    Verify,
    Create,
    Import,
    Export,
    ExportAll,
    Enroll,
    Custody,
    CustodyCheckIn,
    Duress,
    Destroy,
}

impl Pending {
    fn title(&self) -> &'static str {
        match self {
            Pending::Unlock => "Unlock vault",
            Pending::CheckIn => "Check in",
            Pending::Verify => "Verify integrity",
            Pending::Create => "Create vault",
            Pending::Import => "Add a file",
            Pending::Export => "Extract a file",
            Pending::ExportAll => "Extract everything",
            Pending::Enroll => "Protect with split keys",
            Pending::Custody => "Hand a component to a custodian",
            Pending::CustodyCheckIn => "Check in with the custodian",
            Pending::Duress => "Set a duress password",
            Pending::Destroy => "Destroy this vault",
        }
    }
    fn body(&self) -> &'static str {
        match self {
            Pending::Unlock => "Enter the vault password.",
            Pending::CheckIn => {
                "A check-in is a strong presence signal, so it requires the password."
            }
            Pending::Verify => "Every chunk will be decrypted and checked.",
            Pending::Create => {
                "There is no password recovery. If this password is lost, the vault cannot \
                 be opened by anyone, including you."
            }
            Pending::Import => "Enter the vault password to add the selected file.",
            Pending::Enroll => {
                "Enter the vault password. After enrollment the password alone will no \
                 longer open this vault, on this machine or any other."
            }
            Pending::Custody => {
                "Enter the vault password. The custodian will hold one component and \
                 return it only while you keep checking in."
            }
            Pending::CustodyCheckIn => {
                "Enter the vault password. Check-ins are signed with a key derived from \
                 it, which is why somebody holding this computer cannot make them."
            }
            Pending::Duress => {
                "Enter your real password, then the duress password. The duress password \
                 will open this vault into the files you chose and destroy everything else \
                 in it, permanently, the moment it is used."
            }
            Pending::Export => {
                "Enter the vault password. The file is decrypted and written to the folder \
                 you chose."
            }
            Pending::ExportAll => {
                "Enter the vault password. Every file is decrypted and written to the folder \
                 you chose."
            }
            Pending::Destroy => {
                "This overwrites the master key. Afterwards no password, recovery key or \
                 backup of the key material will open this vault. Destroying needs the same \
                 key components as opening, so nobody who cannot read this vault can \
                 destroy it either."
            }
        }
    }
}

/// Which pane the window is showing.
///
/// One section at a time rather than a wall of cards: the previous two-column
/// stack put a nearly empty Vault panel beside a dense Protection panel, left
/// ragged gaps down both columns, and pushed half the application below the
/// fold. Each of these needs a different amount of room, which a shared grid
/// cannot give them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Vault,
    Protection,
    Deadman,
    Records,
    Destruction,
    Duress,
    Guide,
}

impl Section {
    const ALL: [Section; 7] = [
        Section::Vault,
        Section::Protection,
        Section::Deadman,
        Section::Records,
        Section::Destruction,
        Section::Duress,
        Section::Guide,
    ];

    fn label(&self) -> &'static str {
        match self {
            Section::Guide => "Guide",
            Section::Vault => "Vault",
            Section::Protection => "Key protection",
            Section::Deadman => "Deadman",
            Section::Records => "Records",
            Section::Destruction => "Destruction",
            Section::Duress => "Duress",
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Section::Guide => "How to use this",
            Section::Vault => "Vault",
            Section::Protection => "Key protection",
            Section::Deadman => "Deadman policy",
            Section::Records => "Records",
            Section::Destruction => "Destruction",
            Section::Duress => "Duress password",
        }
    }

    fn subtitle(&self) -> &'static str {
        match self {
            Section::Guide => "Everything this program does, in plain words.",
            Section::Vault => "What is stored, and how it is encrypted.",
            Section::Protection => "Which key components are needed to open this vault.",
            Section::Deadman => "What happens if you stop checking in.",
            Section::Records => "The audit chain, the state journal, and recent activity.",
            Section::Destruction => "Irreversible. Read before using.",
            Section::Duress => "A second password that opens something else, and destroys this.",
        }
    }
}

/// Progress from a background transfer.
enum ImportUpdate {
    Progress { done: u64, total: u64 },
    Finished(Result<String, String>),
}

/// A file being added on another thread.
///
/// Importing a large file takes minutes. Doing it on the thread that paints
/// the window means the window stops painting, and an application that has
/// stopped painting is indistinguishable from one that has crashed. So the
/// work moves off, and what comes back is progress.
struct ImportJob {
    updates: Receiver<ImportUpdate>,
    /// What is happening, for the label: "Adding" or "Extracting".
    verb: &'static str,
    name: String,
    done: u64,
    total: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Neutral,
    Good,
    Bad,
}

struct App {
    vault: Option<PathBuf>,
    summary: Option<VaultSummary>,
    entries: Vec<EntrySummary>,
    status: Option<DeadmanStatus>,
    chain: Option<ChainStatusView>,
    log: Vec<AuditEntry>,
    caps: Vec<CapabilityRow>,
    policy: DeadmanPolicy,

    pending: Option<Pending>,
    /// Set when a prompt opens so the field is focused once rather than on
    /// every frame, which prevents typing from ever settling.
    focus_prompt: bool,
    /// Frames this prompt has been visible for.
    ///
    /// A native file dialog confirmed with the Enter key leaves that keypress
    /// queued, and it arrives just as the password prompt appears. Without a
    /// guard the prompt submits itself with an empty password before anyone
    /// can type, which looks exactly like never being asked for one.
    prompt_frames: u32,
    /// Errors raised inside a prompt, shown in the prompt rather than in the
    /// status bar behind it.
    prompt_error: String,
    password: String,
    destroy_confirm: String,
    import_source: Option<PathBuf>,
    export_dir: Option<PathBuf>,
    export_index: Option<usize>,
    /// Token files supplied for this session. Paths only; the secrets are read
    /// when an operation needs them and dropped straight after.
    tokens: Vec<PathBuf>,
    use_password: bool,
    split: Option<zerotrace_ipc::SplitStatusView>,
    watch: Option<zerotrace_ipc::WatchView>,
    autostart: Option<zerotrace_ipc::AutostartView>,
    custody: Option<zerotrace_ipc::CustodyView>,
    /// Names a vault that has just been destroyed, until acknowledged.
    ///
    /// Shown as a message rather than by replacing the pane. The pane was a
    /// dead end: with no Open or Create buttons on it, a destruction left the
    /// window with nothing to do next.
    destroyed_message: Option<String>,
    custody_dir: Option<PathBuf>,
    custody_token: Option<PathBuf>,
    duress_files: Vec<PathBuf>,
    duress_password: String,
    /// Whether a duress password was set since this vault was opened.
    ///
    /// Not read from the vault, and deliberately not persisted. The container
    /// cannot be asked whether it has one, and neither can this window after
    /// it restarts: a display that answered would hand the answer to anybody
    /// who opened the program.
    duress_set_this_session: bool,
    /// Every remembered vault, summarized without opening any of them.
    overviews: Vec<zerotrace_ipc::VaultOverview>,
    /// When the contents on screen were last touched.
    ///
    /// Auto-lock clears what is displayed and any attached tokens. It does not
    /// lock a session, because there is no session: keys are derived per
    /// operation and dropped immediately. What it protects is the screen and
    /// the components sitting ready, which is worth doing and is less than
    /// the name suggests.
    last_activity: std::time::Instant,
    /// Minutes of inactivity before the screen clears. Zero disables it.
    autolock_minutes: u64,
    /// A running import. Held while a file is being added, so the window can
    /// keep painting instead of appearing to have hung.
    import_job: Option<ImportJob>,
    /// A dry run must have been read before the service may be armed.
    dry_run_seen: bool,
    enrol_token: Option<PathBuf>,
    enrol_custodian: Option<PathBuf>,
    report: Option<String>,
    dry_run: Vec<DryRunStep>,

    /// Draft policy being edited. Kept separate from `policy` so a half-typed
    /// value is never written, and so the core's validator decides what is
    /// acceptable rather than the widget.
    draft: DeadmanPolicy,
    draft_loaded: bool,

    section: Section,
    message: String,
    tone: Tone,
    last_poll: std::time::Instant,
}

impl Default for App {
    fn default() -> Self {
        Self {
            vault: None,
            summary: None,
            entries: Vec::new(),
            status: None,
            chain: None,
            log: Vec::new(),
            caps: capabilities(),
            policy: DeadmanPolicy::default(),
            pending: None,
            focus_prompt: false,
            prompt_frames: 0,
            prompt_error: String::new(),
            password: String::new(),
            destroy_confirm: String::new(),
            import_source: None,
            export_dir: None,
            export_index: None,
            tokens: Vec::new(),
            use_password: true,
            split: None,
            watch: None,
            autostart: None,
            custody: None,
            destroyed_message: None,
            custody_dir: None,
            custody_token: None,
            duress_files: Vec::new(),
            duress_password: String::new(),
            duress_set_this_session: false,
            overviews: Vec::new(),
            import_job: None,
            last_activity: std::time::Instant::now(),
            autolock_minutes: 5,
            dry_run_seen: false,
            enrol_token: None,
            enrol_custodian: None,
            report: None,
            dry_run: Vec::new(),
            draft: DeadmanPolicy::default(),
            draft_loaded: false,
            section: Section::Vault,
            message: "Select or create a vault to begin.".into(),
            tone: Tone::Neutral,
            last_poll: std::time::Instant::now(),
        }
    }
}

impl App {
    fn session(&self) -> Option<Session> {
        self.vault.as_ref().map(|p| {
            let mut s = Session::new(p).with_tokens(self.tokens.clone());
            if !self.use_password {
                s = s.without_password();
            }
            s
        })
    }

    fn say(&mut self, msg: impl Into<String>, tone: Tone) {
        self.message = msg.into();
        self.tone = tone;
    }

    /// Refreshes everything that does not need a password.
    fn poll(&mut self) {
        // Refreshed even with no vault selected: the point of the list is to
        // show a lapsed watcher on a vault you are not currently looking at.
        self.overviews = zerotrace_ipc::remembered_vaults();
        let Some(s) = self.session() else { return };
        self.status = s.deadman_status().ok();
        self.chain = s.chain_status().ok();
        self.log = s.audit_tail(60).unwrap_or_default();
        self.policy = s.load_policy();
        self.split = s.split_status().ok();
        self.watch = Some(s.watch_status());

        // A vault destroyed by the background service is destroyed just as
        // thoroughly as one destroyed from here, and the window must not go on
        // displaying its contents, its protection or its policy. Detected by
        // polling rather than by having done it, because the service is a
        // different process.
        if self.vault_is_gone() {
            // Back to the state the window opens in. A destroyed vault is not
            // a vault you are working with, and leaving it selected left no
            // way to create or open another.
            let name = self
                .vault
                .as_ref()
                .and_then(|v| v.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "The vault".into());
            if let Some(v) = &self.vault {
                zerotrace_ipc::forget_vault(v);
            }
            self.clear_vault_state();
            self.vault = None;
            self.status = None;
            self.chain = None;
            self.log.clear();
            self.section = Section::Vault;
            self.destroyed_message = Some(name);
        }
        self.autostart = Some(s.autostart_status());
        self.custody = Some(s.custody_status());
        // Load the draft once, so polling does not overwrite edits in progress.
        if !self.draft_loaded {
            self.draft = self.policy;
            self.draft_loaded = true;
        }
    }

    /// Forgets everything that belonged to the previously selected vault.
    ///
    /// One function rather than a reset at each call site. There were two, they
    /// drifted, and each forgot different fields: one kept the old split
    /// status, the other kept the old deadman policy and would not reload it.
    /// Anything added to the per-vault state belongs here.
    fn clear_vault_state(&mut self) {
        self.summary = None;
        self.entries.clear();
        self.split = None;
        self.report = None;
        self.dry_run.clear();
        self.tokens.clear();
        self.use_password = true;
        self.policy = DeadmanPolicy::default();
        self.draft = DeadmanPolicy::default();
        self.watch = None;
        self.autostart = None;
        self.custody = None;
        self.custody_dir = None;
        self.custody_token = None;
        self.duress_files.clear();
        self.duress_password.clear();
        self.duress_set_this_session = false;
        // A dry run is about one vault, so it does not carry to another.
        self.dry_run_seen = false;
        // Forces the next poll to load the new vault's policy rather than
        // holding the previous one's edits.
        self.draft_loaded = false;
        self.prompt_error.clear();
        self.password.clear();
        self.destroy_confirm.clear();
    }

    /// Points the window at a vault that already exists.
    /// Clears the screen and any attached tokens after a period of inactivity.
    fn pump_autolock(&mut self, ctx: &egui::Context) {
        if self.autolock_minutes == 0 {
            return;
        }
        // Any pointer or keyboard event counts, and so does a running import,
        // which should not be interrupted by a timer.
        let busy = self.import_job.is_some() || self.pending.is_some();
        let touched = ctx.input(|i| {
            i.pointer.any_down()
                || i.pointer.velocity() != egui::Vec2::ZERO
                || !i.events.is_empty()
        });
        if busy || touched {
            self.last_activity = std::time::Instant::now();
            return;
        }

        let limit = std::time::Duration::from_secs(self.autolock_minutes * 60);
        if self.last_activity.elapsed() < limit {
            // Checked again shortly, so the clear happens near the deadline
            // rather than whenever the window next repaints for another reason.
            ctx.request_repaint_after(std::time::Duration::from_secs(5));
            return;
        }

        let had_something = self.summary.is_some() || !self.entries.is_empty()
            || !self.tokens.is_empty();
        self.summary = None;
        self.entries.clear();
        self.tokens.clear();
        self.use_password = true;
        self.last_activity = std::time::Instant::now();
        if had_something {
            self.say(
                format!(
                    "Cleared after {} minutes without activity. Unlock again to see \
                     contents.",
                    self.autolock_minutes
                ),
                Tone::Neutral,
            );
        }
    }

    /// Collects whatever a running import has to say.
    fn pump_import(&mut self, ctx: &egui::Context) {
        let Some(job) = &mut self.import_job else { return };
        let mut finished: Option<Result<String, String>> = None;

        loop {
            match job.updates.try_recv() {
                Ok(ImportUpdate::Progress { done, total }) => {
                    job.done = done;
                    job.total = total;
                }
                Ok(ImportUpdate::Finished(r)) => {
                    finished = Some(r);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                // The thread ended without a verdict, which should not happen
                // but must not leave the window waiting for ever.
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    finished = Some(Err("the import stopped unexpectedly".into()));
                    break;
                }
            }
        }

        // Repainting while work is in progress: without this the bar only
        // moves when the mouse does.
        ctx.request_repaint_after(std::time::Duration::from_millis(100));

        if let Some(result) = finished {
            self.import_job = None;
            match result {
                Ok(name) => {
                    self.say(format!("Done: {name}."), Tone::Good);
                    // Contents are re-read on the next unlock rather than
                    // held: the password is gone by now, deliberately.
                    self.entries.clear();
                    self.summary = None;
                }
                Err(e) => self.say(e, Tone::Bad),
            }
            self.poll();
        }
    }

    /// Reports a destruction, then gets out of the way.
    fn destroyed_modal(&mut self, ctx: &egui::Context) {
        let Some(name) = self.destroyed_message.clone() else { return };
        let mut dismissed = false;

        egui::Window::new("Vault destroyed")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_width(430.0);
                ui.label(
                    egui::RichText::new(format!("{name} has been destroyed."))
                        .size(14.5)
                        .color(ALERT),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(
                        "Its key was overwritten and the container removed. No password, \
                         token or backup of the key will open it.",
                    )
                    .size(12.5)
                    .color(MUTED),
                );
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Copies of the container made before this are unaffected and still \
                         open normally, provided you also kept their key components.",
                    )
                    .size(11.5)
                    .color(DIM),
                );
                ui.add_space(14.0);
                if quiet_button(ui, "Continue").clicked() {
                    dismissed = true;
                }
            });

        if dismissed {
            self.destroyed_message = None;
            self.say("Select or create a vault to begin.", Tone::Neutral);
        }
    }

    /// True when the selected vault has been destroyed.
    ///
    /// Judged only by the journal recording a terminal state, never by the
    /// container being absent. A vault that has been named but not yet created
    /// is also absent, and treating the two alike made the window announce the
    /// destruction of a vault the moment its filename was chosen.
    fn vault_is_gone(&self) -> bool {
        self.status.as_ref().map(|s| s.terminal).unwrap_or(false)
    }

    fn open_vault(&mut self, path: PathBuf) {
        self.clear_vault_state();
        zerotrace_ipc::remember_vault(&path);
        self.vault = Some(path);
        self.poll();
        self.say("Vault selected. Unlock to see its contents.", Tone::Neutral);
    }

    /// Points the window at a vault that is about to be created.
    fn target_new_vault(&mut self, path: PathBuf) {
        self.clear_vault_state();
        self.vault = Some(path);
    }

    /// Runs the action the prompt was collecting a password for.
    ///
    /// The password is cleared before returning, whatever the outcome.
    fn run_pending(&mut self) {
        let Some(action) = self.pending else { return };
        let Some(s) = self.session() else { return };
        let mut pw = std::mem::take(&mut self.password);

        let outcome: Result<(), String> = match action {
            Pending::Create => s
                .create(&pw, &VaultOptions::default())
                .map(|sum| {
                    // A new vault has its own policy, which is the safe
                    // default; the poll at the end of this call loads it.
                    self.draft_loaded = false;
                    self.summary = Some(sum);
                    self.say("Vault created.", Tone::Good);
                })
                .map_err(|e| e.to_string()),

            Pending::Unlock => s
                .unlock(&pw)
                .and_then(|sum| {
                    self.summary = Some(sum);
                    self.entries = s.list(&pw)?;
                    Ok(())
                })
                .map(|_| self.say("Unlocked.", Tone::Good))
                .map_err(|e| e.to_string()),

            Pending::CheckIn => s
                .check_in(&pw)
                .map(|st| {
                    self.status = Some(st);
                    self.say("Checked in.", Tone::Good);
                })
                .map_err(|e| e.to_string()),

            Pending::Verify => s
                .verify(&pw)
                .map(|r| {
                    if r.intact {
                        self.say(
                            format!("Intact. {} chunks verified.", r.chunks_checked),
                            Tone::Good,
                        );
                    } else {
                        self.say(
                            format!(
                                "Damaged. {} of {} chunks failed.",
                                r.chunks_failed, r.chunks_checked
                            ),
                            Tone::Bad,
                        );
                    }
                })
                .map_err(|e| e.to_string()),

            Pending::Import => {
                let src = self.import_source.clone();
                match src {
                    None => Err("no file was selected".to_string()),
                    Some(src) => {
                        let name = src
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "file".into());
                        let total = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
                        let (tx, rx) = channel();
                        let vault = self.vault.clone();
                        let tokens = self.tokens.clone();
                        let use_password = self.use_password;
                        let job_name = name.clone();
                        let password = pw.clone();

                        std::thread::spawn(move || {
                            let Some(vault) = vault else { return };
                            let mut session = Session::new(vault).with_tokens(tokens);
                            if !use_password {
                                session = session.without_password();
                            }
                            let sender = tx.clone();
                            let outcome = session.import_with_progress(
                                &password,
                                &src,
                                &job_name,
                                |done, total| {
                                    let _ = sender.send(ImportUpdate::Progress { done, total });
                                },
                            );
                            let _ = tx.send(ImportUpdate::Finished(
                                outcome.map(|_| job_name).map_err(|e| e.to_string()),
                            ));
                        });

                        self.import_job = Some(ImportJob {
                            updates: rx,
                            verb: "Adding",
                            name,
                            done: 0,
                            total,
                        });
                        self.say("Adding file…", Tone::Neutral);
                        Ok(())
                    }
                }
            }

            Pending::Export | Pending::ExportAll => {
                let dir = self.export_dir.clone();
                match dir {
                    None => Err("no destination folder was selected".to_string()),
                    Some(dir) => {
                        let indices: Vec<usize> = if action == Pending::ExportAll {
                            (0..self.entries.len()).collect()
                        } else {
                            self.export_index.into_iter().collect()
                        };
                        // Extraction is as slow as importing on a large file,
                        // so it moves off the painting thread for the same
                        // reason.
                        let total: u64 = indices
                            .iter()
                            .filter_map(|i| self.entries.get(*i).map(|e| e.size))
                            .sum();
                        let label = if indices.len() == 1 {
                            self.entries
                                .get(indices[0])
                                .map(|e| e.path.clone())
                                .unwrap_or_else(|| "file".into())
                        } else {
                            format!("{} files", indices.len())
                        };

                        let (tx, rx) = channel();
                        let vault = self.vault.clone();
                        let tokens = self.tokens.clone();
                        let use_password = self.use_password;
                        let password = pw.clone();
                        let dest = dir.clone();

                        std::thread::spawn(move || {
                            let Some(vault) = vault else { return };
                            let mut session = Session::new(vault).with_tokens(tokens);
                            if !use_password {
                                session = session.without_password();
                            }
                            let mut base = 0u64;
                            let mut written = 0usize;
                            let mut failures: Vec<String> = Vec::new();

                            for i in indices {
                                let sender = tx.clone();
                                let result = session.export_with_progress(
                                    &password,
                                    i,
                                    &dest,
                                    |done, _| {
                                        let _ = sender.send(ImportUpdate::Progress {
                                            done: base + done,
                                            total,
                                        });
                                    },
                                );
                                match result {
                                    Ok(_) => written += 1,
                                    Err(e) => failures.push(e.to_string()),
                                }
                                base += session
                                    .list(&password)
                                    .ok()
                                    .and_then(|v| v.get(i).map(|e| e.size))
                                    .unwrap_or(0);
                            }

                            let verdict = if written == 0 && !failures.is_empty() {
                                Err(failures.remove(0))
                            } else if failures.is_empty() {
                                Ok(format!(
                                    "{written} file{} to {}",
                                    if written == 1 { "" } else { "s" },
                                    dest.display()
                                ))
                            } else {
                                Ok(format!(
                                    "{written} file(s); {} could not be recovered",
                                    failures.len()
                                ))
                            };
                            let _ = tx.send(ImportUpdate::Finished(verdict));
                        });

                        self.import_job = Some(ImportJob {
                            updates: rx,
                            verb: "Extracting",
                            name: label,
                            done: 0,
                            total,
                        });
                        self.say("Extracting…", Tone::Neutral);
                        Ok(())
                    }
                }
            }

            Pending::Enroll => {
                let token = self.enrol_token.clone();
                let custodian = self.enrol_custodian.clone();
                match token {
                    None => Err("no location was chosen for the recovery token".to_string()),
                    Some(token) => s
                        .enroll_split(&pw, &token, custodian.as_deref())
                        .map(|status| {
                            self.split = Some(status);
                            // Deliberately not retained. Keeping the token
                            // attached after enrollment meant a later
                            // irreversible action could succeed while the
                            // person believed they had supplied nothing, which
                            // is the opposite of what a destructive prompt
                            // should feel like. Requiring it to be attached
                            // again also proves the file that was just written
                            // is readable and correct.
                            let _ = token;
                            self.tokens.clear();
                            self.say(
                                "Enrolled. Move the tokens to separate places, then attach \
                                 one to keep working with this vault.",
                                Tone::Good,
                            );
                        })
                        .map_err(|e| e.to_string()),
                }
            }

            Pending::Custody => {
                let dir = self.custody_dir.clone();
                let token = self.custody_token.clone();
                match (dir, token) {
                    (Some(dir), Some(token)) => {
                        let timeout = self.policy.timeout_seconds.max(3600);
                        s.establish_custody(&pw, &dir, &token, timeout)
                            .map(|_| {
                                self.say(
                                    format!(
                                        "Custody established. Delete your local copy of the \
                                         token now, or the component is still on this machine."
                                    ),
                                    Tone::Good,
                                )
                            })
                            .map_err(|e| e.to_string())
                    }
                    _ => Err("a custodian folder and a token file are both needed".to_string()),
                }
            }

            Pending::Duress => {
                let files = self.duress_files.clone();
                let mut duress = std::mem::take(&mut self.duress_password);

                // On a background thread like any other import: decoy files
                // are ordinary files and can be large, and a window that stops
                // painting looks exactly like one that has crashed.
                let total: u64 = files
                    .iter()
                    .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
                    .sum();
                let (tx, rx) = channel();
                let vault = self.vault.clone();
                let tokens = self.tokens.clone();
                let use_password = self.use_password;
                let password = pw.clone();
                let duress_owned = duress.clone();
                duress.zeroize();

                std::thread::spawn(move || {
                    let Some(vault) = vault else { return };
                    let session = Session::new(vault).with_tokens(tokens);
                    let session = if use_password { session } else { session.without_password() };
                    let sender = tx.clone();
                    let outcome = session.set_duress_password_with_progress(
                        &password,
                        &duress_owned,
                        &files,
                        |done, total| {
                            let _ = sender.send(ImportUpdate::Progress { done, total });
                        },
                    );
                    let _ = tx.send(ImportUpdate::Finished(
                        outcome.map(|_| "duress password set".to_string()).map_err(|e| e.to_string()),
                    ));
                });

                self.import_job = Some(ImportJob {
                    updates: rx,
                    verb: "Preparing",
                    name: "the duress contents".into(),
                    done: 0,
                    total,
                });
                self.duress_set_this_session = true;
                self.say("Preparing the duress contents\u{2026}", Tone::Neutral);
                Ok(())
            }

            Pending::CustodyCheckIn => s
                .custodian_check_in(&pw)
                .map(|_| self.say("Checked in with the custodian.", Tone::Good))
                .map_err(|e| e.to_string()),

            Pending::Destroy => {
                let confirm = std::mem::take(&mut self.destroy_confirm);
                s.panic_destroy(&pw, &confirm)
                    .map(|report| {
                        self.summary = None;
                        self.entries.clear();
                        self.split = None;
                        self.tokens.clear();
                        self.draft_loaded = false;
                        self.report = Some(report);
                        self.say("Vault destroyed.", Tone::Bad);
                    })
                    .map_err(|e| e.to_string())
            }
        };

        if let Err(e) = outcome {
            self.say(e, Tone::Bad);
        }
        self.pending = None;
        self.import_source = None;
        self.enrol_token = None;
        self.enrol_custodian = None;
        self.custody_dir = None;
        self.custody_token = None;
        self.duress_files.clear();
        self.duress_password.clear();
        self.export_dir = None;
        self.export_index = None;
        pw.zeroize();
        self.poll();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // A countdown that only moves when the mouse does would be misleading.
        self.pump_import(ctx);
        self.pump_autolock(ctx);

        if self.vault.is_some() && self.last_poll.elapsed() > std::time::Duration::from_secs(10) {
            self.last_poll = std::time::Instant::now();
            self.poll();
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(1));

        self.top_rail(ctx);
        self.status_rail(ctx);
        self.body(ctx);
        self.prompt(ctx);
        self.destroyed_modal(ctx);
    }
}

impl App {
    fn top_rail(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("rail")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(18.0, 11.0))
                    .stroke(egui::Stroke::new(1.0_f32, EDGE)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("APEX ZEROTRACE").size(15.0).strong().color(TEXT),
                    );
                    ui.label(egui::RichText::new("encrypted vault").size(12.5).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // From the build, so it cannot fall behind the version it ships in.
                        ui.label(
                            egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .size(12.0)
                                .color(DIM),
                        );
                        let shown = self
                            .vault
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "no vault selected".into());
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(shown).size(12.0).monospace().color(DIM),
                            )
                            .truncate(true),
                        );
                    });
                });
            });
    }

    fn status_rail(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(18.0, 10.0))
                    .stroke(egui::Stroke::new(1.0_f32, EDGE)),
            )
            .show(ctx, |ui| {
                let color = match self.tone {
                    Tone::Neutral => MUTED,
                    Tone::Good => OK,
                    Tone::Bad => ALERT,
                };
                ui.horizontal(|ui| {
                    // Right-aligned content first so the growing label truncates
                    // into what is left rather than overlapping it.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&self.message).size(12.5).color(color),
                                )
                                .truncate(true),
                            );
                        });
                    });
                });
            });
    }

    fn body(&mut self, ctx: &egui::Context) {
        self.sidebar(ctx);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(INK)
                    .inner_margin(egui::Margin::symmetric(26.0, 22.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_source("content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        section_title(ui, self.section.title(), self.section.subtitle());
                        // A measured column: a label-and-value row stretched
                        // across a wide window reads badly and looks accidental.
                        measured(ui, 720.0, |ui| match self.section {
                            Section::Guide => self.guide_pane(ui),
                            Section::Vault => self.vault_pane(ui),
                            Section::Protection => self.protection_pane(ui),
                            Section::Deadman => self.deadman_pane(ui),
                            Section::Records => self.records_pane(ui),
                            Section::Destruction => self.destruction_pane(ui),
                            Section::Duress => self.duress_pane(ui),
                        });
                    });
            });
    }

    /// Status and navigation, always visible.
    ///
    /// The state and countdown live here rather than in a pane because they
    /// are what a person opens this window to see, and they should not depend
    /// on which section happens to be selected.
    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(236.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(14.0, 16.0))
                    .stroke(egui::Stroke::new(1.0_f32, EDGE)),
            )
            .show(ctx, |ui| {
                let (state, confidence, required, remaining, terminal, resume) = match &self.status
                {
                    Some(s) => (
                        if s.terminal { "DESTROYED".to_string() } else { s.state.clone() },
                        s.confidence,
                        s.required_confidence,
                        s.seconds_remaining,
                        s.terminal,
                        s.needs_resume,
                    ),
                    None => ("LOCKED".into(), 0, 0, None, false, false),
                };
                let color = state_color(&state);

                ui.label(egui::RichText::new(&state).size(22.0).strong().color(color));
                ui.add_space(3.0);

                if terminal {
                    ui.label(
                        egui::RichText::new("No recovery is possible.").size(11.5).color(MUTED),
                    );
                } else if !self.policy.enabled {
                    ui.label(egui::RichText::new("No deadman policy.").size(11.5).color(MUTED));
                } else if let Some(r) = remaining {
                    ui.label(
                        egui::RichText::new(human_duration(r)).monospace().size(17.0).color(TEXT),
                    );
                    ui.label(egui::RichText::new("until deadline").size(11.0).color(MUTED));
                } else {
                    ui.label(egui::RichText::new("deadline passed").size(13.0).color(ALERT));
                }

                ui.add_space(10.0);
                confidence_meter(ui, confidence, required, color);
                ui.add_space(3.0);
                ui.label(
                    egui::RichText::new(format!("presence {confidence}/100, need {required}"))
                        .size(10.5)
                        .color(DIM),
                );

                if resume {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Interrupted destruction will resume.")
                            .size(10.5)
                            .color(ALERT),
                    );
                }

                ui.add_space(14.0);
                let ready = self.vault.is_some() && !terminal;
                if primary_button(ui, "Check in", ready)
                    .on_hover_text(
                        "Proves you are present. Resets presence to full and restarts the \
                         countdown. Needs your password, and a token if this vault is \
                         split protected.",
                    )
                    .clicked()
                    && ready
                {
                    self.pending = Some(Pending::CheckIn);
                    self.focus_prompt = true;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if quiet_button(ui, "Unlock")
                        .on_hover_text(
                            "Reads the vault so its contents can be listed. Keys are held \
                             for this one operation and then destroyed; there is no \
                             lingering unlocked session.",
                        )
                        .clicked()
                        && ready
                    {
                        self.pending = Some(Pending::Unlock);
                        self.focus_prompt = true;
                    }
                    if quiet_button(ui, "Verify")
                        .on_hover_text(
                            "Decrypts every chunk and checks it against its recorded hash, \
                             to find corruption or tampering in the stored data. Slow on a \
                             large vault. The Records section checks the logs instead.",
                        )
                        .clicked()
                        && ready
                    {
                        self.pending = Some(Pending::Verify);
                        self.focus_prompt = true;
                    }
                });

                ui.add_space(18.0);
                ui.separator();
                ui.add_space(10.0);

                for section in Section::ALL {
                    let detail = self.nav_detail(section);
                    if nav_item(ui, section.label(), detail.as_deref(), self.section == section)
                        .clicked()
                    {
                        self.section = section;
                    }
                    ui.add_space(2.0);
                }

                self.vault_list(ui);
            });
    }

    /// Every remembered vault, with just enough to notice a problem.
    ///
    /// Deliberately status only, and deliberately not several vaults open at
    /// once: destruction is irreversible, and every vault on screen is another
    /// chance to act on the wrong one. What this fixes is the opposite
    /// problem, that a watcher which stopped on a vault you are not looking at
    /// is invisible until you happen to open it.
    fn vault_list(&mut self, ui: &mut egui::Ui) {
        let others: Vec<zerotrace_ipc::VaultOverview> = self
            .overviews
            .iter()
            .filter(|o| {
                self.vault
                    .as_ref()
                    .map(|v| v.display().to_string() != o.path)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if others.is_empty() {
            return;
        }

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(egui::RichText::new("OTHER VAULTS").size(10.5).color(DIM));
        ui.add_space(5.0);

        let mut switch: Option<String> = None;
        for o in &others {
            // Color carries the answer to "is anything wrong here".
            let color = if o.state == "DESTROYED" {
                DIM
            } else if o.interrupted || (o.policy_enabled && !o.watched) {
                WARN
            } else if o.watched {
                OK
            } else {
                MUTED
            };
            let detail = if o.state == "DESTROYED" {
                "destroyed".to_string()
            } else if o.interrupted {
                "watcher was interrupted".to_string()
            } else if o.policy_enabled && !o.watched {
                "not being watched".to_string()
            } else if o.watched {
                match o.seconds_remaining {
                    Some(r) => format!("{} left", human_duration(r)),
                    None => if o.armed { "armed".into() } else { "watching".into() },
                }
            } else {
                "no policy".to_string()
            };

            let resp = ui.allocate_response(
                egui::vec2(ui.available_width(), 34.0),
                egui::Sense::click(),
            );
            let p = ui.painter();
            if resp.hovered() {
                p.rect_filled(resp.rect, R, egui::Color32::from_rgb(0x23, 0x25, 0x2A));
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            p.text(
                egui::pos2(resp.rect.min.x + 13.0, resp.rect.min.y + 11.0),
                egui::Align2::LEFT_CENTER,
                &o.name,
                egui::FontId::proportional(12.5),
                MUTED,
            );
            p.text(
                egui::pos2(resp.rect.min.x + 13.0, resp.rect.min.y + 25.0),
                egui::Align2::LEFT_CENTER,
                &detail,
                egui::FontId::monospace(10.0),
                color,
            );
            if resp.on_hover_text(&o.path).clicked() {
                switch = Some(o.path.clone());
            }
        }

        if let Some(path) = switch {
            self.open_vault(PathBuf::from(path));
        }
    }

    /// A one-line summary under each nav entry, so the sidebar answers most
    /// questions without a click.
    /// How often the service should check, scaled to the deadline.
    ///
    /// A five minute check against a one hour deadline would be a twelfth of
    /// the window; against three days it is nothing. The interval only affects
    /// how promptly the deadline is noticed, never whether it passes.
    fn policy_interval(&self) -> u64 {
        (self.policy.timeout_seconds / 120).clamp(15, 300)
    }

    fn nav_detail(&self, section: Section) -> Option<String> {
        match section {
            Section::Guide => Some("start here".into()),
            Section::Vault => self
                .summary
                .as_ref()
                .map(|s| format!("{} entries", s.entry_count))
                .or(Some("locked".into())),
            Section::Protection => Some(match &self.split {
                Some(s) if s.enrolled => format!("{} of {}", s.threshold, s.components.len()),
                _ => "password only".into(),
            }),
            Section::Deadman => {
                Some(if self.policy.enabled { "enabled".into() } else { "disabled".into() })
            }
            Section::Records => self.chain.as_ref().map(|c| {
                if c.audit_chain == "VERIFIED" && c.audit_anchor != "FAILED" {
                    "verified".into()
                } else {
                    "check".to_string()
                }
            }),
            Section::Duress => Some("second password".into()),
            Section::Destruction => self.status.as_ref().map(|s| {
                if s.terminal {
                    "destroyed".into()
                } else {
                    "available".to_string()
                }
            }),
        }
    }

    /// The guide. Text only, so nothing here can change anything.
    fn guide_pane(&mut self, ui: &mut egui::Ui) {
        for topic in guide::TOPICS {
            card(ui, |ui| {
                ui.label(egui::RichText::new(topic.title).size(14.5).strong().color(TEXT));
                ui.add_space(7.0);
                for (i, para) in topic.body.iter().enumerate() {
                    if i > 0 {
                        ui.add_space(7.0);
                    }
                    ui.label(egui::RichText::new(*para).size(12.5).color(MUTED));
                }
            });
            ui.add_space(12.0);
        }
    }

    fn vault_pane(&mut self, ui: &mut egui::Ui) {
        if let Some(job) = &self.import_job {
            let (done, total, name, verb) =
                (job.done, job.total, job.name.clone(), job.verb);
            card(ui, |ui| {
                ui.label(egui::RichText::new(format!("{verb} {name}")).size(13.5).color(TEXT));
                ui.add_space(8.0);
                let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
                ui.add(
                    egui::ProgressBar::new(frac.clamp(0.0, 1.0))
                        .desired_width(ui.available_width())
                        .fill(OK),
                );
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} of {}",
                        human_bytes(done),
                        human_bytes(total)
                    ))
                    .monospace()
                    .size(11.5)
                    .color(MUTED),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "The window stays responsive while this runs. A large file can \
                         take a while.",
                    )
                    .size(11.0)
                    .color(DIM),
                );
            });
            ui.add_space(16.0);
        }
        explainer(
            ui,
            "Filenames, sizes and timestamps are encrypted, so nothing can be listed until \
             the vault is unlocked. Extract writes a decrypted copy to a folder you choose; \
             the vault keeps its own.",
        );
        self.vault_card(ui);
        ui.add_space(16.0);
        self.contents_card(ui);
    }

    fn protection_pane(&mut self, ui: &mut egui::Ui) {
        let enrolled = self.split.as_ref().map(|s| s.enrolled).unwrap_or(false);
        explainer(
            ui,
            if enrolled {
                "Any two of the enrolled components open this vault. Add token points at a \
                 token file for this session; you will do this each time. Password lost \
                 opens with two tokens instead of your password."
            } else {
                "Protect splits the key across your password and two token files, so a \
                 stolen drive plus a guessed password is not enough. It rewrites 48 bytes, \
                 so it is instant whatever the vault holds. Afterwards your password alone \
                 will not open this vault on any machine. Store each token somewhere the \
                 vault's drive is not, and not both in the same place."
            },
        );
        self.protection_card(ui);
        ui.add_space(16.0);
        self.custody_card(ui);
        ui.add_space(16.0);
        self.capability_card(ui);
    }

    fn deadman_pane(&mut self, ui: &mut egui::Ui) {
        explainer(
            ui,
            "Timeout is how long without a check-in before the vault arms. Heartbeat is how \
             often you intend to check in: inside it a check-in counts at full value, and \
             after it presence falls steadily to nothing at the timeout. Required \
             confidence is the presence score you must stay above; it must exceed 60 so \
             that ambient signals alone can never satisfy it.",
        );
        self.policy_card(ui);
    }

    fn records_pane(&mut self, ui: &mut egui::Ui) {
        explainer(
            ui,
            "These check the logs, not the stored data. The audit chain and state journal \
             detect edits, deletions and reordering. The audit anchor is what catches \
             records removed from the end, which a hash chain alone cannot see.",
        );
        self.integrity_card(ui);
        ui.add_space(16.0);
        self.activity_card(ui);
    }

    fn duress_pane(&mut self, ui: &mut egui::Ui) {
        explainer(
            ui,
            "Set a second password that opens this vault into files you choose, and \
             destroys everything really in it as it does. Somebody watching sees an \
             ordinary vault open. Nothing about the vault reveals whether one exists, \
             including this program when it is closed.",
        );
        self.duress_card(ui);
    }

    fn destruction_pane(&mut self, ui: &mut egui::Ui) {
        explainer(
            ui,
            "Dry run lists what destruction would do and changes nothing. Panic lock clears \
             resident state and leaves your data untouched. Panic destroy is irreversible \
             and needs the same components as opening the vault, so nobody who cannot read \
             it can destroy it either.",
        );
        self.destruction_card(ui);
    }

    fn vault_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            match &self.summary {
                Some(s) => {
                    readout(ui, "Encryption", &s.crypto_suite, TEXT);
                    readout(
                        ui,
                        "Key derivation",
                        &format!(
                            "Argon2id {} MiB t={}",
                            s.kdf_memory_kib / 1024,
                            s.kdf_time_cost
                        ),
                        TEXT,
                    );
                    readout(ui, "Compression", &s.compression, TEXT);
                    readout(ui, "Factors", &s.factors, TEXT);
                    readout(ui, "Entries", &s.entry_count.to_string(), TEXT);
                    readout(
                        ui,
                        "Stored",
                        &format!(
                            "{} of {}",
                            human_bytes(s.stored_bytes),
                            human_bytes(s.plaintext_bytes)
                        ),
                        TEXT,
                    );
                }
                None => {
                    ui.label(
                        egui::RichText::new("Unlock to see vault details.").size(12.5).color(MUTED),
                    );
                }
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if quiet_button(ui, "Open…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Vault", &["azv"])
                        .pick_file()
                    {
                        self.open_vault(p);
                    }
                }
                if quiet_button(ui, "Create…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Vault", &["azv"])
                        .save_file()
                    {
                        let mut p = p;
                        if p.extension().is_none() {
                            p.set_extension("azv");
                        }
                        self.target_new_vault(p);
                        self.pending = Some(Pending::Create);
                        self.focus_prompt = true;
                    }
                }
                if quiet_button(ui, "Add file…").clicked() && self.vault.is_some() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.import_source = Some(p);
                        self.pending = Some(Pending::Import);
                        self.focus_prompt = true;
                    }
                }
            });

            if !self.entries.is_empty() {
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_source("entries")
                    .max_height(110.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                    for e in &self.entries {
                        readout(ui, &e.path, &human_bytes(e.size), MUTED);
                    }
                });
            }
        });
    }

    /// The deadman policy editor.
    ///
    /// Values are edited in hours because seconds are unreadable at this
    /// scale, and every change is handed to `DeadmanPolicy::validate` in the
    /// core. The window never decides what is safe: it shows what the core
    /// refused and why.
    fn policy_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {

            if self.vault.is_none() {
                ui.label(egui::RichText::new("Select a vault first.").size(12.5).color(MUTED));
                return;
            }

            ui.checkbox(&mut self.draft.enabled, "Enabled")
                .on_hover_text("Nothing below has any effect until this is ticked.");
            if !self.draft.enabled {
                ui.add_space(3.0);
                ui.label(
                    egui::RichText::new(
                        "Tick Enabled to change the settings below. While it is off, no \
                         deadline is computed and nothing can destroy this vault on a timer.",
                    )
                    .size(11.5)
                    .color(MUTED),
                );
            }
            ui.add_space(6.0);

            // Chosen from a list rather than typed. A free number field
            // invites combinations the core will refuse, and tells the reader
            // nothing about what a sensible value looks like.
            const TIMEOUTS: &[(u64, &str)] = &[
                (3600, "1 hour"),
                (6 * 3600, "6 hours"),
                (12 * 3600, "12 hours"),
                (24 * 3600, "1 day"),
                (2 * 24 * 3600, "2 days"),
                (3 * 24 * 3600, "3 days"),
                (7 * 24 * 3600, "1 week"),
                (14 * 24 * 3600, "2 weeks"),
                (30 * 24 * 3600, "30 days"),
            ];
            // Must reach below the shortest timeout the core accepts, which is
            // one hour. Starting the list at one hour made a one-hour timeout
            // impossible to configure: the heartbeat has to be strictly
            // shorter, and nothing shorter was offered.
            const HEARTBEATS: &[(u64, &str)] = &[
                (5 * 60, "5 minutes"),
                (15 * 60, "15 minutes"),
                (30 * 60, "30 minutes"),
                (3600, "1 hour"),
                (2 * 3600, "2 hours"),
                (6 * 3600, "6 hours"),
                (12 * 3600, "12 hours"),
                (24 * 3600, "1 day"),
                (2 * 24 * 3600, "2 days"),
                (7 * 24 * 3600, "1 week"),
            ];
            const CONFIDENCE: &[(u32, &str)] = &[
                (70, "70  relaxed"),
                (80, "80  standard"),
                (90, "90  strict"),
                (100, "100  a fresh check-in only"),
            ];

            let name_of = |list: &[(u64, &str)], v: u64| {
                list.iter()
                    .find(|(s, _)| *s == v)
                    .map(|(_, n)| (*n).to_string())
                    .unwrap_or_else(|| human_duration(v))
            };

            ui.add_enabled_ui(self.draft.enabled, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Timeout").size(12.5).color(MUTED))
                        .on_hover_text("How long without a check-in before the vault arms.");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::ComboBox::from_id_source("timeout")
                            .selected_text(name_of(TIMEOUTS, self.draft.timeout_seconds))
                            .width(190.0)
                            .show_ui(ui, |ui| {
                                for (secs, name) in TIMEOUTS {
                                    ui.selectable_value(
                                        &mut self.draft.timeout_seconds,
                                        *secs,
                                        *name,
                                    );
                                }
                            });
                    });
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Heartbeat").size(12.5).color(MUTED))
                        .on_hover_text(
                            "How often you intend to check in. Inside this window a \
                             check-in counts in full.",
                        );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::ComboBox::from_id_source("heartbeat")
                            .selected_text(name_of(HEARTBEATS, self.draft.heartbeat_seconds))
                            .width(190.0)
                            .show_ui(ui, |ui| {
                                // Only intervals shorter than the timeout are
                                // offered, so an unsatisfiable policy cannot be
                                // assembled by picking from the lists.
                                let mut any = false;
                                for (secs, name) in HEARTBEATS
                                    .iter()
                                    .filter(|(s, _)| *s < self.draft.timeout_seconds)
                                {
                                    any = true;
                                    ui.selectable_value(
                                        &mut self.draft.heartbeat_seconds,
                                        *secs,
                                        *name,
                                    );
                                }
                                // Should not happen now that the list reaches
                                // five minutes, but an empty menu that explains
                                // nothing is the worst possible outcome.
                                if !any {
                                    ui.label(
                                        egui::RichText::new(
                                            "No interval is shorter than this timeout. \
                                             Choose a longer timeout.",
                                        )
                                        .size(11.5)
                                        .color(ALERT),
                                    );
                                }
                            });
                    });
                });

                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Required confidence").size(12.5).color(MUTED),
                    )
                    .on_hover_text("The presence score you must stay above.");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let shown = CONFIDENCE
                            .iter()
                            .find(|(v, _)| *v == self.draft.required_confidence)
                            .map(|(_, n)| (*n).to_string())
                            .unwrap_or_else(|| self.draft.required_confidence.to_string());
                        egui::ComboBox::from_id_source("confidence")
                            .selected_text(shown)
                            .width(190.0)
                            .show_ui(ui, |ui| {
                                for (v, name) in CONFIDENCE {
                                    ui.selectable_value(
                                        &mut self.draft.required_confidence,
                                        *v,
                                        *name,
                                    );
                                }
                            });
                    });
                });
            });

            // Picking a shorter timeout can leave a heartbeat that no longer
            // fits; pull it back to the longest that does, rather than leaving
            // an invalid pair on screen for the user to puzzle over.
            if self.draft.heartbeat_seconds >= self.draft.timeout_seconds {
                match HEARTBEATS.iter().rev().find(|(s, _)| *s < self.draft.timeout_seconds) {
                    Some((secs, _)) => self.draft.heartbeat_seconds = *secs,
                    // No listed interval fits. Rather than leave a policy that
                    // can never be saved, fall back to half the timeout, which
                    // always satisfies the rule.
                    None => self.draft.heartbeat_seconds = (self.draft.timeout_seconds / 2).max(60),
                }
            }

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Must be above 60. Only entering your password scores 100. Signs that \
                     the computer is merely switched on, connected, or being typed at \
                     cannot total more than 60 between them, because a burglar sitting at \
                     your desk produces all of them. Above 60, nothing but a real check-in \
                     can hold the deadline open.",
                )
                .size(11.0)
                .color(DIM),
            );

            // Show what the core would say before anything is written.
            let verdict = self.draft.validate();
            ui.add_space(8.0);
            match &verdict {
                Ok(()) if self.draft.enabled => {
                    ui.label(
                        egui::RichText::new(format!(
                            "Vault arms after {} without a check-in.",
                            human_duration(self.draft.timeout_seconds)
                        ))
                        .size(11.5)
                        .color(MUTED),
                    );
                }
                Ok(()) => {
                    ui.label(
                        egui::RichText::new("Disabled. No deadline will be computed.")
                            .size(11.5)
                            .color(MUTED),
                    );
                }
                Err(e) => {
                    ui.label(egui::RichText::new(e.to_string()).size(11.5).color(ALERT));
                }
            }

            // Enforcement lives in the service, not here. Saying so is not a
            // detail: a person who configures a policy, sees a countdown and
            // is told nothing will reasonably conclude they are protected.
            // Believing that wrongly is the worst failure this product has.
            if self.overviews.iter().any(|o| {
                o.interrupted
                    && self.vault.as_ref().map(|v| v.display().to_string() == o.path).unwrap_or(false)
            }) {
                ui.add_space(8.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x2A, 0x20, 0x1C))
                    .rounding(R)
                    .inner_margin(egui::Margin::symmetric(13.0, 11.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new("A WATCHER STOPPED WITHOUT SHUTTING DOWN")
                                .size(12.0)
                                .strong()
                                .color(WARN),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "Its window was closed, the machine lost power, or somebody \
                                 ended the process. This vault was not being watched for \
                                 that period. The Records section has the times.",
                            )
                            .size(11.5)
                            .color(MUTED),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "Nobody can stop a watcher being killed on a machine they \
                                 control. What defends the vault in that case is key \
                                 protection, not the deadline.",
                            )
                            .size(11.0)
                            .color(DIM),
                        );
                    });
            }

            let watching = self.watch.as_ref().map(|w| w.running).unwrap_or(false);
            let armed = self.watch.as_ref().map(|w| w.allow_destruction).unwrap_or(false);
            let stale = self.watch.as_ref().map(|w| w.stale).unwrap_or(false);

            if self.policy.enabled && watching {
                ui.add_space(10.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x18, 0x24, 0x1E))
                    .rounding(R)
                    .inner_margin(egui::Margin::symmetric(13.0, 11.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(if armed {
                                "ENFORCED, CAN DESTROY"
                            } else {
                                "WATCHING ONLY, WILL NEVER DESTROY"
                            })
                            .size(12.0)
                            .strong()
                            .color(if armed { ALERT } else { OK }),
                        );
                        ui.add_space(4.0);
                        let w = self.watch.clone().unwrap();
                        ui.label(
                            egui::RichText::new(format!(
                                "Service running as process {}, checking every {}.",
                                w.pid,
                                human_duration(w.interval_seconds)
                            ))
                            .size(11.5)
                            .color(MUTED),
                        );
                        if !armed {
                            ui.label(
                                egui::RichText::new(
                                    "When the deadline passes this will report ARMED and \
                                     stop there. Nothing will be destroyed. Stop it and use \
                                     Start and arm if that is what you want.",
                                )
                                .size(11.5)
                                .color(WARN),
                            );
                        }
                        ui.add_space(6.0);
                        if quiet_button(ui, "Stop watching").clicked() {
                            if let Some(s) = self.session() {
                                match s.stop_watch() {
                                    Ok(()) => self.say(
                                        "Stop requested. The service exits on its next check.",
                                        Tone::Neutral,
                                    ),
                                    Err(e) => self.say(e.to_string(), Tone::Bad),
                                }
                            }
                        }
                    });
            }

            if stale {
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(
                        "A previous service registered for this vault is no longer running. \
                         The vault is not being watched.",
                    )
                    .size(11.5)
                    .color(WARN),
                );
                if quiet_button(ui, "Clear stale record").clicked() {
                    if let Some(s) = self.session() {
                        let _ = s.clear_stale_watch();
                        self.poll();
                    }
                }
            }

            if self.policy.enabled && !watching {
                ui.add_space(10.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x2A, 0x20, 0x1C))
                    .rounding(R)
                    .inner_margin(egui::Margin::symmetric(13.0, 11.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new("CONFIGURED, NOT ENFORCED")
                                .size(12.0)
                                .strong()
                                .color(WARN),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "This window shows the countdown but never acts on it. \
                                 Nothing will destroy this vault until the background \
                                 service is running and has been given permission.",
                            )
                            .size(11.5)
                            .color(MUTED),
                        );
                        ui.add_space(6.0);
                        let cmd = match &self.vault {
                            Some(v) => format!(
                                "ztd watch {} --interval 300 --allow-destruction",
                                v.display()
                            ),
                            None => "ztd watch <vault> --interval 300 --allow-destruction".into(),
                        };
                        ui.label(egui::RichText::new(&cmd).monospace().size(11.0).color(TEXT));
                        // A disabled button with its reason hidden in hover
                        // text is a wall. Shown here as a step, with the way
                        // through it attached.
                        if !self.dry_run_seen {
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(
                                    "Arming is locked until you have seen a dry run. It \
                                     changes nothing and takes a moment; arming something \
                                     irreversible should not be one unread click.",
                                )
                                .size(11.5)
                                .color(WARN),
                            );
                            ui.add_space(4.0);
                            if quiet_button(ui, "Run dry run now").clicked() {
                                if let Some(s) = self.session() {
                                    self.dry_run = s.dry_run();
                                    self.dry_run_seen = true;
                                    self.section = Section::Destruction;
                                    self.say(
                                        "Dry run only, nothing was changed. Read it, then \
                                         return to Deadman to arm.",
                                        Tone::Neutral,
                                    );
                                }
                            }
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if quiet_button(ui, "Copy command").clicked() {
                                ui.output_mut(|o| o.copied_text = cmd.clone());
                                self.say("Command copied.", Tone::Neutral);
                            }
                            if quiet_button(ui, "Start watching").clicked() {
                                if let Some(s) = self.session() {
                                    match s.start_watch(self.policy_interval(), false) {
                                        Ok(()) => self.say(
                                            "Service started in WATCH ONLY mode. It will \
                                             never destroy this vault, however long the \
                                             deadline is past. Use Start and arm for that.",
                                            Tone::Neutral,
                                        ),
                                        Err(e) => self.say(e.to_string(), Tone::Bad),
                                    }
                                }
                            }
                            // Arming is gated on having read a dry run, so
                            // nothing about what happens can be a surprise.
                            let can_arm = self.dry_run_seen;
                            if ui
                                .add_enabled(can_arm, egui::Button::new("Start and arm").fill(RAISED))
                                .on_hover_text(if can_arm {
                                    "Starts the service with permission to destroy this vault \
                                     when the deadline passes."
                                } else {
                                    "Locked until you have seen a dry run. There is a button \
                                     for that just above."
                                })
                                .clicked()
                            {
                                if let Some(s) = self.session() {
                                    match s.start_watch(self.policy_interval(), true) {
                                        Ok(()) => self.say(
                                            "Service started WITH permission to destroy this \
                                             vault when the deadline passes.",
                                            Tone::Bad,
                                        ),
                                        Err(e) => self.say(e.to_string(), Tone::Bad),
                                    }
                                }
                            }
                        });
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(
                                "Starting from here keeps running if this window is closed, \
                                 but not past a logout or restart. Use Restart at login below \
                                 so it comes back afterwards.",
                            )
                            .size(11.0)
                            .color(DIM),
                        );
                    });
            }

            // Surviving a restart. Deliberately separate from starting the
            // service now: one is a thing running, the other is a thing that
            // will run again.
            if self.policy.enabled {
                if let Some(a) = self.autostart.clone() {
                    ui.add_space(10.0);
                    card(ui, |ui| {
                        ui.label(
                            egui::RichText::new("RESTART AT LOGIN").size(12.0).strong().color(
                                if a.installed { OK } else { MUTED },
                            ),
                        );
                        ui.add_space(4.0);
                        if a.installed {
                            ui.label(
                                egui::RichText::new(if a.allows_destruction {
                                    "Installed, and permitted to destroy this vault when the \
                                     deadline passes."
                                } else {
                                    "Installed. It will watch but not destroy."
                                })
                                .size(11.5)
                                .color(if a.allows_destruction { ALERT } else { MUTED }),
                            );
                            ui.label(
                                egui::RichText::new(&a.location).monospace().size(10.5).color(DIM),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new(
                                    "Not installed. If this computer restarts, nothing will \
                                     watch this vault until you start the service again by \
                                     hand.",
                                )
                                .size(11.5)
                                .color(MUTED),
                            );
                        }
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(&a.description).size(10.5).color(DIM));
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "This starts the watcher when this account logs in. A computer \
                                 sitting at its login screen is not watching anything.",
                            )
                            .size(10.5)
                            .color(DIM),
                        );

                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if !a.installed {
                                if quiet_button(ui, "Install, watch only").clicked() {
                                    if let Some(s) = self.session() {
                                        match s.install_autostart(self.policy_interval(), false) {
                                            Ok(p) => self.say(
                                                format!("Installed at {p}. It will watch but not destroy."),
                                                Tone::Good,
                                            ),
                                            Err(e) => self.say(e.to_string(), Tone::Bad),
                                        }
                                        self.poll();
                                    }
                                }
                                // Same gate as arming the running service: a
                                // dry run must have been read first.
                                let can_arm = self.dry_run_seen;
                                if ui
                                    .add_enabled(
                                        can_arm,
                                        egui::Button::new("Install and arm").fill(RAISED),
                                    )
                                    .on_hover_text(if can_arm {
                                        "After a restart the watcher will come back with \
                                         permission to destroy this vault."
                                    } else {
                                        "Locked until you have seen a dry run. There is a \
                                         button for that above."
                                    })
                                    .clicked()
                                {
                                    if let Some(s) = self.session() {
                                        match s.install_autostart(self.policy_interval(), true) {
                                            Ok(p) => self.say(
                                                format!(
                                                    "Installed at {p} WITH permission to destroy."
                                                ),
                                                Tone::Bad,
                                            ),
                                            Err(e) => self.say(e.to_string(), Tone::Bad),
                                        }
                                        self.poll();
                                    }
                                }
                            } else if quiet_button(ui, "Remove").clicked() {
                                if let Some(s) = self.session() {
                                    match s.remove_autostart() {
                                        Ok(()) => self.say(
                                            "Removed. This vault will not be watched after a \
                                             restart.",
                                            Tone::Neutral,
                                        ),
                                        Err(e) => self.say(e.to_string(), Tone::Bad),
                                    }
                                    self.poll();
                                }
                            }
                        });
                    });
                }
            }

            ui.add_space(8.0);
            let changed = self.draft != self.policy;
            ui.horizontal(|ui| {
                let can_save = changed && verdict.is_ok();
                if ui
                    .add_enabled(can_save, egui::Button::new("Save policy").fill(RAISED))
                    .clicked()
                {
                    if let Some(s) = self.session() {
                        match s.save_policy(&self.draft) {
                            Ok(()) => {
                                self.policy = s.load_policy();
                                self.draft = self.policy;
                                if self.policy.enabled {
                                    self.say(
                                        "Policy saved. Nothing destroys the vault unless the \
                                         service is run with --allow-destruction.",
                                        Tone::Good,
                                    );
                                } else {
                                    self.say("Policy saved and disabled.", Tone::Good);
                                }
                            }
                            Err(e) => self.say(e.to_string(), Tone::Bad),
                        }
                    }
                }
                if changed && quiet_button(ui, "Revert").clicked() {
                    self.draft = self.policy;
                }
            });
        });
    }

    /// Split-key protection: what it is, and what it is not.
    fn protection_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            if self.vault.is_none() {
                ui.label(egui::RichText::new("No vault selected.").size(12.5).color(MUTED));
                return;
            }

            let split = self.split.clone();
            match &split {
                Some(st) if st.enrolled => {
                    readout(
                        ui,
                        "Threshold",
                        &format!("{} of {}", st.threshold, st.components.len()),
                        TEXT,
                    );
                    readout(ui, "Components", &st.components.join(", "), TEXT);
                    readout(
                        ui,
                        "Drive theft",
                        if st.resists_drive_theft { "RESISTED" } else { "NOT RESISTED" },
                        if st.resists_drive_theft { OK } else { ALERT },
                    );
                    readout(
                        ui,
                        "Losing one",
                        if st.tolerates_one_loss { "survivable" } else { "PERMANENT DATA LOSS" },
                        if st.tolerates_one_loss { OK } else { ALERT },
                    );
                }
                _ => {
                    readout(ui, "Status", "NOT ENROLLED", WARN);
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "This vault is protected by its password alone. Someone who \
                             removes the drive and copies the vault needs only to guess \
                             that password, offline, for as long as they like.",
                        )
                        .size(11.5)
                        .color(MUTED),
                    );
                }
            }

            if let Some(st) = &split {
                if !st.notes.is_empty() {
                    ui.add_space(6.0);
                    for n in &st.notes {
                        ui.label(egui::RichText::new(format!("- {n}")).size(11.0).color(WARN));
                    }
                }
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let enrolled = split.as_ref().map(|s| s.enrolled).unwrap_or(false);
                if !enrolled && quiet_button(ui, "Protect\u{2026}").clicked() {
                    if let Some(token) = rfd::FileDialog::new()
                        .set_title("Where to write the recovery token")
                        .set_file_name("zerotrace-token.txt")
                        .save_file()
                    {
                        let custodian = rfd::FileDialog::new()
                            .set_title("Where to write the custodian token (recommended)")
                            .set_file_name("zerotrace-custodian.txt")
                            .save_file();
                        self.enrol_token = Some(token);
                        self.enrol_custodian = custodian;
                        self.pending = Some(Pending::Enroll);
                        self.focus_prompt = true;
                    }
                }
                if enrolled && quiet_button(ui, "Add token\u{2026}").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Select a recovery or custodian token")
                        .pick_file()
                    {
                        match zerotrace_ipc::validate_token_file(&p) {
                            Ok(()) => {
                                if !self.tokens.contains(&p) {
                                    self.tokens.push(p);
                                }
                                self.say(
                                    format!(
                                        "{} token(s) supplied for this session.",
                                        self.tokens.len()
                                    ),
                                    Tone::Good,
                                );
                            }
                            Err(e) => self.say(e.to_string(), Tone::Bad),
                        }
                    }
                }
                if enrolled && !self.tokens.is_empty() && quiet_button(ui, "Clear").clicked() {
                    self.tokens.clear();
                    self.say("Tokens cleared for this session.", Tone::Neutral);
                }
                if enrolled {
                    let mut no_pw = !self.use_password;
                    if ui
                        .checkbox(&mut no_pw, "Password lost")
                        .on_hover_text(
                            "Open with two tokens instead of the password. Both must be \
                             supplied.",
                        )
                        .changed()
                    {
                        self.use_password = !no_pw;
                    }
                }
            });

            if !self.tokens.is_empty() {
                ui.add_space(4.0);
                for t in &self.tokens {
                    ui.label(
                        egui::RichText::new(format!(
                            "token: {}",
                            t.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                        ))
                        .size(11.0)
                        .color(DIM),
                    );
                }
            }
        });
    }

    /// The duress password.
    fn duress_card(&mut self, ui: &mut egui::Ui) {
        if self.vault.is_none() {
            return;
        }
        card(ui, |ui| {
            ui.label(egui::RichText::new("DURESS PASSWORD").size(11.0).color(MUTED));
            ui.add_space(7.0);
            ui.label(
                egui::RichText::new(
                    "A second password that opens this vault into different files, and \
                     destroys the real contents as it does. Quietly: somebody watching sees \
                     an ordinary vault open.",
                )
                .size(11.5)
                .color(MUTED),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "The real contents are gone the moment it is used. Not hidden, not \
                     recoverable. Typing it by mistake is the same as destroying the vault.",
                )
                .size(11.5)
                .color(ALERT),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "Nothing reveals whether a vault has one. Every vault carries the space \
                     for it, filled with random bytes when unused, so examining the file \
                     cannot answer the question.",
                )
                .size(11.0)
                .color(DIM),
            );

            if self.duress_set_this_session {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("A duress password was set for this vault.")
                        .size(12.0)
                        .strong()
                        .color(OK),
                );
                ui.label(
                    egui::RichText::new(
                        "Shown only until this window is closed. Neither the vault nor this \
                         program can be asked afterwards whether one exists, which is what \
                         keeps it worth having.",
                    )
                    .size(11.0)
                    .color(DIM),
                );
            }

            ui.add_space(10.0);
            if quiet_button(ui, "Choose the files it will show\u{2026}").clicked() {
                // Worded as choosing existing files rather than placing a new
                // one. The first version read as "where to put the decoy",
                // which led to naming a file that did not exist and a failure
                // partway through.
                if let Some(files) = rfd::FileDialog::new()
                    .set_title("Pick files that already exist, to show under duress")
                    .pick_files()
                {
                    let missing: Vec<&PathBuf> =
                        files.iter().filter(|p| !p.is_file()).collect();
                    if !missing.is_empty() {
                        self.say(
                            "Those must be files that already exist on this computer."
                                .to_string(),
                            Tone::Bad,
                        );
                    } else if !files.is_empty() {
                        self.duress_files = files;
                        self.pending = Some(Pending::Duress);
                        self.focus_prompt = true;
                    }
                }
            }
            if !self.duress_files.is_empty() {
                ui.add_space(4.0);
                for f in &self.duress_files {
                    ui.label(
                        egui::RichText::new(format!(
                            "will show: {}",
                            f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                        ))
                        .size(11.0)
                        .color(DIM),
                    );
                }
            }
        });
    }

    /// Remote custody: the one arrangement that outlives this machine.
    fn custody_card(&mut self, ui: &mut egui::Ui) {
        let enrolled = self.split.as_ref().map(|s| s.enrolled).unwrap_or(false);
        if !enrolled {
            return;
        }
        let view = self.custody.clone();

        card(ui, |ui| {
            ui.label(egui::RichText::new("REMOTE CUSTODY").size(11.0).color(MUTED));
            ui.add_space(7.0);
            ui.label(
                egui::RichText::new(
                    "Everything else here runs on this computer, and whoever controls this \
                     computer can stop it. A custodian holds one component somewhere else, \
                     and destroys it if you stop checking in. That is the only part of this \
                     that an attacker at your desk cannot switch off.",
                )
                .size(11.5)
                .color(MUTED),
            );
            ui.add_space(9.0);

            match &view {
                Some(v) if v.established => {
                    readout(ui, "Custodian", &v.directory, TEXT);
                    readout(
                        ui,
                        "Reachable",
                        if v.reachable { "yes" } else { "not right now" },
                        if v.reachable { OK } else { WARN },
                    );
                    if v.expired {
                        readout(ui, "Status", "EXPIRED, COMPONENT DESTROYED", ALERT);
                    } else if let Some(r) = v.seconds_remaining {
                        readout(ui, "Holds until", &human_duration(r), OK);
                    }
                    ui.add_space(9.0);
                    if quiet_button(ui, "Check in with custodian").clicked() {
                        self.pending = Some(Pending::CustodyCheckIn);
                        self.focus_prompt = true;
                    }
                }
                _ => {
                    ui.label(
                        egui::RichText::new(
                            "Not established. The deadline currently depends on a program \
                             running on this computer.",
                        )
                        .size(11.5)
                        .color(WARN),
                    );
                    ui.add_space(9.0);
                    if quiet_button(ui, "Establish custody\u{2026}").clicked() {
                        if let Some(dir) = rfd::FileDialog::new()
                            .set_title("A folder the custodian will use, NOT on this disk")
                            .pick_folder()
                        {
                            if let Some(token) = rfd::FileDialog::new()
                                .set_title("The custodian token to hand over")
                                .pick_file()
                            {
                                self.custody_dir = Some(dir);
                                self.custody_token = Some(token);
                                self.pending = Some(Pending::Custody);
                                self.focus_prompt = true;
                            }
                        }
                    }
                    ui.add_space(5.0);
                    ui.label(
                        egui::RichText::new(
                            "Choose a folder on another machine, a network share, or a \
                             device kept elsewhere. On this disk it protects nothing.",
                        )
                        .size(11.0)
                        .color(DIM),
                    );
                }
            }
        });
    }

    fn integrity_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            heading(ui, "Chain status");
            match &self.chain {
                Some(c) => {
                    readout(ui, "Audit chain", &c.audit_chain, assurance_color(&c.audit_chain));
                    readout(
                        ui,
                        "State journal",
                        &c.journal_chain,
                        assurance_color(&c.journal_chain),
                    );
                    readout(ui, "Audit anchor", &c.audit_anchor, assurance_color(&c.audit_anchor));
                    if !c.detail.is_empty() {
                        ui.add_space(5.0);
                        ui.label(egui::RichText::new(&c.detail).size(11.5).color(ALERT));
                    }
                }
                None => {
                    ui.label(egui::RichText::new("No vault selected.").size(12.5).color(MUTED));
                }
            }
        });
    }

    fn capability_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            heading(ui, "This build enforces");
            // A nested scroll area with only a max height collapses to almost
            // nothing here, so the height is set explicitly.
            egui::ScrollArea::vertical()
                .id_source("caps")
                .min_scrolled_height(300.0)
                .max_height(300.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                for c in &self.caps {
                    let color = assurance_color(&c.assurance);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&c.name).size(12.0).color(MUTED),
                            )
                            .truncate(true),
                        )
                        .on_hover_text(&c.note);
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    egui::RichText::new(&c.assurance)
                                        .monospace()
                                        .size(11.0)
                                        .color(color),
                                );
                            },
                        );
                    });
                }
            });
        });
    }

    /// The vault's contents, with a way to get files back out.
    ///
    /// Deliberately full width and below the summary panels: a list of what is
    /// stored is the thing a person opens a vault to see, and it was
    /// previously a cramped scroll area inside another card.
    fn contents_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.horizontal(|ui| {
                heading(ui, "Stored files");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !self.entries.is_empty() && quiet_button(ui, "Extract all\u{2026}").clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.export_dir = Some(d);
                            self.pending = Some(Pending::ExportAll);
                            self.focus_prompt = true;
                        }
                    }
                });
            });

            if self.vault.is_none() {
                ui.label(egui::RichText::new("No vault selected.").size(12.5).color(MUTED));
                return;
            }
            if self.entries.is_empty() {
                ui.label(
                    egui::RichText::new(
                        "Unlock the vault to list its contents. Filenames and sizes are \
                         encrypted, so nothing can be shown until it is open.",
                    )
                    .size(12.5)
                    .color(MUTED),
                );
                return;
            }

            ui.add_space(2.0);
            egui::ScrollArea::vertical()
                .id_source("contents")
                .max_height(360.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let mut extract: Option<usize> = None;
                    for e in &self.entries {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&e.path).size(13.0).color(TEXT),
                                )
                                .truncate(true),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if quiet_button(ui, "Extract\u{2026}").clicked() {
                                        extract = Some(e.index);
                                    }
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{:>9}   {} chunk{}",
                                            human_bytes(e.size),
                                            e.chunks,
                                            if e.chunks == 1 { "" } else { "s" }
                                        ))
                                        .monospace()
                                        .size(11.5)
                                        .color(MUTED),
                                    );
                                },
                            );
                        });
                        ui.add_space(3.0);
                    }
                    if let Some(i) = extract {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.export_dir = Some(d);
                            self.export_index = Some(i);
                            self.pending = Some(Pending::Export);
                            self.focus_prompt = true;
                        }
                    }
                });
        });
    }

    fn activity_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            heading(ui, "Recent activity");
            if self.log.is_empty() {
                ui.label(egui::RichText::new("No records yet.").size(12.5).color(MUTED));
                return;
            }
            egui::ScrollArea::vertical()
                .id_source("activity")
                .max_height(320.0)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                for e in &self.log {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("{:>4}", e.sequence))
                                .monospace()
                                .size(11.5)
                                .color(DIM),
                        );
                        ui.label(
                            egui::RichText::new(&e.event).monospace().size(11.5).color(TEXT),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    egui::RichText::new(human_time(e.timestamp))
                                        .monospace()
                                        .size(11.0)
                                        .color(DIM),
                                );
                            },
                        );
                    });
                }
            });
        });
    }

    fn destruction_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "Destroying a vault overwrites its master key. No password, recovery key \
                     or backup of the key material restores it afterwards. Copies of the \
                     container made earlier, on backups, snapshots or other machines, are \
                     not affected and will still open.",
                )
                .size(11.5)
                .color(MUTED),
            );
            ui.add_space(10.0);

            let ready = self.vault.is_some();
            ui.horizontal(|ui| {
                if quiet_button(ui, "Dry run").clicked() && ready {
                    if let Some(s) = self.session() {
                        self.dry_run = s.dry_run();
                        self.dry_run_seen = true;
                        self.report = None;
                        self.say("Dry run only. Nothing was changed.", Tone::Neutral);
                    }
                }
                if quiet_button(ui, "Panic lock").clicked() && ready {
                    if let Some(s) = self.session() {
                        let rows = s.panic_lock();
                        self.dry_run = rows
                            .into_iter()
                            .map(|r| DryRunStep {
                                stage: format!("{}: {}", r.name, r.assurance),
                                detail: r.note,
                            })
                            .collect();
                        self.say("Panic lock. The vault was not destroyed.", Tone::Neutral);
                    }
                }
                if danger_button(ui, "Panic destroy…").clicked() && ready {
                    self.destroy_confirm.clear();
                    self.pending = Some(Pending::Destroy);
                    self.focus_prompt = true;
                }
            });

            if !self.dry_run.is_empty() {
                ui.add_space(10.0);
                egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                    for step in &self.dry_run {
                        ui.label(egui::RichText::new(&step.stage).size(12.0).color(TEXT));
                        ui.label(egui::RichText::new(&step.detail).size(11.5).color(MUTED));
                        ui.add_space(5.0);
                    }
                });
            }

            if let Some(report) = &self.report {
                ui.add_space(10.0);
                egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(report).monospace().size(11.0).color(TEXT));
                });
            }
        });
    }

    /// The password prompt. Also the destroy confirmation, because the two
    /// must be collected together: neither alone should reach the core.
    fn prompt(&mut self, ctx: &egui::Context) {
        let Some(action) = self.pending else {
            self.prompt_frames = 0;
            return;
        };
        if self.prompt_frames == 0 {
            self.prompt_error.clear();
        }
        self.prompt_frames = self.prompt_frames.saturating_add(1);
        let mut canceled = false;
        let mut submit = false;

        egui::Window::new(action.title())
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_width(430.0);
                let body_color = if action == Pending::Destroy { ALERT } else { MUTED };
                ui.label(egui::RichText::new(action.body()).size(12.5).color(body_color));
                ui.add_space(12.0);

                ui.label(egui::RichText::new("Password").size(12.0).color(MUTED));
                let pw = ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                if self.focus_prompt {
                    pw.request_focus();
                    self.focus_prompt = false;
                }
                // A single-line TextEdit consumes Enter, so the key press has
                // to be read from the field's own response rather than from
                // the global input state.
                // Enter is honoured only once the prompt has been on screen
                // for a moment, and only with something in the field. Both
                // guards exist for the same reason: a keypress left over from
                // a native file dialog must not answer a question the person
                // has not yet seen.
                let settled = self.prompt_frames > 2;
                let has_input = !self.password.is_empty() || !self.use_password;
                let entered_in_field = settled
                    && has_input
                    && pw.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                // A split-protected vault needs its components here too, so the
                // dialog collects them rather than failing after the fact.
                // Only actions that open an existing vault need components.
                // Create makes a new one, so asking for a token there is
                // nonsense, and it happened because the status of the
                // previously selected vault was still in hand.
                let split_protected = action != Pending::Create
                    && self.split.as_ref().map(|s| s.enrolled).unwrap_or(false);
                let mut components_ready = true;

                if split_protected {
                    ui.add_space(10.0);
                    let needed = if self.use_password { 1usize } else { 2usize };
                    components_ready = self.tokens.len() >= needed;

                    ui.label(
                        egui::RichText::new("Key components").size(12.0).color(MUTED),
                    );
                    if self.tokens.is_empty() {
                        ui.label(
                            egui::RichText::new(if action == Pending::Destroy {
                                "This vault is split protected. Attach a recovery or \
                                 custodian token. The password alone cannot open this \
                                 vault, and so cannot destroy it either."
                            } else {
                                "This vault is split protected. Attach a recovery or \
                                 custodian token; the password alone will not open it."
                            })
                            .size(11.5)
                            .color(ALERT),
                        );
                    } else {
                        // Shown in the alert color on a destructive prompt: a
                        // component carried over from an earlier operation
                        // must never be invisible at the moment it authorizes
                        // something irreversible.
                        let color = if action == Pending::Destroy { ALERT } else { OK };
                        for t in &self.tokens {
                            ui.label(
                                egui::RichText::new(format!(
                                    "attached: {}",
                                    t.file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_default()
                                ))
                                .size(11.5)
                                .color(color),
                            );
                        }
                        if action == Pending::Destroy {
                            ui.label(
                                egui::RichText::new(
                                    "This component is already attached and will authorize \
                                     the destruction.",
                                )
                                .size(11.0)
                                .color(ALERT),
                            );
                        }
                    }
                    ui.horizontal(|ui| {
                        if quiet_button(ui, "Attach token\u{2026}").clicked() {
                            if let Some(p) =
                                rfd::FileDialog::new().set_title("Select a token file").pick_file()
                            {
                                match zerotrace_ipc::validate_token_file(&p) {
                                    Ok(()) => {
                                        if !self.tokens.contains(&p) {
                                            self.tokens.push(p);
                                        }
                                        self.prompt_error.clear();
                                    }
                                    // Rejected here rather than accepted and
                                    // failed later: a wrong file should be a
                                    // correction, not a dead end.
                                    Err(e) => self.prompt_error = e.to_string(),
                                }
                            }
                        }
                        if !self.tokens.is_empty() && quiet_button(ui, "Clear").clicked() {
                            self.tokens.clear();
                            self.prompt_error.clear();
                        }
                    });
                    if !self.prompt_error.is_empty() {
                        ui.label(
                            egui::RichText::new(&self.prompt_error).size(11.5).color(ALERT),
                        );
                    }
                }

                if action == Pending::Duress {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new("Duress password").size(12.0).color(MUTED),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.duress_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(
                            "Choose a completely different phrase, not a variation of your \
                             real one. Two passwords a keystroke apart get confused under \
                             pressure, and confusing them destroys the vault.",
                        )
                        .size(11.0)
                        .color(WARN),
                    );
                }

                if action == Pending::Destroy {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(format!("Type {DESTROY_CONFIRMATION} to confirm"))
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.destroy_confirm)
                            .desired_width(f32::INFINITY),
                    );
                }

                // Shown for every prompt, not only the split-protected ones:
                // an error raised inside a modal belongs inside it, not in the
                // status bar behind it.
                if !self.prompt_error.is_empty() {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(&self.prompt_error).size(11.5).color(ALERT));
                }

                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    let label = if action == Pending::Destroy {
                        "Destroy permanently"
                    } else {
                        "Continue"
                    };
                    let clicked = if action == Pending::Destroy {
                        // Disabled until every required component is present, so
                        // the irreversible step cannot be reached in a state
                        // that would only fail.
                        ui.add_enabled_ui(components_ready, |ui| danger_button(ui, label).clicked())
                            .inner
                    } else {
                        ui.add_enabled_ui(components_ready, |ui| quiet_button(ui, label).clicked())
                            .inner
                    };
                    // Enter must not submit the destroy dialog: a destructive
                    // action should need a deliberate click.
                    let entered = action != Pending::Destroy && entered_in_field;
                    if clicked || entered {
                        if self.password.is_empty() && self.use_password {
                            self.prompt_error =
                                "Enter the vault password before continuing.".to_string();
                        } else {
                            submit = true;
                        }
                    }
                    if quiet_button(ui, "Cancel").clicked() {
                        canceled = true;
                    }
                });
            });

        if canceled {
            self.password.clear();
            self.destroy_confirm.clear();
            self.prompt_error.clear();
            self.pending = None;
            self.say("Canceled. Nothing was changed.", Tone::Neutral);
        } else if submit {
            self.run_pending();
        }
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut app = App::default();
    if let Some(p) = args.iter().find(|a| !a.starts_with("--")) {
        app.open_vault(PathBuf::from(p));
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Apex ZeroTrace"),
        ..Default::default()
    };

    eframe::run_native(
        "Apex ZeroTrace",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Box::new(app)
        }),
    )
}
