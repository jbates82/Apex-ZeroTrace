//! `ztd`, the resident ZeroTrace service.
//!
//! The policy must not depend on the GUI or the CLI being alive (INV-8), so
//! evaluation lives in a process whose only job is to keep looking. It holds
//! no vault keys and cannot decrypt anything (INV-9): it reads the audit log
//! and the state journal, both of which are metadata, and writes state
//! records. Destruction, when it happens, needs only the container path and
//! the header offset of the wrapped key.
//!
//! # What this is not
//!
//! It is not integrated with any OS service manager. There is no Windows
//! Service wrapper, no systemd unit, no launchd plist, so nothing restarts it
//! if it dies. That is Phase 6 and is reported as NOT IMPLEMENTED rather than
//! implied.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use zerotrace_audit::AuditLog;
use zerotrace_auth::audit_events as ev;
use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::{self, TimeAnchor};
use zerotrace_core::{Assurance, VaultId};
use zerotrace_destroy::{authorize, execute, needs_resume, Trigger};
use zerotrace_journal::{AuditAnchor, StateJournal};
use zerotrace_policy::DeadmanPolicy;
use zerotrace_presence::{PresenceConfig, PresenceEngine, SignalKind};
use zerotrace_audit::AuditLog as ServiceAuditLog;
use zerotrace_platform::watch;
use zerotrace_sanitize::SanitizationProfile;

const USAGE: &str = "\
Apex ZeroTrace service

  ztd watch <vault> [options]     evaluate the deadman policy continuously
  ztd once  <vault> [options]     evaluate once and exit

Options:
  --interval SECONDS   how often to evaluate, default 60
  --profile standard|enhanced|maximum
  --allow-destruction  permit destruction when the deadline passes
  --dry-run            report what would happen and change nothing

Without --allow-destruction the service observes, records state, and stops at
ARMED without destroying anything. This is the default, on purpose.
";

struct Config {
    vault: PathBuf,
    interval: Duration,
    profile: SanitizationProfile,
    allow_destruction: bool,
    dry_run: bool,
    once: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Apex ZeroTrace service {}", env!("CARGO_PKG_VERSION"));
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let once = match args[0].as_str() {
        "watch" => false,
        "once" => true,
        other => {
            eprintln!("ztd: unknown command {other}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let Some(vault) = args.get(1).map(PathBuf::from) else {
        eprintln!("ztd: a vault path is required");
        return ExitCode::FAILURE;
    };

    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1));
    let cfg = Config {
        vault,
        interval: Duration::from_secs(
            flag("--interval").and_then(|s| s.parse().ok()).unwrap_or(60),
        ),
        profile: match flag("--profile").map(|s| s.as_str()) {
            Some("enhanced") => SanitizationProfile::Enhanced,
            Some("maximum") => SanitizationProfile::Maximum,
            _ => SanitizationProfile::Standard,
        },
        allow_destruction: args.iter().any(|a| a == "--allow-destruction"),
        dry_run: args.iter().any(|a| a == "--dry-run"),
        once,
    };

    match run(cfg) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ztd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Appends an audit record. Best effort: an audit failure must not stop the
/// service from watching, but it must not pass silently either.
fn note_event(vault: &Path, event: &str, detail: &str) {
    let id = ServiceAuditLog::open(audit_path(vault), VaultId::nil())
        .and_then(|l| l.records())
        .ok()
        .and_then(|r| r.first().map(|x| x.vault_id))
        .unwrap_or_else(VaultId::nil);
    match ServiceAuditLog::open(audit_path(vault), id) {
        Ok(mut log) => {
            if log.append(event, detail).is_err() {
                eprintln!("ztd: warning: could not write an audit record");
            }
        }
        Err(e) => eprintln!("ztd: warning: could not open the audit log: {e}"),
    }
}

fn audit_path(v: &Path) -> PathBuf {
    PathBuf::from(format!("{}.audit", v.display()))
}
fn journal_path(v: &Path) -> PathBuf {
    PathBuf::from(format!("{}.journal", v.display()))
}
fn policy_path(v: &Path) -> PathBuf {
    PathBuf::from(format!("{}.policy", v.display()))
}

fn load_policy(v: &Path) -> DeadmanPolicy {
    let Ok(text) = std::fs::read_to_string(policy_path(v)) else {
        return DeadmanPolicy::default();
    };
    let mut p = DeadmanPolicy::default();
    for line in text.lines() {
        let Some((k, val)) = line.split_once('=') else { continue };
        let (k, val) = (k.trim(), val.trim());
        match k {
            "enabled" => p.enabled = val == "true",
            "timeout_seconds" => p.timeout_seconds = val.parse().unwrap_or(p.timeout_seconds),
            "heartbeat_seconds" => {
                p.heartbeat_seconds = val.parse().unwrap_or(p.heartbeat_seconds)
            }
            "required_confidence" => {
                p.required_confidence = val.parse().unwrap_or(p.required_confidence)
            }
            "warning_threshold" => p.warning_threshold = val.parse().unwrap_or(p.warning_threshold),
            "critical_threshold" => {
                p.critical_threshold = val.parse().unwrap_or(p.critical_threshold)
            }
            "destroy_after_failures" => {
                p.destroy_after_failures = val.parse().unwrap_or(p.destroy_after_failures)
            }
            _ => {}
        }
    }
    // An invalid policy is replaced by the disabled default rather than being
    // partially honoured.
    if p.validate().is_err() {
        return DeadmanPolicy::default();
    }
    p
}

fn presence_from_audit(log: &AuditLog, engine: &mut PresenceEngine) -> zerotrace_core::Result<()> {
    for r in log.records()? {
        let kind = match r.event.as_str() {
            ev::AUTH_SUCCESS => SignalKind::PasswordAuth,
            "DEADMAN_CHECKIN" => SignalKind::ExplicitCheckIn,
            ev::FILE_IMPORTED | ev::FILE_EXPORTED | ev::VAULT_OPENED => SignalKind::VaultOperation,
            _ => continue,
        };
        engine.observe(kind, TimeAnchor { wall: r.timestamp, monotonic: r.timestamp.max(0) as u64 });
    }
    Ok(())
}

/// Releases the watch registration however the process leaves `run`.
struct WatchGuard {
    vault: PathBuf,
    held: bool,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        if self.held {
            watch::release(&self.vault);
        }
    }
}

fn run(cfg: Config) -> zerotrace_core::Result<ExitCode> {
    let origin = Instant::now();

    // Registered before anything else, so a second service on the same vault
    // is refused rather than quietly racing the first on its journal.
    // A watcher that stopped without releasing its lock was killed, crashed,
    // or had its window closed. That cannot be prevented on a machine someone
    // else controls, but it can be written down, so the lapse is visible on
    // return rather than silently absorbed.
    if !cfg.once {
        if let watch::WatchStatus::Stale(old) = watch::status(&cfg.vault) {
            let gone_for = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64 - old.heartbeat_at)
                .unwrap_or(0)
                .max(0);
            note_event(
                &cfg.vault,
                ev::WATCH_INTERRUPTED,
                &format!(
                    "previous watcher {} stopped without shutting down, unwatched for {}s",
                    old.pid, gone_for
                ),
            );
            println!(
                "  NOTE: the previous watcher stopped without shutting down, and this vault \
                 was unwatched for {gone_for} seconds. Recorded in the audit log."
            );
        }
    }

    let _guard = if cfg.once {
        // A single evaluation neither needs exclusivity nor should it disturb
        // a long-running watcher already registered for this vault.
        WatchGuard { vault: cfg.vault.clone(), held: false }
    } else {
        watch::acquire(&cfg.vault, cfg.interval.as_secs(), cfg.allow_destruction)?;
        WatchGuard { vault: cfg.vault.clone(), held: true }
    };
    println!("ZeroTrace service watching {}", cfg.vault.display());
    println!("  interval          {}s", cfg.interval.as_secs());
    println!("  profile           {}", cfg.profile.label());
    println!(
        "  destruction       {}",
        if cfg.dry_run {
            "DRY RUN, nothing will be destroyed"
        } else if cfg.allow_destruction {
            "PERMITTED once the deadline passes"
        } else {
            "NOT PERMITTED, will stop at ARMED"
        }
    );
    println!("  service manager   {}", Assurance::NotImplemented.label());
    if !cfg.once {
        println!("  process id        {}", std::process::id());
    }

    // Closing this window kills the watcher, and nothing announces that it has
    // happened: the desktop window would still show a countdown. Believing you
    // are protected when you are not is this product's worst failure, so the
    // warning says why rather than only saying don't.
    //
    // Not shown for `once`, which evaluates and exits by design.
    if !cfg.once {
        println!();
        println!("  ========================================================");
        println!("   DO NOT CLOSE THIS WINDOW");
        println!("  ========================================================");
        println!();
        println!("   Closing it stops the watcher. Nothing is destroyed and");
        println!("   no files are harmed, but this vault stops being watched");
        println!("   and the deadline will never be acted on. The desktop");
        println!("   window would still show a countdown, so you would have");
        println!("   no sign that protection had stopped.");
        println!();
        println!("   Minimize it instead. To stop deliberately, press Ctrl-C");
        println!("   here, or use Stop watching in the desktop window.");
        println!();
        println!("   To have the watcher start again by itself after a");
        println!("   restart, use Restart at login in the Deadman section.");
    }
    println!();

    if !cfg.once {
        note_event(&cfg.vault, ev::WATCH_STARTED, if cfg.allow_destruction {
            "armed"
        } else {
            "watch only"
        });
    }

    let mut reported = Reported::default();

    loop {
        // Checked before the work, so a stop takes effect promptly and cannot
        // interrupt an evaluation already under way.
        if !cfg.once && watch::stop_requested(&cfg.vault) {
            note_event(&cfg.vault, ev::WATCH_STOPPED, "requested");
            println!("Stop requested. Shutting down.");
            return Ok(ExitCode::SUCCESS);
        }
        // Refreshed before the work: a lock that stops moving is how anyone
        // else knows this watcher has gone.
        if !cfg.once {
            if let Err(e) = watch::heartbeat(&cfg.vault) {
                eprintln!("ztd: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
        let outcome = tick(&cfg, origin, &mut reported)?;
        if cfg.once || outcome == Tick::Terminal {
            return Ok(ExitCode::SUCCESS);
        }
        // Slept in short steps so a stop request is noticed quickly even when
        // the interval is long, rather than up to an interval later.
        let mut slept = Duration::from_secs(0);
        while slept < cfg.interval {
            let step = Duration::from_secs(1).min(cfg.interval - slept);
            std::thread::sleep(step);
            slept += step;
            if watch::stop_requested(&cfg.vault) {
                note_event(&cfg.vault, ev::WATCH_STOPPED, "requested");
                println!("Stop requested. Shutting down.");
                return Ok(ExitCode::SUCCESS);
            }
        }
    }
}

/// Steps the journal one state at a time until it reaches `target`.
///
/// Recording only the destination would skip stages, which the state machine
/// refuses and which would leave the journal unable to show how a vault came
/// to be armed.
fn advance_to(
    journal: &mut StateJournal,
    target: DeadmanState,
    now: TimeAnchor,
    deadline: i64,
    confidence: u32,
    anchor: AuditAnchor,
) -> zerotrace_core::Result<()> {
    const ORDER: [DeadmanState; 4] = [
        DeadmanState::Normal,
        DeadmanState::Warning,
        DeadmanState::Critical,
        DeadmanState::Armed,
    ];
    let index = |s: DeadmanState| ORDER.iter().position(|x| *x == s);
    let (Some(from), Some(to)) = (index(journal.state()), index(target)) else {
        // Anything outside the pre-commitment range is not this function's
        // business; destruction stages are driven by the destroy crate.
        return journal.record(target, now, deadline, confidence, anchor).map(|_| ());
    };

    if to < from {
        // Recovery is a single legal step backwards.
        journal.record(target, now, deadline, confidence, anchor)?;
        return Ok(());
    }
    for step in (from + 1)..=to {
        journal.record(ORDER[step], now, deadline, confidence, anchor)?;
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
enum Tick {
    Continue,
    Terminal,
}

/// Remembers what has already been said, so a state that persists for hours
/// does not fill the log with the same line every interval.
#[derive(Default)]
struct Reported {
    armed_notice: bool,
}

fn tick(cfg: &Config, origin: Instant, reported: &mut Reported) -> zerotrace_core::Result<Tick> {
    let log = AuditLog::open(audit_path(&cfg.vault), VaultId::nil())?;
    let policy_for_presence = load_policy(&cfg.vault);
    let mut engine = PresenceEngine::new(PresenceConfig::from_policy(
        policy_for_presence.heartbeat_seconds,
        policy_for_presence.timeout_seconds,
    ));
    presence_from_audit(&log, &mut engine)?;

    // The monotonic origin belongs to this process, so it cannot be compared
    // against timestamps written by earlier ones. Setting it from the wall
    // clock made the two agree by construction and disabled the rollback
    // check: shutting down, winding the clock back and starting again bought
    // unlimited time.
    //
    // The clock is instead held at or above the newest timestamp already
    // recorded, which is a time known to have happened.
    let raw = time::now(origin);
    let recorded = log
        .records()
        .ok()
        .and_then(|r| r.last().map(|x| x.timestamp))
        .unwrap_or(0)
        .max(
            StateJournal::open(journal_path(&cfg.vault), VaultId::nil())
                .ok()
                .and_then(|j| j.records().ok())
                .and_then(|r| r.last().map(|x| x.observed.wall))
                .unwrap_or(0),
        );
    let (now, clock) = time::not_before(raw, recorded);
    if let zerotrace_core::time::ClockAnomaly::Rollback { seconds } = clock {
        // Recorded, because a clock that went backwards across a restart is
        // either a misconfiguration or an attempt, and both are worth seeing.
        note_event(
            &cfg.vault,
            ev::CLOCK_ANOMALY,
            &format!("wall clock {seconds}s behind the newest record; held at the record"),
        );
        println!("  NOTE: the system clock is {seconds}s behind what this vault has already recorded.");
    }

    let assessment = engine.assess(now);
    let since_strong = assessment.last_strong_age.unwrap_or(u64::MAX);
    let policy = load_policy(&cfg.vault);
    let computed = policy.evaluate(assessment.confidence, since_strong);

    let vault_id = log.records()?.first().map(|r| r.vault_id).unwrap_or_else(VaultId::nil);
    let mut journal = StateJournal::open(journal_path(&cfg.vault), vault_id)?;

    // An interrupted destruction is finished before anything else is
    // considered: reverting would resurrect a committed decision.
    if needs_resume(&journal) {
        println!("[{}] resuming an interrupted destruction", raw.wall);
        if cfg.dry_run {
            println!("  dry run: would resume from {}", journal.state().label());
            return Ok(Tick::Terminal);
        }
        let report = execute(&cfg.vault, &mut journal, cfg.profile, Trigger::DeadlineExpired, now)?;
        println!("{}", report.render());
        return Ok(Tick::Terminal);
    }

    if journal.state().is_terminal() {
        println!("[{}] vault is DESTROYED; nothing further to do", raw.wall);
        return Ok(Tick::Terminal);
    }

    let records = log.records()?;
    let anchor = AuditAnchor {
        records: records.len() as u64,
        last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
    };
    let deadline = if policy.enabled { now.wall + policy.timeout_seconds as i64 } else { 0 };

    if computed != journal.state() {
        // The state machine forbids skipping stages, so every intermediate
        // state gets its own record. That is the point of the rule: a vault
        // cannot arrive at ARMED with no evidence it passed through WARNING
        // and CRITICAL first.
        if let Err(e) = advance_to(&mut journal, computed, now, deadline, assessment.confidence, anchor)
        {
            eprintln!("  warning: could not record the transition: {e}");
        } else {
            println!(
                "[{}] now {} (confidence {})",
                raw.wall,
                journal.state().label(),
                assessment.confidence
            );
        }
    }

    if computed != DeadmanState::Armed {
        reported.armed_notice = false;
    }

    if computed == DeadmanState::Armed {
        if !cfg.allow_destruction {
            // Deliberately not terminal. An observer that stopped here would
            // release its lock and leave the vault unwatched for ever: a
            // check-in would return it to NORMAL with nothing following the
            // countdown any more, which looks exactly like a deadman switch
            // that silently gave up.
            if !reported.armed_notice {
                reported.armed_notice = true;
                println!(
                    "[{}] ARMED. This service was started without --allow-destruction, so \
                     nothing will be destroyed. It keeps watching: check in and it will \
                     follow the countdown again.",
                    raw.wall
                );
            }
            return Ok(Tick::Continue);
        }
        if cfg.dry_run {
            println!("[{}] ARMED. Dry run, so nothing is destroyed. Steps that would run:", raw.wall);
            for (stage, detail) in zerotrace_destroy::simulate(&cfg.vault, cfg.profile) {
                println!("  {stage:<28} {detail}");
            }
            return Ok(Tick::Terminal);
        }

        println!("[{}] ARMED and destruction is permitted. Authorizing.", raw.wall);
        let auth = authorize(&mut journal, vault_id, now, Trigger::DeadlineExpired, anchor)?;
        println!("  authorization committed at journal record {}", auth.journal_sequence);
        let report = execute(&cfg.vault, &mut journal, cfg.profile, Trigger::DeadlineExpired, now)?;
        println!("{}", report.render());
        return Ok(Tick::Terminal);
    }

    Ok(Tick::Continue)
}
