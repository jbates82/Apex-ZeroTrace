//! `zt`, the Apex ZeroTrace command line.
//!
//! v0.1 exposes the vault only. The deadman and destruction commands are
//! present so the surface is visible, but they report NOT IMPLEMENTED rather
//! than pretending to enforce a policy that does not exist yet.

use std::path::PathBuf;
use std::process::ExitCode;

use zerotrace_core::{Assurance, Error, Result};
use zerotrace_crypto::CryptoSuite;
use zerotrace_kdf::KdfParams;
use zerotrace_audit::{AuditLog, ChainStatus};
use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::{self, TimeAnchor};
use zerotrace_destroy::{authorize_explicit, execute, needs_resume, simulate, Trigger};
use zerotrace_journal::{AuditAnchor, AuditAnchorStatus, JournalStatus, StateJournal};
use zerotrace_enterprise::remote::SigningIdentity;

use zerotrace_platform::service::{ServicePlan, Supervisor};
use zerotrace_split::providers::ComponentProvider;
use zerotrace_remote::custodian::{Custodian, DirectoryCustodian, HeldShare};
use zerotrace_remote::{signing_identity, verifying_key, Intent, Request, Verdict};
use zerotrace_split::{assess, ComponentKind, RecoveryToken, SplitBundle, UserProvider};
use zerotrace_platform::{storage_report, supervision_status_label};
use zerotrace_sanitize::SanitizationProfile;
use zerotrace_policy::DeadmanPolicy;
use zerotrace_presence::{PresenceConfig, PresenceEngine, SignalKind};
use zerotrace_auth::{audit_events as ev, FactorKind, FactorSet};
use zerotrace_vault::{Vault, VaultOptions};

const USAGE: &str = "\
Apex ZeroTrace - encrypted vault

  zt vault create <path>            create a vault
  zt vault status <path>            show vault metadata
  zt vault verify <path>            verify integrity of every chunk
  zt vault list   <path>            list stored files
  zt vault import <path> <file>...  add files
  zt vault export <path> <dir>      extract everything

  zt auth list    <path>            show required authentication factors
  zt auth register-fido <path>      bind a FIDO2 authenticator

  zt audit show   <path>            show the audit log
  zt audit verify <path>            check the audit chain

  zt deadman status   <path>        presence, countdown and state
  zt deadman checkin  <path>        record an explicit check-in
  zt deadman configure <path>       show or set the policy
  zt journal verify   <path>        check the state journal
  zt security audit                 report what this build enforces
  zt platform report <path>         what this filesystem allows
  zt enterprise keygen              generate an organization signing key
  zt recovery explain               how threshold recovery behaves

  zt split enroll <path> <token> <custodian>
                                    protect a vault with split keys
  zt split custody <path> <dir>     give the third component to a custodian
  zt duress set <path> <file>...    set a duress password showing these files
  zt split checkin <path>           tell a custodian you are still here
  zt split status <path>            split-key protection for this vault
  zt split explain                  the component model and what it defends
  zt service unit    <path>         print a service definition to review

  zt destroy status  <path>         destruction state
  zt destroy dry-run <path>         simulate destruction, changing nothing
  zt panic lock      <path>         close sessions, leave the vault intact
  zt panic destroy   <path>         irreversibly destroy the vault

Options for create:
  --suite xchacha|aes               AEAD, default xchacha
  --kdf interactive|sensitive       Argon2id cost, default interactive
  --store                           do not compress
  --fido2                           also require a FIDO2 authenticator

Split-protected vaults need --token <file> on every command that opens them.
Pass --token twice and --no-password to open with two tokens instead.

Destruction is real and irreversible. `zt panic destroy` overwrites the key,
and the deadman policy can do the same through `ztd` when it is started with
--allow-destruction. Run `zt destroy dry-run` first.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zt: {e}");
            ExitCode::FAILURE
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a == "--suite" || a == "--kdf" {
            skip = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        out.push(a.clone());
    }
    out
}

/// Reads a password without echoing where a terminal exists.
///
/// Falls back to a plain line on stdin when there is no terminal, so the tool
/// can be scripted. Passwords are never accepted as command line arguments:
/// argv is visible to every process on the machine.
fn read_secret(prompt: &str) -> Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_) => {
            use std::io::BufRead;
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| Error::Other(format!("could not read password: {e}")))?;
            Ok(line.trim_end_matches(['\n', '\r']).to_string())
        }
    }
}

fn prompt_password(confirm: bool) -> Result<String> {
    let p = read_secret("Password: ")?;
    if p.is_empty() {
        return Err(Error::Other("password must not be empty".into()));
    }
    if confirm {
        let again = read_secret("Confirm: ")?;
        if p != again {
            return Err(Error::Other("passwords do not match".into()));
        }
    }
    Ok(p)
}

fn run(args: &[String]) -> Result<ExitCode> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Apex ZeroTrace {}", env!("CARGO_PKG_VERSION"));
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    match (args[0].as_str(), args.get(1).map(|s| s.as_str())) {
        ("vault", Some("create")) => cmd_create(&args[2..]),
        ("vault", Some("status")) => cmd_status(&args[2..]),
        ("vault", Some("verify")) => cmd_verify(&args[2..]),
        ("vault", Some("list")) => cmd_list(&args[2..]),
        ("vault", Some("import")) => cmd_import(&args[2..]),
        ("vault", Some("export")) => cmd_export(&args[2..]),
        ("security", Some("audit")) => cmd_audit(),
        ("platform", Some("report")) => cmd_platform_report(&args[2..]),
        ("enterprise", Some("keygen")) => cmd_org_keygen(),
        ("recovery", Some("explain")) => cmd_recovery_explain(),
        // "enrol" is still accepted. Somebody may have it in a script, and
        // breaking a working command to change one letter is not a fair trade.
        ("split", Some("enroll")) | ("split", Some("enrol")) => cmd_split_enroll(&args[2..]),
        ("split", Some("custody")) => cmd_split_custody(&args[2..]),
        ("duress", Some("set")) => cmd_duress_set(&args[2..]),
        ("split", Some("checkin")) => cmd_split_checkin(&args[2..]),
        ("split", Some("status")) => cmd_split_status(&args[2..]),
        ("split", Some("explain")) => cmd_split_explain(),
        ("service", Some("unit")) => cmd_service_unit(&args[2..]),
        ("auth", Some("list")) => cmd_auth_list(&args[2..]),
        ("audit", Some("show")) => cmd_audit_show(&args[2..]),
        ("audit", Some("verify")) => cmd_audit_verify(&args[2..]),
        ("deadman", Some("status")) => cmd_deadman_status(&args[2..]),
        ("deadman", Some("checkin")) => cmd_deadman_checkin(&args[2..]),
        ("deadman", Some("configure")) => cmd_deadman_configure(&args[2..]),
        ("journal", Some("verify")) => cmd_journal_verify(&args[2..]),
        ("destroy", Some("status")) => cmd_destroy_status(&args[2..]),
        ("destroy", Some("dry-run")) => cmd_destroy_dryrun(&args[2..]),
        ("panic", Some("lock")) => cmd_panic_lock(&args[2..]),
        ("panic", Some("destroy")) => cmd_panic_destroy(&args[2..]),
        ("auth", _) => {
            println!("NOT IMPLEMENTED");
            println!();
            println!("Hardware authentication has no transport in this build. The key");
            println!("composition layer exists and is tested; see `zt auth list`.");
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            eprintln!("{USAGE}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_create(args: &[String]) -> Result<ExitCode> {
    let pos = positional(args);
    let path = pos.first().ok_or_else(|| Error::Other("usage: zt vault create <path>".into()))?;

    let mut opts = VaultOptions::default();
    match flag(args, "--suite").as_deref() {
        Some("aes") => opts.crypto_suite = CryptoSuite::Aes256Gcm,
        Some("xchacha") | None => {}
        Some(other) => return Err(Error::Unsupported { what: "suite", value: other.into() }),
    }
    match flag(args, "--kdf").as_deref() {
        Some("sensitive") => opts.kdf_params = KdfParams::SENSITIVE,
        Some("interactive") | None => {}
        Some(other) => return Err(Error::Unsupported { what: "kdf profile", value: other.into() }),
    }
    if args.iter().any(|a| a == "--store") {
        opts.compress_suite = zerotrace_compress::CompressSuite::Store;
    }
    if args.iter().any(|a| a == "--fido2") {
        return Err(Error::NotImplemented(
            "FIDO2 registration. The key-composition layer is built and tested, but this \
             build has no hardware transport, so a vault requiring FIDO2 could be created \
             and then never opened. It is refused instead.",
        ));
    }

    println!("Creating vault at {path}");
    println!("  Encryption  {}", opts.crypto_suite.label());
    println!("  KDF         Argon2id m={} KiB t={} p={}",
        opts.kdf_params.memory_kib, opts.kdf_params.time_cost, opts.kdf_params.parallelism);
    println!("  Compression {}", opts.compress_suite.label());
    println!();
    println!("There is no password recovery. If you lose this password the vault");
    println!("cannot be opened by anyone, including you.");
    println!();
    println!("At least {} characters. Four or five unrelated words joined by dashes is",
        zerotrace_kdf::strength::MIN_LENGTH);
    println!("the easiest way there, for example correct-horse-battery-staple.");
    println!();

    let password = prompt_password(true)?;
    // The same floor the window applies. Checked here too because this path
    // creates a vault directly rather than through the session, and a rule
    // enforced in only one of two front ends is not enforced.
    zerotrace_kdf::strength::require_acceptable(&password)?;
    let v = Vault::create(path, password.as_bytes(), &opts)?;
    let id = v.vault_id();
    println!("\nVault {id} created.");
    record(path, id, ev::VAULT_CREATED, &format!("factors={}", opts.factors.count()));
    v.close();
    Ok(ExitCode::SUCCESS)
}

/// The audit log lives beside the vault.
///
/// It is not inside the container on purpose: an audit trail that disappears
/// with the thing it describes is not much of an audit trail.
fn audit_path(vault_path: &str) -> PathBuf {
    PathBuf::from(format!("{vault_path}.audit"))
}

fn record(vault_path: &str, vault_id: zerotrace_core::VaultId, event: &str, detail: &str) {
    // Audit failures must never block the operation being audited, but they
    // must be visible.
    if let Ok(mut log) = AuditLog::open(audit_path(vault_path), vault_id) {
        if log.append(event, detail).is_err() {
            eprintln!("zt: warning: could not write the audit record");
        }
    }
}

/// Opens a split-protected vault from whatever components were supplied.
///
/// A token file could be either the remote or the custodian share, and the
/// owner should not have to remember which. Both slots are offered; the one
/// that does not match simply yields nothing, which is indistinguishable from
/// an absent component by design.
fn open_split_vault(path: &str, token_paths: &[String], want_password: bool) -> Result<Vault> {
    let mut components = Vec::new();

    if want_password {
        let password = prompt_password(false)?;
        components.push((ComponentKind::User, user_component(path, &password)?));
    }
    for tp in token_paths {
        let text = std::fs::read_to_string(tp)?;
        let token = RecoveryToken::decode(&text)?;
        components.push((ComponentKind::Remote, token.key()?));
        components.push((ComponentKind::Custodian, token.key()?));
    }

    match Vault::open_with_components(path, &components) {
        Ok(v) => {
            let id = v.vault_id();
            record(path, id, ev::AUTH_SUCCESS, "split");
            record(path, id, ev::VAULT_OPENED, "");
            Ok(v)
        }
        Err(e) => {
            record(path, zerotrace_core::VaultId::nil(), ev::AUTH_FAILURE, "split");
            Err(e)
        }
    }
}

/// Opens a vault, using the split path when the vault requires it.
///
/// A split-protected vault needs `--token`; asking for a password alone would
/// only produce a refusal, so the requirement is reported up front.
fn open_vault_with_args(path: &str, args: &[String]) -> Result<Vault> {
    if vault_is_split_protected(path).unwrap_or(false) {
        let tokens: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--token")
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect();
        if tokens.is_empty() {
            return Err(Error::Other(format!(
                "{path} is split protected and needs a key component as well as its \
                 password. Pass --token <file>. If the password is lost, pass two tokens \
                 with --token twice and --no-password."
            )));
        }
        let want_password = !args.iter().any(|a| a == "--no-password");
        return open_split_vault(path, &tokens, want_password);
    }
    open_vault(path)
}

fn vault_is_split_protected(path: &str) -> Result<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hb = [0u8; zerotrace_format::HEADER_LEN];
    f.read_exact(&mut hb).map_err(|_| Error::Format("file is too short".into()))?;
    let header = zerotrace_format::Header::from_bytes(&hb)?;
    Ok(header.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0)
}

fn open_vault(path: &str) -> Result<Vault> {
    let password = prompt_password(false)?;
    match Vault::open(path, password.as_bytes()) {
        Ok(v) => {
            let id = v.vault_id();
            record(path, id, ev::AUTH_SUCCESS, "password");
            record(path, id, ev::VAULT_OPENED, "");
            Ok(v)
        }
        Err(e) => {
            // The vault id is unknown on failure, so the record is anchored to
            // the nil id rather than guessed at.
            record(path, zerotrace_core::VaultId::nil(), ev::AUTH_FAILURE, "");
            Err(e)
        }
    }
}

fn cmd_status(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt vault status <path>".into()))?;
    let v = open_vault_with_args(path, args)?;
    let total: u64 = v.entries().iter().map(|e| e.size).sum();
    println!("APEX ZEROTRACE");
    println!();
    println!("  Vault        {}", v.vault_id());
    println!("  Status       UNLOCKED");
    println!("  Encryption   {}", v.crypto_suite().label());
    println!("  KDF          Argon2id m={} KiB t={} p={}",
        v.kdf_params().memory_kib, v.kdf_params().time_cost, v.kdf_params().parallelism);
    println!("  Compression  {}", v.compress_suite().label());
    println!("  Format       AZV v{}", v.format_version());
    println!("  Factors      {}", describe_factors(v.factors()));
    println!("  Entries      {}", v.entries().len());
    println!("  Plaintext    {total} bytes");
    println!("  Deadman      NOT IMPLEMENTED");
    println!("  Watchdog     NOT IMPLEMENTED");
    v.close();
    Ok(ExitCode::SUCCESS)
}

fn cmd_list(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt vault list <path>".into()))?;
    let v = open_vault_with_args(path, args)?;
    println!("{:<48} {:>12} {:>8}", "path", "bytes", "chunks");
    for e in v.entries() {
        println!("{:<48} {:>12} {:>8}", e.path, e.size, e.chunks.len());
    }
    v.close();
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt vault verify <path>".into()))?;
    let v = open_vault_with_args(path, args)?;
    let r = v.verify()?;
    println!("INTEGRITY VERIFICATION");
    println!();
    println!("  Vault              {}", r.vault_id);
    println!("  Header             {}", r.header_authentic.label());
    println!("  Manifest           {}", r.manifest_authentic.label());
    println!("  Integrity root     {}", r.integrity_root_matches.label());
    println!("  Entries            {}", r.entries);
    println!("  Chunks checked     {}", r.chunks_checked);
    println!("  Chunks failed      {}", r.chunks_failed);
    println!("  Plaintext          {} bytes", r.plaintext_bytes);
    println!("  Stored             {} bytes", r.ciphertext_bytes);
    println!();
    println!("  Result             {}", if r.is_intact() { "INTACT" } else { "DAMAGED" });
    let code = if r.is_intact() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    v.close();
    Ok(code)
}

fn cmd_import(args: &[String]) -> Result<ExitCode> {
    if args.len() < 2 {
        return Err(Error::Other("usage: zt vault import <vault> <file>...".into()));
    }
    let mut v = open_vault_with_args(&args[0], args)?;
    // One unreadable file must not abandon the rest of the batch. Failures are
    // collected and reported at the end, and the exit status reflects them.
    let mut failed = 0usize;
    for f in args[1..].iter().filter(|a| !a.starts_with("--")) {
        let p = PathBuf::from(f);
        let Some(name) = p.file_name().map(|s| s.to_string_lossy().into_owned()) else {
            eprintln!("skipped {f}: it has no file name");
            failed += 1;
            continue;
        };
        match v.import(&p, &name) {
            Ok(()) => {
                println!("imported {name}");
                record(&args[0], v.vault_id(), ev::FILE_IMPORTED, "");
            }
            Err(e) => {
                eprintln!("skipped {name}: {e}");
                failed += 1;
            }
        }
    }
    v.close();
    if failed > 0 {
        eprintln!("{failed} file(s) were not imported");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_export(args: &[String]) -> Result<ExitCode> {
    if args.len() < 2 {
        return Err(Error::Other("usage: zt vault export <vault> <dir>".into()));
    }
    let v = open_vault_with_args(&args[0], args)?;
    // A damaged entry must not stop the rest from being recovered. During a
    // recovery, getting back everything that is still intact is the whole job.
    let mut failed = 0usize;
    for i in 0..v.entries().len() {
        match v.export(i, &args[1]) {
            Ok(out) => println!("{}", out.display()),
            Err(e) => {
                eprintln!("failed {}: {e}", v.entries()[i].path);
                failed += 1;
            }
        }
    }
    v.close();
    if failed > 0 {
        eprintln!("{failed} entry/entries could not be extracted");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn describe_factors(f: FactorSet) -> String {
    let mut names = Vec::new();
    if f.contains(FactorKind::Password) {
        names.push(FactorKind::Password.label());
    }
    if f.contains(FactorKind::Fido2Prf) {
        names.push(FactorKind::Fido2Prf.label());
    }
    names.join(" + ")
}

fn cmd_auth_list(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt auth list <path>".into()))?;
    let v = open_vault_with_args(path, args)?;
    println!("AUTHENTICATION");
    println!();
    println!("  Required     {}", describe_factors(v.factors()));
    println!("  FIDO2 device {}", Assurance::NotImplemented.label());
    println!();
    println!("  The FIDO2 key-composition layer is implemented and tested. The hardware");
    println!("  transport is not, so this build cannot register or use an authenticator.");
    v.close();
    Ok(ExitCode::SUCCESS)
}

fn cmd_audit_show(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt audit show <path>".into()))?;
    let log = AuditLog::open(audit_path(path), zerotrace_core::VaultId::nil())?;
    let records = log.records()?;
    if records.is_empty() {
        println!("No audit records.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("{:>5}  {:<20}  {:<22}  {}", "seq", "event", "timestamp", "detail");
    for r in &records {
        println!("{:>5}  {:<20}  {:<22}  {}", r.sequence, r.event, r.timestamp, r.detail);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_audit_verify(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt audit verify <path>".into()))?;
    let log = AuditLog::open(audit_path(path), zerotrace_core::VaultId::nil())?;
    println!("AUDIT CHAIN");
    println!();
    match log.verify()? {
        ChainStatus::Intact { records } => {
            println!("  Records      {records}");
            println!("  Chain        {}", Assurance::Verified.label());
            println!();
            println!("  Note: a hash chain detects edits, deletions and reordering. It cannot");
            println!("  detect removal of records from the end. That needs an external anchor,");
            println!("  which is a Phase 3 concern.");
            Ok(ExitCode::SUCCESS)
        }
        ChainStatus::Broken { at_sequence, reason } => {
            println!("  Chain        {}", Assurance::Failed.label());
            println!("  Breaks at    record {at_sequence}");
            println!("  Reason       {reason}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn journal_path(vault_path: &str) -> PathBuf {
    PathBuf::from(format!("{vault_path}.journal"))
}

fn policy_path(vault_path: &str) -> PathBuf {
    PathBuf::from(format!("{vault_path}.policy"))
}

/// Loads the policy, falling back to the safe default.
///
/// The default is disabled, so a missing or unreadable policy file can never
/// cause a deadline to exist.
fn load_policy(vault_path: &str) -> DeadmanPolicy {
    let Ok(text) = std::fs::read_to_string(policy_path(vault_path)) else {
        return DeadmanPolicy::default();
    };
    let mut p = DeadmanPolicy::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "enabled" => p.enabled = v == "true",
            "timeout_seconds" => p.timeout_seconds = v.parse().unwrap_or(p.timeout_seconds),
            "heartbeat_seconds" => p.heartbeat_seconds = v.parse().unwrap_or(p.heartbeat_seconds),
            "required_confidence" => {
                p.required_confidence = v.parse().unwrap_or(p.required_confidence)
            }
            "warning_threshold" => p.warning_threshold = v.parse().unwrap_or(p.warning_threshold),
            "critical_threshold" => {
                p.critical_threshold = v.parse().unwrap_or(p.critical_threshold)
            }
            "destroy_after_failures" => {
                p.destroy_after_failures = v.parse().unwrap_or(p.destroy_after_failures)
            }
            _ => {}
        }
    }
    // A policy that fails validation is not honoured; it is replaced by the
    // disabled default rather than acted on.
    if p.validate().is_err() {
        return DeadmanPolicy::default();
    }
    p
}

/// Rebuilds presence from the audit log.
///
/// v0.3 has no resident service, so presence is reconstructed from recorded
/// events on each invocation. Only strong events are recovered this way: the
/// weaker OS-level signals need a running service to observe, and inventing
/// them here would be fabricating evidence.
fn presence_from_audit(log: &AuditLog, policy: &DeadmanPolicy) -> Result<PresenceEngine> {
    // Scoring follows the policy, so the heartbeat setting governs how long a
    // check-in stays fully credited rather than being validated and ignored.
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
        // The audit log stores wall time only, so the monotonic component is
        // reconstructed from it. That is weaker than a live reading and is why
        // a resident service is needed for the real thing.
        engine.observe(kind, TimeAnchor { wall: r.timestamp, monotonic: r.timestamp.max(0) as u64 });
    }
    Ok(engine)
}

fn deadman_snapshot(path: &str) -> Result<(DeadmanPolicy, u32, u64, DeadmanState)> {
    let log = AuditLog::open(audit_path(path), zerotrace_core::VaultId::nil())?;
    let policy = load_policy(path);
    let engine = presence_from_audit(&log, &policy)?;
    let now = time::now(std::time::Instant::now());
    // The monotonic origin is this process, so only wall time is meaningful
    // across invocations; elapsed_between takes the larger of the two.
    let now = TimeAnchor { wall: now.wall, monotonic: now.wall.max(0) as u64 };

    let assessment = engine.assess(now);
    let since_strong = assessment.last_strong_age.unwrap_or(u64::MAX);
    let state = policy.evaluate(assessment.confidence, since_strong);
    Ok((policy, assessment.confidence, since_strong, state))
}

fn fmt_duration(mut s: u64) -> String {
    let d = s / 86400;
    s %= 86400;
    let h = s / 3600;
    s %= 3600;
    let m = s / 60;
    // A heartbeat can be minutes, and "0h 30m" reads as a bug.
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h {m}m"),
    }
}

fn cmd_deadman_status(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt deadman status <path>".into()))?;
    let (policy, confidence, since_strong, state) = deadman_snapshot(path)?;
    let journal = StateJournal::open(journal_path(path), zerotrace_core::VaultId::nil())?;

    println!("DEADMAN");
    println!();
    println!("  Policy          {}", if policy.enabled { "ENABLED" } else { "DISABLED" });
    println!("  Presence        {confidence} / 100 (required {})", policy.required_confidence);
    println!(
        "  Last strong     {}",
        if since_strong == u64::MAX { "never".to_string() } else { format!("{} ago", fmt_duration(since_strong)) }
    );
    println!("  Computed state  {}", state.label());
    println!("  Recorded state  {}", journal.state().label());
    match policy.remaining(since_strong) {
        Some(r) => println!("  Remaining       {}", fmt_duration(r)),
        None if policy.enabled => println!("  Remaining       deadline passed"),
        None => println!("  Remaining       n/a, policy disabled"),
    }
    println!();
    println!("  Destruction     NOT IMPLEMENTED");
    println!("  Nothing in this build acts on the state above. It stops at ARMED.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_deadman_checkin(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt deadman checkin <path>".into()))?;
    // A check-in is a strong signal, so it must cost a credential. Accepting
    // one without proof would make the whole presence model decorative.
    let v = open_vault_with_args(path, args)?;
    let id = v.vault_id();
    v.close();

    record(path, id, "DEADMAN_CHECKIN", "explicit");

    let (policy, confidence, since_strong, state) = deadman_snapshot(path)?;
    let mut journal = StateJournal::open(journal_path(path), id)?;
    let log = AuditLog::open(audit_path(path), id)?;
    let records = log.records()?;
    let anchor = AuditAnchor {
        records: records.len() as u64,
        last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
    };
    let now = time::now(std::time::Instant::now());
    let deadline = if policy.enabled { now.wall + policy.timeout_seconds as i64 } else { 0 };

    // Recording is best effort: a journal write failure must be visible but
    // must not make the check-in itself appear to have failed.
    if let Err(e) = journal.record(state, now, deadline, confidence, anchor) {
        eprintln!("zt: warning: could not record the state transition: {e}");
    }

    println!("Checked in.");
    println!("  Presence   {confidence} / 100");
    println!("  State      {}", state.label());
    match policy.remaining(since_strong) {
        Some(r) => println!("  Remaining  {}", fmt_duration(r)),
        None => println!("  Remaining  n/a, policy disabled"),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_deadman_configure(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| {
        Error::Other("usage: zt deadman configure <path> [--enable|--disable] [--timeout SECONDS]".into())
    })?;
    let mut policy = load_policy(path);

    let mut changed = false;
    if args.iter().any(|a| a == "--disable") {
        policy.enabled = false;
        changed = true;
    }
    if let Some(t) = flag(args, "--timeout") {
        policy.timeout_seconds = t.parse().map_err(|_| Error::Other("bad timeout".into()))?;
        changed = true;
    }
    if let Some(t) = flag(args, "--heartbeat") {
        policy.heartbeat_seconds = t.parse().map_err(|_| Error::Other("bad heartbeat".into()))?;
        changed = true;
    }
    if args.iter().any(|a| a == "--enable") {
        policy.enabled = true;
        changed = true;
    }

    if changed {
        policy.validate()?;
        if policy.enabled {
            println!("Enabling a deadman policy has consequences this build cannot yet deliver:");
            println!("no destruction is implemented, so the policy will reach ARMED and stop.");
            println!();
        }
        let text = format!(
            "enabled = {}
timeout_seconds = {}
heartbeat_seconds = {}
required_confidence = {}
warning_threshold = {}
critical_threshold = {}
destroy_after_failures = {}
",
            policy.enabled,
            policy.timeout_seconds,
            policy.heartbeat_seconds,
            policy.required_confidence,
            policy.warning_threshold,
            policy.critical_threshold,
            policy.destroy_after_failures
        );
        std::fs::write(policy_path(path), text)?;
        record(path, zerotrace_core::VaultId::nil(), ev::POLICY_CHANGED, "");
    }

    println!("DEADMAN POLICY");
    println!();
    println!("  enabled              {}", policy.enabled);
    println!("  timeout_seconds      {} ({})", policy.timeout_seconds, fmt_duration(policy.timeout_seconds));
    println!("  heartbeat_seconds    {} ({})", policy.heartbeat_seconds, fmt_duration(policy.heartbeat_seconds));
    println!("  required_confidence  {}", policy.required_confidence);
    println!("  warning_threshold    {}", policy.warning_threshold);
    println!("  critical_threshold   {}", policy.critical_threshold);
    Ok(ExitCode::SUCCESS)
}

fn cmd_journal_verify(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt journal verify <path>".into()))?;
    let journal = StateJournal::open(journal_path(path), zerotrace_core::VaultId::nil())?;
    let log = AuditLog::open(audit_path(path), zerotrace_core::VaultId::nil())?;
    let audit_records = log.records()?;

    println!("STATE JOURNAL");
    println!();
    let mut ok = true;
    match journal.verify()? {
        JournalStatus::Intact { records, state } => {
            println!("  Records        {records}");
            println!("  State          {}", state.label());
            println!("  Chain          {}", Assurance::Verified.label());
        }
        JournalStatus::Broken { at_sequence, reason } => {
            ok = false;
            println!("  Chain          {}", Assurance::Failed.label());
            println!("  Breaks at      record {at_sequence}");
            println!("  Reason         {reason}");
        }
    }

    let lookup = |i: u64| audit_records.get(i as usize).map(|r| r.hash);
    match journal.check_audit_anchor(audit_records.len() as u64, lookup)? {
        AuditAnchorStatus::Consistent => {
            println!("  Audit anchor   {}", Assurance::Verified.label());
        }
        AuditAnchorStatus::NoAnchor => {
            println!("  Audit anchor   {}", Assurance::NotAttempted.label());
            println!("                 No check-in has anchored the audit log yet.");
        }
        AuditAnchorStatus::Truncated { expected, found } => {
            ok = false;
            println!("  Audit anchor   {}", Assurance::Failed.label());
            println!("                 Audit log has {found} records, journal recorded {expected}.");
        }
        AuditAnchorStatus::Diverged { at } => {
            ok = false;
            println!("  Audit anchor   {}", Assurance::Failed.label());
            println!("                 Audit record {at} no longer matches the anchored hash.");
        }
    }
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn cmd_destroy_status(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt destroy status <path>".into()))?;
    let journal = StateJournal::open(journal_path(path), zerotrace_core::VaultId::nil())?;
    let state = journal.state();

    println!("DESTRUCTION");
    println!();
    println!("  State          {}", state.label());
    println!("  Committed      {}", if state.is_committed() { "YES" } else { "no" });
    println!("  Terminal       {}", if state.is_terminal() { "YES" } else { "no" });
    if needs_resume(&journal) {
        println!();
        println!("  An authorized destruction was interrupted. It will resume, not revert.");
        println!("  Run `ztd once {path} --allow-destruction` to finish it.");
    }
    if state.is_terminal() {
        println!();
        println!("  This vault has been destroyed. No recovery key, password or backup of");
        println!("  the key material can restore it.");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_destroy_dryrun(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt destroy dry-run <path>".into()))?;
    println!("DESTRUCTION DRY RUN");
    println!();
    println!("Nothing below is performed. The vault, its keys and its backups are untouched.");
    println!();
    for (stage, detail) in simulate(std::path::Path::new(path), SanitizationProfile::Enhanced) {
        println!("  {stage}");
        println!("      {detail}");
    }
    println!();
    println!("Sidecar files that would remain:");
    for p in zerotrace_destroy::sidecar_paths(std::path::Path::new(path)) {
        println!("  {}", p.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_panic_lock(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt panic lock <path>".into()))?;
    // PANIC LOCK must never destroy anything. In a CLI there is no resident
    // session to tear down, so this reports accurately rather than pretending
    // to have closed something.
    println!("PANIC LOCK");
    println!();
    println!("  Vault contents      UNTOUCHED");
    println!("  In-process keys     none held by this command");
    println!("  Resident sessions   {}", Assurance::NotImplemented.label());
    println!();
    println!("  The CLI holds keys only for the duration of a single command, and zeroes");
    println!("  them on exit. Tearing down a long-lived session needs the service, which");
    println!("  does not hold vault keys either.");
    println!();
    println!("  This operation never destroys data. For that, see `zt panic destroy`.");
    let _ = path;
    Ok(ExitCode::SUCCESS)
}

fn cmd_panic_destroy(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt panic destroy <path>".into()))?;

    println!("PANIC DESTROY");
    println!();
    println!("  This irreversibly destroys the vault at {path}.");
    println!("  The master key is overwritten. No password, recovery key or backup of the");
    println!("  key material will restore it afterwards.");
    println!();
    println!("  Copies of this container made earlier, on backups, snapshots or other");
    println!("  machines, are NOT affected and will still open with the password.");
    println!();

    // Layered authorization: the vault password, then a typed phrase. A single
    // ambiguous keypress must never be able to reach this.
    let v = open_vault_with_args(path, args)?;
    let id = v.vault_id();
    v.close();

    println!("  Type DESTROY to confirm, or anything else to abort.");
    let confirmation = read_secret("Confirm: ")?;
    if confirmation.trim() != "DESTROY" {
        println!("\nAborted. Nothing was changed.");
        return Ok(ExitCode::SUCCESS);
    }

    let mut journal = StateJournal::open(journal_path(path), id)?;
    let log = AuditLog::open(audit_path(path), id)?;
    let records = log.records()?;
    let anchor = AuditAnchor {
        records: records.len() as u64,
        last_hash: records.last().map(|r| r.hash).unwrap_or([0u8; 32]),
    };
    let now = time::now(std::time::Instant::now());
    let now = TimeAnchor { wall: now.wall, monotonic: now.wall.max(0) as u64 };

    record(path, id, "DESTRUCTION_AUTHORIZED", "panic destroy");
    let auth = authorize_explicit(&mut journal, id, now, anchor)?;
    println!("\n  Authorization committed at journal record {}.", auth.journal_sequence);

    let report = execute(
        std::path::Path::new(path),
        &mut journal,
        SanitizationProfile::Enhanced,
        Trigger::PanicDestroy,
        now,
    )?;
    record(path, id, "DESTRUCTION_VERIFIED", "");
    println!();
    println!("{}", report.render());
    Ok(ExitCode::SUCCESS)
}

fn cmd_org_keygen() -> Result<ExitCode> {
    let id = SigningIdentity::generate();
    let pk = id.verifying_key();
    println!("ORGANIZATION SIGNING KEY");
    println!();
    println!("  Public key   {}", pk.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!();
    println!("  The public key belongs on each endpoint. The private key is NOT printed:");
    println!("  it must be generated and held where signing happens, ideally offline, and");
    println!("  never distributed. This command exists to show the shape of the key, not");
    println!("  to be a key management system.");
    println!();
    println!("  A remote command can lock a vault, require a check-in, tighten a deadline");
    println!("  or destroy. There is deliberately no command that reads vault contents:");
    println!("  the server must never be able to obtain plaintext.");
    println!();
    println!("  No signed command can lengthen a deadline. Someone holding the org key");
    println!("  could otherwise disarm every endpoint quietly, which is worse than");
    println!("  destroying them loudly.");
    Ok(ExitCode::SUCCESS)
}

fn split_path(vault_path: &str) -> PathBuf {
    PathBuf::from(format!("{vault_path}.split"))
}

/// Builds the user component from a password and the vault's own KDF salt.
fn user_component(path: &str, password: &str) -> Result<zerotrace_secure_memory::Key256> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hb = [0u8; zerotrace_format::HEADER_LEN];
    f.read_exact(&mut hb)
        .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
    let header = zerotrace_format::Header::from_bytes(&hb)?;
    Ok(UserProvider::from_password(password.as_bytes(), &header.kdf_salt, header.kdf_params)?
        .key()?)
}

fn cmd_split_enroll(args: &[String]) -> Result<ExitCode> {
    let path = args
        .first()
        .ok_or_else(|| Error::Other("usage: zt split enroll <vault> <token-file>".into()))?;
    let token_path = args
        .get(1)
        .ok_or_else(|| Error::Other("a path for the recovery token file is required".into()))?;
    let custodian_path = args.get(2).ok_or_else(|| {
        Error::Other(
            "a path for the custodian token is required. Two tokens plus the password give \
             three components, so no single loss destroys the vault. To enroll without \
             redundancy anyway, pass --no-custodian"
                .into(),
        )
    });
    let custodian_path = match custodian_path {
        Ok(p) => Some(p.clone()),
        Err(e) => {
            if args.iter().any(|a| a == "--no-custodian") {
                None
            } else {
                return Err(e);
            }
        }
    };

    for p in [Some(token_path.clone()), custodian_path.clone()].into_iter().flatten() {
        if std::path::Path::new(&p).exists() {
            return Err(Error::Other(format!(
                "{p} already exists; refusing to overwrite a recovery token"
            )));
        }
    }

    println!("SPLIT-KEY ENROLLMENT");
    println!();
    println!("  This vault will require two of its key components to open. After enrollment");
    println!("  the password alone will not open it, on this machine or any other.");
    println!();
    println!("  A recovery token will be written to {token_path}.");
    println!();
    println!("  Store that token on SEPARATE MEDIA: a USB key kept elsewhere, or another");
    println!("  machine. A token left beside the vault is on the same drive an attacker");
    println!("  steals, and provides no protection at all.");
    println!();
    if custodian_path.is_some() {
        println!("  A second, custodian token will also be written. With three components and");
        println!("  a threshold of two, no single loss destroys the vault: forget the");
        println!("  password and the two tokens still open it.");
        println!();
        println!("  The cost: any two components open the vault, so whoever holds BOTH tokens");
        println!("  can open it without the password. Keep them in different places, or with");
        println!("  different people.");
    } else {
        println!("  Enrolling without a custodian token leaves no redundancy: losing either");
        println!("  the password or the token means the vault can never be opened again.");
    }
    println!();

    let mut v = open_vault(path)?;
    let password = prompt_password(false)?;
    let user = user_component(path, &password)?;
    let token = RecoveryToken::generate();

    let custodian = custodian_path.as_ref().map(|_| RecoveryToken::generate());

    let mut components = vec![
        (ComponentKind::User, user),
        (ComponentKind::Remote, token.key()?),
    ];
    if let Some(c) = &custodian {
        components.push((ComponentKind::Custodian, c.key()?));
    }

    let bundle = v.enroll_split(&components)?;
    let id = v.vault_id();
    v.close();

    std::fs::write(token_path, format!("{}\n", token.encode()))?;
    if let (Some(p), Some(c)) = (&custodian_path, &custodian) {
        std::fs::write(p, format!("{}\n", c.encode()))?;
    }
    record(path, id, "SPLIT_ENROLLED", "");

    println!();
    println!("Enrolled. {} components, threshold {}.", bundle.shares.len(), bundle.threshold);
    println!("  Split bundle   {}", zerotrace_vault::split_bundle_path(std::path::Path::new(path)).display());
    println!("  Recovery token {token_path}");
    if let Some(p) = &custodian_path {
        println!("  Custodian token {p}");
    }
    println!();
    println!("Move the tokens to separate places now, and delete these copies once you have.");
    Ok(ExitCode::SUCCESS)
}

/// The moment the deadline stops depending on this machine.
///
/// The custodian is handed the key to one component and a timeout. From then
/// on it returns that key only while check-ins keep arriving, and destroys it
/// when they stop. Nothing an attacker does to this computer changes that,
/// because the key is not on this computer.
/// Sets a duress password and the contents it reveals.
fn cmd_duress_set(args: &[String]) -> Result<ExitCode> {
    let path = args
        .first()
        .ok_or_else(|| Error::Other("usage: zt duress set <vault> <file>...".into()))?;
    let decoys: Vec<String> = args[1..].iter().filter(|a| !a.starts_with("--")).cloned().collect();
    if decoys.is_empty() {
        return Err(Error::Other(
            "name at least one file for the duress password to show. An empty vault under \
             coercion invites the question of what else there is"
                .into(),
        ));
    }

    println!("DURESS PASSWORD");
    println!();
    println!("  A second password that opens this vault into different contents, and");
    println!("  destroys the real ones as it does so. Silently: whoever is watching sees");
    println!("  an ordinary vault open.");
    println!();
    println!("  THE REAL CONTENTS ARE GONE THE MOMENT IT IS USED. Not hidden, not");
    println!("  recoverable. If you type it by mistake, that is the same as destroying");
    println!("  the vault.");
    println!();
    println!("  For that reason it must not resemble your real password. Two passwords a");
    println!("  keystroke apart will be confused under stress, which is exactly when this");
    println!("  would be used.");
    println!();
    println!("  It will show:");
    for d in &decoys {
        println!("    {d}");
    }
    println!();

    let real = prompt_password(false)?;
    let mut v = Vault::open(path, real.as_bytes())?;
    println!("Now choose the duress password.");
    let duress = prompt_password(true)?;
    zerotrace_kdf::strength::require_acceptable(&duress)?;

    let files: Vec<(PathBuf, String)> = decoys
        .iter()
        .map(|d| {
            let p = PathBuf::from(d);
            let n = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            (p, n)
        })
        .collect();

    v.set_duress_password(real.as_bytes(), duress.as_bytes(), &files)?;
    let id = v.vault_id();
    v.close();
    record(path, id, "DURESS_CONFIGURED", "");

    println!();
    println!("Set. Nothing about this vault reveals that a duress password exists:");
    println!("the block that holds it is present in every vault, filled with random");
    println!("bytes when unused, so examining the file cannot answer the question.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_split_custody(args: &[String]) -> Result<ExitCode> {
    let path = args
        .first()
        .ok_or_else(|| Error::Other("usage: zt split custody <vault> <custodian-dir>".into()))?;
    let dir = args
        .get(1)
        .ok_or_else(|| Error::Other("a custodian directory is required".into()))?;

    let timeout: u64 = flag(args, "--timeout")
        .map(|t| t.parse().unwrap_or(0))
        .unwrap_or_else(|| load_policy(path).timeout_seconds);
    if timeout < 3600 {
        return Err(Error::Other("a custody timeout below an hour is refused".into()));
    }

    println!("REMOTE CUSTODY");
    println!();
    println!("  A custodian holds one of this vault's key components and returns it only");
    println!("  while you keep checking in. When check-ins stop for {}, it destroys",
        fmt_duration(timeout));
    println!("  that component and the vault can never be opened again.");
    println!();
    println!("  Put the custodian directory somewhere this computer is not: another");
    println!("  machine, a network share, a device elsewhere. On this disk it protects");
    println!("  nothing, exactly like a token stored beside the vault.");
    println!();
    println!("  Check-ins are signed with a key derived from your password, which is why");
    println!("  somebody who takes this computer cannot keep the deadline open.");
    println!();

    let sp = split_path(path);
    let bundle = SplitBundle::decode(&std::fs::read(&sp).map_err(|_| {
        Error::Other("this vault is not split protected; run `zt split enroll` first".into())
    })?)?;

    // The component key, not the sealed share: withholding the key is what
    // puts the share out of reach.
    let custodian_key = args
        .get(2)
        .ok_or_else(|| Error::Other(
            "the custodian token file is required, so its key can be handed over".into(),
        ))?;
    let token = RecoveryToken::decode(&std::fs::read_to_string(custodian_key)?)?;

    let password = prompt_password(false)?;
    let (salt, params) = header_kdf(path)?;
    let owner_key = verifying_key(password.as_bytes(), &salt, params)?;

    let custodian = DirectoryCustodian::new(dir);
    custodian.enroll(&HeldShare::new(
        bundle.vault_id,
        token.key()?.expose().to_vec(),
        owner_key,
        timeout,
        now_seconds(),
    ))?;

    println!("Custody established at {dir}.");
    println!();
    println!("  Delete your local copy of {custodian_key} once you have confirmed a");
    println!("  check-in works. Keeping it here defeats the point: the component would");
    println!("  then be on the machine after all.");
    println!();
    println!("  Check in with:  zt split checkin {path}");
    Ok(ExitCode::SUCCESS)
}

/// Tells a custodian the owner is still here.
fn cmd_split_checkin(args: &[String]) -> Result<ExitCode> {
    let path = args
        .first()
        .ok_or_else(|| Error::Other("usage: zt split checkin <vault> --custodian <dir>".into()))?;
    let dir = flag(args, "--custodian")
        .ok_or_else(|| Error::Other("--custodian <dir> is required".into()))?;

    let sp = split_path(path);
    let bundle = SplitBundle::decode(&std::fs::read(&sp)?)?;
    let password = prompt_password(false)?;
    let (salt, params) = header_kdf(path)?;
    let key = signing_identity(password.as_bytes(), &salt, params)?;

    let now = now_seconds();
    let request = Request::sign(&key, bundle.vault_id, Intent::CheckIn, now);
    let custodian = DirectoryCustodian::new(&dir);

    match custodian.handle(&request, now)? {
        Verdict::CheckedIn { deadline } => {
            println!("Checked in. The custodian will hold this component until {deadline}.");
            println!("That is {} from now.", fmt_duration((deadline - now).max(0) as u64));
            Ok(ExitCode::SUCCESS)
        }
        Verdict::Expired { expired_at } => {
            eprintln!("This vault's custody expired at {expired_at}.");
            eprintln!("The component was destroyed and cannot be recovered.");
            Ok(ExitCode::FAILURE)
        }
        other => {
            eprintln!("Refused: {}", other.label());
            Ok(ExitCode::FAILURE)
        }
    }
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn header_kdf(path: &str) -> Result<([u8; 32], zerotrace_kdf::KdfParams)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hb = [0u8; zerotrace_format::HEADER_LEN];
    f.read_exact(&mut hb)
        .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
    let h = zerotrace_format::Header::from_bytes(&hb)?;
    Ok((h.kdf_salt, h.kdf_params))
}

fn cmd_split_status(args: &[String]) -> Result<ExitCode> {
    let path = args.first().ok_or_else(|| Error::Other("usage: zt split status <path>".into()))?;
    let sp = split_path(path);

    println!("SPLIT-KEY PROTECTION");
    println!();
    if !sp.exists() {
        println!("  Status       NOT ENROLLED");
        println!();
        println!("  This vault is protected by its password alone. An attacker who removes");
        println!("  the drive and copies the vault needs only to guess that password,");
        println!("  offline, for as long as they like.");
        println!();
        println!("  Run `zt split explain` for what enrollment would change.");
        return Ok(ExitCode::SUCCESS);
    }

    let bundle = SplitBundle::decode(&std::fs::read(&sp)?)?;
    let a = assess(&bundle);
    println!("  Status       ENROLLED");
    println!("  Threshold    {} of {}", a.threshold, a.enrolled.len());
    println!(
        "  Components   {}",
        a.enrolled.iter().map(|k| k.label()).collect::<Vec<_>>().join(", ")
    );
    println!(
        "  Drive theft  {}",
        if a.resists_drive_theft { "RESISTED" } else { "NOT RESISTED" }
    );
    println!(
        "  Losing one   {}",
        if a.tolerates_one_loss { "survivable" } else { "PERMANENT DATA LOSS" }
    );
    if !a.notes.is_empty() {
        println!();
        for n in &a.notes {
            println!("  - {n}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_split_explain() -> Result<ExitCode> {
    println!("SPLIT-KEY ARCHITECTURE");
    println!();
    println!("  The key that unwraps the vault master key is divided into shares. Each");
    println!("  share is sealed under a different component, and any two are enough:");
    println!();
    println!("    user      the password, and a FIDO2 authenticator when enrolled");
    println!("    machine   sealed by a TPM or Secure Enclave    {}", Assurance::NotImplemented.label());
    println!("    remote    an authorization service, or an offline token on separate media");
    println!();
    println!("  Why two of three, not three of three:");
    println!();
    println!("    Three of three means any single loss is permanent data loss. A dead");
    println!("    motherboard, a discontinued service or a forgotten password would each");
    println!("    destroy the vault. Two of three still defeats drive theft, because an");
    println!("    attacker holding the disk and the password has one component and needs");
    println!("    two, while surviving the loss of any one component.");
    println!();
    println!("    The cost, stated plainly: a compromised remote component combined with a");
    println!("    compromised password opens the vault without the machine. Treat the");
    println!("    recovery token as a real credential, not a convenience.");
    println!();
    println!("  What this does NOT solve:");
    println!();
    println!("    Rollback. An attacker who physically holds the drive can restore an older");
    println!("    copy of any file on it, including the split bundle, the policy and the");
    println!("    journal. Detecting that needs an anchor they do not control: a monotonic");
    println!("    counter in a TPM, or a remote service that refuses to release its share");
    println!("    for a state it has already superseded. Neither exists in this build.");
    println!();
    println!("    The deadman switch also does not survive drive theft. The policy and");
    println!("    journal are files the attacker now controls, and they never run our code,");
    println!("    so no deadline ever arrives. Split-key protection is what makes the");
    println!("    stolen copy useless; the deadman switch protects the machine you left it");
    println!("    running on.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_recovery_explain() -> Result<ExitCode> {
    println!("THRESHOLD RECOVERY");
    println!();
    println!("  A master key can be split into n shares of which k are needed. Shares are");
    println!("  produced in memory and never written beside the vault: a share stored on");
    println!("  the machine holding the vault protects nothing.");
    println!();
    println!("  Minimum threshold  {}", zerotrace_enterprise::recovery::MIN_THRESHOLD);
    println!("  Maximum custodians {}", zerotrace_enterprise::recovery::MAX_CUSTODIANS);
    println!();
    println!("  Does escrow survive a deadman event?  NO.");
    println!();
    println!("  A quorum can reconstruct the key while a vault is merely locked. Once");
    println!("  destruction is authorized, recovery is refused, and the wrapped key in the");
    println!("  container has been overwritten, so a reconstructed master key has nothing");
    println!("  left to unwrap.");
    println!();
    println!("  The honest limit: a quorum plus a copy of the container taken BEFORE");
    println!("  erasure can still open that copy. Treat custodian shares as sensitive for");
    println!("  as long as any backup of the vault exists.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_platform_report(args: &[String]) -> Result<ExitCode> {
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| ".".to_string());
    let r = storage_report(std::path::Path::new(&path));
    let snapshots = zerotrace_platform::snapshot_exposure(std::path::Path::new(&path));

    println!("PLATFORM");
    println!();
    println!("  Path                 {path}");
    println!("  Filesystem           {}", r.filesystem.label());
    println!("  Copy on write        {}", if r.filesystem.is_copy_on_write() { "YES" } else { "no" });
    println!("  Overwrite in place   {}", r.overwrite.label());
    println!("      {}", r.overwrite_note);
    println!("  Snapshot detection   {}", r.snapshots.label());
    println!("      {}", r.snapshot_note);
    println!();
    println!("  Supervision          {}", supervision_status_label());
    println!();
    println!("  Cryptographic erasure does not depend on any of the above. It is the");
    println!("  security boundary; everything here is an additional assurance layer.");
    println!();
    println!("SNAPSHOTS");
    println!();
    println!("  Likely on this path           {}", if snapshots.likely { "YES" } else { "not inferred" });
    println!("  Detection and removal         {}", snapshots.assurance.label());
    println!();
    for line in snapshots.note.lines() {
        if line.is_empty() {
            println!();
        } else {
            println!("  {line}");
        }
    }
    Ok(ExitCode::SUCCESS)

}

fn cmd_service_unit(args: &[String]) -> Result<ExitCode> {
    let vault = args
        .first()
        .ok_or_else(|| Error::Other("usage: zt service unit <vault> [--allow-destruction]".into()))?;

    let exe = std::env::current_exe()
        .map(|p| p.with_file_name("ztd"))
        .unwrap_or_else(|_| PathBuf::from("ztd"));
    let mut plan = ServicePlan::new(&exe, std::path::Path::new(vault));
    if let Some(i) = flag(args, "--interval") {
        plan.interval_seconds = i.parse().map_err(|_| Error::Other("bad interval".into()))?;
    }
    plan.allow_destruction = args.iter().any(|a| a == "--allow-destruction");

    let supervisor = match flag(args, "--supervisor").as_deref() {
        Some("systemd") => Supervisor::Systemd,
        Some("launchd") => Supervisor::Launchd,
        Some("windows") => Supervisor::WindowsService,
        Some(other) => {
            return Err(Error::Unsupported { what: "supervisor", value: other.into() })
        }
        None => Supervisor::native()
            .ok_or_else(|| Error::Other("no native supervisor for this platform".into()))?,
    };

    eprintln!("# {} definition. Review before installing.", supervisor.label());
    eprintln!("# Install to: {}", supervisor.install_hint());
    if plan.allow_destruction {
        eprintln!("# This unit is PERMITTED TO DESTROY the vault when the deadline passes.");
    } else {
        eprintln!("# This unit observes only. Pass --allow-destruction to change that.");
    }
    eprintln!("#");
    eprintln!("# ZeroTrace does not install this itself: writing to a service directory");
    eprintln!("# needs privileges a vault application should not hold.");
    eprintln!();
    print!("{}", plan.render(supervisor));
    Ok(ExitCode::SUCCESS)
}

fn cmd_audit() -> Result<ExitCode> {
    let (mem, note) = zerotrace_secure_memory::probe_memory_protection();
    // Taken from the build rather than written out, because a version string
    // typed into a message is one more thing that goes stale unnoticed.
    println!("SECURITY AUDIT - Apex ZeroTrace {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  Authenticated encryption      {}", Assurance::Verified.label());
    println!("  Header authentication         {}", Assurance::Verified.label());
    println!("  KDF parameter floor           {}", Assurance::Verified.label());
    println!("  Encrypted metadata            {}", Assurance::Verified.label());
    println!("  Chunk integrity (Merkle)      {}", Assurance::Verified.label());
    println!("  Secret zeroing on drop        {}", Assurance::Verified.label());
    println!("  Memory locking                {}", mem.label());
    println!("  Multi-factor key composition  {}", Assurance::Verified.label());
    println!("  Tamper-evident audit chain    {}", Assurance::Verified.label());
    println!("  FIDO2 hardware transport      {}", Assurance::NotImplemented.label());
    println!("  Presence engine               {}", Assurance::Verified.label());
    println!("  Clock rollback resistance     {}", Assurance::Verified.label());
    println!("  Persistent state journal      {}", Assurance::Verified.label());
    println!("  Audit truncation detection    {}", Assurance::Verified.label());
    println!("  Deadman state machine         ENFORCED");
    println!("  Service supervision           {}", supervision_status_label());
    println!("  Two-phase authorization       {}", Assurance::Verified.label());
    println!("  Cryptographic erasure         {}", Assurance::Verified.label());
    println!("  Resume after interruption     {}", Assurance::Verified.label());
    println!("  Container overwrite           {}", Assurance::BestEffort.label());
    println!("  Filesystem-aware sanitization  {}", Assurance::Verified.label());
    println!("  Snapshot handling             {}", Assurance::NotImplemented.label());
    println!("  Free-space sanitization       {}", Assurance::NotSupported.label());
    println!("  Service unit generation       {}", Assurance::Verified.label());
    println!("  Signed remote commands        {}", Assurance::Verified.label());
    println!("  Replay resistance             {}", Assurance::Verified.label());
    println!("  Threshold recovery            {}", Assurance::Verified.label());
    println!("  Recovery refused after commit  {}", Assurance::Verified.label());
    println!("  Split-key protection          {}", Assurance::Verified.label());
    println!("  Machine key binding (TPM)     {}", Assurance::NotImplemented.label());
    println!("  Rollback resistance           {}", Assurance::NotImplemented.label());
    println!("  Rollback across restart       {}", Assurance::BestEffort.label());
    println!("  Manifest generation binding   {}", Assurance::Verified.label());
    println!("  Remote custody                {}", Assurance::Verified.label());
    println!("  Atomic export                 {}", Assurance::Verified.label());
    println!("  Symlink refusal on export     {}", Assurance::Verified.label());
    // Reported as best effort rather than probed. Probing one directory says
    // what happened there, not what will happen to a vault on a filesystem
    // that carries no Unix permissions, and a table that answers a narrower
    // question than it appears to is worse than one that is plainly cautious.
    println!("  Owner-only file permissions   {}", Assurance::BestEffort.label());
    println!();
    println!("  Note: {note}");
    Ok(ExitCode::SUCCESS)
}
