//! Starting the watcher again after a reboot, without elevated privileges.
//!
//! # Why this is separate from `service`
//!
//! `service` generates a system-wide definition: a unit in `/etc/systemd`, a
//! Windows service registration. Those need administrator rights, and a vault
//! application asking for elevation is a bad smell.
//!
//! This module does something narrower and unprivileged: it registers the
//! watcher to start when *this user* logs in. Every location it writes to is
//! ordinary user-writable space, so nothing needs elevating and nothing is
//! installed for anyone else on the machine.
//!
//! Both exist because they answer different questions. A machine that should
//! watch a vault whether or not anyone logs in wants the system service. A
//! person who wants their own vault watched again after a restart wants this,
//! and should not have to open a terminal to get it.
//!
//! # What it does not promise
//!
//! Autostart means "starts when this account logs in", not "always running".
//! A machine sitting at a login screen is not watching anything. That is worth
//! stating rather than implying, and the interface says so.

use std::path::{Path, PathBuf};

use zerotrace_core::{Error, Result};

/// A short stable tag for a vault, so several vaults can autostart
/// independently without their entries colliding.
fn tag(vault: &Path) -> String {
    let digest = zerotrace_crypto::sha256(vault.display().to_string().as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Windows reads APPDATA directly and never needs this, so it would be dead
/// code there.
#[cfg(not(target_os = "windows"))]
fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| Error::Other("could not determine your home directory".into()))
}

/// Where this platform keeps per-user startup entries.
pub fn directory() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Other("APPDATA is not set".into()))?;
        Ok(appdata.join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home()?.join("Library").join("LaunchAgents"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().unwrap_or_default().join(".config"));
        Ok(base.join("autostart"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        Err(Error::NotImplemented("autostart on this platform"))
    }
}

/// The file that would hold this vault's entry.
pub fn entry_path(vault: &Path) -> Result<PathBuf> {
    let dir = directory()?;
    let t = tag(vault);
    #[cfg(target_os = "windows")]
    {
        // A batch file rather than a shortcut: a .lnk has to be built through
        // COM, while this is a plain file write that does the same job.
        Ok(dir.join(format!("apex-zerotrace-{t}.cmd")))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(dir.join(format!("com.apex.zerotrace.{t}.plist")))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(dir.join(format!("apex-zerotrace-{t}.desktop")))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (dir, t);
        Err(Error::NotImplemented("autostart on this platform"))
    }
}

/// What an installed entry will run.
#[derive(Debug, Clone)]
pub struct AutostartPlan {
    pub ztd: PathBuf,
    pub vault: PathBuf,
    pub interval_seconds: u64,
    /// Off by default. An entry that can destroy data has to be asked for.
    pub allow_destruction: bool,
}

impl AutostartPlan {
    pub fn new(ztd: &Path, vault: &Path) -> Self {
        Self {
            ztd: ztd.to_path_buf(),
            vault: vault.to_path_buf(),
            interval_seconds: 300,
            allow_destruction: false,
        }
    }

    fn args(&self) -> String {
        let mut a = format!(
            "watch \"{}\" --interval {}",
            self.vault.display(),
            self.interval_seconds
        );
        if self.allow_destruction {
            a.push_str(" --allow-destruction");
        }
        a
    }

    /// Renders the entry for this platform.
    pub fn render(&self) -> String {
        #[cfg(target_os = "windows")]
        {
            format!(
                "@echo off\r\n\
                 REM Apex ZeroTrace watcher, started when this user logs in.\r\n\
                 REM Delete this file to stop it starting.\r\n\
                 REM Destruction permitted: {}\r\n\
                 start \"Apex ZeroTrace\" /MIN \"{}\" {}\r\n",
                self.allow_destruction,
                self.ztd.display(),
                self.args()
            )
        }
        #[cfg(target_os = "macos")]
        {
            let mut args = String::new();
            args.push_str(&format!("    <string>{}</string>\n", self.ztd.display()));
            args.push_str("    <string>watch</string>\n");
            args.push_str(&format!("    <string>{}</string>\n", self.vault.display()));
            args.push_str("    <string>--interval</string>\n");
            args.push_str(&format!("    <string>{}</string>\n", self.interval_seconds));
            if self.allow_destruction {
                args.push_str("    <string>--allow-destruction</string>\n");
            }
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n\
                 \x20 <key>Label</key>\n  <string>com.apex.zerotrace.{}</string>\n\
                 \x20 <key>ProgramArguments</key>\n  <array>\n{args}  </array>\n\
                 \x20 <key>RunAtLoad</key>\n  <true/>\n\
                 \x20 <key>KeepAlive</key>\n  <true/>\n\
                 </dict>\n</plist>\n",
                tag(&self.vault)
            )
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            format!(
                "[Desktop Entry]\n\
                 Type=Application\n\
                 Name=Apex ZeroTrace watcher\n\
                 Comment=Watches a vault's deadman policy. Destruction permitted: {}\n\
                 Exec={} {}\n\
                 Terminal=false\n\
                 X-GNOME-Autostart-enabled=true\n",
                self.allow_destruction,
                self.ztd.display(),
                self.args()
            )
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            String::new()
        }
    }
}

/// Whether an entry is installed for this vault, and what it runs.
pub fn installed(vault: &Path) -> Option<PathBuf> {
    let p = entry_path(vault).ok()?;
    p.exists().then_some(p)
}

/// Whether the installed entry is permitted to destroy.
///
/// Read from the file rather than remembered, so an entry edited by hand is
/// reported as it actually is.
pub fn installed_allows_destruction(vault: &Path) -> bool {
    let Some(p) = installed(vault) else { return false };
    std::fs::read_to_string(p)
        .map(|t| t.contains("--allow-destruction"))
        .unwrap_or(false)
}

/// Installs the entry. Overwrites any existing one for this vault.
pub fn install(plan: &AutostartPlan) -> Result<PathBuf> {
    if !plan.ztd.exists() {
        return Err(Error::Other(format!(
            "the service program was not found at {}",
            plan.ztd.display()
        )));
    }
    let dir = directory()?;
    std::fs::create_dir_all(&dir)?;
    let path = entry_path(&plan.vault)?;
    std::fs::write(&path, plan.render())?;

    // The desktop entry has to be executable on some desktops.
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(path)
}

/// Removes the entry. Succeeds when there was nothing to remove.
pub fn remove(vault: &Path) -> Result<()> {
    let path = entry_path(vault)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// What autostart means on this platform, for the interface to show.
pub fn description() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "A small file is placed in your Startup folder. It runs when you log in, \
         and needs no administrator rights. Delete it, or press Remove, to stop it."
    }
    #[cfg(target_os = "macos")]
    {
        "A launch agent is placed in your own Library folder. It runs when you log \
         in, and needs no administrator rights."
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "A desktop entry is placed in your own configuration folder. It runs when \
         you log in, and needs no administrator rights."
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        "Autostart is not implemented for this platform."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(dir: &Path, allow: bool) -> AutostartPlan {
        let ztd = dir.join("ztd");
        std::fs::write(&ztd, b"#!/bin/sh\n").unwrap();
        let mut p = AutostartPlan::new(&ztd, &dir.join("v.azv"));
        p.allow_destruction = allow;
        p
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ztauto_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn destruction_is_off_by_default() {
        let d = tmp("default");
        let p = AutostartPlan::new(&d.join("ztd"), &d.join("v.azv"));
        assert!(!p.allow_destruction);
        assert!(!p.render().contains("--allow-destruction"));
    }

    #[test]
    fn enabling_destruction_is_visible_in_the_entry() {
        let d = tmp("armed");
        let text = plan(&d, true).render();
        assert!(text.contains("--allow-destruction"));
        // And stated in words, not only as a flag.
        assert!(text.contains("Destruction permitted: true"), "{text}");
    }

    #[test]
    fn the_entry_names_the_vault_and_interval() {
        let d = tmp("args");
        let mut p = plan(&d, false);
        p.interval_seconds = 45;
        let text = p.render();
        assert!(text.contains("v.azv"));
        assert!(text.contains("--interval 45"));
    }

    #[test]
    fn different_vaults_get_different_entries() {
        // Otherwise autostarting one vault would silently replace another.
        let d = tmp("distinct");
        let a = entry_path(&d.join("a.azv")).unwrap();
        let b = entry_path(&d.join("b.azv")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn installing_without_the_service_program_is_refused() {
        let d = tmp("missing");
        let p = AutostartPlan::new(&d.join("nonexistent-ztd"), &d.join("v.azv"));
        assert!(install(&p).is_err());
    }

    #[test]
    fn install_and_remove_round_trip() {
        let d = tmp("roundtrip");
        let vault = d.join("v.azv");
        let mut p = plan(&d, true);
        p.vault = vault.clone();

        assert!(installed(&vault).is_none());
        let written = install(&p).unwrap();
        assert!(written.exists());
        assert_eq!(installed(&vault), Some(written.clone()));
        assert!(installed_allows_destruction(&vault));

        remove(&vault).unwrap();
        assert!(installed(&vault).is_none());
        // Removing twice is not an error.
        remove(&vault).unwrap();

        let _ = std::fs::remove_file(written);
    }

    #[test]
    fn an_unarmed_entry_reports_that_it_cannot_destroy() {
        let d = tmp("unarmed");
        let vault = d.join("v.azv");
        let mut p = plan(&d, false);
        p.vault = vault.clone();
        let written = install(&p).unwrap();
        assert!(!installed_allows_destruction(&vault));
        remove(&vault).unwrap();
        let _ = std::fs::remove_file(written);
    }
}
