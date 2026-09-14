//! Service-manager integration.
//!
//! The deadman policy must keep running when the GUI is closed or crashes
//! (INV-8), and something must restart the service if it dies. That job
//! belongs to the operating system's supervisor, not to ZeroTrace.
//!
//! This module generates the unit definitions. It deliberately does not
//! install them: writing to `/etc/systemd/system` or the Windows service
//! database needs privileges the vault application should not hold, and a
//! silent privileged install is exactly the behavior a security tool should
//! not have. The definitions are printed for an administrator to review and
//! install.

use std::path::Path;

/// Supervisors ZeroTrace can generate definitions for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    Systemd,
    Launchd,
    WindowsService,
}

impl Supervisor {
    /// The supervisor native to the platform this binary was built for.
    pub fn native() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Some(Supervisor::Systemd)
        }
        #[cfg(target_os = "macos")]
        {
            Some(Supervisor::Launchd)
        }
        #[cfg(target_os = "windows")]
        {
            Some(Supervisor::WindowsService)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Supervisor::Systemd => "systemd",
            Supervisor::Launchd => "launchd",
            Supervisor::WindowsService => "Windows Service",
        }
    }

    /// Where the definition belongs, for the instructions.
    pub fn install_hint(&self) -> &'static str {
        match self {
            Supervisor::Systemd => "~/.config/systemd/user/zerotrace.service",
            Supervisor::Launchd => "~/Library/LaunchAgents/com.apex.zerotrace.plist",
            Supervisor::WindowsService => "registered with sc.exe or New-Service",
        }
    }
}

/// What the generated unit will do.
#[derive(Debug, Clone)]
pub struct ServicePlan {
    pub executable: String,
    pub vault: String,
    pub interval_seconds: u64,
    /// When false, the unit observes and records but never destroys.
    pub allow_destruction: bool,
}

impl ServicePlan {
    pub fn new(executable: &Path, vault: &Path) -> Self {
        Self {
            executable: executable.display().to_string(),
            vault: vault.display().to_string(),
            interval_seconds: 300,
            // Off by default. A unit file that destroys data should have to be
            // written deliberately, not arrived at by accepting defaults.
            allow_destruction: false,
        }
    }

    fn args(&self) -> String {
        let mut a = format!("watch {} --interval {}", self.vault, self.interval_seconds);
        if self.allow_destruction {
            a.push_str(" --allow-destruction");
        }
        a
    }

    /// Renders the definition for `supervisor`.
    pub fn render(&self, supervisor: Supervisor) -> String {
        match supervisor {
            Supervisor::Systemd => self.systemd(),
            Supervisor::Launchd => self.launchd(),
            Supervisor::WindowsService => self.windows(),
        }
    }

    fn systemd(&self) -> String {
        // A user unit rather than a system one: the service needs no
        // privileges, and running it as root would give it more authority over
        // the filesystem than the task requires.
        format!(
            "[Unit]\n\
             Description=Apex ZeroTrace deadman service\n\
             Documentation=man:ztd(1)\n\
             After=default.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} {args}\n\
             Restart=always\n\
             RestartSec=10\n\
             # The service holds no vault keys, so it needs no elevated access.\n\
             NoNewPrivileges=true\n\
             PrivateTmp=true\n\
             ProtectSystem=strict\n\
             ProtectHome=read-only\n\
             ReadWritePaths={vault_dir}\n\
             ProtectKernelTunables=true\n\
             ProtectControlGroups=true\n\
             RestrictSUIDSGID=true\n\
             MemoryDenyWriteExecute=true\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            exe = self.executable,
            args = self.args(),
            vault_dir = Path::new(&self.vault)
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".into()),
        )
    }

    fn launchd(&self) -> String {
        let args: Vec<String> = self.args().split_whitespace().map(String::from).collect();
        let mut arg_xml = String::new();
        arg_xml.push_str(&format!("    <string>{}</string>\n", self.executable));
        for a in &args {
            arg_xml.push_str(&format!("    <string>{a}</string>\n"));
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \x20 <key>Label</key>\n\
             \x20 <string>com.apex.zerotrace</string>\n\
             \x20 <key>ProgramArguments</key>\n\
             \x20 <array>\n{arg_xml}\
             \x20 </array>\n\
             \x20 <key>RunAtLoad</key>\n\
             \x20 <true/>\n\
             \x20 <key>KeepAlive</key>\n\
             \x20 <true/>\n\
             \x20 <key>ProcessType</key>\n\
             \x20 <string>Background</string>\n\
             </dict>\n\
             </plist>\n"
        )
    }

    fn windows(&self) -> String {
        // A command rather than a file: Windows services are registered, not
        // described by a document on disk.
        format!(
            "REM Register the Apex ZeroTrace service. Run from an elevated prompt.\n\
             REM Review the arguments before running: {destruction}\n\
             \n\
             sc.exe create ApexZeroTrace ^\n\
             \x20 binPath= \"{exe} {args}\" ^\n\
             \x20 start= auto ^\n\
             \x20 DisplayName= \"Apex ZeroTrace deadman service\"\n\
             \n\
             sc.exe failure ApexZeroTrace reset= 86400 actions= restart/10000/restart/10000/restart/10000\n\
             sc.exe description ApexZeroTrace \"Evaluates the ZeroTrace deadman policy. Holds no vault keys.\"\n",
            exe = self.executable,
            args = self.args(),
            destruction = if self.allow_destruction {
                "THIS UNIT IS PERMITTED TO DESTROY THE VAULT"
            } else {
                "this unit observes only and will not destroy the vault"
            },
        )
    }
}

/// Whether a supervisor is actually managing ZeroTrace right now.
///
/// Returns `None` when it cannot be determined, which is the usual case and is
/// reported as such rather than as "not running".
pub fn supervision_status() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // systemd sets this for processes it started.
        if std::env::var_os("INVOCATION_ID").is_some() {
            return Some(true);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ServicePlan {
        ServicePlan::new(Path::new("/usr/local/bin/ztd"), Path::new("/home/u/vaults/v.azv"))
    }

    #[test]
    fn destruction_is_off_by_default_in_a_generated_unit() {
        let p = plan();
        assert!(!p.allow_destruction);
        for s in [Supervisor::Systemd, Supervisor::Launchd, Supervisor::WindowsService] {
            let text = p.render(s);
            assert!(
                !text.contains("--allow-destruction"),
                "{} unit enabled destruction by default",
                s.label()
            );
        }
    }

    #[test]
    fn enabling_destruction_is_visible_in_every_unit() {
        let mut p = plan();
        p.allow_destruction = true;
        for s in [Supervisor::Systemd, Supervisor::Launchd, Supervisor::WindowsService] {
            assert!(p.render(s).contains("--allow-destruction"), "{}", s.label());
        }
        // And the Windows script warns in words, not just in a flag.
        assert!(p.render(Supervisor::WindowsService).contains("PERMITTED TO DESTROY"));
    }

    #[test]
    fn the_systemd_unit_restarts_and_drops_privileges() {
        let text = plan().render(Supervisor::Systemd);
        assert!(text.contains("Restart=always"), "the service must be restarted if it dies");
        assert!(text.contains("NoNewPrivileges=true"));
        assert!(text.contains("ProtectSystem=strict"));
        assert!(text.contains("ReadWritePaths=/home/u/vaults"));
        assert!(text.contains("[Install]"));
    }

    #[test]
    fn the_launchd_plist_is_well_formed_and_keeps_alive() {
        let text = plan().render(Supervisor::Launchd);
        assert!(text.starts_with("<?xml"));
        assert!(text.contains("<key>KeepAlive</key>"));
        assert!(text.contains("com.apex.zerotrace"));
        assert_eq!(text.matches("<array>").count(), text.matches("</array>").count());
        assert_eq!(text.matches("<dict>").count(), text.matches("</dict>").count());
    }

    #[test]
    fn the_windows_script_configures_restart_on_failure() {
        let text = plan().render(Supervisor::WindowsService);
        assert!(text.contains("sc.exe create ApexZeroTrace"));
        assert!(text.contains("sc.exe failure"), "the service must restart after a crash");
        assert!(text.contains("start= auto"));
    }

    #[test]
    fn the_interval_reaches_the_command_line() {
        let mut p = plan();
        p.interval_seconds = 42;
        assert!(p.render(Supervisor::Systemd).contains("--interval 42"));
    }

    #[test]
    fn supervision_status_is_unknown_rather_than_false_when_undetectable() {
        // Under a plain shell this must be None, not Some(false): "not
        // supervised" and "cannot tell" are different claims.
        if std::env::var_os("INVOCATION_ID").is_none() {
            assert_eq!(supervision_status(), None);
        }
    }
}
