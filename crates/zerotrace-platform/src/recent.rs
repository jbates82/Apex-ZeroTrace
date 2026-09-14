//! The list of vaults this user has opened.
//!
//! Paths only. Nothing about a vault's contents, its keys, or whether it is
//! protected is recorded here: the file is unencrypted, so it must hold
//! nothing that would help anyone who reads it beyond telling them a vault
//! exists at a path they could have found by looking.
//!
//! It exists so the window can show, at a glance, which of several vaults are
//! still being watched. Someone running three or four vaults otherwise has to
//! open each in turn to notice that a watcher has stopped, which is exactly
//! the kind of lapse that goes unnoticed for weeks.

use std::path::{Path, PathBuf};

use zerotrace_core::Result;

/// Most vaults remembered. Beyond this the oldest are dropped.
pub const MAX_REMEMBERED: usize = 12;

fn config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("ApexZeroTrace"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support").join("ApexZeroTrace"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|c| c.join("apex-zerotrace"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        None
    }
}

fn list_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("recent"))
}

/// Reads the remembered paths, newest first.
///
/// Entries whose file has gone are dropped: a list of vaults that no longer
/// exist is noise, and a destroyed vault should not linger in it.
pub fn load() -> Vec<PathBuf> {
    let Some(p) = list_path() else { return Vec::new() };
    let Ok(text) = std::fs::read_to_string(p) else { return Vec::new() };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .take(MAX_REMEMBERED)
        .collect()
}

/// Records a vault as most recently used.
///
/// Best effort: failing to remember a path is not worth interrupting anyone
/// over, so the result is returned but callers may ignore it.
pub fn remember(vault: &Path) -> Result<()> {
    let Some(path) = list_path() else { return Ok(()) };
    let mut list = load();
    list.retain(|p| p != vault);
    list.insert(0, vault.to_path_buf());
    list.truncate(MAX_REMEMBERED);

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text: String =
        list.iter().map(|p| format!("{}\n", p.display())).collect();
    std::fs::write(path, text)?;
    Ok(())
}

/// Removes a vault from the list.
pub fn forget(vault: &Path) -> Result<()> {
    let Some(path) = list_path() else { return Ok(()) };
    let list: Vec<PathBuf> = load().into_iter().filter(|p| p != vault).collect();
    let text: String = list.iter().map(|p| format!("{}\n", p.display())).collect();
    std::fs::write(path, text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_holds_paths_and_nothing_else() {
        // The file is unencrypted, so it must not describe a vault beyond
        // saying one exists at a path.
        let v = std::env::temp_dir().join("ztrecent-probe.azv");
        std::fs::write(&v, b"x").unwrap();
        let _ = remember(&v);
        if let Some(p) = list_path() {
            if let Ok(text) = std::fs::read_to_string(p) {
                assert!(!text.contains("password"));
                assert!(!text.contains("token"));
                assert!(!text.contains("key"));
            }
        }
        let _ = forget(&v);
        let _ = std::fs::remove_file(v);
    }

    #[test]
    fn vaults_that_no_longer_exist_are_dropped() {
        let gone = std::env::temp_dir().join("ztrecent-gone.azv");
        let _ = std::fs::remove_file(&gone);
        let _ = remember(&gone);
        assert!(!load().contains(&gone), "a missing vault should not be listed");
    }
}
