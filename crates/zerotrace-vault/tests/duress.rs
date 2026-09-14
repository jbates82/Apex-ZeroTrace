//! The duress password, and what it does to the real contents.

use std::path::PathBuf;
use zerotrace_vault::{Identity, Vault, VaultOptions};

const REAL: &[u8] = b"correct-horse-battery-staple";
const DURESS: &[u8] = b"winter-harbor-lantern-quiet";

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ztduress_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &PathBuf, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

/// A vault holding one secret and one innocuous file behind a duress password.
fn prepared(dir: &PathBuf) -> PathBuf {
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, REAL, &VaultOptions::default()).unwrap();
    v.import(&write(dir, "merger.txt", b"the merger closes on the fourteenth"), "merger.txt")
        .unwrap();
    let decoy = write(dir, "shopping.txt", b"milk, bread, a new drill bit");
    v.set_duress_password(REAL, DURESS, &[(decoy, "shopping.txt".into())]).unwrap();
    v.close();
    vp
}

#[test]
fn the_real_password_opens_the_real_contents() {
    let dir = tmp("real");
    let vp = prepared(&dir);
    let v = Vault::open(&vp, REAL).unwrap();
    assert_eq!(v.opened_as(), Identity::Real);
    assert_eq!(v.entries().len(), 1);
    assert_eq!(v.entries()[0].path, "merger.txt");
}

#[test]
fn the_duress_password_shows_the_decoy_and_destroys_the_real_contents() {
    let dir = tmp("duress");
    let vp = prepared(&dir);

    // Under coercion: the decoy opens, looking like an ordinary vault.
    let v = Vault::open(&vp, DURESS).unwrap();
    assert_eq!(v.opened_as(), Identity::Decoy);
    assert_eq!(v.entries().len(), 1);
    assert_eq!(v.entries()[0].path, "shopping.txt");
    let out = v.export(0, dir.join("out")).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), b"milk, bread, a new drill bit");
    v.close();

    // And the real contents are gone, permanently, to everyone.
    assert!(
        Vault::open(&vp, REAL).is_err(),
        "the real password still opened the vault after duress"
    );
}

#[test]
fn the_decoy_keeps_working_after_it_has_fired() {
    // It has to. Somebody watching will ask for it again, and a vault that
    // opened once and then refused would be an obvious tell.
    let dir = tmp("again");
    let vp = prepared(&dir);

    for round in 0..3 {
        let v = Vault::open(&vp, DURESS).unwrap();
        assert_eq!(v.opened_as(), Identity::Decoy, "round {round}");
        assert_eq!(v.entries()[0].path, "shopping.txt");
        v.close();
    }
}

#[test]
fn a_vault_without_a_duress_password_is_indistinguishable() {
    // The block is written whether or not the feature is used. If it only
    // appeared once somebody enabled it, examining the file would reveal that
    // a second password exists, and a duress password known to exist protects
    // nobody.
    let dir = tmp("indist");
    let plain = dir.join("plain.azv");
    Vault::create(&plain, REAL, &VaultOptions::default()).unwrap().close();
    let with = prepared(&dir);

    let a = std::fs::read(&plain).unwrap();
    let b = std::fs::read(&with).unwrap();
    let block = zerotrace_format::HEADER_LEN..zerotrace_format::HEADER_LEN + zerotrace_format::DECOY_BLOCK_LEN;
    assert_eq!(a[block.clone()].len(), 256);
    assert_eq!(b[block.clone()].len(), 256);

    // Neither block is all zeroes, and neither is obviously structured.
    for (name, bytes) in [("no duress", &a[block.clone()]), ("duress", &b[block.clone()])] {
        assert!(bytes.iter().any(|&x| x != 0), "{name}: block is zeroed");
        let ones: u32 = bytes.iter().map(|x| x.count_ones()).sum();
        // Random bytes and ciphertext both sit near half the bits set. A
        // structured or padded block would not.
        assert!((768..1280).contains(&ones), "{name}: {ones} bits set looks non-random");
    }

    // And a wrong password fails the same way on both.
    assert!(Vault::open(&plain, DURESS).is_err());
}

#[test]
fn a_wrong_password_destroys_nothing() {
    let dir = tmp("wrongpw");
    let vp = prepared(&dir);

    for bad in [&b"not-the-password-at-all"[..], b"", b"winter-harbor-lantern-quie"] {
        assert!(Vault::open(&vp, bad).is_err());
    }
    // Both identities survive an attacker guessing.
    assert_eq!(Vault::open(&vp, REAL).unwrap().entries().len(), 1);
    assert_eq!(Vault::open(&vp, DURESS).unwrap().opened_as(), Identity::Decoy);
}

#[test]
fn the_container_does_not_shrink_when_duress_fires() {
    // Size is what an adversary can measure without any password. A container
    // that shrank on duress would announce what had happened.
    let dir = tmp("size");
    let vp = prepared(&dir);
    let before = std::fs::metadata(&vp).unwrap().len();
    Vault::open(&vp, DURESS).unwrap().close();
    let after = std::fs::metadata(&vp).unwrap().len();
    assert_eq!(before, after, "the container changed size when duress fired");
}

#[test]
fn a_duress_vault_needs_something_to_show() {
    let dir = tmp("empty");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, REAL, &VaultOptions::default()).unwrap();
    let err = v.set_duress_password(REAL, DURESS, &[]).unwrap_err();
    assert!(format!("{err}").contains("something to show"), "{err}");
}

#[test]
fn a_duress_password_close_to_the_real_one_is_refused() {
    // The failure this guard exists for: two passwords a keystroke apart,
    // confused under pressure, destroying the vault by accident.
    let dir = tmp("similar");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, REAL, &VaultOptions::default()).unwrap();
    let decoy = write(&dir, "shopping.txt", b"milk");

    for near in [
        &b"correct-horse-battery-stapl"[..],
        b"correct-horse-battery-stap1e",
        b"correct-horse-battery-staple",
    ] {
        let err = v
            .set_duress_password(REAL, near, &[(decoy.clone(), "shopping.txt".into())])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("too close") || msg.contains("must be different"),
            "{msg}"
        );
    }

    // A genuinely different phrase is accepted.
    assert!(v
        .set_duress_password(REAL, DURESS, &[(decoy, "shopping.txt".into())])
        .is_ok());
}

#[test]
fn duress_fires_wherever_a_password_is_accepted() {
    // Not only on unlock. Every operation that opens a vault goes through one
    // function, and the duress identity is reached inside it, so extracting or
    // verifying under coercion destroys the real contents just as opening
    // does. Anything else would be a trap: a person reaching for Extract under
    // pressure would get no protection at all.
    for op in ["list", "export", "verify"] {
        let dir = tmp(&format!("everywhere_{op}"));
        let vp = prepared(&dir);

        let v = Vault::open(&vp, DURESS).unwrap();
        assert_eq!(v.opened_as(), Identity::Decoy, "{op}");
        match op {
            "export" => {
                v.export(0, dir.join("out")).unwrap();
            }
            "verify" => {
                assert!(v.verify().unwrap().is_intact(), "{op}");
            }
            _ => {
                assert_eq!(v.entries().len(), 1, "{op}");
            }
        }
        v.close();

        assert!(
            Vault::open(&vp, REAL).is_err(),
            "{op}: the real contents survived a duress open"
        );
    }
}

#[test]
fn a_failed_setup_leaves_no_trace_beside_the_vault() {
    // A scratch file called v.azv.decoy-build sitting next to a vault tells
    // anybody who looks that a duress password was being arranged.
    let dir = tmp("noscratch");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, REAL, &VaultOptions::default()).unwrap();

    let missing = dir.join("does-not-exist.txt");
    assert!(v
        .set_duress_password(REAL, DURESS, &[(missing, "x.txt".into())])
        .is_err());

    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("decoy") || n.contains("build"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}
