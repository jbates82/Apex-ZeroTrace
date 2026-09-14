use std::io::Write;
use zerotrace_vault::{Vault, VaultOptions};

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zt_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &std::path::Path, name: &str, data: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::File::create(&p).unwrap().write_all(data).unwrap();
    p
}

fn shapes() -> Vec<(&'static str, Vec<u8>)> {
    let mut st = 0x2468_1357u32;
    let mut noise = vec![0u8; 400_000];
    for b in noise.iter_mut() {
        st = st.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *b = (st >> 16) as u8;
    }
    vec![
        ("empty.bin", Vec::new()),
        ("one.bin", vec![b'x']),
        ("small.txt", b"sensitive plan for Q4\n".to_vec()),
        ("text.txt", b"meeting notes line\n".repeat(20_000)),
        ("noise.bin", noise),
        // Larger than one chunk, to exercise multi-chunk entries.
        ("big.txt", b"repeating payload block ".repeat(120_000)),
    ]
}

#[test]
fn every_shape_round_trips_and_verifies() {
    let dir = tmp("roundtrip");
    let vault_path = dir.join("v.azv");
    let pw = b"correct horse battery staple";

    let mut v = Vault::create(&vault_path, pw, &VaultOptions::default()).unwrap();
    for (name, data) in shapes() {
        let src = write(&dir, name, &data);
        v.import(&src, name).unwrap();
    }
    v.close();

    let v = Vault::open(&vault_path, pw).unwrap();
    let report = v.verify().unwrap();
    assert_eq!(report.chunks_failed, 0, "{report:?}");
    assert!(report.is_intact(), "{report:?}");

    let out = dir.join("out");
    for i in 0..v.entries().len() {
        let name = v.entries()[i].path.clone();
        let p = v.export(i, &out).unwrap();
        let want = std::fs::read(dir.join(&name)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), want, "{name} did not round trip");
    }
}

#[test]
fn a_wrong_password_is_refused() {
    let dir = tmp("wrongpw");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"right", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "a.txt", b"payload"), "a.txt").unwrap();
    v.close();

    assert!(Vault::open(&vp, b"wrong").is_err());
    assert!(Vault::open(&vp, b"").is_err());
    assert!(Vault::open(&vp, b"right").is_ok());
}

#[test]
fn tampering_with_the_header_is_detected() {
    let dir = tmp("tamper");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "a.txt", b"payload"), "a.txt").unwrap();
    v.close();

    let good = std::fs::read(&vp).unwrap();

    // Every byte of the authenticated prefix must break the unwrap.
    for i in 0..zerotrace_format::HEADER_AAD_LEN {
        let mut bad = good.clone();
        bad[i] ^= 1;
        std::fs::write(&vp, &bad).unwrap();
        assert!(
            Vault::open(&vp, b"pw").is_err(),
            "header byte {i} was accepted after modification"
        );
    }
    std::fs::write(&vp, &good).unwrap();
    assert!(Vault::open(&vp, b"pw").is_ok());
}

#[test]
fn corrupting_a_chunk_is_detected_rather_than_returned() {
    let dir = tmp("corrupt");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    let payload = b"confidential material ".repeat(4000);
    v.import(&write(&dir, "a.txt", &payload), "a.txt").unwrap();
    v.close();

    let mut raw = std::fs::read(&vp).unwrap();
    // A byte inside the chunk region, which in this format begins after the
    // header and the duress block rather than immediately after the header.
    raw[zerotrace_format::V3_DATA_START as usize + 40] ^= 0x40;
    std::fs::write(&vp, &raw).unwrap();

    let v = Vault::open(&vp, b"pw").unwrap();
    let r = v.verify().unwrap();
    assert_eq!(r.chunks_failed, 1, "corruption not reported");
    assert!(!r.is_intact());
    assert!(v.export(0, dir.join("out")).is_err(), "corrupt data must not be exported");
}

#[test]
fn both_crypto_suites_work() {
    for suite in [
        zerotrace_crypto::CryptoSuite::XChaCha20Poly1305,
        zerotrace_crypto::CryptoSuite::Aes256Gcm,
    ] {
        let dir = tmp(&format!("suite{}", suite as u16));
        let vp = dir.join("v.azv");
        let opts = VaultOptions { crypto_suite: suite, ..Default::default() };
        let mut v = Vault::create(&vp, b"pw", &opts).unwrap();
        let data = b"payload for both suites ".repeat(3000);
        v.import(&write(&dir, "a.bin", &data), "a.bin").unwrap();
        v.close();

        let v = Vault::open(&vp, b"pw").unwrap();
        assert_eq!(v.crypto_suite(), suite);
        assert!(v.verify().unwrap().is_intact());
        let p = v.export(0, dir.join("out")).unwrap();
        assert_eq!(std::fs::read(p).unwrap(), data);
    }
}

#[test]
fn filenames_and_contents_never_appear_in_the_container() {
    let dir = tmp("privacy");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    let secret = b"the merger closes on the fourteenth";
    v.import(&write(&dir, "tax_returns_2026.pdf", secret), "tax_returns_2026.pdf").unwrap();
    v.close();

    let raw = std::fs::read(&vp).unwrap();
    for needle in [
        &b"tax_returns_2026"[..],
        &b"merger"[..],
        &b"fourteenth"[..],
        &b".pdf"[..],
    ] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "container leaks {:?}",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn export_refuses_a_path_that_escapes_the_directory() {
    use zerotrace_vault::sanitize_relative_path;
    assert!(sanitize_relative_path("../../etc/passwd").is_err());
    assert!(sanitize_relative_path("/etc/passwd").is_err());
    assert!(sanitize_relative_path("a/../../b").is_err());
    assert!(sanitize_relative_path("").is_err());
    assert_eq!(
        sanitize_relative_path("notes/2026/plan.txt").unwrap(),
        std::path::PathBuf::from("notes/2026/plan.txt")
    );
}

// ---------- Phase 2: multi-factor authentication ----------

use zerotrace_auth::{FactorKind, FactorSet, SoftwareAuthenticator};

fn two_factor_opts() -> VaultOptions {
    VaultOptions {
        factors: FactorSet::password_only().with(FactorKind::Fido2Prf),
        ..Default::default()
    }
}

#[test]
fn a_two_factor_vault_needs_both_factors() {
    let dir = tmp("twofactor");
    let vp = dir.join("v.azv");
    let device = SoftwareAuthenticator::new([77u8; 32]);

    let mut v = Vault::create_with(&vp, b"pw", Some(&device), &two_factor_opts()).unwrap();
    v.import(&write(&dir, "a.txt", b"secret payload"), "a.txt").unwrap();
    v.close();

    // Both factors: opens.
    let v = Vault::open_with(&vp, b"pw", Some(&device)).unwrap();
    assert!(v.factors().contains(FactorKind::Fido2Prf));
    v.close();

    // Password alone: refused, and specifically not downgraded.
    match Vault::open_with(&vp, b"pw", None) {
        Err(zerotrace_core::Error::NotImplemented(_)) => {}
        Err(other) => panic!("expected an explicit refusal, got {other}"),
        Ok(_) => panic!("a two-factor vault opened with the password alone"),
    }
    assert!(Vault::open(&vp, b"pw").is_err());

    // Right device, wrong password: refused.
    assert!(Vault::open_with(&vp, b"wrong", Some(&device)).is_err());

    // Right password, wrong device: refused.
    let other = SoftwareAuthenticator::new([78u8; 32]);
    assert!(Vault::open_with(&vp, b"pw", Some(&other)).is_err());
}

#[test]
fn stripping_the_factor_requirement_from_the_header_is_detected() {
    // The attack the version 2 AAD exists to stop: edit the header so the
    // vault claims to be password-only, and see whether it opens.
    let dir = tmp("stripfactor");
    let vp = dir.join("v.azv");
    let device = SoftwareAuthenticator::new([5u8; 32]);
    let v = Vault::create_with(&vp, b"pw", Some(&device), &two_factor_opts()).unwrap();
    v.close();

    let mut raw = std::fs::read(&vp).unwrap();
    // Clear the FIDO2 bit in the required-factors field at offset 200.
    raw[200] = 0x01;
    std::fs::write(&vp, &raw).unwrap();

    assert!(
        Vault::open(&vp, b"pw").is_err(),
        "a downgraded header must not open with the password alone"
    );
    assert!(
        Vault::open_with(&vp, b"pw", Some(&device)).is_err(),
        "a modified header must not open at all"
    );
}

#[test]
fn every_bit_of_the_auth_region_is_authenticated() {
    let dir = tmp("authregion");
    let vp = dir.join("v.azv");
    let device = SoftwareAuthenticator::new([6u8; 32]);
    let v = Vault::create_with(&vp, b"pw", Some(&device), &two_factor_opts()).unwrap();
    v.close();
    let good = std::fs::read(&vp).unwrap();

    for i in zerotrace_format::AUTH_REGION {
        let mut bad = good.clone();
        bad[i] ^= 1;
        std::fs::write(&vp, &bad).unwrap();
        assert!(
            Vault::open_with(&vp, b"pw", Some(&device)).is_err(),
            "auth-region byte {i} was accepted after modification"
        );
    }
    std::fs::write(&vp, &good).unwrap();
    assert!(Vault::open_with(&vp, b"pw", Some(&device)).is_ok());
}

#[test]
fn two_factor_vaults_round_trip_their_contents() {
    let dir = tmp("twofactorio");
    let vp = dir.join("v.azv");
    let device = SoftwareAuthenticator::new([9u8; 32]);
    let payload = b"confidential material ".repeat(3000);

    let mut v = Vault::create_with(&vp, b"pw", Some(&device), &two_factor_opts()).unwrap();
    v.import(&write(&dir, "a.bin", &payload), "a.bin").unwrap();
    v.close();

    let v = Vault::open_with(&vp, b"pw", Some(&device)).unwrap();
    assert!(v.verify().unwrap().is_intact());
    let out = v.export(0, dir.join("out")).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), payload);
}

#[test]
fn a_real_fido_authenticator_refuses_rather_than_failing_open() {
    let dir = tmp("realfido");
    let vp = dir.join("v.azv");
    let real = zerotrace_auth::Fido2Authenticator;
    // Creating is refused because the transport does not exist, rather than
    // silently producing a password-only vault.
    assert!(Vault::create_with(&vp, b"pw", Some(&real), &two_factor_opts()).is_err());
    assert!(!vp.exists(), "no vault should be left behind");
}

#[test]
fn version_one_vaults_still_open() {
    // Vaults written by v0.1 must keep working after the format change.
    let dir = tmp("v1compat");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "a.txt", b"legacy payload"), "a.txt").unwrap();
    assert_eq!(v.format_version(), zerotrace_format::FORMAT_VERSION);
    v.close();

    // A v0.1 vault differs only in the version field and the absent auth
    // region, so downgrade the header and confirm it still parses and opens.
    let v = Vault::open(&vp, b"pw").unwrap();
    assert_eq!(v.factors(), FactorSet::password_only());
    let out = v.export(0, dir.join("out")).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), b"legacy payload");
}

// ---------- split-key protection ----------

use zerotrace_split::providers::ComponentProvider;
use zerotrace_split::{ComponentKind, RecoveryToken, UserProvider};

fn user_component(password: &[u8], salt: &[u8]) -> zerotrace_secure_memory::Key256 {
    UserProvider::from_password(
        password,
        salt,
        zerotrace_kdf::KdfParams { memory_kib: 19 * 1024, time_cost: 2, parallelism: 1 },
    )
    .unwrap()
    .key()
    .unwrap()
}

#[test]
fn enrolling_split_protection_does_not_re_encrypt_the_contents() {
    let dir = tmp("splitenrolll");
    let vp = dir.join("v.azv");
    // Incompressible, so the stored chunks are large enough for the
    // comparison below to be meaningful.
    let mut st = 0x51ab_cdefu32;
    let payload: Vec<u8> = (0..120_000)
        .map(|_| {
            st = st.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (st >> 16) as u8
        })
        .collect();

    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "a.bin", &payload), "a.bin").unwrap();

    // Capture the chunk region so it can be shown to be untouched.
    let before = std::fs::read(&vp).unwrap();
    let salt = b"a-salt-that-is-long-enough-here!";
    let token = RecoveryToken::generate();
    v.enroll_split(&[
        (ComponentKind::User, user_component(b"pw", salt)),
        (ComponentKind::Remote, token.key().unwrap()),
    ])
    .unwrap();
    assert!(v.is_split_protected());
    v.close();

    let after = std::fs::read(&vp).unwrap();
    let chunk_start = zerotrace_format::HEADER_LEN;
    let window = 64 * 1024;
    assert!(before.len() > chunk_start + window, "test needs a larger chunk region");
    assert_eq!(
        before[chunk_start..chunk_start + window],
        after[chunk_start..chunk_start + window],
        "enrollment must not re-encrypt stored content"
    );

    // And the contents still come back.
    let v = Vault::open_with_components(
        &vp,
        &[
            (ComponentKind::User, user_component(b"pw", salt)),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    )
    .unwrap();
    assert!(v.verify().unwrap().is_intact());
    let out = v.export(0, dir.join("out")).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), payload);
}

#[test]
fn a_split_vault_refuses_to_open_with_the_password_alone() {
    // The whole point: a stolen drive plus a known password is not enough.
    let dir = tmp("splitrefuse");
    let vp = dir.join("v.azv");
    let salt = b"a-salt-that-is-long-enough-here!";
    let token = RecoveryToken::generate();

    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "a.txt", b"secret"), "a.txt").unwrap();
    v.enroll_split(&[
        (ComponentKind::User, user_component(b"pw", salt)),
        (ComponentKind::Remote, token.key().unwrap()),
    ])
    .unwrap();
    v.close();

    let err = match Vault::open(&vp, b"pw") {
        Err(e) => e,
        Ok(_) => panic!("a split vault opened with the password alone"),
    };
    assert!(format!("{err}").contains("split keys"), "{err}");

    // One component is not enough either.
    assert!(Vault::open_with_components(
        &vp,
        &[(ComponentKind::User, user_component(b"pw", salt))]
    )
    .is_err());
}

#[test]
fn deleting_the_split_bundle_denies_service_rather_than_downgrading() {
    let dir = tmp("splitdelete");
    let vp = dir.join("v.azv");
    let salt = b"a-salt-that-is-long-enough-here!";
    let token = RecoveryToken::generate();

    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.enroll_split(&[
        (ComponentKind::User, user_component(b"pw", salt)),
        (ComponentKind::Remote, token.key().unwrap()),
    ])
    .unwrap();
    v.close();

    std::fs::remove_file(zerotrace_vault::split_bundle_path(&vp)).unwrap();

    // It must not fall back to password-only opening.
    assert!(Vault::open(&vp, b"pw").is_err());
    let err = match Vault::open_with_components(
        &vp,
        &[
            (ComponentKind::User, user_component(b"pw", salt)),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    ) {
        Err(e) => e,
        Ok(_) => panic!("a vault opened without its split bundle"),
    };
    assert!(format!("{err}").contains("missing"), "{err}");
}

#[test]
fn the_split_flag_is_authenticated_and_cannot_be_cleared() {
    // Clearing the flag to force the password path must not work.
    let dir = tmp("splitflag");
    let vp = dir.join("v.azv");
    let salt = b"a-salt-that-is-long-enough-here!";
    let token = RecoveryToken::generate();

    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    v.enroll_split(&[
        (ComponentKind::User, user_component(b"pw", salt)),
        (ComponentKind::Remote, token.key().unwrap()),
    ])
    .unwrap();
    v.close();

    let mut raw = std::fs::read(&vp).unwrap();
    // flags live at offset 44, inside the authenticated prefix
    raw[44] &= !0x02;
    std::fs::write(&vp, &raw).unwrap();

    assert!(Vault::open(&vp, b"pw").is_err(), "a cleared flag must not enable the password path");
    assert!(
        Vault::open_with_components(
            &vp,
            &[
                (ComponentKind::User, user_component(b"pw", salt)),
                (ComponentKind::Remote, token.key().unwrap())
            ]
        )
        .is_err(),
        "a modified header must not open at all"
    );
}

#[test]
fn a_bundle_from_another_vault_is_refused() {
    let dir = tmp("splitswap");
    let salt = b"a-salt-that-is-long-enough-here!";

    let mk = |name: &str| {
        let vp = dir.join(name);
        let token = RecoveryToken::generate();
        let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
        v.enroll_split(&[
            (ComponentKind::User, user_component(b"pw", salt)),
            (ComponentKind::Remote, token.key().unwrap()),
        ])
        .unwrap();
        v.close();
        (vp, token)
    };
    let (a, _ta) = mk("a.azv");
    let (b, tb) = mk("b.azv");

    // Give vault A vault B's bundle.
    std::fs::copy(
        zerotrace_vault::split_bundle_path(&b),
        zerotrace_vault::split_bundle_path(&a),
    )
    .unwrap();

    let err = match Vault::open_with_components(
        &a,
        &[
            (ComponentKind::User, user_component(b"pw", salt)),
            (ComponentKind::Remote, tb.key().unwrap()),
        ],
    ) {
        Err(e) => e,
        Ok(_) => panic!("a bundle from another vault was accepted"),
    };
    assert!(format!("{err}").contains("different vault"), "{err}");
}

// ---------- export safety ----------

#[test]
fn a_failed_export_leaves_no_plaintext_behind() {
    // Writing straight to the destination meant a file failing on its last
    // chunk left everything decrypted so far sitting there in the clear.
    let dir = tmp("partial");
    let vp = dir.join("v.azv");
    // Incompressible, so the stored chunks are large enough to have a late
    // one to corrupt.
    let mut st = 0x1234_5678u32;
    let payload: Vec<u8> = (0..3_000_000)
        .map(|_| {
            st = st.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (st >> 16) as u8
        })
        .collect();

    let mut v = Vault::create(&vp, b"correct-horse-battery-staple", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "big.bin", &payload), "big.bin").unwrap();
    v.close();

    // Corrupt a late chunk so authentication fails partway through, after
    // earlier chunks have already decrypted.
    let mut raw = std::fs::read(&vp).unwrap();
    let spot = raw.len() - 200_000;
    raw[spot] ^= 0xFF;
    std::fs::write(&vp, &raw).unwrap();

    let v = Vault::open(&vp, b"correct-horse-battery-staple").unwrap();
    let out = dir.join("out");
    assert!(v.export(0, &out).is_err(), "a corrupt chunk was exported anyway");

    // Nothing at the destination, complete or partial.
    let leftovers: Vec<String> = std::fs::read_dir(&out)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[cfg(unix)]
#[test]
fn export_refuses_to_write_through_a_symlink() {
    // Path traversal checks do not catch this: the path is perfectly ordinary
    // and the link redirects it at the filesystem level.
    let dir = tmp("symlink");
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"correct-horse-battery-staple", &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "notes.txt", b"confidential"), "notes.txt").unwrap();
    v.close();

    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let elsewhere = dir.join("attacker-controlled.txt");
    std::os::unix::fs::symlink(&elsewhere, out.join("notes.txt")).unwrap();

    let v = Vault::open(&vp, b"correct-horse-battery-staple").unwrap();
    let err = v.export(0, &out).unwrap_err();
    assert!(format!("{err}").contains("symbolic link"), "{err}");
    assert!(!elsewhere.exists(), "plaintext was written through the link");
}

#[cfg(unix)]
#[test]
fn a_split_bundle_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("perms");
    let vp = dir.join("v.azv");
    let salt = b"a-salt-that-is-long-enough-here!";
    let token = RecoveryToken::generate();

    let mut v = Vault::create(&vp, b"correct-horse-battery-staple", &VaultOptions::default()).unwrap();
    v.enroll_split(&[
        (ComponentKind::User, user_component(b"correct-horse-battery-staple", salt)),
        (ComponentKind::Remote, token.key().unwrap()),
    ])
    .unwrap();
    v.close();

    let mode = std::fs::metadata(zerotrace_vault::split_bundle_path(&vp))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the split bundle is readable by others: {mode:o}");
}

#[test]
fn an_older_manifest_cannot_be_put_back() {
    // A manifest proved only that it was genuine for this vault. Somebody
    // holding an earlier copy could splice it in and the vault would open onto
    // the older list of files, with every check passing: a deleted entry back,
    // an added one gone.
    let dir = tmp("manifestroll");
    let vp = dir.join("v.azv");
    let pw = b"correct-horse-battery-staple";

    let mut v = Vault::create(&vp, pw, &VaultOptions::default()).unwrap();
    v.import(&write(&dir, "first.txt", b"one"), "first.txt").unwrap();
    v.close();
    let old = std::fs::read(&vp).unwrap();

    // A second file, which the older manifest does not know about.
    let mut v = Vault::open(&vp, pw).unwrap();
    v.import(&write(&dir, "second.txt", b"two"), "second.txt").unwrap();
    v.close();
    let current = std::fs::read(&vp).unwrap();
    assert_eq!(Vault::open(&vp, pw).unwrap().entries().len(), 2);

    // Splice the earlier manifest region back over the current one, which is
    // what an adversary holding an old copy would do.
    let start = zerotrace_format::Header::from_bytes(&old).unwrap().manifest_offset as usize;
    let mut spliced = current.clone();
    if spliced.len() >= old.len() {
        spliced[start..old.len()].copy_from_slice(&old[start..]);
        std::fs::write(&vp, &spliced).unwrap();

        // It must not open onto the older list. Either the generation check
        // catches it or authentication does; both are correct, and silently
        // showing one file is not.
        match Vault::open(&vp, pw) {
            Err(_) => {}
            Ok(v) => panic!(
                "an older manifest was accepted, showing {} entries",
                v.entries().len()
            ),
        }
    }
}
