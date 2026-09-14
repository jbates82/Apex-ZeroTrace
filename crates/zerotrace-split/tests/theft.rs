//! The stolen-drive scenario, modeled directly.

use zerotrace_core::VaultId;
use zerotrace_crypto::{random_key, CryptoSuite};
use zerotrace_kdf::KdfParams;
use zerotrace_secure_memory::Key256;
use zerotrace_split::providers::{gather, ComponentProvider};
use zerotrace_split::{
    assess, seal, unseal, ComponentKind, MachineProvider, RecoveryToken, SplitBundle, UserProvider,
    THRESHOLD,
};

const SALT: &[u8] = b"a-salt-that-is-long-enough-here!";

fn user(password: &[u8]) -> UserProvider {
    UserProvider::from_password(
        password,
        SALT,
        KdfParams { memory_kib: 19 * 1024, time_cost: 2, parallelism: 1 },
    )
    .unwrap()
}

/// A vault enrolled with the two components that exist today.
fn enrolled(release: &Key256, id: VaultId) -> (SplitBundle, RecoveryToken) {
    let u = user(b"correct horse battery staple");
    let token = RecoveryToken::generate();
    let bundle = seal(
        release,
        id,
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    )
    .unwrap();
    (bundle, token)
}

#[test]
fn a_quorum_of_components_releases_the_key() {
    let release = random_key();
    let id = VaultId::from_bytes([1u8; 16]);
    let (bundle, token) = enrolled(&release, id);
    let u = user(b"correct horse battery staple");

    let got = unseal(
        &bundle,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    )
    .unwrap();
    assert_eq!(got, release);
}

#[test]
fn the_stolen_drive_scenario() {
    // The attacker has everything written to disk, and guesses the password.
    // They must still be short of the threshold.
    let release = random_key();
    let id = VaultId::from_bytes([2u8; 16]);
    let (bundle, token) = enrolled(&release, id);

    // Step 1-4: the attacker copies the vault. That means they hold the
    // encoded bundle verbatim, so the test uses exactly those bytes.
    let stolen = SplitBundle::decode(&bundle.encode()).unwrap();
    assert_eq!(stolen, bundle);

    // Step 5: they guess the password correctly. One component.
    let guessed = user(b"correct horse battery staple");
    let err = unseal(&stolen, &[(ComponentKind::User, guessed.key().unwrap())]).unwrap_err();
    assert!(
        format!("{err}").contains("1 of 2"),
        "a password alone must not release the key: {err}"
    );

    // The machine component cannot help them, and cannot help anyone yet.
    assert!(MachineProvider.key().is_err());

    // Only the token, which is not on the drive, completes the quorum.
    assert!(unseal(
        &stolen,
        &[
            (ComponentKind::User, guessed.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap())
        ]
    )
    .is_ok());
}

#[test]
fn a_wrong_password_is_indistinguishable_from_an_absent_component() {
    // Distinguishing them would let an attacker test component keys one at a
    // time, turning a two-of-three into two separate one-of-one problems.
    let release = random_key();
    let id = VaultId::from_bytes([3u8; 16]);
    let (bundle, token) = enrolled(&release, id);

    let wrong = user(b"not the password");
    let with_wrong = unseal(
        &bundle,
        &[
            (ComponentKind::User, wrong.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    )
    .unwrap_err();
    let with_none =
        unseal(&bundle, &[(ComponentKind::Remote, token.key().unwrap())]).unwrap_err();
    assert_eq!(format!("{with_wrong}"), format!("{with_none}"));
}

#[test]
fn a_share_cannot_be_moved_between_vaults() {
    let release = random_key();
    let a = VaultId::from_bytes([4u8; 16]);
    let b = VaultId::from_bytes([5u8; 16]);
    let (bundle_a, token_a) = enrolled(&release, a);
    let (mut bundle_b, _) = enrolled(&random_key(), b);

    // Graft vault A's user share into vault B's bundle.
    let a_user = bundle_a.shares.iter().find(|s| s.component == ComponentKind::User).unwrap();
    if let Some(slot) = bundle_b.shares.iter_mut().find(|s| s.component == ComponentKind::User) {
        *slot = a_user.clone();
    }

    let u = user(b"correct horse battery staple");
    assert!(
        unseal(
            &bundle_b,
            &[
                (ComponentKind::User, u.key().unwrap()),
                (ComponentKind::Remote, token_a.key().unwrap())
            ]
        )
        .is_err(),
        "a share from another vault must not be accepted"
    );
}

#[test]
fn a_share_cannot_be_moved_between_component_slots() {
    let release = random_key();
    let id = VaultId::from_bytes([6u8; 16]);
    let (mut bundle, token) = enrolled(&release, id);

    // Relabel the remote share as the user share.
    let remote = bundle.shares.iter().find(|s| s.component == ComponentKind::Remote).unwrap().clone();
    if let Some(slot) = bundle.shares.iter_mut().find(|s| s.component == ComponentKind::User) {
        slot.ciphertext = remote.ciphertext.clone();
        slot.nonce = remote.nonce;
    }

    assert!(
        unseal(&bundle, &[(ComponentKind::User, token.key().unwrap())]).is_err(),
        "a relabelled share must not authenticate"
    );
}

#[test]
fn tampering_with_any_byte_of_a_share_is_detected() {
    let release = random_key();
    let id = VaultId::from_bytes([7u8; 16]);
    let (bundle, token) = enrolled(&release, id);
    let u = user(b"correct horse battery staple");

    for i in 0..bundle.shares[0].ciphertext.len() {
        let mut bad = bundle.clone();
        bad.shares[0].ciphertext[i] ^= 1;
        // With one share destroyed only one component remains usable, which is
        // below the threshold.
        assert!(unseal(
            &bad,
            &[
                (ComponentKind::User, u.key().unwrap()),
                (ComponentKind::Remote, token.key().unwrap())
            ]
        )
        .is_err(), "byte {i} was accepted");
    }
}

#[test]
fn fewer_components_than_the_threshold_is_refused_at_enrolment() {
    let release = random_key();
    let u = user(b"pw");
    let err = seal(
        &release,
        VaultId::nil(),
        CryptoSuite::XChaCha20Poly1305,
        &[(ComponentKind::User, u.key().unwrap())],
    )
    .unwrap_err();
    assert!(format!("{err}").contains("at least"));
}

#[test]
fn enrolling_the_same_component_twice_is_refused() {
    let release = random_key();
    let u = user(b"pw");
    assert!(seal(
        &release,
        VaultId::nil(),
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::User, u.key().unwrap())
        ],
    )
    .is_err());
}

#[test]
fn the_bundle_survives_encoding_and_rejects_junk() {
    let release = random_key();
    let id = VaultId::from_bytes([8u8; 16]);
    let (bundle, _) = enrolled(&release, id);
    assert_eq!(SplitBundle::decode(&bundle.encode()).unwrap(), bundle);

    assert!(SplitBundle::decode(b"").is_err());
    assert!(SplitBundle::decode(b"not a bundle at all").is_err());
    let encoded = bundle.encode();
    for n in 0..encoded.len() {
        let _ = SplitBundle::decode(&encoded[..n]);
    }
}

#[test]
fn the_assessment_says_what_is_weak_rather_than_only_what_is_strong() {
    let release = random_key();
    let id = VaultId::from_bytes([9u8; 16]);
    let (bundle, _) = enrolled(&release, id);
    let a = assess(&bundle);

    assert!(a.resists_drive_theft, "two off-drive components meet the threshold");
    assert!(!a.tolerates_one_loss, "two enrolled with threshold two has no redundancy");
    assert!(
        a.notes.iter().any(|n| n.contains("losing either one")),
        "the loss risk must be stated: {:?}",
        a.notes
    );
    assert!(
        a.notes.iter().any(|n| n.contains("No machine component")),
        "the missing machine binding must be stated: {:?}",
        a.notes
    );
    assert!(
        a.notes.iter().any(|n| n.contains("separate media")),
        "the token placement warning must be stated: {:?}",
        a.notes
    );
}

#[test]
fn three_components_tolerate_losing_one() {
    // What the enrollment becomes once a machine component exists.
    let release = random_key();
    let id = VaultId::from_bytes([10u8; 16]);
    let u = user(b"pw");
    let token = RecoveryToken::generate();
    let machine = random_key(); // stands in for a TPM-sealed key

    let bundle = seal(
        &release,
        id,
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::Machine, machine.clone()),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    )
    .unwrap();

    assert!(bundle.tolerates_one_loss());
    assert_eq!(THRESHOLD, 2);

    // Any two of the three work.
    for pair in [
        vec![(ComponentKind::User, u.key().unwrap()), (ComponentKind::Machine, machine.clone())],
        vec![(ComponentKind::User, u.key().unwrap()), (ComponentKind::Remote, token.key().unwrap())],
        vec![
            (ComponentKind::Machine, machine.clone()),
            (ComponentKind::Remote, token.key().unwrap()),
        ],
    ] {
        assert_eq!(unseal(&bundle, &pair).unwrap(), release);
    }

    // Any one alone does not.
    for single in [
        vec![(ComponentKind::User, u.key().unwrap())],
        vec![(ComponentKind::Machine, machine.clone())],
        vec![(ComponentKind::Remote, token.key().unwrap())],
    ] {
        assert!(unseal(&bundle, &single).is_err());
    }
}

#[test]
fn a_recovery_token_round_trips_and_rejects_junk() {
    let t = RecoveryToken::generate();
    let text = t.encode();
    assert!(text.starts_with("apex-zerotrace-recovery-token:v1:"));
    let back = RecoveryToken::decode(&text).unwrap();
    assert_eq!(back.key().unwrap(), t.key().unwrap());

    assert!(RecoveryToken::decode("").is_err());
    assert!(RecoveryToken::decode("apex-zerotrace-recovery-token:v1:zz").is_err());
    assert!(RecoveryToken::decode("some other file entirely").is_err());
}

#[test]
fn gather_reports_which_components_were_unavailable() {
    let u = user(b"pw");
    let machine = MachineProvider;
    let (got, missing) = gather(&[&u, &machine]);
    assert_eq!(got.len(), 1);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].0, ComponentKind::Machine);
    assert!(missing[0].1.contains("TPM"), "{}", missing[0].1);
}

// ---------- redundancy via a custodian component ----------

/// Three components, all available today: password, a recovery token, and a
/// custodian share held elsewhere.
fn three(release: &Key256, id: VaultId) -> (SplitBundle, RecoveryToken, RecoveryToken) {
    let u = user(b"correct horse battery staple");
    let token = RecoveryToken::generate();
    let custodian = RecoveryToken::generate();
    let bundle = seal(
        release,
        id,
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap()),
            (ComponentKind::Custodian, custodian.key().unwrap()),
        ],
    )
    .unwrap();
    (bundle, token, custodian)
}

#[test]
fn any_single_component_can_be_lost() {
    // The point of the third component: no single loss destroys the vault.
    let release = random_key();
    let id = VaultId::from_bytes([20u8; 16]);
    let (bundle, token, custodian) = three(&release, id);
    let u = user(b"correct horse battery staple");

    assert!(bundle.tolerates_one_loss());

    // Password forgotten: the two tokens still open it.
    assert_eq!(
        unseal(
            &bundle,
            &[
                (ComponentKind::Remote, token.key().unwrap()),
                (ComponentKind::Custodian, custodian.key().unwrap())
            ]
        )
        .unwrap(),
        release
    );

    // Token lost: password and custodian open it.
    assert_eq!(
        unseal(
            &bundle,
            &[
                (ComponentKind::User, u.key().unwrap()),
                (ComponentKind::Custodian, custodian.key().unwrap())
            ]
        )
        .unwrap(),
        release
    );

    // Custodian unreachable: password and token open it.
    assert_eq!(
        unseal(
            &bundle,
            &[
                (ComponentKind::User, u.key().unwrap()),
                (ComponentKind::Remote, token.key().unwrap())
            ]
        )
        .unwrap(),
        release
    );
}

#[test]
fn a_stolen_drive_is_still_useless_with_three_components() {
    let release = random_key();
    let id = VaultId::from_bytes([21u8; 16]);
    let (bundle, _, _) = three(&release, id);
    let stolen = SplitBundle::decode(&bundle.encode()).unwrap();

    // Password guessed correctly, everything on the drive copied: still short.
    let guessed = user(b"correct horse battery staple");
    assert!(unseal(&stolen, &[(ComponentKind::User, guessed.key().unwrap())]).is_err());
}

#[test]
fn the_assessment_warns_that_two_tokens_bypass_the_password() {
    // The cost of buying redundancy with a second token rather than a machine
    // component. It must be stated, not discovered.
    let release = random_key();
    let id = VaultId::from_bytes([22u8; 16]);
    let (bundle, _, _) = three(&release, id);
    let a = assess(&bundle);

    assert!(a.tolerates_one_loss);
    assert!(a.resists_drive_theft);
    assert!(
        a.notes.iter().any(|n| n.contains("without the password")),
        "the two-token risk must be stated: {:?}",
        a.notes
    );
    assert!(
        a.notes.iter().any(|n| n.contains("different places")),
        "storage guidance must be given: {:?}",
        a.notes
    );
}

#[test]
fn a_custodian_share_cannot_be_passed_off_as_a_remote_one() {
    let release = random_key();
    let id = VaultId::from_bytes([23u8; 16]);
    let (bundle, token, custodian) = three(&release, id);

    // Offer the custodian's key in the remote slot and vice versa. Neither
    // authenticates, because the slot is bound into the AAD.
    let err = unseal(
        &bundle,
        &[
            (ComponentKind::Remote, custodian.key().unwrap()),
            (ComponentKind::Custodian, token.key().unwrap()),
        ],
    )
    .unwrap_err();
    assert!(format!("{err}").contains("0 of 2"), "{err}");
}

#[test]
fn a_token_containing_non_ascii_is_refused_rather_than_panicking() {
    // Found by mutation fuzzing. The length check counted bytes while the
    // slice that followed required character boundaries, so a token holding
    // one multi-byte character passed the check and then panicked. The same
    // shape existed in five parsers.
    let prefix = "apex-zerotrace-recovery-token:v1:";
    for body in [
        // 64 bytes, but fewer than 64 characters.
        "0d8cdabef581841b74b3579df5df94e323f6d59d5d2bf0329ڜ4f4cbdb0999d6",
        "ڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜڜ",
        "é".repeat(32).as_str(),
    ] {
        let token = format!("{prefix}{body}");
        // The only requirement is that it returns rather than panicking.
        assert!(RecoveryToken::decode(&token).is_err(), "{body} was accepted");
    }
}

#[test]
fn a_bundle_with_trailing_bytes_is_refused() {
    // Accepting them would let one bundle be presented in several encodings,
    // and give somebody a place to hide data every other tool overlooks.
    let release = random_key();
    let id = VaultId::from_bytes([30u8; 16]);
    let (bundle, _) = enrolled(&release, id);

    let mut extended = bundle.encode();
    extended.extend_from_slice(b"hidden");
    let err = SplitBundle::decode(&extended).unwrap_err();
    assert!(format!("{err}").contains("trailing"), "{err}");

    // The unmodified bundle is still fine.
    assert!(SplitBundle::decode(&bundle.encode()).is_ok());
}

#[test]
fn a_bundle_naming_one_component_twice_is_refused() {
    // One share would silently shadow another, and which one won would depend
    // on iteration order.
    let release = random_key();
    let id = VaultId::from_bytes([31u8; 16]);
    let (bundle, _) = enrolled(&release, id);

    let mut doubled = bundle.clone();
    let first = doubled.shares[0].clone();
    doubled.shares.push(first);
    doubled.shares[1].component = ComponentKind::User;

    let err = SplitBundle::decode(&doubled.encode()).unwrap_err();
    assert!(format!("{err}").contains("more than once"), "{err}");
}

#[test]
fn a_bundle_and_every_component_rebuild_nothing_without_the_container() {
    // What destruction actually protects, stated as a test rather than as a
    // claim in a document.
    //
    // The split bundle and the components between them reconstruct the release
    // key. The release key unwraps the master key. But the wrapped master key
    // lives in the container, so once it has been overwritten there is nothing
    // for the release key to act on, and a quorum holds a key to a door that
    // no longer exists.
    //
    // This is why copies matter and components do not: a backup of the
    // container taken beforehand still opens, while every component in the
    // world does not.
    let release = random_key();
    let id = VaultId::from_bytes([40u8; 16]);
    let u = user(b"correct horse battery staple");
    let token = RecoveryToken::generate();
    let custodian = RecoveryToken::generate();

    let bundle = seal(
        &release,
        id,
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, u.key().unwrap()),
            (ComponentKind::Remote, token.key().unwrap()),
            (ComponentKind::Custodian, custodian.key().unwrap()),
        ],
    )
    .unwrap();

    // Every component, held at once, as an adversary with everything but the
    // container would have.
    let everything = [
        (ComponentKind::User, u.key().unwrap()),
        (ComponentKind::Remote, token.key().unwrap()),
        (ComponentKind::Custodian, custodian.key().unwrap()),
    ];
    let rebuilt = unseal(&bundle, &everything).unwrap();
    assert_eq!(rebuilt, release, "the release key is recoverable, as designed");

    // And that is the end of what they can do. The release key is not the
    // master key; it only unwraps one, and the wrapped master key is not in
    // the bundle.
    let encoded = bundle.encode();
    assert!(
        !encoded.windows(32).any(|w| w == release.expose()),
        "the release key itself is in the bundle"
    );
}
