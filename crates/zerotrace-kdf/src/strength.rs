//! How good a password has to be.
//!
//! Length is what matters and nothing else is required. Forcing a symbol and a
//! digit produces `Password1!`, which is worse than four unrelated words and
//! harder to remember. The rule here is therefore a length floor, with a
//! passphrase encouraged rather than demanded.
//!
//! Enforced when a vault is created, because that is the only moment a
//! password can be chosen. An existing vault cannot be made to have a better
//! one retroactively.

use zerotrace_core::{Error, Result};

/// Shortest password accepted for a new vault.
///
/// Fifteen characters, which four short words and their separators reach
/// comfortably, and which a single word does not.
pub const MIN_LENGTH: usize = 15;

/// A word count at which a dash-separated phrase is worth calling strong.
pub const PASSPHRASE_WORDS: usize = 4;

/// How many distinct characters a password needs.
///
/// `aaaaaaaaaaaaaaaaaaaa` clears a length floor and is worthless. So does
/// `111111111111111`, and so does any phrase repeated to length. Length is a
/// good proxy for strength only when the characters are not all the same few.
pub const MIN_DISTINCT_CHARS: usize = 6;

/// Longest run of one repeated character that is tolerated.
pub const MAX_RUN: usize = 4;

/// What was made of a proposed password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strength {
    /// Below the floor. Refused.
    TooShort { have: usize, need: usize },
    /// Long enough, but built from too few different characters, or from one
    /// short piece repeated. Refused.
    TooRepetitive { reason: &'static str },
    /// Long enough, but a single run of characters.
    Acceptable,
    /// A phrase of several separated words.
    Strong { words: usize },
}

impl Strength {
    pub fn is_acceptable(&self) -> bool {
        !matches!(self, Strength::TooShort { .. } | Strength::TooRepetitive { .. })
    }

    /// A sentence to show the person choosing.
    pub fn advice(&self) -> String {
        match self {
            Strength::TooShort { have, need } => format!(
                "Too short: {have} characters, and {need} are needed. Four or five \
                 unrelated words joined by dashes is the easiest way to get there, for \
                 example correct-horse-battery-staple."
            ),
            Strength::TooRepetitive { reason } => format!(
                "Long enough, but {reason}. Length only helps when the characters are not \
                 all the same few. Four or five unrelated words joined by dashes is the \
                 easiest way to a password that is genuinely hard to guess, for example \
                 correct-horse-battery-staple."
            ),
            Strength::Acceptable => "Long enough. A phrase of several unrelated words \
                 joined by dashes would be easier to remember and harder to guess."
                .to_string(),
            Strength::Strong { words } => format!(
                "A phrase of {words} words. Easy to remember, and long enough that \
                 guessing it is not worth attempting."
            ),
        }
    }
}

/// Counts the words in a separated phrase.
fn word_count(password: &str) -> usize {
    password
        .split(['-', ' ', '_', '.'])
        .filter(|w| w.len() >= 2)
        .count()
}

/// Assesses a proposed password.
/// Whether the whole password is one short piece repeated.
///
/// Catches `passwordpasswordpassword` and `abababababababab`, which a length
/// floor and a distinct-character count both wave through.
fn is_repeated_unit(chars: &[char]) -> bool {
    let n = chars.len();
    for unit in 1..=n / 2 {
        if n % unit != 0 {
            continue;
        }
        if (unit..n).all(|i| chars[i] == chars[i % unit]) {
            return true;
        }
    }
    false
}

pub fn assess(password: &str) -> Strength {
    let have = password.chars().count();
    if have < MIN_LENGTH {
        return Strength::TooShort { have, need: MIN_LENGTH };
    }

    let chars: Vec<char> = password.chars().collect();

    let mut distinct: Vec<char> = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < MIN_DISTINCT_CHARS {
        return Strength::TooRepetitive {
            reason: "it is built from too few different characters",
        };
    }

    if is_repeated_unit(&chars) {
        return Strength::TooRepetitive { reason: "it is one short piece repeated" };
    }

    let mut run = 1usize;
    for w in chars.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        if run > MAX_RUN {
            return Strength::TooRepetitive {
                reason: "it contains a long run of one repeated character",
            };
        }
    }
    let words = word_count(password);
    if words >= PASSPHRASE_WORDS {
        Strength::Strong { words }
    } else {
        Strength::Acceptable
    }
}

/// Refuses a password that does not meet the floor.
///
/// Called when a vault is created. Opening an existing vault never applies
/// this: a vault made under an older rule must still open.
pub fn require_acceptable(password: &str) -> Result<()> {
    let s = assess(password);
    if s.is_acceptable() {
        Ok(())
    } else {
        Err(Error::Other(s.advice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passwords_are_refused_however_complex() {
        // The reason complexity rules are not used: this passes every symbol
        // and digit rule ever written and is still terrible.
        for p in ["P@ssw0rd!", "x", "", "Tr0ub4dor&3"] {
            assert!(!assess(p).is_acceptable(), "{p} was accepted");
            assert!(require_acceptable(p).is_err());
        }
    }

    #[test]
    fn a_long_passphrase_is_strong() {
        match assess("correct-horse-battery-staple") {
            Strength::Strong { words } => assert_eq!(words, 4),
            other => panic!("expected strong, got {other:?}"),
        }
        assert!(require_acceptable("correct-horse-battery-staple").is_ok());
    }

    #[test]
    fn spaces_and_underscores_count_as_separators() {
        assert!(matches!(assess("correct horse battery staple"), Strength::Strong { .. }));
        assert!(matches!(assess("correct_horse_battery_staple"), Strength::Strong { .. }));
    }

    #[test]
    fn repetitive_passwords_are_refused_however_long() {
        // Every one of these clears the length floor and is worthless.
        for p in [
            "aaaaaaaaaaaaaaaaaaaa",
            "111111111111111",
            "passwordpasswordpassword",
            "abababababababab",
            "correct-horse-aaaaaaaaaa",
        ] {
            assert!(!assess(p).is_acceptable(), "{p} was accepted");
            assert!(require_acceptable(p).is_err());
        }
    }

    #[test]
    fn an_ordinary_long_password_is_still_acceptable() {
        // The guard must not reject reasonable choices. Doubled letters are
        // common in real words and must survive.
        for p in [
            "Tr0ub4dor-and-three-more",
            "bookkeeper-committee-fluffy",
            "a-long-enough-passphrase",
        ] {
            assert!(assess(p).is_acceptable(), "{p} was refused");
        }
    }

    #[test]
    fn the_boundary_is_where_it_says_it_is() {
        // Varied characters, so this measures the length rule and nothing
        // else. A run of one letter would now be refused for being
        // repetitive, which would make this test pass for the wrong reason.
        let alphabet = "abcdefghijklmnopqrstuvwxyz";
        let just_short: String = alphabet.chars().take(MIN_LENGTH - 1).collect();
        let just_long: String = alphabet.chars().take(MIN_LENGTH).collect();
        assert!(!assess(&just_short).is_acceptable());
        assert!(assess(&just_long).is_acceptable());
    }

    #[test]
    fn advice_names_the_shortfall() {
        let a = assess("short").advice();
        assert!(a.contains("15"), "{a}");
        assert!(a.contains("dashes"), "{a}");
    }
}
