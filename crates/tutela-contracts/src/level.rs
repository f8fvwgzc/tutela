//! The four levels (CONTRACTS.md section 3).
//!
//! The proto enum in `tutela.authz.v1` is Phase B.

use core::fmt;
use core::str::FromStr;

/// The JSON spelling was not one of the four levels.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("a level must be one of `none`, `read`, `write` or `full`")]
pub struct LevelError;

/// A level on an item, a field or a feature: `none < read < write < full`.
///
/// A closed set. The derived [`Ord`] follows exactly this order. The JSON
/// spelling is the lowercase string; anything else (`"None"`, `"admin"`, a
/// number, `null`) is an error, which means deny.
///
/// Owner-only admin actions sit above the four levels. They are not a level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Level {
    /// `none`: you cannot tell it exists.
    None,
    /// `read`: open and view it.
    Read,
    /// `write`: edit it and create items inside it.
    Write,
    /// `full`: write, plus delete and archive.
    Full,
}

impl Level {
    /// Every level, from low to high.
    pub const ALL: [Self; 4] = [Self::None, Self::Read, Self::Write, Self::Full];

    /// The JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::Full => "full",
        }
    }

    /// The position in the order, from 0 (`none`) to 3 (`full`).
    const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Read => 1,
            Self::Write => 2,
            Self::Full => 3,
        }
    }

    /// The lower of two levels.
    ///
    /// Used for `field level = min(role level, closest field rule)` and for
    /// delegated access `min(person, agent)`.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// `true` if this level is at least `required`.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Level {
    type Err = LevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or(LevelError)
    }
}

string_serde!(Level, "a level: none, read, write or full");

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn order_is_none_read_write_full() {
        assert!(Level::None < Level::Read);
        assert!(Level::Read < Level::Write);
        assert!(Level::Write < Level::Full);
        let mut sorted = [Level::Full, Level::None, Level::Write, Level::Read];
        sorted.sort();
        assert_eq!(sorted, Level::ALL);
    }

    #[test]
    fn min_and_satisfies() {
        assert_eq!(Level::Full.min(Level::Read), Level::Read);
        assert_eq!(Level::Read.min(Level::Full), Level::Read);
        assert_eq!(Level::None.min(Level::Full), Level::None);
        assert!(Level::Full.satisfies(Level::Write));
        assert!(Level::Write.satisfies(Level::Write));
        assert!(!Level::Read.satisfies(Level::Write));
        assert!(Level::None.satisfies(Level::None));
    }

    #[test]
    fn json_is_the_lowercase_string() {
        for l in Level::ALL {
            let json = serde_json::to_string(&l).unwrap();
            assert_eq!(json, format!("\"{}\"", l.as_str()));
            assert_eq!(serde_json::from_str::<Level>(&json).unwrap(), l);
        }
        for bad in [
            "\"None\"",
            "\"admin\"",
            "\"owner\"",
            "\"READ\"",
            "\"\"",
            "0",
            "1",
            "null",
            "true",
            "{}",
            "[]",
        ] {
            assert!(serde_json::from_str::<Level>(bad).is_err(), "{bad}");
        }
        assert_eq!("Full".parse::<Level>(), Err(LevelError));
    }

    fn level() -> impl Strategy<Value = Level> {
        prop::sample::select(Level::ALL.to_vec())
    }

    proptest! {
        #[test]
        fn min_matches_ord(a in level(), b in level()) {
            prop_assert_eq!(a.min(b), Ord::min(a, b));
            prop_assert_eq!(a.min(b), b.min(a));
            prop_assert!(a.min(b) <= a && a.min(b) <= b);
            prop_assert_eq!(a.satisfies(b), a >= b);
        }

        #[test]
        fn round_trip(a in level()) {
            prop_assert_eq!(a.to_string().parse::<Level>(), Ok(a));
        }
    }
}
