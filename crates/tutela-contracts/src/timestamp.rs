//! JSON times: RFC 3339, UTC, `Z` suffix, exactly 3 fractional digits
//! (CONTRACTS.md section 0). Example: `2026-10-25T09:30:00.000Z`.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};

/// Why a time was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The text is not `YYYY-MM-DDTHH:MM:SS.sssZ`.
    #[error("a time must be `YYYY-MM-DDTHH:MM:SS.sssZ` (UTC, 3 fractional digits)")]
    Format,
    /// The date or time does not exist (for example February 30 or second 60).
    #[error("the date or time does not exist")]
    Invalid,
    /// The time is outside the years 0000 to 9999.
    #[error("the time must be in the years 0000 to 9999")]
    OutOfRange,
}

/// A point in time with millisecond precision, written as
/// `YYYY-MM-DDTHH:MM:SS.sssZ`.
///
/// Readers accept only this exact form: no offset other than `Z`, no lowercase
/// `t` or `z`, exactly 3 fractional digits, no leap second.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    /// The length of the text form.
    pub const TEXT_LEN: usize = 24;

    /// Makes a time from milliseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] outside the years 0000 to 9999.
    pub fn from_unix_millis(millis: i64) -> Result<Self, TimestampError> {
        let dt =
            DateTime::<Utc>::from_timestamp_millis(millis).ok_or(TimestampError::OutOfRange)?;
        Self::from_datetime(dt)
    }

    /// Makes a time from a [`DateTime`]. Precision below one millisecond is
    /// dropped (truncated).
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] outside the years 0000 to 9999,
    /// and [`TimestampError::Invalid`] for a leap second.
    pub fn from_datetime(dt: DateTime<Utc>) -> Result<Self, TimestampError> {
        if !(0..=9999).contains(&dt.year()) {
            return Err(TimestampError::OutOfRange);
        }
        let nanos = dt.nanosecond();
        if nanos >= 1_000_000_000 {
            return Err(TimestampError::Invalid);
        }
        let truncated = dt
            .with_nanosecond(nanos - nanos % 1_000_000)
            .ok_or(TimestampError::Invalid)?;
        Ok(Self(truncated))
    }

    /// The time as a [`DateTime`].
    #[must_use]
    pub const fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub fn unix_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    /// Parses the exact text form.
    ///
    /// # Errors
    ///
    /// Returns a [`TimestampError`] when `s` is not in the exact form or the
    /// date does not exist.
    pub fn parse(s: &str) -> Result<Self, TimestampError> {
        let b: &[u8; Self::TEXT_LEN] = s
            .as_bytes()
            .try_into()
            .map_err(|_| TimestampError::Format)?;
        for (i, &c) in b.iter().enumerate() {
            let ok = match i {
                4 | 7 => c == b'-',
                10 => c == b'T',
                13 | 16 => c == b':',
                19 => c == b'.',
                23 => c == b'Z',
                _ => c.is_ascii_digit(),
            };
            if !ok {
                return Err(TimestampError::Format);
            }
        }
        let num = |start: usize, len: usize| -> Result<u32, TimestampError> {
            let digits = b.get(start..start + len).ok_or(TimestampError::Format)?;
            Ok(digits
                .iter()
                .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0')))
        };
        let year = i32::try_from(num(0, 4)?).map_err(|_| TimestampError::Format)?;
        let date =
            NaiveDate::from_ymd_opt(year, num(5, 2)?, num(8, 2)?).ok_or(TimestampError::Invalid)?;
        let naive = date
            .and_hms_milli_opt(num(11, 2)?, num(14, 2)?, num(17, 2)?, num(20, 3)?)
            .ok_or(TimestampError::Invalid)?;
        Ok(Self(naive.and_utc()))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.0;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            d.year(),
            d.month(),
            d.day(),
            d.hour(),
            d.minute(),
            d.second(),
            d.timestamp_subsec_millis()
        )
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(Timestamp, "an RFC 3339 UTC time with 3 fractional digits");

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn doc_example() {
        let t = Timestamp::parse("2026-10-25T09:30:00.000Z").unwrap();
        assert_eq!(t.to_string(), "2026-10-25T09:30:00.000Z");
        let t = Timestamp::parse("2026-10-25T09:31:12.345Z").unwrap();
        assert_eq!(t.unix_millis() % 1000, 345);
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            "\"2026-10-25T09:31:12.345Z\""
        );
    }

    #[test]
    fn rejects_other_forms() {
        let cases: &[(&str, TimestampError)] = &[
            ("2026-10-25T09:30:00Z", TimestampError::Format),
            ("2026-10-25T09:30:00.0Z", TimestampError::Format),
            ("2026-10-25T09:30:00.0000Z", TimestampError::Format),
            ("2026-10-25T09:30:00.000+00:00", TimestampError::Format),
            ("2026-10-25T09:30:00.000z", TimestampError::Format),
            ("2026-10-25t09:30:00.000Z", TimestampError::Format),
            ("2026-10-25 09:30:00.000Z", TimestampError::Format),
            ("2026-10-25T09:30:00,000Z", TimestampError::Format),
            ("+2026-10-25T09:30:00.000", TimestampError::Format),
            ("2026-02-30T09:30:00.000Z", TimestampError::Invalid),
            ("2026-13-01T09:30:00.000Z", TimestampError::Invalid),
            ("2026-10-25T24:00:00.000Z", TimestampError::Invalid),
            ("2026-10-25T09:60:00.000Z", TimestampError::Invalid),
            ("2016-12-31T23:59:60.000Z", TimestampError::Invalid),
            ("", TimestampError::Format),
        ];
        for (input, err) in cases {
            assert_eq!(Timestamp::parse(input), Err(*err), "{input:?}");
        }
        assert!(serde_json::from_str::<Timestamp>("1792920600").is_err());
    }

    #[test]
    fn construction() {
        let t = Timestamp::from_unix_millis(1_792_920_600_123).unwrap();
        assert_eq!(t.unix_millis(), 1_792_920_600_123);
        let dt = DateTime::<Utc>::from_timestamp(1_792_920_600, 123_456_789).unwrap();
        assert_eq!(
            Timestamp::from_datetime(dt).unwrap().unix_millis(),
            1_792_920_600_123
        );
        assert_eq!(
            Timestamp::from_datetime(dt)
                .unwrap()
                .as_datetime()
                .nanosecond(),
            123_000_000
        );
        assert_eq!(
            Timestamp::from_unix_millis(-62_167_219_200_001),
            Err(TimestampError::OutOfRange)
        );
        assert!(Timestamp::from_unix_millis(-62_167_219_200_000).is_ok());
        assert_eq!(
            Timestamp::from_unix_millis(-62_167_219_200_000)
                .unwrap()
                .to_string(),
            "0000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            Timestamp::from_unix_millis(253_402_300_800_000),
            Err(TimestampError::OutOfRange)
        );
        assert_eq!(
            Timestamp::from_unix_millis(253_402_300_799_999)
                .unwrap()
                .to_string(),
            "9999-12-31T23:59:59.999Z"
        );
    }

    proptest! {
        #[test]
        fn round_trip(ms in -62_167_219_200_000i64..253_402_300_800_000i64) {
            let t = Timestamp::from_unix_millis(ms).unwrap();
            let text = t.to_string();
            prop_assert_eq!(text.len(), Timestamp::TEXT_LEN);
            prop_assert_eq!(Timestamp::parse(&text), Ok(t));
            prop_assert_eq!(t.unix_millis(), ms);
        }

        #[test]
        fn never_panics(s in "\\PC{0,30}", d in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z") {
            let _ = Timestamp::parse(&s);
            let _ = Timestamp::parse(&d);
        }
    }
}
