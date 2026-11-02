//! Canonical JSON (RFC 8785, JCS) for the values Tutela signs and hashes.
//!
//! The audit.v1 producer signature (CONTRACTS.md 9.3) and the local audit
//! chain are computed over these bytes. Tutela's signed values hold only
//! strings, whole numbers, booleans, arrays and objects, so this writes
//! those and refuses the rest:
//!
//! - object members sorted by their names as UTF-16 code units;
//! - no whitespace;
//! - strings escaped as ECMAScript `JSON.stringify` does (RFC 8785 3.2.2.2):
//!   `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other control characters as
//!   `\u00xx` in lowercase hex, everything else as itself;
//! - integers in plain decimal, at most 2^53 − 1 in size.
//!
//! A float or a `null` is refused: a writer leaves an empty field out
//! (CONTRACTS.md 9.3), and a float has no single text that every reader
//! agrees on.

use std::fmt::Write as _;

use serde_json::Value;

use crate::encoding::MAX_JSON_INT;

/// Why a value has no canonical form here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JcsError {
    /// A number that is not a whole number within ±(2^53 − 1).
    #[error("only whole numbers up to 2^53 - 1 have a canonical form here")]
    Number,
    /// A `null`: writers leave an empty field out.
    #[error("null has no canonical form here; leave the field out")]
    Null,
}

/// The canonical text of `value`.
///
/// # Errors
///
/// [`JcsError`] for a float, a number out of range, or a `null`.
pub fn to_canonical_string(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Null => return Err(JcsError::Null),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_JSON_INT {
                    return Err(JcsError::Number);
                }
                let _ = write!(out, "{u}");
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_JSON_INT {
                    return Err(JcsError::Number);
                }
                let _ = write!(out, "{i}");
            } else {
                return Err(JcsError::Number);
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, v)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_are_sorted_by_utf16_and_nothing_is_padded() {
        // U+E000 sorts after U+1F600 in UTF-16 (a surrogate pair starts with
        // 0xD83D), but before it as UTF-8 bytes or code points.
        let v = json!({"b": 1, "a": [true, false, "x"], "\u{e000}": 1, "\u{1f600}": 2, "": {}});
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "{\"\":{},\"a\":[true,false,\"x\"],\"b\":1,\"\u{1f600}\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn strings_are_escaped_as_ecmascript_does() {
        let v = json!("q\"b\\s/\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é");
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "\"q\\\"b\\\\s/\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é\""
        );
    }

    #[test]
    fn floats_nulls_and_large_numbers_are_refused() {
        assert_eq!(to_canonical_string(&json!(1.5)), Err(JcsError::Number));
        assert_eq!(
            to_canonical_string(&json!({"a": null})),
            Err(JcsError::Null)
        );
        assert_eq!(
            to_canonical_string(&json!(MAX_JSON_INT + 1)),
            Err(JcsError::Number)
        );
        assert_eq!(to_canonical_string(&json!(-42)).unwrap(), "-42");
        assert_eq!(
            to_canonical_string(&json!(MAX_JSON_INT)).unwrap(),
            MAX_JSON_INT.to_string()
        );
    }

    #[test]
    fn the_rfc_8785_string_example_matches() {
        // RFC 8785 3.2.3: the "string" member of its example.
        let v = json!({"string": "\u{20ac}$\u{f}\nA'B\"\\\\\"/", "literals": [true, false]});
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "{\"literals\":[true,false],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }
}
