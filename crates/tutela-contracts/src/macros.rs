//! Crate-private macros.

/// Implements `Serialize` (through `Display`) and `Deserialize` (through
/// `FromStr`) for a type whose wire form is one JSON string.
///
/// Only a JSON string is accepted. A number, `null`, an object or an array is
/// a type error.
macro_rules! string_serde {
    ($ty:ty, $expecting:expr) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct StrVisitor;

                impl ::serde::de::Visitor<'_> for StrVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> ::core::result::Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        v.parse::<$ty>()
                            .map_err(|e| E::custom($crate::error_chain(&e)))
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }
    };
}

/// Defines a unit type whose wire form is one fixed JSON string, for example
/// `"1.0"` or `"audit.v1"`. Any other value is rejected.
macro_rules! fixed_string {
    ($(#[$meta:meta])* $name:ident, $value:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
        pub struct $name;

        impl $name {
            #[doc = concat!("The only valid value: `", $value, "`.")]
            pub const VALUE: &'static str = $value;
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($value)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::FixedValueError;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                if s == $value {
                    Ok(Self)
                } else {
                    Err($crate::FixedValueError { expected: $value })
                }
            }
        }

        string_serde!($name, concat!("the string `", $value, "`"));
    };
}

/// Defines a Tutela id of the form `<prefix><uuidv7>` (CONTRACTS.md 1.2).
macro_rules! prefixed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name($crate::id::Uuid7);

        impl $name {
            #[doc = concat!("The fixed text prefix of this id: `", $prefix, "`.")]
            pub const PREFIX: &'static str = $prefix;

            /// Makes the id from a UUIDv7.
            #[must_use]
            pub const fn new(uuid: $crate::id::Uuid7) -> Self {
                Self(uuid)
            }

            /// The UUIDv7 inside the id.
            #[must_use]
            pub const fn uuid(&self) -> $crate::id::Uuid7 {
                self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($prefix)?;
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::id::IdError;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                let rest = s
                    .strip_prefix($prefix)
                    .ok_or($crate::id::IdError::Prefix { expected: $prefix })?;
                Ok(Self($crate::id::Uuid7::parse(rest)?))
            }
        }

        string_serde!($name, concat!("a `", $prefix, "<uuidv7>` id string"));
    };
}
