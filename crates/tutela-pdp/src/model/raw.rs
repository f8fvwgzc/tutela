//! The manifest as TOML gives it to us, before any check
//! (docs/MANIFEST.md). Every struct refuses unknown keys, so a typo never
//! drops a restriction silently.

use std::collections::BTreeMap;

use core::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) version: i64,
    pub(crate) app: App,
    #[serde(default)]
    pub(crate) types: BTreeMap<String, Type>,
    #[serde(default)]
    pub(crate) roles: BTreeMap<String, Role>,
    #[serde(default)]
    pub(crate) field_rules: Vec<FieldRule>,
    #[serde(default)]
    pub(crate) conditions: Vec<Condition>,
    #[serde(default)]
    pub(crate) ui: BTreeMap<String, Ui>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct App {
    pub(crate) name: String,
    pub(crate) audience: Option<String>,
}

/// A string or an array of strings. Hand-written, not `#[serde(untagged)]`:
/// an untagged enum first copies the whole value into a buffer, recursively,
/// so deep input could exhaust the stack.
#[derive(Debug)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OneOrMany;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a type name or an array of type names")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<OneOrMany, E> {
                Ok(OneOrMany::One(v.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<OneOrMany, A::Error> {
                let mut out = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    out.push(s);
                }
                Ok(OneOrMany::Many(out))
            }
        }
        d.deserialize_any(V)
    }
}

impl OneOrMany {
    pub(crate) fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Type {
    pub(crate) parent: OneOrMany,
    #[serde(default)]
    pub(crate) container: bool,
    pub(crate) starts: Option<String>,
    pub(crate) ai_reach: Option<String>,
    #[serde(default)]
    pub(crate) features: Vec<String>,
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) fields: BTreeMap<String, Field>,
    #[serde(default)]
    pub(crate) actions: BTreeMap<String, Action>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Field {
    pub(crate) sensitivity: String,
    #[serde(rename = "type")]
    pub(crate) field_type: Option<String>,
    #[serde(default)]
    pub(crate) grants_access: bool,
    pub(crate) label: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) needs: String,
    pub(crate) grant: Option<bool>,
}

/// A grant value: a level string or `true`. Hand-written for the same
/// reason as [`OneOrMany`].
#[derive(Debug)]
pub(crate) enum GrantValue {
    Flag(bool),
    Level(String),
}

impl<'de> Deserialize<'de> for GrantValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = GrantValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a level string or `true`")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<GrantValue, E> {
                Ok(GrantValue::Flag(v))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<GrantValue, E> {
                Ok(GrantValue::Level(v.to_owned()))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Role {
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) grants: BTreeMap<String, GrantValue>,
    pub(crate) assignable_to: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct FieldRule {
    pub(crate) field: String,
    pub(crate) role: Option<String>,
    pub(crate) max: String,
    pub(crate) display: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Condition {
    pub(crate) role: String,
    #[serde(rename = "type")]
    pub(crate) resource_type: String,
    #[serde(deserialize_with = "template")]
    pub(crate) when: Template,
    #[serde(rename = "else")]
    pub(crate) otherwise: String,
}

/// The deepest template (MANIFEST.md section 8).
pub(crate) const MAX_TEMPLATE_DEPTH: usize = 4;

/// The most branches of `and` and `or`.
pub(crate) const MAX_BRANCHES: usize = 16;

/// One condition template: a table with exactly one key.
#[derive(Debug)]
pub(crate) enum Template {
    Eq(Compare),
    In(CompareMany),
    Contains(Compare),
    IsPrincipal(String),
    InGroup(String),
    And(Vec<Template>),
    Or(Vec<Template>),
    Not(Box<Template>),
}

fn template<'de, D: Deserializer<'de>>(d: D) -> Result<Template, D::Error> {
    TemplateSeed { depth: 1 }.deserialize(d)
}

/// Reads a template and stops with an error past [`MAX_TEMPLATE_DEPTH`],
/// before it reads any deeper. So the stack use is bounded whatever the input.
struct TemplateSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for TemplateSeed {
    type Value = Template;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Template, D::Error> {
        if self.depth > MAX_TEMPLATE_DEPTH {
            return Err(de::Error::custom("a template is at most 4 levels deep"));
        }
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for TemplateSeed {
    type Value = Template;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a condition template: a table with exactly one key")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Template, A::Error> {
        let Some(key) = map.next_key::<String>()? else {
            return Err(de::Error::custom("a template needs exactly one key"));
        };
        let next = self.depth + 1;
        let t = match key.as_str() {
            "eq" => Template::Eq(map.next_value()?),
            "in" => Template::In(map.next_value()?),
            "contains" => Template::Contains(map.next_value()?),
            "is_principal" => Template::IsPrincipal(map.next_value()?),
            "in_group" => Template::InGroup(map.next_value()?),
            "and" => Template::And(map.next_value_seed(BranchSeed { depth: next })?),
            "or" => Template::Or(map.next_value_seed(BranchSeed { depth: next })?),
            "not" => Template::Not(Box::new(map.next_value_seed(TemplateSeed { depth: next })?)),
            other => {
                return Err(de::Error::unknown_variant(
                    other,
                    &[
                        "eq",
                        "in",
                        "contains",
                        "is_principal",
                        "in_group",
                        "and",
                        "or",
                        "not",
                    ],
                ));
            }
        };
        if map.next_key::<String>()?.is_some() {
            return Err(de::Error::custom("a template needs exactly one key"));
        }
        Ok(t)
    }
}

/// The templates of `and` and `or`: at most [`MAX_BRANCHES`].
struct BranchSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BranchSeed {
    type Value = Vec<Template>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<Template>, D::Error> {
        if self.depth > MAX_TEMPLATE_DEPTH {
            return Err(de::Error::custom("a template is at most 4 levels deep"));
        }
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for BranchSeed {
    type Value = Vec<Template>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of templates")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Template>, A::Error> {
        let mut out = Vec::new();
        while let Some(t) = seq.next_element_seed(TemplateSeed { depth: self.depth })? {
            if out.len() == MAX_BRANCHES {
                return Err(de::Error::custom("`and` and `or` take 2 to 16 templates"));
            }
            out.push(t);
        }
        Ok(out)
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compare {
    pub(crate) field: String,
    pub(crate) value: Scalar,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompareMany {
    pub(crate) field: String,
    pub(crate) values: Vec<Scalar>,
}

/// A template value: a string, an integer or a boolean, nothing nested. Not
/// `toml::Value`, which could hold arbitrarily deep tables.
#[derive(Debug)]
pub(crate) enum Scalar {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Scalar;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, an integer or a boolean")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Scalar, E> {
                Ok(Scalar::Boolean(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Scalar, E> {
                Ok(Scalar::Integer(v))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Scalar, E> {
                i64::try_from(v)
                    .map(Scalar::Integer)
                    .map_err(|_| E::custom("an integer must fit in 64 bits"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Scalar, E> {
                Ok(Scalar::String(v.to_owned()))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ui {
    #[serde(default)]
    pub(crate) actions: Vec<String>,
    #[serde(default)]
    pub(crate) fields: Vec<String>,
    #[serde(default)]
    pub(crate) routes: Vec<String>,
    pub(crate) when_denied: String,
    pub(crate) reason: Option<String>,
}
