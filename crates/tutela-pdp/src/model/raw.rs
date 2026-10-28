//! The manifest as TOML gives it to us, before any check
//! (docs/MANIFEST.md). Every struct refuses unknown keys, so a typo never
//! drops a restriction silently.

use std::collections::BTreeMap;

use serde::Deserialize;

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

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
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

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum GrantValue {
    Flag(bool),
    Level(String),
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
    pub(crate) when: Template,
    #[serde(rename = "else")]
    pub(crate) otherwise: String,
}

/// One condition template: a table with exactly one key.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compare {
    pub(crate) field: String,
    pub(crate) value: toml::Value,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompareMany {
    pub(crate) field: String,
    pub(crate) values: Vec<toml::Value>,
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
