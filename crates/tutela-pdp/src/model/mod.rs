//! The model language and its compiler ([`docs/MANIFEST.md`]).
//!
//! [`Model::from_toml`] reads a `tutela.resources.toml` and returns a
//! compiled [`Model`], or [`Issues`]: every problem found, each with the place
//! in the manifest. The compiler never repairs input and never guesses.
//! Unknown keys are errors.
//!
//! [`diff`] compares two models of the same app and classifies each change
//! as narrowing, neutral or widening (MANIFEST.md section 10).
//!
//! A [`Model`] can only be made by the compiler, so every model in memory
//! has passed every check.
//!
//! [`docs/MANIFEST.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/MANIFEST.md

mod compile;
mod diff;
mod raw;

#[cfg(test)]
mod tests_diff;
#[cfg(test)]
mod tests_manifest;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use tutela_contracts::claims::Audience;
use tutela_contracts::keys::{
    ActionKey, ActionName, ActionRequirement, FieldKey, FieldName, Label, ResourceType, UiKey,
    check_name,
};
use tutela_contracts::level::Level;
use tutela_contracts::principal::PrincipalKind;

pub use diff::{Change, Class, DiffError, MAX_DIFF_LINES, ModelDiff, diff};

/// The only manifest format version.
pub const MANIFEST_VERSION: i64 = 1;

/// The largest manifest in bytes (4 MiB).
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// The owner-only admin keys (MANIFEST.md section 6). They sit above the four
/// levels; Full never includes them.
pub const ADMIN_KEYS: [&str; 6] = [
    "manage_access",
    "manage_fields",
    "manage_boundaries",
    "manage_agents",
    "approve_move",
    "read_audit",
];

/// `true` if `name` is one of the [`ADMIN_KEYS`].
#[must_use]
pub fn is_admin_key(name: &ActionName) -> bool {
    ADMIN_KEYS.contains(&name.as_str())
}

/// One problem in a manifest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Issue {
    /// Where: a dotted path into the manifest, for example
    /// `types.invoice.fields.amount`. Empty for the whole file.
    pub at: String,
    /// What is wrong, in short English.
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.at.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.at, self.message)
        }
    }
}

/// Every problem the compiler found. Never empty.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("the manifest has {} problem(s): {}", .0.len(), join(.0))]
pub struct Issues(
    /// The problems, in the order they were found.
    pub Vec<Issue>,
);

fn join(issues: &[Issue]) -> String {
    issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

macro_rules! model_name {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(String);

        impl $name {
            /// Parses a name (CONTRACTS.md section 2.1).
            ///
            /// # Errors
            ///
            /// Returns the grammar error when `s` is not a name.
            pub fn parse(s: &str) -> Result<Self, tutela_contracts::keys::NameError> {
                check_name(s)?;
                Ok(Self(s.to_owned()))
            }

            /// The name text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

model_name!(
    /// An app name: the app's model namespace.
    AppName
);
model_name!(
    /// A role key, for example `legal_reviewer`.
    RoleKey
);
model_name!(
    /// A group key, named by the `in_group` template.
    GroupKey
);

/// The five seeded roles (MANIFEST.md section 5.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SeededRole {
    /// `owner`: Full, every grant and every admin key. Never an agent.
    Owner,
    /// `member`: Full.
    Member,
    /// `viewer`: Read.
    Viewer,
    /// `guest`: Read, only where invited.
    Guest,
    /// `agent`: Read. Agents only.
    Agent,
}

impl SeededRole {
    /// Every seeded role.
    pub const ALL: [Self; 5] = [
        Self::Owner,
        Self::Member,
        Self::Viewer,
        Self::Guest,
        Self::Agent,
    ];

    /// The role key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
            Self::Viewer => "viewer",
            Self::Guest => "guest",
            Self::Agent => "agent",
        }
    }

    fn from_key(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.key() == s)
    }
}

/// How sensitive a field is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Sensitivity {
    /// `public`.
    Public,
    /// `internal`.
    Internal,
    /// `confidential`: starts at None for every role.
    Confidential,
    /// `secret`: starts at None for every role.
    Secret,
}

impl Sensitivity {
    /// The label that output built from this field carries.
    #[must_use]
    pub fn label(self) -> Label {
        match self {
            Self::Public => Label::PUBLIC,
            Self::Internal => Label::INTERNAL,
            Self::Confidential => Label::CONFIDENTIAL,
            Self::Secret => Label::SECRET,
        }
    }

    /// `true` for confidential and secret: the field starts hidden.
    #[must_use]
    pub const fn starts_hidden(self) -> bool {
        matches!(self, Self::Confidential | Self::Secret)
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// The value type of a field, for condition templates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum FieldType {
    /// `string`.
    String,
    /// `integer`: from −(2^53 − 1) to 2^53 − 1 in requests and conditions.
    Integer,
    /// `boolean`.
    Boolean,
    /// `string_list`: an array of strings.
    StringList,
    /// `principal`: a principal string.
    Principal,
}

impl FieldType {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "string" => Some(Self::String),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "string_list" => Some(Self::StringList),
            "principal" => Some(Self::Principal),
            _ => None,
        }
    }
}

/// One data field of a type.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FieldDef {
    /// The sensitivity.
    pub sensitivity: Sensitivity,
    /// The value type.
    pub field_type: FieldType,
    /// `true` if the field decides access (conditions read it).
    pub grants_access: bool,
    /// A display label.
    pub label: Option<String>,
}

/// A custom action of a type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct CustomAction {
    /// The level it needs, or owner-only.
    pub needs: ActionRequirement,
    /// `true` if the role must also hold `<type>:<action>`.
    pub grant: bool,
}

/// What a new scope of a container type starts as.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Starts {
    /// Inherits from above (the blueprint default).
    Open,
    /// Stops inheritance from above.
    Private,
}

/// How far an agent assigned at a scope may read.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum AiReach {
    /// Only inside that scope (the default).
    Project,
    /// Also other scopes under the same parent. Not recommended.
    Team,
}

/// A resource type.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TypeDef {
    /// A display label.
    pub label: Option<String>,
    /// The types that may be the direct parent.
    pub parents: BTreeSet<ResourceType>,
    /// `true` if other resources may live inside it.
    pub container: bool,
    /// What a new scope of this type starts as (containers only).
    pub starts: Starts,
    /// The default `ai_reach` of a new scope (containers only).
    pub ai_reach: AiReach,
    /// The data fields.
    pub fields: BTreeMap<FieldName, FieldDef>,
    /// The features, with their `@` (`@ai`).
    pub features: BTreeSet<FieldName>,
    /// The custom actions.
    pub actions: BTreeMap<ActionName, CustomAction>,
}

/// Who may receive a role.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SubjectKind {
    /// A principal of this kind.
    Principal(PrincipalKind),
    /// A group.
    Group,
}

impl SubjectKind {
    /// Every subject kind.
    pub const ALL: [Self; 6] = [
        Self::Principal(PrincipalKind::User),
        Self::Principal(PrincipalKind::ServiceAccount),
        Self::Principal(PrincipalKind::Key),
        Self::Principal(PrincipalKind::Agent),
        Self::Principal(PrincipalKind::Workload),
        Self::Group,
    ];

    /// The manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Principal(k) => k.as_str(),
            Self::Group => "group",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// A role: levels per type, field and feature, plus grants.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Role {
    /// A display label.
    pub label: Option<String>,
    /// The seeded role this is, if any (also when a manifest replaced it).
    pub seeded: Option<SeededRole>,
    /// The item level per type. A type not listed is `none`.
    pub levels: BTreeMap<ResourceType, Level>,
    /// Levels for single fields and features. A data field is never above
    /// the type level; a feature may be, when the type level is at least Read.
    pub field_levels: BTreeMap<FieldKey, Level>,
    /// Custom-action grants and admin keys.
    pub grants: BTreeSet<ActionKey>,
    /// Who may receive the role.
    pub assignable_to: BTreeSet<SubjectKind>,
}

impl Role {
    /// The item level for a type.
    #[must_use]
    pub fn level(&self, resource_type: &ResourceType) -> Level {
        self.levels
            .get(resource_type)
            .copied()
            .unwrap_or(Level::None)
    }

    /// `true` if the role holds this grant or admin key.
    #[must_use]
    pub fn holds(&self, key: &ActionKey) -> bool {
        self.grants.contains(key)
    }

    /// `true` if the role holds any admin key.
    #[must_use]
    pub fn has_admin_key(&self) -> bool {
        self.grants.iter().any(|k| is_admin_key(k.action()))
    }

    /// A role that gives nothing: what a role is in a model that lacks it.
    pub(crate) fn nothing() -> Self {
        Self {
            label: None,
            seeded: None,
            levels: BTreeMap::new(),
            field_levels: BTreeMap::new(),
            grants: BTreeSet::new(),
            assignable_to: BTreeSet::new(),
        }
    }
}

/// How a field hidden by a rule is shown.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum FieldDisplay {
    /// Shown as "Restricted".
    Restricted,
    /// Removed.
    Remove,
}

/// A field rule at the org root.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FieldRule {
    /// The field or feature.
    pub field: FieldKey,
    /// The role, or `None` for all roles.
    pub role: Option<RoleKey>,
    /// The cap.
    pub max: Level,
    /// How the hidden field is shown.
    pub display: FieldDisplay,
    /// `true` for the rule a confidential or secret field gets on its own.
    pub implicit: bool,
}

/// A value in a condition template.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Value {
    /// A string, 1 to 256 characters.
    String(String),
    /// An integer from −(2^53 − 1) to 2^53 − 1.
    Integer(i64),
    /// A boolean.
    Boolean(bool),
}

/// A vetted condition template (MANIFEST.md section 8). Each one compiles to
/// both the Rust check and the SQL list filter.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Template {
    /// The field equals the value.
    Eq {
        /// The field.
        field: FieldName,
        /// The value.
        value: Value,
    },
    /// The field equals one of the values.
    In {
        /// The field.
        field: FieldName,
        /// The values, 1 to 64, all of one type.
        values: Vec<Value>,
    },
    /// The string-list field holds the value.
    Contains {
        /// The field.
        field: FieldName,
        /// The value.
        value: String,
    },
    /// The principal field is the principal being checked.
    IsPrincipal {
        /// The field.
        field: FieldName,
    },
    /// The principal is in the group.
    InGroup {
        /// The group.
        group: GroupKey,
    },
    /// All are true.
    And(Vec<Template>),
    /// Any is true.
    Or(Vec<Template>),
    /// The template is false.
    Not(Box<Template>),
}

/// A condition at the org root.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Condition {
    /// The role it narrows.
    pub role: RoleKey,
    /// The type it narrows.
    pub resource_type: ResourceType,
    /// The template.
    pub when: Template,
    /// The level when the template is false. Not above the role's level.
    pub otherwise: Level,
}

/// An HTTP method of a route.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

/// An API route behind a UI key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub struct Route {
    /// The method.
    pub method: Method,
    /// The path, starting with `/`, maybe with `{name}` placeholders.
    pub path: String,
}

/// What the UI shows when access is denied.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum WhenDenied {
    /// Show it as normal.
    Show,
    /// Show it greyed out, with the reason.
    Disable,
    /// Show nothing.
    Hide,
    /// Show the value, not editable.
    Readonly,
}

/// A UI key: the actions, fields and routes behind one UI component.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct UiComponent {
    /// The actions it needs.
    pub actions: BTreeSet<ActionKey>,
    /// The fields and features it shows.
    pub fields: BTreeSet<FieldKey>,
    /// The API routes behind it.
    pub routes: Vec<Route>,
    /// The mode when denied.
    pub when_denied: WhenDenied,
    /// The text shown when denied.
    pub reason: Option<String>,
}

/// The org-root field rules of one field.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct RootCaps {
    /// The all-roles rule.
    all: Option<Level>,
    /// The rules for one role.
    roles: BTreeMap<RoleKey, Level>,
}

/// A compiled model. Only [`Model::from_toml`] makes one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Model {
    app: AppName,
    audience: Option<Audience>,
    types: BTreeMap<ResourceType, TypeDef>,
    roles: BTreeMap<RoleKey, Role>,
    field_rules: Vec<FieldRule>,
    /// The org-root field rules by field: the all-roles cap and the caps
    /// for single roles. Looked up without cloning keys (the evaluator calls
    /// [`Model::root_cap`] for every field of every check).
    rule_caps: BTreeMap<FieldKey, RootCaps>,
    conditions: Vec<Condition>,
    ui: BTreeMap<UiKey, UiComponent>,
}

impl Model {
    /// Compiles a `tutela.resources.toml`.
    ///
    /// The call blocks while the compiler runs on its own thread with a
    /// fixed 32 MiB stack (the `toml` crate parses recursively).
    ///
    /// # Errors
    ///
    /// Returns [`Issues`]: at most 100 problems, then one "and N more".
    pub fn from_toml(source: &str) -> Result<Self, Issues> {
        compile::compile(source)
    }

    /// The app name.
    #[must_use]
    pub const fn app(&self) -> &AppName {
        &self.app
    }

    /// The audience, if the manifest names one.
    #[must_use]
    pub const fn audience(&self) -> Option<&Audience> {
        self.audience.as_ref()
    }

    /// The declared types (not `org`).
    #[must_use]
    pub const fn types(&self) -> &BTreeMap<ResourceType, TypeDef> {
        &self.types
    }

    /// The roles, seeded ones included.
    #[must_use]
    pub const fn roles(&self) -> &BTreeMap<RoleKey, Role> {
        &self.roles
    }

    /// The field rules at the org root, implicit ones included, sorted by
    /// field and role.
    #[must_use]
    pub fn field_rules(&self) -> &[FieldRule] {
        &self.field_rules
    }

    /// The conditions at the org root.
    #[must_use]
    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// The UI keys.
    #[must_use]
    pub const fn ui(&self) -> &BTreeMap<UiKey, UiComponent> {
        &self.ui
    }

    /// The cap the org-root field rules put on one role's field: the rule for
    /// the role if there is one, else the all-roles rule, else Full.
    #[must_use]
    pub fn root_cap(&self, role: &RoleKey, field: &FieldKey) -> Level {
        self.rule_caps
            .get(field)
            .and_then(|c| c.roles.get(role).copied().or(c.all))
            .unwrap_or(Level::Full)
    }

    /// One role's own level on one field or feature, when its level on the
    /// item is `item` (after conditions). Field rules are not applied here;
    /// they cap the result. The diff and the evaluator share this function.
    /// A field or feature the type does not declare is `none` (masked).
    ///
    /// - A data field: the role's level for the field (or the item level if
    ///   the role sets none), never above `item`.
    /// - A feature: `none` when `item` is `none`; else the role's level for
    ///   the feature, or `item` if the role sets none. A feature may be above
    ///   the item level (a Viewer may ask the AI).
    #[must_use]
    pub fn effective_field_level(&self, role: &RoleKey, field: &FieldKey, item: Level) -> Level {
        let Some(r) = self.roles.get(role) else {
            return Level::None;
        };
        let declared = self.types.get(field.resource_type()).is_some_and(|d| {
            if field.is_feature() {
                d.features.contains(field.field())
            } else {
                d.fields.contains_key(field.field())
            }
        });
        // An undeclared field or feature is masked.
        if !declared {
            return Level::None;
        }
        let own = r.field_levels.get(field).copied();
        if field.is_feature() {
            if item == Level::None {
                Level::None
            } else {
                own.unwrap_or(item)
            }
        } else {
            own.unwrap_or(item).min(item)
        }
    }

    /// One role's level on one field or feature at the org root, with the
    /// role's full level on the item: min(effective level, org-root rules).
    #[must_use]
    pub fn root_field_level(&self, role: &RoleKey, field: &FieldKey) -> Level {
        self.roles.get(role).map_or(Level::None, |r| {
            let item = r.level(field.resource_type());
            self.effective_field_level(role, field, item)
                .min(self.root_cap(role, field))
        })
    }

    /// `true` if the role may use a custom action with its full level on
    /// the item.
    #[must_use]
    pub fn allows_custom(&self, role: &RoleKey, key: &ActionKey) -> bool {
        let item = self
            .roles
            .get(role)
            .map_or(Level::None, |r| r.level(key.resource_type()));
        self.allows_custom_at(role, key, item)
    }

    /// `true` if the role may use a custom action when its level on the
    /// item is `item` (after conditions). The diff and the evaluator share
    /// this function.
    ///
    /// - A level action: `item` meets `needs`, and the role holds the grant
    ///   when the action asks for one.
    /// - An owner-only custom action (`needs = "owner"`): `item` is Full and
    ///   the role holds the grant.
    ///
    /// Admin keys are not custom actions: they need the key only (see
    /// [`Role::holds`]).
    #[must_use]
    pub fn allows_custom_at(&self, role: &RoleKey, key: &ActionKey, item: Level) -> bool {
        let (Some(r), Some(def)) = (
            self.roles.get(role),
            self.types
                .get(key.resource_type())
                .and_then(|t| t.actions.get(key.action())),
        ) else {
            return false;
        };
        match def.needs {
            ActionRequirement::OwnerOnly => item == Level::Full && r.holds(key),
            ActionRequirement::Level(l) => item.satisfies(l) && (!def.grant || r.holds(key)),
        }
    }
}
