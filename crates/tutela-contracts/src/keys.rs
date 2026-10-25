//! Permission keys and the names inside them (CONTRACTS.md section 2).
//!
//! - names: lowercase `snake_case`, 1 to 64 characters;
//! - field keys `<type>.<field>` and feature keys `<type>.@<feature>`;
//! - action keys `<type>:<action>`, with the four built-in actions;
//! - permission keys: an action key, a field key or a feature key;
//! - UI keys: 2 to 8 names joined by `.`, at most 128 characters. A UI key is
//!   not a permission key.
//!
//! The manifest `tutela.resources.toml` that declares types, fields, actions
//! and UI keys is Phase A.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use crate::level::Level;

/// The longest name in characters.
pub const NAME_MAX_LEN: usize = 64;

/// Why a name was rejected (CONTRACTS.md 2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty.
    #[error("a name must not be empty")]
    Empty,
    /// The name is longer than 64 characters.
    #[error("a name is at most 64 characters")]
    TooLong,
    /// The name does not start with `a-z`.
    #[error("a name must start with a lowercase letter a-z")]
    Start,
    /// The name has a character outside `a-z 0-9 _`.
    #[error("a name may only contain a-z, 0-9 and `_`")]
    Char,
    /// A `_` is doubled or at the end.
    #[error("a `_` in a name must sit between two letters or digits")]
    Underscore,
}

/// Checks the name grammar `[a-z][a-z0-9]*(_[a-z0-9]+)*`, 1 to 64 characters
/// (CONTRACTS.md 2.1).
///
/// # Errors
///
/// Returns a [`NameError`] when `s` is not a name.
pub fn check_name(s: &str) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err(NameError::Empty);
    };
    if bytes.len() > NAME_MAX_LEN {
        return Err(NameError::TooLong);
    }
    if !first.is_ascii_lowercase() {
        return Err(NameError::Start);
    }
    let mut after_underscore = false;
    for &b in bytes {
        match b {
            b'a'..=b'z' | b'0'..=b'9' => after_underscore = false,
            b'_' if after_underscore => return Err(NameError::Underscore),
            b'_' => after_underscore = true,
            _ => return Err(NameError::Char),
        }
    }
    if after_underscore {
        return Err(NameError::Underscore);
    }
    Ok(())
}

/// Why a key or a resource id was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// A name inside the key is invalid.
    #[error("invalid name: {0}")]
    Name(#[from] NameError),
    /// A field key is not `<type>.<field>` or `<type>.@<feature>`.
    #[error("a field key must be `<type>.<field>` or `<type>.@<feature>`")]
    FieldKeyShape,
    /// An action key is not `<type>:<action>`.
    #[error("an action key must be `<type>:<action>`")]
    ActionKeyShape,
    /// A UI key does not have 2 to 8 names.
    #[error("a UI key must have 2 to 8 names joined by `.`")]
    UiKeyParts,
    /// A UI key is longer than 128 characters.
    #[error("a UI key is at most 128 characters")]
    UiKeyTooLong,
    /// A resource id is not 1 to 256 visible ASCII characters.
    #[error("a resource id must be 1 to 256 visible ASCII characters")]
    ResourceId,
}

/// Defines a string newtype that holds one name.
macro_rules! name_type {
    ($(#[$meta:meta])* $name:ident, $expecting:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            /// Parses a name.
            ///
            /// # Errors
            ///
            /// Returns a [`NameError`] when `s` is not a name (CONTRACTS.md 2.1).
            pub fn parse(s: &str) -> Result<Self, NameError> {
                check_name(s)?;
                Ok(Self(Cow::Owned(s.to_owned())))
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

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        string_serde!($name, $expecting);
    };
}

name_type!(
    /// A resource type name, for example `invoice` (CONTRACTS.md 2.1).
    ///
    /// `org` and every name that starts with `tutela_` are reserved: they parse
    /// (they appear on the wire) but products cannot declare them.
    ResourceType,
    "a resource type name"
);

impl ResourceType {
    /// `org`: the root type of every resource tree. Its ids are org ids.
    pub const ORG: Self = Self(Cow::Borrowed("org"));

    /// `true` for `org` and for `tutela_*` names, which products and tenants
    /// cannot declare.
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        self.0 == "org" || self.0.starts_with("tutela_")
    }
}

name_type!(
    /// An action name, for example `approve` or the built-in `read`.
    ActionName,
    "an action name"
);

impl ActionName {
    /// The built-in action `read`.
    pub const READ: Self = Self(Cow::Borrowed("read"));
    /// The built-in action `write`.
    pub const WRITE: Self = Self(Cow::Borrowed("write"));
    /// The built-in action `delete`.
    pub const DELETE: Self = Self(Cow::Borrowed("delete"));
    /// The built-in action `manage_access`.
    pub const MANAGE_ACCESS: Self = Self(Cow::Borrowed("manage_access"));

    /// The built-in action with this name, if it is one. A custom action
    /// must not use a built-in name.
    #[must_use]
    pub fn builtin(&self) -> Option<BuiltinAction> {
        BuiltinAction::ALL
            .into_iter()
            .find(|a| a.as_str() == self.as_str())
    }
}

name_type!(
    /// A data label, for example `confidential` (CONTRACTS.md 2.1 and 6.3).
    ///
    /// The known labels are `public`, `internal`, `confidential` and `secret`,
    /// from low to high. Output carries the highest label of its inputs.
    Label,
    "a label name"
);

impl Label {
    /// `public`.
    pub const PUBLIC: Self = Self(Cow::Borrowed("public"));
    /// `internal`.
    pub const INTERNAL: Self = Self(Cow::Borrowed("internal"));
    /// `confidential`.
    pub const CONFIDENTIAL: Self = Self(Cow::Borrowed("confidential"));
    /// `secret`.
    pub const SECRET: Self = Self(Cow::Borrowed("secret"));

    /// The rank of a known label, from `public` = 0 to `secret` = 3, or
    /// `None` for a label this version does not know.
    #[must_use]
    pub fn rank(&self) -> Option<u8> {
        match self.as_str() {
            "public" => Some(0),
            "internal" => Some(1),
            "confidential" => Some(2),
            "secret" => Some(3),
            _ => None,
        }
    }
}

/// The four built-in actions. Every type has them; nobody declares them
/// (CONTRACTS.md 2.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum BuiltinAction {
    /// `read`: open and view the item. Needs Read.
    Read,
    /// `write`: change the item and create items inside it. Needs Write.
    Write,
    /// `delete`: delete or archive the item. Needs Full.
    Delete,
    /// `manage_access`: change roles, invite people and change fields marked
    /// `grants_access`. Owner-only admin, above the four levels. Never
    /// implied by Full. Never held by an agent.
    ManageAccess,
}

impl BuiltinAction {
    /// Every built-in action.
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Delete, Self::ManageAccess];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::ManageAccess => "manage_access",
        }
    }

    /// The action name.
    #[must_use]
    pub const fn name(self) -> ActionName {
        match self {
            Self::Read => ActionName::READ,
            Self::Write => ActionName::WRITE,
            Self::Delete => ActionName::DELETE,
            Self::ManageAccess => ActionName::MANAGE_ACCESS,
        }
    }

    /// What the action needs.
    #[must_use]
    pub const fn requirement(self) -> ActionRequirement {
        match self {
            Self::Read => ActionRequirement::Level(Level::Read),
            Self::Write => ActionRequirement::Level(Level::Write),
            Self::Delete => ActionRequirement::Level(Level::Full),
            Self::ManageAccess => ActionRequirement::OwnerOnly,
        }
    }
}

impl fmt::Display for BuiltinAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an action needs: a level, or owner-only admin (CONTRACTS.md 2.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ActionRequirement {
    /// At least this level on the item.
    Level(Level),
    /// An owner-only admin action. It sits above the four levels and is never
    /// granted by default.
    OwnerOnly,
}

/// A field name or a feature name of one type (CONTRACTS.md 2.2 and 6.1).
///
/// A field name is a bare name (`amount`). A feature name is `@` plus a name
/// (`@ai`). Field masks list these. They sort by bytes, so `@ai` comes before
/// `amount`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FieldName(String);

impl FieldName {
    /// Parses `name` (a field) or `@name` (a feature).
    ///
    /// # Errors
    ///
    /// Returns a [`NameError`] when the part after the optional `@` is not a
    /// name.
    pub fn parse(s: &str) -> Result<Self, NameError> {
        check_name(s.strip_prefix('@').unwrap_or(s))?;
        Ok(Self(s.to_owned()))
    }

    /// `true` for a feature name (`@name`).
    #[must_use]
    pub fn is_feature(&self) -> bool {
        self.0.starts_with('@')
    }

    /// The name without the `@`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.strip_prefix('@').unwrap_or(&self.0)
    }

    /// The text, with the `@` for a feature.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FieldName {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(FieldName, "a field name or a feature name (`@name`)");

/// A field key `<type>.<field>` (at most 129 characters) or a feature key
/// `<type>.@<feature>` (at most 130 characters) (CONTRACTS.md 2.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FieldKey {
    resource_type: ResourceType,
    field: FieldName,
}

impl FieldKey {
    /// Makes a field key or a feature key.
    #[must_use]
    pub const fn new(resource_type: ResourceType, field: FieldName) -> Self {
        Self {
            resource_type,
            field,
        }
    }

    /// Parses `<type>.<field>` or `<type>.@<feature>`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when `s` is not exactly one type name, one `.`
    /// and one field or feature name.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        let (t, f) = s.split_once('.').ok_or(KeyError::FieldKeyShape)?;
        Ok(Self {
            resource_type: ResourceType::parse(t)?,
            field: FieldName::parse(f)?,
        })
    }

    /// The type.
    #[must_use]
    pub const fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    /// The field or feature name.
    #[must_use]
    pub const fn field(&self) -> &FieldName {
        &self.field
    }

    /// `true` for a feature key (`<type>.@<feature>`).
    #[must_use]
    pub fn is_feature(&self) -> bool {
        self.field.is_feature()
    }
}

impl fmt::Display for FieldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.resource_type, self.field)
    }
}

impl FromStr for FieldKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(
    FieldKey,
    "a field key `<type>.<field>` or `<type>.@<feature>`"
);

/// An action key `<type>:<action>`, at most 129 characters (CONTRACTS.md 2.3).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ActionKey {
    resource_type: ResourceType,
    action: ActionName,
}

impl ActionKey {
    /// Makes an action key.
    #[must_use]
    pub const fn new(resource_type: ResourceType, action: ActionName) -> Self {
        Self {
            resource_type,
            action,
        }
    }

    /// The action key of a built-in action on a type, for example
    /// `invoice:read`.
    #[must_use]
    pub const fn builtin(resource_type: ResourceType, action: BuiltinAction) -> Self {
        Self::new(resource_type, action.name())
    }

    /// Parses `<type>:<action>`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when `s` is not exactly one type name, one `:`
    /// and one action name.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        let (t, a) = s.split_once(':').ok_or(KeyError::ActionKeyShape)?;
        Ok(Self {
            resource_type: ResourceType::parse(t)?,
            action: ActionName::parse(a)?,
        })
    }

    /// The type.
    #[must_use]
    pub const fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    /// The action name.
    #[must_use]
    pub const fn action(&self) -> &ActionName {
        &self.action
    }

    /// The built-in action, if the action is one.
    #[must_use]
    pub fn as_builtin(&self) -> Option<BuiltinAction> {
        self.action.builtin()
    }
}

impl fmt::Display for ActionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource_type, self.action)
    }
}

impl FromStr for ActionKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(ActionKey, "an action key `<type>:<action>`");

/// A permission key: an action key, a field key or a feature key
/// (CONTRACTS.md 2.4). It is the `action` of an audit.v1 record.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PermissionKey {
    /// `<type>:<action>`.
    Action(ActionKey),
    /// `<type>.<field>` or `<type>.@<feature>`.
    Field(FieldKey),
}

impl PermissionKey {
    /// Parses a permission key. A key with a `:` is an action key; any other
    /// key must be a field or feature key.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when `s` is neither.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        if s.contains(':') {
            ActionKey::parse(s).map(Self::Action)
        } else {
            FieldKey::parse(s).map(Self::Field)
        }
    }

    /// The type the key belongs to.
    #[must_use]
    pub const fn resource_type(&self) -> &ResourceType {
        match self {
            Self::Action(k) => k.resource_type(),
            Self::Field(k) => k.resource_type(),
        }
    }
}

impl fmt::Display for PermissionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action(k) => fmt::Display::fmt(k, f),
            Self::Field(k) => fmt::Display::fmt(k, f),
        }
    }
}

impl FromStr for PermissionKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(
    PermissionKey,
    "a permission key (action, field or feature key)"
);

impl From<ActionKey> for PermissionKey {
    fn from(k: ActionKey) -> Self {
        Self::Action(k)
    }
}

impl From<FieldKey> for PermissionKey {
    fn from(k: FieldKey) -> Self {
        Self::Field(k)
    }
}

/// A UI component key: 2 to 8 names joined by `.`, at most 128 characters,
/// for example `invoices.approve_button` (CONTRACTS.md 2.5).
///
/// A UI key is **not** a permission key. UI hiding is never security.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UiKey(String);

impl UiKey {
    /// The longest UI key in characters.
    pub const MAX_LEN: usize = 128;

    /// Parses a UI key.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when `s` is too long, has fewer than 2 or more
    /// than 8 parts, or has a part that is not a name.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        if s.len() > Self::MAX_LEN {
            return Err(KeyError::UiKeyTooLong);
        }
        let mut parts = 0usize;
        for part in s.split('.') {
            check_name(part)?;
            parts += 1;
        }
        if !(2..=8).contains(&parts) {
            return Err(KeyError::UiKeyParts);
        }
        Ok(Self(s.to_owned()))
    }

    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The names in the key.
    pub fn parts(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }
}

impl fmt::Display for UiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for UiKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(UiKey, "a UI key");

/// A product's own resource id: 1 to 256 visible ASCII characters
/// (`%x21-7E`). Numbers are sent as strings (CONTRACTS.md 6.5).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ResourceId(String);

impl ResourceId {
    /// The longest resource id in characters.
    pub const MAX_LEN: usize = 256;

    /// Parses a resource id.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::ResourceId`] when `s` is empty, too long or has a
    /// character that is not visible ASCII.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        if crate::text::is_visible_ascii_str(s, 1, Self::MAX_LEN) {
            Ok(Self(s.to_owned()))
        } else {
            Err(KeyError::ResourceId)
        }
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ResourceId {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(ResourceId, "a resource id string");

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn name_table_from_the_doc() {
        for ok in [
            "invoice",
            "purchase_order",
            "line2",
            "po_line_v2",
            "a",
            &"a".repeat(64),
        ] {
            assert_eq!(check_name(ok), Ok(()), "{ok:?}");
        }
        let cases: &[(&str, NameError)] = &[
            ("Invoice", NameError::Start),
            ("_invoice", NameError::Start),
            ("invoice_", NameError::Underscore),
            ("invoice__line", NameError::Underscore),
            ("2fa", NameError::Start),
            ("invoice-line", NameError::Char),
            ("invoice.line", NameError::Char),
            ("invoiCe", NameError::Char),
            ("", NameError::Empty),
            ("caf\u{e9}", NameError::Char),
        ];
        for (input, err) in cases {
            assert_eq!(check_name(input), Err(*err), "{input:?}");
        }
        assert_eq!(check_name(&"a".repeat(65)), Err(NameError::TooLong));
    }

    #[test]
    fn reserved_types() {
        assert!(ResourceType::ORG.is_reserved());
        assert!(ResourceType::parse("tutela_role").unwrap().is_reserved());
        assert!(!ResourceType::parse("invoice").unwrap().is_reserved());
        assert!(!ResourceType::parse("tutelarole").unwrap().is_reserved());
        assert_eq!(ResourceType::parse("org").unwrap(), ResourceType::ORG);
    }

    #[test]
    fn field_and_feature_keys() {
        let k = FieldKey::parse("invoice.amount").unwrap();
        assert_eq!(k.resource_type().as_str(), "invoice");
        assert_eq!(k.field().as_str(), "amount");
        assert!(!k.is_feature());
        assert_eq!(k.to_string(), "invoice.amount");
        let k = FieldKey::parse("task.@ai").unwrap();
        assert!(k.is_feature());
        assert_eq!(k.field().name(), "ai");
        assert_eq!(k.to_string(), "task.@ai");

        let max_field = format!("{}.{}", "a".repeat(64), "b".repeat(64));
        assert_eq!(max_field.len(), 129);
        assert!(FieldKey::parse(&max_field).is_ok());
        let max_feature = format!("{}.@{}", "a".repeat(64), "b".repeat(64));
        assert_eq!(max_feature.len(), 130);
        assert!(FieldKey::parse(&max_feature).is_ok());

        let cases: &[(&str, KeyError)] = &[
            ("invoice", KeyError::FieldKeyShape),
            ("invoice.amount.x", KeyError::Name(NameError::Char)),
            ("invoice..amount", KeyError::Name(NameError::Start)),
            (".amount", KeyError::Name(NameError::Empty)),
            ("invoice.", KeyError::Name(NameError::Empty)),
            ("invoice.@", KeyError::Name(NameError::Empty)),
            ("invoice.@@ai", KeyError::Name(NameError::Start)),
            ("invoice.a@i", KeyError::Name(NameError::Char)),
            ("@invoice.amount", KeyError::Name(NameError::Start)),
            ("Invoice.amount", KeyError::Name(NameError::Start)),
            ("invoice:amount", KeyError::FieldKeyShape),
        ];
        for (input, err) in cases {
            assert_eq!(FieldKey::parse(input), Err(*err), "{input:?}");
        }
    }

    #[test]
    fn action_keys_and_builtins() {
        let k = ActionKey::parse("invoice:approve").unwrap();
        assert_eq!(k.action().as_str(), "approve");
        assert_eq!(k.as_builtin(), None);
        assert_eq!(k.to_string(), "invoice:approve");
        for action in BuiltinAction::ALL {
            let key = ActionKey::builtin(ResourceType::parse("invoice").unwrap(), action);
            assert_eq!(key.to_string(), format!("invoice:{}", action.as_str()));
            assert_eq!(
                ActionKey::parse(&key.to_string()).unwrap().as_builtin(),
                Some(action)
            );
            assert_eq!(action.name().builtin(), Some(action));
            assert_eq!(action.to_string(), action.as_str());
        }
        assert_eq!(
            BuiltinAction::Read.requirement(),
            ActionRequirement::Level(Level::Read)
        );
        assert_eq!(
            BuiltinAction::Write.requirement(),
            ActionRequirement::Level(Level::Write)
        );
        assert_eq!(
            BuiltinAction::Delete.requirement(),
            ActionRequirement::Level(Level::Full)
        );
        assert_eq!(
            BuiltinAction::ManageAccess.requirement(),
            ActionRequirement::OwnerOnly
        );
        assert!(ActionKey::parse("tutela_role:write").is_ok());
        assert!(ActionKey::parse("project:read_audit").is_ok());

        let max = format!("{}:{}", "a".repeat(64), "b".repeat(64));
        assert_eq!(max.len(), 129);
        assert!(ActionKey::parse(&max).is_ok());

        let cases: &[(&str, KeyError)] = &[
            ("invoice", KeyError::ActionKeyShape),
            ("invoice:approve:x", KeyError::Name(NameError::Char)),
            ("invoice::approve", KeyError::Name(NameError::Start)),
            (":approve", KeyError::Name(NameError::Empty)),
            ("invoice:", KeyError::Name(NameError::Empty)),
            ("audit.read", KeyError::ActionKeyShape),
            ("invoice:Approve", KeyError::Name(NameError::Start)),
            ("invoice: approve", KeyError::Name(NameError::Start)),
        ];
        for (input, err) in cases {
            assert_eq!(ActionKey::parse(input), Err(*err), "{input:?}");
        }
    }

    #[test]
    fn permission_keys() {
        let a = PermissionKey::parse("invoice:approve").unwrap();
        assert!(matches!(a, PermissionKey::Action(_)));
        let f = PermissionKey::parse("invoice.amount").unwrap();
        assert!(matches!(f, PermissionKey::Field(_)));
        let g = PermissionKey::parse("task.@ai").unwrap();
        assert!(matches!(&g, PermissionKey::Field(k) if k.is_feature()));
        for k in [&a, &f, &g] {
            assert_eq!(
                k.resource_type().as_str() == "invoice",
                !k.to_string().starts_with("task")
            );
            let json = serde_json::to_string(k).unwrap();
            assert_eq!(&serde_json::from_str::<PermissionKey>(&json).unwrap(), k);
        }
        for bad in [
            "invoice",
            "invoice.amount:x",
            "invoice:a.b",
            "",
            "invoices.approve.button",
        ] {
            assert!(PermissionKey::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ui_keys() {
        let k = UiKey::parse("invoices.approve_button").unwrap();
        assert_eq!(
            k.parts().collect::<Vec<_>>(),
            ["invoices", "approve_button"]
        );
        assert!(UiKey::parse("a.b.c.d.e.f.g.h").is_ok());
        assert_eq!(UiKey::parse("a.b.c.d.e.f.g.h.i"), Err(KeyError::UiKeyParts));
        assert_eq!(UiKey::parse("invoices"), Err(KeyError::UiKeyParts));
        assert_eq!(
            UiKey::parse("invoices."),
            Err(KeyError::Name(NameError::Empty))
        );
        assert_eq!(
            UiKey::parse("invoices.@ai"),
            Err(KeyError::Name(NameError::Start))
        );
        assert_eq!(UiKey::parse(""), Err(KeyError::Name(NameError::Empty)));
        let at_limit = format!("{}.{}", "a".repeat(63), "b".repeat(64));
        assert_eq!(at_limit.len(), 128);
        assert!(UiKey::parse(&at_limit).is_ok());
        let over = format!("{}.{}", "a".repeat(64), "b".repeat(64));
        assert_eq!(UiKey::parse(&over), Err(KeyError::UiKeyTooLong));
        // A UI key and a field key can look alike; the place decides the kind.
        assert!(UiKey::parse("invoice.amount").is_ok());
        assert!(FieldKey::parse("invoice.amount").is_ok());
    }

    #[test]
    fn resource_ids() {
        assert!(ResourceId::parse("inv-881").is_ok());
        assert!(ResourceId::parse("12345").is_ok());
        assert!(ResourceId::parse(&"x".repeat(256)).is_ok());
        for bad in ["", "a b", "tab\t", &"x".repeat(257), "caf\u{e9}"] {
            assert_eq!(ResourceId::parse(bad), Err(KeyError::ResourceId), "{bad:?}");
        }
    }

    #[test]
    fn labels() {
        let labels = [
            Label::PUBLIC,
            Label::INTERNAL,
            Label::CONFIDENTIAL,
            Label::SECRET,
        ];
        for (i, l) in labels.iter().enumerate() {
            assert_eq!(l.rank(), u8::try_from(i).ok());
            assert_eq!(&Label::parse(l.as_str()).unwrap(), l);
        }
        assert_eq!(Label::parse("client_visible").unwrap().rank(), None);
        assert!(Label::parse("client-visible").is_err());
    }

    #[test]
    fn serde_rejects_non_strings() {
        assert!(serde_json::from_str::<ResourceType>("null").is_err());
        assert!(serde_json::from_str::<ResourceType>("1").is_err());
        assert!(serde_json::from_str::<FieldName>("[\"a\"]").is_err());
        assert!(serde_json::from_str::<FieldName>("\"Amount\"").is_err());
    }

    const NAME: &str = "[a-z][a-z0-9]{0,8}(_[a-z0-9]{1,6}){0,3}";

    proptest! {
        #[test]
        fn names_round_trip(s in NAME) {
            prop_assert_eq!(check_name(&s), Ok(()));
            let t = ResourceType::parse(&s).unwrap();
            prop_assert_eq!(t.to_string(), s);
        }

        #[test]
        fn any_uppercase_or_symbol_is_rejected(s in NAME, at in any::<prop::sample::Index>(), bad in "[A-Z .:@/-]") {
            let i = at.index(s.len() + 1);
            let mut broken = s.clone();
            broken.insert_str(i, &bad);
            prop_assert!(check_name(&broken).is_err());
        }

        #[test]
        fn keys_round_trip(t in NAME, f in NAME, feature in any::<bool>()) {
            let field = if feature { format!("@{f}") } else { f.clone() };
            let fk = format!("{t}.{field}");
            prop_assert_eq!(FieldKey::parse(&fk).unwrap().to_string(), fk.clone());
            prop_assert_eq!(PermissionKey::parse(&fk).unwrap().to_string(), fk);
            let ak = format!("{t}:{f}");
            prop_assert_eq!(ActionKey::parse(&ak).unwrap().to_string(), ak.clone());
            let pk = PermissionKey::parse(&ak).unwrap();
            prop_assert_eq!(pk.to_string(), ak);
        }

        #[test]
        fn ui_keys_round_trip(parts in prop::collection::vec("[a-z][a-z0-9_]{0,6}[a-z0-9]", 2..=8)) {
            let parts: Vec<String> = parts.into_iter().filter(|p| check_name(p).is_ok()).collect();
            prop_assume!(parts.len() >= 2);
            let s = parts.join(".");
            prop_assert_eq!(UiKey::parse(&s).unwrap().to_string(), s);
        }

        #[test]
        fn parsers_never_panic(s in "\\PC{0,80}") {
            let _ = check_name(&s);
            let _ = FieldKey::parse(&s);
            let _ = ActionKey::parse(&s);
            let _ = PermissionKey::parse(&s);
            let _ = UiKey::parse(&s);
            let _ = ResourceId::parse(&s);
        }
    }
}
