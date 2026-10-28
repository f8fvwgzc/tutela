//! Compare two models and classify each change (docs/MANIFEST.md section 10).
//!
//! The diff compares **effective** permissions per role and type, not text:
//! item levels, field and feature levels at the org root, custom actions,
//! admin keys, conditions and who may receive a role. Anything that lets
//! someone gain access is widening. When a change is hard to judge (a changed
//! condition), it counts as widening, to be safe.

use core::fmt;
use std::collections::BTreeSet;

use tutela_contracts::keys::{ActionKey, FieldKey, ResourceType};
use tutela_contracts::level::Level;

use super::{AiReach, Model, RoleKey, Starts, Template, TypeDef, is_admin_key};

/// The class of one change, or of a whole diff.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    /// Nobody gains or loses access.
    Neutral,
    /// Someone loses access.
    Narrowing,
    /// Someone gains access. Needs approval.
    Widening,
}

impl Class {
    /// The upper-case word used in diffs: `NEUTRAL`, `NARROWING`, `WIDENING`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "NEUTRAL",
            Self::Narrowing => "NARROWING",
            Self::Widening => "WIDENING",
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One change between two models.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Change {
    /// What the change does to access.
    pub class: Class,
    /// What changed, in short English, with ids and keys only.
    pub what: String,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<10} {}", self.class.as_str(), self.what)
    }
}

/// Every change between two models, sorted.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ModelDiff {
    /// The changes. Empty when the models give the same access.
    pub changes: Vec<Change>,
}

impl ModelDiff {
    /// The class of the whole diff: widening if any change is, else
    /// narrowing if any change is, else neutral.
    #[must_use]
    pub fn class(&self) -> Class {
        self.changes
            .iter()
            .map(|c| c.class)
            .max()
            .unwrap_or(Class::Neutral)
    }

    /// `true` if any change lets someone gain access.
    #[must_use]
    pub fn is_widening(&self) -> bool {
        self.class() == Class::Widening
    }
}

/// Why two models cannot be compared.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiffError {
    /// The models belong to different apps. An app may change only its own
    /// model namespace.
    #[error("the models belong to different apps (`{old}` and `{new}`)")]
    AppMismatch {
        /// The old app.
        old: String,
        /// The new app.
        new: String,
    },
}

struct Out(Vec<Change>);

impl Out {
    fn push(&mut self, class: Class, what: String) {
        self.0.push(Change { class, what });
    }

    /// Up is widening, down is narrowing.
    fn ordered<T: Ord + fmt::Display>(&mut self, what: &str, old: T, new: T) {
        if new > old {
            self.push(Class::Widening, format!("{what}: {old} -> {new}"));
        } else if new < old {
            self.push(Class::Narrowing, format!("{what}: {old} -> {new}"));
        }
    }

    fn allowed(&mut self, what: &str, old: bool, new: bool) {
        match (old, new) {
            (false, true) => self.push(Class::Widening, format!("{what}: now allowed")),
            (true, false) => self.push(Class::Narrowing, format!("{what}: no longer allowed")),
            _ => {}
        }
    }
}

/// Compares two models of the same app.
///
/// # Errors
///
/// Returns [`DiffError::AppMismatch`] when the apps differ.
pub fn diff(old: &Model, new: &Model) -> Result<ModelDiff, DiffError> {
    if old.app != new.app {
        return Err(DiffError::AppMismatch {
            old: old.app.to_string(),
            new: new.app.to_string(),
        });
    }
    let mut out = Out(Vec::new());
    if old.audience != new.audience {
        out.push(Class::Neutral, "app audience changed".into());
    }
    types(&mut out, old, new);
    roles(&mut out, old, new);
    ui(&mut out, old, new);
    let mut changes = out.0;
    changes.sort();
    changes.dedup();
    Ok(ModelDiff { changes })
}

fn field_keys(t: &ResourceType, d: &TypeDef) -> BTreeSet<FieldKey> {
    d.fields
        .keys()
        .chain(d.features.iter())
        .map(|f| FieldKey::new(t.clone(), f.clone()))
        .collect()
}

fn action_keys(t: &ResourceType, d: &TypeDef) -> BTreeSet<ActionKey> {
    d.actions
        .keys()
        .map(|a| ActionKey::new(t.clone(), a.clone()))
        .collect()
}

fn types(out: &mut Out, old: &Model, new: &Model) {
    for t in old.types.keys().filter(|t| !new.types.contains_key(*t)) {
        out.push(Class::Narrowing, format!("type `{t}` removed"));
    }
    for t in new.types.keys().filter(|t| !old.types.contains_key(*t)) {
        out.push(
            Class::Neutral,
            format!("type `{t}` added (no data of it exists yet)"),
        );
    }
    for (t, o) in &old.types {
        let Some(n) = new.types.get(t) else { continue };
        match (o.starts, n.starts) {
            (Starts::Private, Starts::Open) => {
                out.push(
                    Class::Widening,
                    format!("type `{t}` starts: private -> open"),
                );
            }
            (Starts::Open, Starts::Private) => {
                out.push(
                    Class::Narrowing,
                    format!("type `{t}` starts: open -> private"),
                );
            }
            _ => {}
        }
        let reach = |r: AiReach| match r {
            AiReach::Project => "project",
            AiReach::Team => "team",
        };
        if o.ai_reach < n.ai_reach {
            out.push(
                Class::Widening,
                format!(
                    "type `{t}` ai_reach: {} -> {}",
                    reach(o.ai_reach),
                    reach(n.ai_reach)
                ),
            );
        } else if o.ai_reach > n.ai_reach {
            out.push(
                Class::Narrowing,
                format!(
                    "type `{t}` ai_reach: {} -> {}",
                    reach(o.ai_reach),
                    reach(n.ai_reach)
                ),
            );
        }
        if o.parents != n.parents || o.container != n.container || o.label != n.label {
            out.push(
                Class::Neutral,
                format!("type `{t}` parents, container flag or label changed"),
            );
        }
        let ok = field_keys(t, o);
        let nk = field_keys(t, n);
        for k in ok.difference(&nk) {
            out.push(Class::Narrowing, format!("field `{k}` removed"));
        }
        for k in nk.difference(&ok) {
            out.push(Class::Neutral, format!("field `{k}` added"));
        }
        for (f, of) in &o.fields {
            let Some(nf) = n.fields.get(f) else { continue };
            let k = FieldKey::new(t.clone(), f.clone());
            if of.sensitivity != nf.sensitivity {
                let (a, b) = (of.sensitivity.label(), nf.sensitivity.label());
                // Lower sensitivity: output labels get lower.
                if nf.sensitivity < of.sensitivity {
                    out.push(
                        Class::Widening,
                        format!("field `{k}` sensitivity: {a} -> {b}"),
                    );
                } else {
                    out.push(
                        Class::Narrowing,
                        format!("field `{k}` sensitivity: {a} -> {b}"),
                    );
                }
            }
            match (of.grants_access, nf.grants_access) {
                (true, false) => out.push(
                    Class::Widening,
                    format!("field `{k}` no longer needs manage_access to change"),
                ),
                (false, true) => out.push(
                    Class::Narrowing,
                    format!("field `{k}` now needs manage_access to change"),
                ),
                _ => {}
            }
            if of.field_type != nf.field_type || of.label != nf.label {
                out.push(Class::Neutral, format!("field `{k}` type or label changed"));
            }
        }
        let oa = action_keys(t, o);
        let na = action_keys(t, n);
        for k in oa.difference(&na) {
            out.push(Class::Narrowing, format!("action `{k}` removed"));
        }
        for k in na.difference(&oa) {
            out.push(Class::Neutral, format!("action `{k}` added"));
        }
    }
}

fn common_types(old: &Model, new: &Model) -> Vec<ResourceType> {
    core::iter::once(ResourceType::ORG)
        .chain(
            old.types
                .keys()
                .filter(|t| new.types.contains_key(*t))
                .cloned(),
        )
        .collect()
}

fn roles(out: &mut Out, old: &Model, new: &Model) {
    for r in old.roles.keys().filter(|r| !new.roles.contains_key(*r)) {
        out.push(Class::Narrowing, format!("role `{r}` removed"));
    }
    for r in new.roles.keys().filter(|r| !old.roles.contains_key(*r)) {
        out.push(
            Class::Neutral,
            format!("role `{r}` added (nobody holds it yet)"),
        );
    }
    let common = common_types(old, new);
    for (rk, o) in &old.roles {
        let Some(n) = new.roles.get(rk) else { continue };
        let at = format!("role `{rk}`");
        for k in n.assignable_to.difference(&o.assignable_to) {
            out.push(
                Class::Widening,
                format!("{at}: may now be assigned to `{}`", k.as_str()),
            );
        }
        for k in o.assignable_to.difference(&n.assignable_to) {
            out.push(
                Class::Narrowing,
                format!("{at}: may no longer be assigned to `{}`", k.as_str()),
            );
        }
        if o.label != n.label {
            out.push(Class::Neutral, format!("{at}: label changed"));
        }
        for t in &common {
            out.ordered(&format!("{at} on `{t}`"), o.level(t), n.level(t));
            role_type(out, old, new, rk, t, &at);
        }
    }
}

/// Fields, features, actions, admin keys and conditions of one role on one
/// type that both models have.
fn role_type(out: &mut Out, old: &Model, new: &Model, rk: &RoleKey, t: &ResourceType, at: &str) {
    let (od, nd) = (old.types.get(t), new.types.get(t));
    if let Some(nd) = nd {
        let ok = od.map(|d| field_keys(t, d)).unwrap_or_default();
        for k in field_keys(t, nd) {
            let before = if ok.contains(&k) {
                old.root_field_level(rk, &k)
            } else {
                // An unknown field is masked: it was `none` before.
                Level::None
            };
            out.ordered(
                &format!("{at} on `{k}`"),
                before,
                new.root_field_level(rk, &k),
            );
        }
        let oa = od.map(|d| action_keys(t, d)).unwrap_or_default();
        for k in action_keys(t, nd) {
            let before = oa.contains(&k) && old.allows_custom(rk, &k);
            out.allowed(&format!("{at} on `{k}`"), before, new.allows_custom(rk, &k));
        }
    }
    let admin = |m: &Model| -> BTreeSet<ActionKey> {
        m.roles.get(rk).map_or_else(BTreeSet::new, |r| {
            r.grants
                .iter()
                .filter(|g| g.resource_type() == t && is_admin_key(g.action()))
                .cloned()
                .collect()
        })
    };
    let (oa, na) = (admin(old), admin(new));
    for k in na.difference(&oa) {
        out.push(Class::Widening, format!("{at}: admin key `{k}` added"));
    }
    for k in oa.difference(&na) {
        out.push(Class::Narrowing, format!("{at}: admin key `{k}` removed"));
    }
    let conds = |m: &Model| -> BTreeSet<(Template, Level)> {
        m.conditions
            .iter()
            .filter(|c| &c.role == rk && &c.resource_type == t)
            .map(|c| (c.when.clone(), c.otherwise))
            .collect()
    };
    let (oc, nc) = (conds(old), conds(new));
    for c in oc.difference(&nc) {
        out.push(
            Class::Widening,
            format!(
                "{at} on `{t}`: a condition was removed or changed (else {})",
                c.1
            ),
        );
    }
    for c in nc.difference(&oc) {
        out.push(
            Class::Narrowing,
            format!("{at} on `{t}`: a condition was added (else {})", c.1),
        );
    }
}

fn ui(out: &mut Out, old: &Model, new: &Model) {
    for k in old.ui.keys().filter(|k| !new.ui.contains_key(*k)) {
        out.push(Class::Neutral, format!("UI key `{k}` removed"));
    }
    for (k, n) in &new.ui {
        match old.ui.get(k) {
            None => out.push(Class::Neutral, format!("UI key `{k}` added")),
            Some(o) if o != n => out.push(Class::Neutral, format!("UI key `{k}` changed")),
            Some(_) => {}
        }
    }
}
