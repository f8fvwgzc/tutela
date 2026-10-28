//! Compare two models and classify each change (docs/MANIFEST.md section 10).
//!
//! The diff compares **effective** permissions per role and type, not text.
//! A type or role that the old model does not have is compared against a
//! baseline where it gives nobody anything, so a removed and re-added type,
//! a rename or a rollback cannot widen access without approval. Field and
//! feature levels are compared at every item level a condition could leave
//! ([`Model::effective_field_level`], shared with the evaluator). Anything
//! that lets someone gain access is widening. When a change is hard to judge
//! (a changed condition), it counts as widening, to be safe.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use tutela_contracts::keys::{ActionKey, ActionRequirement, FieldKey, ResourceType};
use tutela_contracts::level::Level;

use super::{
    AiReach, FieldRule, Model, RoleKey, Starts, Template, TypeDef, UiComponent, is_admin_key,
};

/// The class of one change, or of a whole diff.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Class {
    /// Nobody gains or loses access.
    #[default]
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

/// The most diff lines kept. The class always counts every change.
pub const MAX_DIFF_LINES: usize = 10_000;

/// Every change between two models, widening ones first.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ModelDiff {
    changes: Vec<Change>,
    omitted: usize,
    class: Class,
}

impl ModelDiff {
    /// The changes, at most [`MAX_DIFF_LINES`], widening ones first. Empty
    /// when the models are the same.
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// How many changes were left out beyond [`MAX_DIFF_LINES`].
    #[must_use]
    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    /// The class of the whole diff, over every change (also omitted ones):
    /// widening if any change is, else narrowing if any is, else neutral.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// `true` if any change lets someone gain access.
    #[must_use]
    pub fn is_widening(&self) -> bool {
        self.class == Class::Widening
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

/// The changes, kept per class: at most [`MAX_DIFF_LINES`] lines of each
/// class are kept, the rest only counted. So the cap bounds memory, and the
/// class still counts every change. The comparison work itself grows with
/// roles × types × fields, which the count limits bound.
#[derive(Default)]
struct Out {
    kept: [Vec<Change>; 3],
    seen: [usize; 3],
}

impl Out {
    fn push(&mut self, class: Class, what: String) {
        self.push_with(class, || what);
    }

    #[cfg(debug_assertions)]
    fn is_empty(&self) -> bool {
        self.seen.iter().all(|n| *n == 0)
    }

    /// Counts the change, and formats its line only if it is kept.
    fn push_with(&mut self, class: Class, what: impl FnOnce() -> String) {
        let k = class as usize;
        self.seen[k] += 1;
        if self.kept[k].len() < MAX_DIFF_LINES {
            self.kept[k].push(Change {
                class,
                what: what(),
            });
        }
    }

    fn finish(self) -> ModelDiff {
        let Self { mut kept, seen } = self;
        let class = [Class::Widening, Class::Narrowing, Class::Neutral]
            .into_iter()
            .find(|c| seen[*c as usize] > 0)
            .unwrap_or(Class::Neutral);
        let total: usize = seen.iter().sum();
        let mut changes = Vec::new();
        for c in [Class::Widening, Class::Narrowing, Class::Neutral] {
            let mut v = std::mem::take(&mut kept[c as usize]);
            v.sort();
            v.dedup();
            let room = MAX_DIFF_LINES - changes.len();
            changes.extend(v.into_iter().take(room));
        }
        ModelDiff {
            omitted: total.saturating_sub(changes.len()),
            changes,
            class,
        }
    }

    /// Up is widening, down is narrowing, equal is no line. The label is
    /// made only when a line is kept.
    fn ordered<T: Ord + fmt::Display>(&mut self, old: T, new: T, what: impl FnOnce() -> String) {
        let class = match new.cmp(&old) {
            core::cmp::Ordering::Greater => Class::Widening,
            core::cmp::Ordering::Less => Class::Narrowing,
            core::cmp::Ordering::Equal => return,
        };
        self.push_with(class, || format!("{}: {old} -> {new}", what()));
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
    let mut out = Out::default();
    if old.audience != new.audience {
        out.push(Class::Neutral, "app audience changed".into());
    }
    types(&mut out, old, new);
    field_rules(&mut out, old, new);
    roles(&mut out, old, new);
    ui(&mut out, old, new);
    Ok(out.finish())
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

/// Lower is easier to use: read < write < full < owner-only.
const fn needs_rank(n: ActionRequirement) -> u8 {
    match n {
        ActionRequirement::Level(l) => match l {
            Level::None => 0,
            Level::Read => 1,
            Level::Write => 2,
            Level::Full => 3,
        },
        ActionRequirement::OwnerOnly => 4,
    }
}

const fn needs_str(n: ActionRequirement) -> &'static str {
    match n {
        ActionRequirement::Level(l) => l.as_str(),
        ActionRequirement::OwnerOnly => "owner",
    }
}

fn types(out: &mut Out, old: &Model, new: &Model) {
    for t in old.types.keys().filter(|t| !new.types.contains_key(*t)) {
        out.push(Class::Narrowing, format!("type `{t}` removed"));
    }
    for t in new.types.keys().filter(|t| !old.types.contains_key(*t)) {
        // The role lines classify it: a new type is compared against a
        // baseline where nobody has any access.
        out.push(Class::Neutral, format!("type `{t}` added"));
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
        match (o.ai_reach, n.ai_reach) {
            (AiReach::Project, AiReach::Team) => {
                out.push(
                    Class::Widening,
                    format!("type `{t}` ai_reach: project -> team"),
                );
            }
            (AiReach::Team, AiReach::Project) => {
                out.push(
                    Class::Narrowing,
                    format!("type `{t}` ai_reach: team -> project"),
                );
            }
            _ => {}
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
                let class = if nf.sensitivity < of.sensitivity {
                    Class::Widening
                } else {
                    Class::Narrowing
                };
                out.push(class, format!("field `{k}` sensitivity: {a} -> {b}"));
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
        // `needs` and `grant` directly: conditions and per-scope data decide
        // who sits at which level, so a lower bar is widening for someone.
        for (a, oc) in &o.actions {
            let Some(nc) = n.actions.get(a) else { continue };
            let k = ActionKey::new(t.clone(), a.clone());
            if oc.needs != nc.needs {
                let what = format!(
                    "action `{k}` needs: {} -> {}",
                    needs_str(oc.needs),
                    needs_str(nc.needs)
                );
                let class = if needs_rank(nc.needs) < needs_rank(oc.needs) {
                    Class::Widening
                } else {
                    Class::Narrowing
                };
                out.push(class, what);
            }
            match (oc.grant, nc.grant) {
                (true, false) => out.push(
                    Class::Widening,
                    format!("action `{k}` no longer needs a grant"),
                ),
                (false, true) => {
                    out.push(Class::Narrowing, format!("action `{k}` now needs a grant"));
                }
                _ => {}
            }
        }
    }
}

fn rule_name(field: &FieldKey, role: Option<&RoleKey>) -> String {
    match role {
        Some(r) => format!("field rule `{field}` for `{r}`"),
        None => format!("field rule `{field}` for all roles"),
    }
}

type Rules<'m> = BTreeMap<(&'m FieldKey, Option<&'m RoleKey>), &'m FieldRule>;

fn all_field_keys(m: &Model) -> BTreeSet<FieldKey> {
    m.types.iter().flat_map(|(t, d)| field_keys(t, d)).collect()
}

/// One line per org-root field rule that is added, removed or changed.
fn field_rules(out: &mut Out, old: &Model, new: &Model) {
    let (of, nf) = (all_field_keys(old), all_field_keys(new));
    let o: Rules<'_> = old
        .field_rules
        .iter()
        .map(|r| ((&r.field, r.role.as_ref()), r))
        .collect();
    let n: Rules<'_> = new
        .field_rules
        .iter()
        .map(|r| ((&r.field, r.role.as_ref()), r))
        .collect();
    for (&(field, role), r) in &o {
        // A removed field's rules go with the field.
        if n.contains_key(&(field, role)) || !nf.contains(field) {
            continue;
        }
        // Without a rule for the role, the all-roles rule caps it (or
        // nothing does). Without the all-roles rule, nothing caps the roles
        // that had no rule of their own.
        let after = match role {
            Some(_) => n.get(&(field, None)).map_or(Level::Full, |a| a.max),
            None => Level::Full,
        };
        let what = format!(
            "{} removed (max {} -> {})",
            rule_name(field, role),
            r.max,
            after
        );
        let class = match after.cmp(&r.max) {
            core::cmp::Ordering::Greater => Class::Widening,
            core::cmp::Ordering::Less => Class::Narrowing,
            core::cmp::Ordering::Equal => Class::Neutral,
        };
        out.push(class, what);
    }
    for (&(field, role), r) in &n {
        // A new field's rules are part of adding the field.
        if !of.contains(field) {
            continue;
        }
        let what = rule_name(field, role);
        match o.get(&(field, role)) {
            None => {
                // A rule for one role beats the all-roles rule at the same
                // scope, so it can loosen it.
                let all = n.get(&(field, None)).map(|a| a.max);
                let class = match (role, all) {
                    (Some(_), Some(cap)) if r.max > cap => Class::Widening,
                    _ => Class::Narrowing,
                };
                out.push(class, format!("{what} added (max {})", r.max));
            }
            Some(p) => {
                out.ordered(p.max, r.max, || format!("{what} max"));
                if p.display != r.display {
                    out.push(Class::Neutral, format!("{what} display changed"));
                }
            }
        }
    }
}

/// What one role holds on one type in one model. When `present` is false the
/// role or the type is missing there: the baseline, where nobody has anything.
struct Side<'m> {
    model: &'m Model,
    role: &'m RoleKey,
    present: bool,
}

impl Side<'_> {
    fn level(&self, t: &ResourceType) -> Level {
        if !self.present {
            return Level::None;
        }
        self.model
            .roles
            .get(self.role)
            .map_or(Level::None, |r| r.level(t))
    }

    fn has_field(&self, k: &FieldKey) -> bool {
        self.present
            && self.model.types.get(k.resource_type()).is_some_and(|d| {
                if k.is_feature() {
                    d.features.contains(k.field())
                } else {
                    d.fields.contains_key(k.field())
                }
            })
    }

    /// An unknown field is masked: `none`.
    fn effective(&self, k: &FieldKey, item: Level) -> Level {
        if self.has_field(k) {
            self.model.effective_field_level(self.role, k, item)
        } else {
            Level::None
        }
    }

    fn root(&self, k: &FieldKey) -> Level {
        if self.has_field(k) {
            self.model.root_field_level(self.role, k)
        } else {
            Level::None
        }
    }

    fn allows(&self, k: &ActionKey, item: Level) -> bool {
        self.present
            && self
                .model
                .types
                .get(k.resource_type())
                .is_some_and(|d| d.actions.contains_key(k.action()))
            && self.model.allows_custom_at(self.role, k, item)
    }

    fn grants(&self, t: &ResourceType) -> BTreeSet<ActionKey> {
        if !self.present {
            return BTreeSet::new();
        }
        self.model
            .roles
            .get(self.role)
            .map_or_else(BTreeSet::new, |r| {
                r.grants
                    .iter()
                    .filter(|g| g.resource_type() == t)
                    .cloned()
                    .collect()
            })
    }

    /// The role's conditions on the type, with their place in the manifest.
    fn conditions(&self, t: &ResourceType) -> BTreeMap<(&Template, Level), usize> {
        if !self.present {
            return BTreeMap::new();
        }
        self.model
            .conditions
            .iter()
            .enumerate()
            .filter(|(_, c)| &c.role == self.role && &c.resource_type == t)
            .map(|(i, c)| ((&c.when, c.otherwise), i))
            .collect()
    }
}

fn roles(out: &mut Out, old: &Model, new: &Model) {
    for r in old.roles.keys().filter(|r| !new.roles.contains_key(*r)) {
        out.push(Class::Narrowing, format!("role `{r}` removed"));
    }
    // Each type's keys, built once.
    let keys: BTreeMap<&ResourceType, (BTreeSet<FieldKey>, BTreeSet<ActionKey>)> = new
        .types
        .iter()
        .map(|(t, d)| (t, (field_keys(t, d), action_keys(t, d))))
        .collect();
    let none = (BTreeSet::new(), BTreeSet::new());
    // The type-level part of `unchanged`, once per type.
    let same_type: BTreeSet<&ResourceType> = core::iter::once(&ResourceType::ORG)
        .chain(new.types.keys())
        .filter(|t| {
            old.types.get(*t) == new.types.get(*t) && type_rules(old, t) == type_rules(new, t)
        })
        .collect();
    for (rk, n) in &new.roles {
        let at = format!("role `{rk}`");
        let o = old.roles.get(rk);
        match o {
            // The type lines classify it, against the baseline.
            None => out.push(Class::Neutral, format!("{at} added")),
            Some(o) => {
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
            }
        }
        for t in core::iter::once(&ResourceType::ORG).chain(new.types.keys()) {
            let present = o.is_some() && (*t == ResourceType::ORG || old.types.contains_key(t));
            let before = Side {
                model: old,
                role: rk,
                present,
            };
            let after = Side {
                model: new,
                role: rk,
                present: true,
            };
            let (fk, ak) = keys.get(t).unwrap_or(&none);
            // Nothing that this role's access on this type depends on has
            // changed: there is nothing to compare.
            if present && same_type.contains(t) && unchanged(old, new, rk, t) {
                // In test and debug builds, check that skipping is safe: the
                // full comparison must find nothing.
                #[cfg(debug_assertions)]
                {
                    let mut scratch = Out::default();
                    role_type(&mut scratch, &before, &after, t, &at, fk, ak);
                    debug_assert!(
                        scratch.is_empty(),
                        "skipped a changed role and type: {at} on {t}"
                    );
                }
                continue;
            }
            role_type(out, &before, &after, t, &at, fk, ak);
        }
    }
}

/// The org-root field rules of one type.
fn type_rules<'m>(
    m: &'m Model,
    t: &ResourceType,
) -> Vec<(
    &'m FieldKey,
    Option<&'m RoleKey>,
    Level,
    super::FieldDisplay,
)> {
    m.field_rules
        .iter()
        .filter(|r| r.field.resource_type() == t)
        .map(|r| (&r.field, r.role.as_ref(), r.max, r.display))
        .collect()
}

/// `true` if the role's levels, grants and conditions on the type are the
/// same in both models. The caller checks the type itself and its org-root
/// field rules, once per type.
fn unchanged(old: &Model, new: &Model, rk: &RoleKey, t: &ResourceType) -> bool {
    let (Some(o), Some(n)) = (old.roles.get(rk), new.roles.get(rk)) else {
        return false;
    };
    let on_type = |k: &FieldKey| k.resource_type() == t;
    let cond = |c: &&super::Condition| &c.role == rk && &c.resource_type == t;
    o.level(t) == n.level(t)
        && o.field_levels
            .iter()
            .filter(|(k, _)| on_type(k))
            .eq(n.field_levels.iter().filter(|(k, _)| on_type(k)))
        && o.grants
            .iter()
            .filter(|g| g.resource_type() == t)
            .eq(n.grants.iter().filter(|g| g.resource_type() == t))
        && old
            .conditions
            .iter()
            .filter(cond)
            .map(|c| (&c.when, c.otherwise))
            .eq(new
                .conditions
                .iter()
                .filter(cond)
                .map(|c| (&c.when, c.otherwise)))
}

/// One role on one type: the item level, every field and feature at every
/// item level a condition could leave, the org-root level, custom actions,
/// grants, admin keys and conditions.
fn role_type(
    out: &mut Out,
    before: &Side<'_>,
    after: &Side<'_>,
    t: &ResourceType,
    at: &str,
    fk: &BTreeSet<FieldKey>,
    ak: &BTreeSet<ActionKey>,
) {
    let (ol, nl) = (before.level(t), after.level(t));
    out.ordered(ol, nl, || format!("{at} on `{t}`"));
    {
        let top = ol.max(nl);
        for k in fk {
            // Conditions only lower the item level, so every level from
            // `none` up to the role's level can occur.
            let mut up = None;
            let mut down = None;
            for item in Level::ALL.into_iter().filter(|l| *l <= top) {
                let (a, b) = (before.effective(k, item), after.effective(k, item));
                if b > a && up.is_none() {
                    up = Some((item, a, b));
                }
                if b < a && down.is_none() {
                    down = Some((item, a, b));
                }
            }
            if let Some((item, a, b)) = up {
                out.push_with(Class::Widening, || {
                    format!("{at} on `{k}` (item level {item}): {a} -> {b}")
                });
            } else if let Some((item, a, b)) = down {
                out.push_with(Class::Narrowing, || {
                    format!("{at} on `{k}` (item level {item}): {a} -> {b}")
                });
            }
            out.ordered(before.root(k), after.root(k), || {
                format!("{at} on `{k}` at the org root")
            });
        }
        for k in ak {
            // As for fields: at every item level a condition could leave.
            let mut up = None;
            let mut down = None;
            for item in Level::ALL.into_iter().filter(|l| *l <= top) {
                let (a, b) = (before.allows(k, item), after.allows(k, item));
                if b && !a && up.is_none() {
                    up = Some(item);
                }
                if a && !b && down.is_none() {
                    down = Some(item);
                }
            }
            if let Some(item) = up {
                out.push_with(Class::Widening, || {
                    format!("{at} on `{k}` (item level {item}): now allowed")
                });
            } else if let Some(item) = down {
                out.push_with(Class::Narrowing, || {
                    format!("{at} on `{k}` (item level {item}): no longer allowed")
                });
            }
        }
    }
    let (og, ng) = (before.grants(t), after.grants(t));
    for k in ng.difference(&og) {
        let kind = if is_admin_key(k.action()) {
            "admin key"
        } else {
            "grant"
        };
        out.push_with(Class::Widening, || format!("{at}: {kind} `{k}` added"));
    }
    for k in og.difference(&ng) {
        let kind = if is_admin_key(k.action()) {
            "admin key"
        } else {
            "grant"
        };
        out.push_with(Class::Narrowing, || format!("{at}: {kind} `{k}` removed"));
    }
    let (oc, nc) = (before.conditions(t), after.conditions(t));
    for (c, i) in oc.iter().filter(|(c, _)| !nc.contains_key(*c)) {
        out.push_with(Class::Widening, || {
            format!(
                "{at} on `{t}`: old conditions[{}] was removed or changed (else {})",
                i, c.1
            )
        });
    }
    for (c, i) in nc.iter().filter(|(c, _)| !oc.contains_key(*c)) {
        out.push_with(Class::Narrowing, || {
            format!(
                "{at} on `{t}`: new conditions[{}] was added (else {})",
                i, c.1
            )
        });
    }
}

/// A UI key is a declared guard: removing it, or taking actions, fields or
/// routes away from it, leaves a route less guarded.
fn ui(out: &mut Out, old: &Model, new: &Model) {
    fn weaker(o: &UiComponent, n: &UiComponent) -> bool {
        !o.actions.is_subset(&n.actions)
            || !o.fields.is_subset(&n.fields)
            || o.routes.iter().any(|r| !n.routes.contains(r))
    }
    for k in old.ui.keys().filter(|k| !new.ui.contains_key(*k)) {
        out.push(
            Class::Widening,
            format!("UI key `{k}` removed: its routes lose a declared guard"),
        );
    }
    for (k, n) in &new.ui {
        match old.ui.get(k) {
            None => out.push(Class::Neutral, format!("UI key `{k}` added")),
            Some(o) if weaker(o, n) => out.push(
                Class::Widening,
                format!("UI key `{k}`: an action, field or route was taken away"),
            ),
            Some(o) if o != n => {
                let more = o.actions.len() < n.actions.len()
                    || o.fields.len() < n.fields.len()
                    || o.routes.len() < n.routes.len();
                if more {
                    out.push(Class::Narrowing, format!("UI key `{k}`: more is guarded"));
                }
                if o.when_denied != n.when_denied || o.reason != n.reason {
                    out.push(
                        Class::Neutral,
                        format!("UI key `{k}`: denied mode or reason changed"),
                    );
                }
            }
            Some(_) => {}
        }
    }
}
