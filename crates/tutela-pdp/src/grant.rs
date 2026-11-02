//! Nobody grants what they do not hold (PERMISSION-MODEL.md 7.1 step 6, 15;
//! ADR-0043).
//!
//! A change of a tenant's data (an assignment, a group membership, a group,
//! a private flag) is compared before and after, for every principal it can
//! reach, with the calculation of the impact report. Every gain is then held
//! up to what the person making the change holds at the same place, before
//! the change. A gain above it is an excess, and the change is refused.
//!
//! The comparison is the one of [`crate::impact`]: per type, every condition
//! counted as false for the lowest answer and true for the highest. So the
//! grantee is taken at the highest it can get and the granter at the lowest
//! it can hold. A granter whose own role has conditions may be refused a
//! grant it could make on some rows: the rule errs on the side of refusing.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use tutela_contracts::keys::{FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;

use crate::api::{PathEntry, PdpError, ScopePaths};
use crate::data::{Index, ScopeIndex};
use crate::eval::{Ctx, Walk, resolve_unseen, rule_nodes};
use crate::impact::{
    Access, Budget, Change, Delta, ImpactReport, Seat, Tally, compare, keys_of, types_below,
};
use crate::model::Model;
use crate::pdp::{Bundle, Pdp};

/// What one principal is given, and where: (scope, role, direct). A direct
/// assignment wins over a group's at its scope, so the two are told apart.
type Given = BTreeSet<(PathEntry, String, bool)>;

fn given(index: &Index, p: &Principal) -> Given {
    let mut out = Given::new();
    let direct = index.by_principal.get(p).into_iter().flatten();
    for &bi in direct {
        if let Some(b) = index.bindings.get(bi) {
            out.insert((b.scope.clone(), b.role.to_string(), true));
        }
    }
    for &gi in index.groups_of(p) {
        for &bi in index.by_group.get(gi).into_iter().flatten() {
            if let Some(b) = index.bindings.get(bi) {
                out.insert((b.scope.clone(), b.role.to_string(), false));
            }
        }
    }
    out
}

/// What a scope says to everyone: its private flag and its field rules.
type ScopeFacts = BTreeMap<PathEntry, (bool, BTreeSet<(FieldKey, Option<String>, Level)>)>;

fn facts(index: &Index) -> ScopeFacts {
    let mut out = ScopeFacts::new();
    for s in &index.private {
        out.entry(s.clone()).or_default().0 = true;
    }
    for r in &index.field_rules {
        out.entry(r.scope.clone()).or_default().1.insert((
            r.field.clone(),
            r.role.as_ref().map(ToString::to_string),
            r.max,
        ));
    }
    out
}

/// Every principal the data of `index` names.
fn named(index: &Index) -> impl Iterator<Item = &Principal> {
    index.by_principal.keys().chain(index.member_of.keys())
}

/// The types a resource at `place` can be or hold, with their keys. A place
/// whose type holds nothing by the model can still have rows below it
/// (ADR-0013 item 1), so every type counts there.
fn place_keys(model: &Model, place: &PathEntry) -> Vec<(ResourceType, Vec<Access>)> {
    let ty = &place.type_name;
    let def = model.types().get(ty);
    let every = place.is_org() || def.is_none_or(|d| !d.container);
    let mut types: BTreeSet<ResourceType> = if every {
        model.types().keys().cloned().collect()
    } else {
        types_below(model, ty)
    };
    types.insert(ty.clone());
    types
        .into_iter()
        .map(|t| {
            let keys = keys_of(model, &t);
            (t, keys)
        })
        .collect()
}

/// The path of a place after the change. `None` for a scope the change
/// removed: nothing can be gained there. A place of the data after the
/// change that cannot be placed fails closed.
fn path_of<P: ScopePaths + ?Sized>(
    tenant: &TenantKey,
    place: &PathEntry,
    after: &P,
    in_after: bool,
) -> Result<Option<Vec<PathEntry>>, PdpError> {
    if place.is_org() {
        return Ok(Some(Vec::new()));
    }
    match after.ancestors(tenant, place) {
        Ok(p) => Ok(Some(p)),
        Err(_) if !in_after => Ok(None),
        Err(e) => Err(crate::search::path_error(place, e)),
    }
}

/// What a change of one tenant's data gives beyond what `granter` holds
/// (PERMISSION-MODEL.md 7.1 step 6). `before` and `after` hold the same
/// tenant, with its data before and after the change; `after_paths` are the
/// scope paths after it.
///
/// Each line of the answer is a gain someone gets that the granter does not
/// hold at that place before the change: the change may go ahead only when
/// [`ImpactReport::no_impact`] is `true`. Losses are never lines. `limit`
/// bounds the work ([`crate::MAX_IMPACT_WORK`]); a check that reaches it ends
/// with `complete: false`, which is never "no excess".
///
/// # Errors
///
/// [`PdpError::NoBundle`] for a tenant that is not loaded in both.
pub fn grant_excess<P: ScopePaths + ?Sized>(
    before: &Pdp,
    after: &Pdp,
    tenant: &TenantKey,
    after_paths: &P,
    granter: &Principal,
    limit: usize,
) -> Result<ImpactReport, PdpError> {
    let b0 = before.bundle(tenant, None)?;
    let b1 = after.bundle(tenant, None)?;
    let mut budget = Budget::new(limit);
    let mut tally = Tally::default();
    let complete = excess(
        b0,
        b1,
        tenant,
        after_paths,
        granter,
        &mut budget,
        &mut tally,
    )?;
    Ok(ImpactReport {
        complete,
        lines: tally.lines(),
    })
}

/// The scopes where something changed for `p`, the scope facts that changed
/// for everyone included.
fn changed_for(
    b0: &Bundle,
    b1: &Bundle,
    p: &Principal,
    all: &BTreeSet<PathEntry>,
) -> BTreeSet<PathEntry> {
    let (g0, g1) = (given(&b0.index, p), given(&b1.index, p));
    let mut out = all.clone();
    out.extend(g0.symmetric_difference(&g1).map(|(s, _, _)| s.clone()));
    out
}

/// One place, before and after.
struct Side<'a, 'm, 'i> {
    ctx: (Ctx<'m>, Ctx<'m>),
    walks: (&'a Walk<'a, 'i>, &'a Walk<'a, 'i>),
    rules: (&'a [&'i ScopeIndex], &'a [&'i ScopeIndex]),
}

/// The gains of `p` at one place that `granter` does not hold there before
/// the change. `None` when the budget ran out.
fn beyond(
    side: &Side<'_, '_, '_>,
    here: &[(ResourceType, Vec<Access>)],
    p: &Principal,
    granter: &Principal,
    budget: &mut Budget,
) -> Option<Vec<Delta>> {
    let (ctx0, ctx1) = side.ctx;
    let (w0, w1) = side.walks;
    let (r0, r1) = side.rules;
    let mut found = Vec::new();
    for (t, keys) in here {
        let s0 = resolve_unseen(ctx0, w0, t, p);
        let s1 = resolve_unseen(ctx1, w1, t, p);
        let deltas = compare(
            &Seat::unseen(ctx0, r0, &s0),
            &Seat::unseen(ctx1, r1, &s1),
            keys,
            budget,
        )?;
        let gains: Vec<Delta> = deltas
            .into_iter()
            .filter(|d| d.change == Change::Gain)
            .collect();
        if gains.is_empty() {
            continue;
        }
        // What the granter holds here before the change, at the lowest its
        // conditions can leave it.
        let g = resolve_unseen(ctx0, w0, t, granter);
        let held = Seat::unseen(ctx0, r0, &g);
        if !budget.take(gains.len()) {
            return None;
        }
        found.extend(gains.into_iter().filter(|d| d.to > held.range(&d.access).0));
    }
    Some(found)
}

fn excess<'b, P: ScopePaths + ?Sized>(
    b0: &'b Bundle,
    b1: &'b Bundle,
    tenant: &TenantKey,
    after_paths: &P,
    granter: &Principal,
    budget: &mut Budget,
    tally: &mut Tally<'b>,
) -> Result<bool, PdpError> {
    let (f0, f1) = (facts(&b0.index), facts(&b1.index));
    let scopes: BTreeSet<&PathEntry> = f0.keys().chain(f1.keys()).collect();
    let everyone: BTreeSet<PathEntry> = scopes
        .into_iter()
        .filter(|s| f0.get(*s) != f1.get(*s))
        .cloned()
        .collect();
    let mut who: BTreeSet<&'b Principal> = named(&b0.index).chain(named(&b1.index)).collect();
    if everyone.is_empty() {
        who.retain(|p| given(&b0.index, p) != given(&b1.index, p));
    }
    // Every place where an answer can differ from its parent's, with its path.
    let mut places: BTreeMap<&PathEntry, Vec<PathEntry>> = BTreeMap::new();
    for place in b0.index.scopes.keys().chain(b1.index.scopes.keys()) {
        let in_after = b1.index.scopes.contains_key(place);
        if let Some(path) = path_of(tenant, place, after_paths, in_after)? {
            places.insert(place, path);
        }
    }
    let (ctx0, ctx1) = (b0.ctx(), b1.ctx());
    let mut types: HashMap<&PathEntry, Vec<(ResourceType, Vec<Access>)>> = HashMap::new();
    // One answer per place and per pair of deciding assignments: a group of
    // thousands costs one comparison at a place.
    type Key = (Vec<usize>, Vec<usize>, bool);
    let mut seen: HashMap<(&PathEntry, Key), Vec<Delta>> = HashMap::new();
    for p in who {
        let changed = changed_for(b0, b1, p, &everyone);
        for (place, path) in &places {
            let reached = changed.contains(*place) || path.iter().any(|a| changed.contains(a));
            if !reached {
                continue;
            }
            if !budget.take(1) {
                return Ok(false);
            }
            let (w0, w1) = (
                Walk::new(&b0.index, place, path),
                Walk::new(&b1.index, place, path),
            );
            let (r0, r1) = (rule_nodes(&w0), rule_nodes(&w1));
            let here = types
                .entry(*place)
                .or_insert_with(|| place_keys(&b1.model, place));
            let Some((t0, _)) = here.first() else {
                continue;
            };
            let (s0, s1) = (
                resolve_unseen(ctx0, &w0, t0, p),
                resolve_unseen(ctx1, &w1, t0, p),
            );
            let key: Key = (
                s0.roles.iter().map(|r| r.binding).collect(),
                s1.roles.iter().map(|r| r.binding).collect(),
                s0.is_agent(),
            );
            let found = match seen.entry((*place, key)) {
                Entry::Occupied(o) => o.into_mut(),
                Entry::Vacant(v) => {
                    let side = Side {
                        ctx: (ctx0, ctx1),
                        walks: (&w0, &w1),
                        rules: (&r0, &r1),
                    };
                    let Some(found) = beyond(&side, here, p, granter, budget) else {
                        return Ok(false);
                    };
                    v.insert(found)
                }
            };
            for d in found.iter() {
                tally.add(p, place, d);
            }
        }
    }
    Ok(true)
}
