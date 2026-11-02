//! Moves and links across scopes (PERMISSION-MODEL.md 9, 10; ADR-0025).
//!
//! A move is a `write` that changes an item's parent. It crosses the scopes
//! it leaves and the scopes it enters; the scopes the two paths share are not
//! crossed. It needs the rules of every crossed scope, and then the access
//! of every principal is compared before and after. A move that would give
//! anyone more waits for the owner of the source, or is blocked. A comparison
//! that hit a bound counts as looser.
//!
//! A link changes nobody's access: Tutela does not read links when it
//! decides. The rules only say who may make one.

use std::collections::{BTreeSet, HashMap};

use tutela_contracts::decision::{Effect, Reason, ReasonCode, RuleId};
use tutela_contracts::keys::{ActionKey, BuiltinAction, FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;

use crate::api::{
    LinkVerdict, MoveDecision, MoveOutcome, PathEntry, PdpError, ResourceRef, WriteCheckRequest,
};
use crate::data::{BoundaryRule, LinksFrom, MoveRule, OnLooser, ScopeIndex};
use crate::eval::{
    Side, Walk, action_kind, closest_cap, reason, resolve, resolve_unseen, rule_nodes, side_allows,
};
use crate::impact::{
    Access, Budget, Change, Delta, ImpactLine, Seat, Tally, compare, keys_of, types_below,
};
use crate::model::RoleKey;
use crate::pdp::{Bundle, Who, decision_reason, in_tenant, rule_ids, this_entry};

/// The most principals a move compares.
pub const MAX_MOVE_CANDIDATES: usize = 10_000;

/// The most comparisons one move makes, each of one key for one principal.
pub const MAX_MOVE_WORK: usize = 1_000_000;

/// The most lines in a move's `gains`.
pub const MAX_MOVE_LINES: usize = 100;

fn boundary(b: &Bundle, s: &PathEntry) -> BoundaryRule {
    b.index
        .scopes
        .get(s)
        .map(|i| i.boundary)
        .unwrap_or_default()
}

fn boundary_id(s: &PathEntry) -> Option<RuleId> {
    RuleId::parse(&format!("boundary:{s}")).ok()
}

/// How the two paths differ: the scopes left and entered, nearest first.
fn crossed<'p>(old: &'p [PathEntry], new: &'p [PathEntry]) -> (&'p [PathEntry], &'p [PathEntry]) {
    let shared = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    (
        old.get(..old.len() - shared).unwrap_or_default(),
        new.get(..new.len() - shared).unwrap_or_default(),
    )
}

/// May every side do `action` on a scope? The scope's field values are not
/// known, so its conditions count as false.
fn scope_allows(
    b: &Bundle,
    who: &Who<'_>,
    scope: &PathEntry,
    above: &[PathEntry],
    action: &ActionKey,
) -> Result<bool, PdpError> {
    let ctx = b.ctx();
    let kind = action_kind(&b.model, action)?;
    let walk = Walk::new(&b.index, scope, above);
    Ok(who.all().all(|p| {
        let side = resolve_unseen(ctx, &walk, &scope.type_name, p);
        side_allows(ctx, &side, action, kind, who.delegated())
    }))
}

/// May this one person approve for `scope`? Admin keys never pass through
/// delegation and never go to agents.
fn may_approve(
    b: &Bundle,
    p: &Principal,
    scope: &PathEntry,
    above: &[PathEntry],
    key: &ActionKey,
) -> Result<bool, PdpError> {
    let ctx = b.ctx();
    let kind = action_kind(&b.model, key)?;
    let walk = Walk::new(&b.index, scope, above);
    let side = resolve_unseen(ctx, &walk, &scope.type_name, p);
    Ok(side_allows(ctx, &side, key, kind, false))
}

fn admin_key(scope: &PathEntry, name: &str) -> Result<ActionKey, PdpError> {
    ActionKey::parse(&format!("{}:{name}", scope.type_name))
        .map_err(|_| PdpError::invalid("a scope type does not make an action key"))
}

/// The path above entry `i` of `path`.
fn above(path: &[PathEntry], i: usize) -> &[PathEntry] {
    path.get(i + 1..).unwrap_or_default()
}

/// What stopped a move at a boundary rule, if anything.
fn rule_stops(
    b: &Bundle,
    who: &Who<'_>,
    path: &[PathEntry],
    crossed: &[PathEntry],
    far: bool,
    rule_of: fn(&BoundaryRule) -> Option<MoveRule>,
) -> Result<Option<(Reason, PathEntry)>, PdpError> {
    for (i, s) in crossed.iter().enumerate() {
        // The nearest scope has the default. A scope further out adds a rule
        // only when it set one, so a team's silence does not stop its
        // projects' owners.
        let rule = rule_of(&boundary(b, s)).or((i == 0).then_some(MoveRule::Members));
        let rule = match rule {
            Some(MoveRule::Members) if far && i == 0 => Some(MoveRule::Owners),
            r => r,
        };
        let stop = |detail: String| Some((reason(ReasonCode::BoundaryRule, &detail), s.clone()));
        match rule {
            None => {}
            Some(MoveRule::Nobody) => return Ok(stop(format!("{s} lets nothing cross"))),
            Some(MoveRule::Members) => {
                let write = ActionKey::builtin(s.type_name.clone(), BuiltinAction::Write);
                if !scope_allows(b, who, s, above(path, i), &write)? {
                    return Ok(stop(format!("a move across {s} needs write on it")));
                }
            }
            Some(MoveRule::Owners) => {
                let key = admin_key(s, "approve_move")?;
                if !scope_allows(b, who, s, above(path, i), &key)? {
                    return Ok(stop(format!("a move across {s} needs {key}")));
                }
            }
        }
    }
    Ok(None)
}

/// Every principal who could hold access through `nodes`: the assignments
/// there, and the members of the groups there. With no assignment on the
/// path the answer is a default deny, so nobody else can gain. `None` above
/// [`MAX_MOVE_CANDIDATES`].
fn candidates<'b>(
    b: &'b Bundle,
    nodes: impl Iterator<Item = &'b PathEntry>,
) -> Option<BTreeSet<&'b Principal>> {
    let mut out: BTreeSet<&Principal> = BTreeSet::new();
    let mut groups: BTreeSet<usize> = BTreeSet::new();
    for n in nodes {
        if let Some(s) = b.index.scopes.get(n) {
            out.extend(s.direct.keys());
            groups.extend(s.groups.keys().copied());
        }
    }
    if !groups.is_empty() {
        out.extend(
            b.index
                .member_of
                .iter()
                .filter(|(_, of)| !of.is_disjoint(&groups))
                .map(|(p, _)| p),
        );
    }
    (out.len() <= MAX_MOVE_CANDIDATES).then_some(out)
}

/// What the move gives anyone. `None` when the comparison hit a bound.
fn gains<'b>(
    b: &'b Bundle,
    this: &'b PathEntry,
    req: &'b WriteCheckRequest,
    new_path: &'b [PathEntry],
) -> Option<Vec<ImpactLine>> {
    let ctx = b.ctx();
    let res = &req.resource;
    let ty = &res.type_name;
    let who = candidates(b, core::iter::once(this).chain(&res.path).chain(new_path))?;
    // The conditions read the values after the write.
    let mut after_attrs = res.attrs.clone();
    after_attrs.extend(req.new_attrs.iter().map(|(k, v)| (k.clone(), v.clone())));
    let own = keys_of(&b.model, ty);
    let below: Vec<(ResourceType, Vec<Access>)> = types_below(&b.model, ty)
        .into_iter()
        .map(|t| {
            let keys = keys_of(&b.model, &t);
            (t, keys)
        })
        .collect();
    let old_walk = Walk::new(&b.index, this, &res.path);
    let new_walk = Walk::new(&b.index, this, new_path);
    let old_rules = rule_nodes(&old_walk);
    let new_rules = rule_nodes(&new_walk);

    let mut budget = Budget::new(MAX_MOVE_WORK);
    let mut tally = Tally::default();
    // Below the item nothing depends on the principal, once its deciding
    // assignments are known, so a group of thousands costs one comparison.
    let mut seen: HashMap<(Vec<usize>, Vec<usize>, bool), Vec<Delta>> = HashMap::new();
    let binds = |s: &Side<'_, '_>| s.roles.iter().map(|r| r.binding).collect::<Vec<usize>>();
    for p in who {
        let before = resolve(ctx, &old_walk, ty, &res.attrs, p);
        let after = resolve(ctx, &new_walk, ty, &after_attrs, p);
        let deltas = compare(
            &Seat::seen(ctx, &old_rules, &before),
            &Seat::seen(ctx, &new_rules, &after),
            &own,
            &mut budget,
        )?;
        let key = (binds(&before), binds(&after), before.is_agent());
        for d in deltas.iter().filter(|d| d.change == Change::Gain) {
            tally.add(p, this, d);
        }
        if !seen.contains_key(&key) {
            let mut all = Vec::new();
            for (t, keys) in &below {
                let s0 = resolve_unseen(ctx, &old_walk, t, p);
                let s1 = resolve_unseen(ctx, &new_walk, t, p);
                all.extend(compare(
                    &Seat::unseen(ctx, &old_rules, &s0),
                    &Seat::unseen(ctx, &new_rules, &s1),
                    keys,
                    &mut budget,
                )?);
            }
            seen.insert(key.clone(), all);
        }
        for d in seen.get(&key).into_iter().flatten() {
            if d.change == Change::Gain {
                tally.add(p, this, d);
            }
        }
    }
    let mut lines = tally.lines();
    lines.extend(raised_caps(
        b,
        this,
        &below,
        &old_rules,
        &new_rules,
        &mut budget,
    )?);
    Some(lines)
}

/// The field rules the move leaves behind or finds, per role. A principal
/// assigned below the moved item is not on either path, and this call does
/// not know the tree below it. But the rules above that assignment still cap
/// its fields (PERMISSION-MODEL.md 7.1 step 5), so a cap that goes up can give
/// it more. Such a line names the role, not who holds it.
fn raised_caps(
    b: &Bundle,
    this: &PathEntry,
    below: &[(ResourceType, Vec<Access>)],
    old_rules: &[&ScopeIndex],
    new_rules: &[&ScopeIndex],
    budget: &mut Budget,
) -> Option<Vec<ImpactLine>> {
    let ctx = b.ctx();
    let fields: BTreeSet<&FieldKey> = old_rules
        .iter()
        .chain(new_rules)
        .flat_map(|n| n.rules.keys())
        .filter(|f| below.iter().any(|(t, _)| t == f.resource_type()))
        .collect();
    let roles: BTreeSet<&RoleKey> = b.index.bindings.iter().map(|b| &b.role).collect();
    let mut out = Vec::new();
    for f in fields {
        for role in &roles {
            if !budget.take(1) {
                return None;
            }
            let item = b
                .model
                .roles()
                .get(*role)
                .map_or(Level::None, |r| r.level(f.resource_type()));
            let own = b.model.effective_field_level(role, f, item);
            let from = own.min(closest_cap(ctx, old_rules, role, f).0);
            let to = own.min(closest_cap(ctx, new_rules, role, f).0);
            if to > from {
                out.push(ImpactLine {
                    change: Change::Gain,
                    kind: "role".to_owned(),
                    key: f.to_string(),
                    from: from.as_str().to_owned(),
                    to: to.as_str().to_owned(),
                    conditional: true,
                    principals: vec![role.to_string()],
                    scopes: vec![this.clone()],
                });
            }
        }
    }
    Some(out)
}

/// The verdict on a move. The caller has checked the principals and that the
/// resource is in this tenant.
pub(crate) fn check_move(
    b: &Bundle,
    who: &Who<'_>,
    req: &WriteCheckRequest,
    new_path: &[PathEntry],
) -> Result<MoveDecision, PdpError> {
    let res = &req.resource;
    let ty = &res.type_name;
    let this = this_entry(res)?;
    if this.is_org() {
        return Err(PdpError::invalid("an org has no parent"));
    }
    let moved = ResourceRef {
        path: new_path.to_vec(),
        ..res.clone()
    };
    this_entry(&moved)?;
    let parent = new_path
        .first()
        .ok_or_else(|| PdpError::invalid("the path must end at the org"))?;
    let def = b
        .model
        .types()
        .get(ty)
        .ok_or_else(|| PdpError::UnknownType(ty.clone()))?;
    if !def.parents.contains(&parent.type_name) {
        return Err(PdpError::invalid(
            "the new parent's type may not hold this type",
        ));
    }

    let (left, entered) = crossed(&res.path, new_path);
    let ctx = b.ctx();
    let refuse = |why: Reason, ids: Vec<RuleId>| MoveDecision {
        effect: Effect::Deny,
        outcome: MoveOutcome::Refused,
        reason: why,
        rule_ids: ids,
        left: left.to_vec(),
        entered: entered.to_vec(),
        looser: false,
        complete: true,
        approve_at: Vec::new(),
        gains: Vec::new(),
    };
    if !in_tenant(&b.index, &moved) {
        let r = reason(
            ReasonCode::TenantMismatch,
            "the new path is not in this tenant",
        );
        return Ok(refuse(r, Vec::new()));
    }
    if res.path.last() != new_path.last() {
        let r = reason(ReasonCode::BoundaryRule, "a move stays inside its org");
        return Ok(refuse(r, Vec::new()));
    }

    // A move is a write on the item.
    let walk = Walk::new(&b.index, &this, &res.path);
    let sides: Vec<Side<'_, '_>> = who
        .all()
        .map(|p| resolve(ctx, &walk, ty, &res.attrs, p))
        .collect();
    let write = ActionKey::builtin(ty.clone(), BuiltinAction::Write);
    let write_kind = action_kind(&b.model, &write)?;
    let delegated = who.delegated();
    let allowed: Vec<bool> = sides
        .iter()
        .map(|s| side_allows(ctx, s, &write, write_kind, delegated))
        .collect();
    let ids = rule_ids(ctx, &sides, &BTreeSet::new());
    if !allowed.iter().all(|&a| a) {
        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, write_kind, delegated);
        return Ok(refuse(r, ids));
    }
    if left.is_empty() && entered.is_empty() {
        return Ok(MoveDecision {
            effect: Effect::Allow,
            outcome: MoveOutcome::Allowed,
            reason: reason(ReasonCode::Allowed, "the path does not change"),
            rule_ids: ids,
            left: Vec::new(),
            entered: Vec::new(),
            looser: false,
            complete: true,
            approve_at: Vec::new(),
            gains: Vec::new(),
        });
    }

    // The rules of the scopes it crosses. Across teams (more than one scope
    // on a side), only owners of both sides (PERMISSION-MODEL.md 9).
    let far = left.len() > 1 || entered.len() > 1;
    let stop = match rule_stops(b, who, &res.path, left, far, |r| r.moves_out)? {
        Some(stop) => Some(stop),
        None => rule_stops(b, who, new_path, entered, far, |r| r.moves_in)?,
    };
    if let Some((why, scope)) = stop {
        let mut ids = ids;
        ids.extend(boundary_id(&scope));
        return Ok(refuse(why, ids));
    }
    // A new child of a scope is a write on it (PERMISSION-MODEL.md 5.2).
    let write_parent = ActionKey::builtin(parent.type_name.clone(), BuiltinAction::Write);
    if !scope_allows(b, who, parent, above(new_path, 0), &write_parent)? {
        let r = reason(
            ReasonCode::LevelTooLow,
            &format!("a move into {parent} needs write on it"),
        );
        return Ok(refuse(r, ids));
    }

    // Before and after. Stopping at a bound can never mean "no change".
    let (lines, complete) =
        gains(b, &this, req, new_path).map_or((Vec::new(), false), |l| (l, true));
    let looser = !complete || !lines.is_empty();
    let mut gains_out = lines;
    gains_out.truncate(MAX_MOVE_LINES);
    let mut decision = MoveDecision {
        effect: Effect::Allow,
        outcome: MoveOutcome::Allowed,
        reason: Reason::new(ReasonCode::Allowed),
        rule_ids: ids,
        left: left.to_vec(),
        entered: entered.to_vec(),
        looser,
        complete,
        approve_at: Vec::new(),
        gains: gains_out,
    };
    if !looser {
        return Ok(decision);
    }

    // The source's owner decides. When nothing is left, the source is still
    // the old parent.
    let sources: Vec<(usize, &PathEntry)> = if left.is_empty() {
        res.path.iter().enumerate().take(1).collect()
    } else {
        left.iter().enumerate().collect()
    };
    if let Some((_, s)) = sources
        .iter()
        .find(|(_, s)| boundary(b, s).on_looser == Some(OnLooser::Block))
    {
        decision.effect = Effect::Deny;
        decision.outcome = MoveOutcome::Refused;
        decision.reason = reason(
            ReasonCode::BoundaryRule,
            &format!("{s} blocks a move into a looser scope"),
        );
        decision.rule_ids.extend(boundary_id(s));
        return Ok(decision);
    }
    let mover = (!delegated).then_some(who.subject);
    let approvers: Vec<&Principal> = mover.into_iter().chain(&req.approved_by).collect();
    let mut waiting = Vec::new();
    for (i, s) in sources {
        let key = admin_key(s, "approve_move")?;
        let mut ok = false;
        for a in &approvers {
            ok = ok || may_approve(b, a, s, above(&res.path, i), &key)?;
        }
        if !ok {
            waiting.push(s.clone());
        }
    }
    if !waiting.is_empty() {
        decision.effect = Effect::Deny;
        decision.outcome = MoveOutcome::NeedsApproval;
        decision.reason = reason(
            ReasonCode::ApprovalRequired,
            if complete {
                "the move gives someone more access, and waits for the source owner"
            } else {
                "the comparison hit a bound, so the move waits for the source owner"
            },
        );
        decision.approve_at = waiting;
    }
    Ok(decision)
}

/// The verdict on one new link. The caller has checked the principals and
/// that the source is in this tenant.
pub(crate) fn check_link(
    b: &Bundle,
    who: &Who<'_>,
    source: &ResourceRef,
    target: &ResourceRef,
) -> Result<LinkVerdict, PdpError> {
    let ctx = b.ctx();
    let t = this_entry(target)?;
    crate::pdp::check_attrs(&b.model, &target.type_name, &target.attrs, true)?;
    let this = this_entry(source)?;
    let verdict = |effect, reason, rule_ids| LinkVerdict {
        target: t.clone(),
        effect,
        reason,
        rule_ids,
    };
    if !in_tenant(&b.index, target) {
        let r = reason(
            ReasonCode::TenantMismatch,
            "the target is not in this tenant",
        );
        return Ok(verdict(Effect::Deny, r, Vec::new()));
    }
    let org = |r: &ResourceRef, e: &PathEntry| r.path.last().unwrap_or(e).clone();
    if org(source, &this) != org(target, &t) {
        let r = reason(ReasonCode::BoundaryRule, "a link stays inside its org");
        return Ok(verdict(Effect::Deny, r, Vec::new()));
    }

    // The link is a write on its source.
    let write = ActionKey::builtin(source.type_name.clone(), BuiltinAction::Write);
    let kind = action_kind(&b.model, &write)?;
    let walk = Walk::new(&b.index, &this, &source.path);
    let sides: Vec<Side<'_, '_>> = who
        .all()
        .map(|p| resolve(ctx, &walk, &source.type_name, &source.attrs, p))
        .collect();
    let allowed: Vec<bool> = sides
        .iter()
        .map(|s| side_allows(ctx, s, &write, kind, who.delegated()))
        .collect();
    let ids = rule_ids(ctx, &sides, &BTreeSet::new());
    if !allowed.iter().all(|&a| a) {
        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, kind, who.delegated());
        return Ok(verdict(Effect::Deny, r, ids));
    }

    // A link to something you cannot open would tell that it exists. The
    // reason hides why (PERMISSION-MODEL.md 9).
    let read = ActionKey::builtin(target.type_name.clone(), BuiltinAction::Read);
    let read_kind = action_kind(&b.model, &read)?;
    let target_walk = Walk::new(&b.index, &t, &target.path);
    let readable = who.all().all(|p| {
        let side = resolve(ctx, &target_walk, &target.type_name, &target.attrs, p);
        side_allows(ctx, &side, &read, read_kind, who.delegated())
    });
    if !readable {
        return Ok(verdict(
            Effect::Deny,
            Reason::new(ReasonCode::NotAllowed),
            Vec::new(),
        ));
    }

    // The scopes the link reaches into, nearest the target first. Once a
    // scope holds the source too, so does everything above it.
    let chain: BTreeSet<&PathEntry> = core::iter::once(&this).chain(&source.path).collect();
    let nodes: Vec<&PathEntry> = core::iter::once(&t).chain(&target.path).collect();
    for (i, n) in nodes.iter().enumerate() {
        if chain.contains(*n) || n.is_org() {
            break;
        }
        let parent = nodes.get(i + 1).copied();
        let stopped = match boundary(b, n).links_from {
            Some(LinksFrom::Nobody) => true,
            Some(LinksFrom::Team) => !parent.is_some_and(|p| chain.contains(p)),
            Some(LinksFrom::Any) | None => false,
        };
        if stopped {
            let r = reason(
                ReasonCode::BoundaryRule,
                &format!("{n} takes no link from here"),
            );
            let mut ids = ids;
            ids.extend(boundary_id(n));
            return Ok(verdict(Effect::Deny, r, ids));
        }
    }
    Ok(verdict(
        Effect::Allow,
        Reason::new(ReasonCode::Allowed),
        ids,
    ))
}
