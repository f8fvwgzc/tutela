//! The evaluator: `Pdp::check`, `Pdp::batch`, `Pdp::list_filter` and
//! `Pdp::write_check` (CONTRACTS.md 6.5 to 6.8, PERMISSION-MODEL.md 7).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use tutela_contracts::decision::{
    Decision, Effect, FieldMask, Obligation, Reason, ReasonCode, RuleId,
};
use tutela_contracts::encoding::MAX_JSON_INT;
use tutela_contracts::keys::{ActionKey, BuiltinAction, FieldKey, FieldName, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::TenantKey;

use crate::api::{
    CheckRequest, FieldVerdict, ListFilterRequest, MAX_ACTORS, MAX_PATH, PathEntry, PdpError,
    ResourceRef, ScopePaths, WriteCheckRequest, WriteDecision,
};
use crate::data::{Index, LoadError, TenantData};
use crate::eval::{
    ActionKind, Ctx, Outcome, RuleRef, Side, Walk, action_kind, allow_reason, condition_id,
    deny_reason, field_levels, reason, resolve, rule_nodes, side_allows,
};
use crate::filter::{ListFilter, Listing};
use crate::model::Model;

/// One tenant's model and data at one revision.
struct Bundle {
    rev: u64,
    model: Arc<Model>,
    index: Index,
}

impl Bundle {
    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            model: &self.model,
            index: &self.index,
        }
    }
}

/// The embedded decision engine (PDP = policy decision point).
///
/// It holds one bundle per tenant: a compiled [`Model`] and the tenant's
/// [`TenantData`] at one revision. Every call runs the same steps
/// (PERMISSION-MODEL.md 7.1); `list_filter` builds its filter from the same
/// rules as `check`. An error is never an allow: callers fail closed.
#[derive(Default)]
pub struct Pdp {
    tenants: HashMap<TenantKey, Bundle>,
    /// The highest revision loaded per tenant. A lower one is refused.
    highest: HashMap<TenantKey, u64>,
}

/// The two kinds of principals in a request, checked.
struct Who<'a> {
    subject: &'a Principal,
    actors: &'a [Principal],
}

impl Who<'_> {
    fn delegated(&self) -> bool {
        !self.actors.is_empty()
    }

    fn all(&self) -> impl Iterator<Item = &Principal> {
        core::iter::once(self.subject).chain(self.actors)
    }
}

/// Checks the principals of a request: a delegated request has a `user`
/// subject and 1 to 4 `agent` actors (CONTRACTS.md 4.5).
fn who<'a>(subject: &'a Principal, actors: &'a [Principal]) -> Result<Who<'a>, PdpError> {
    if !actors.is_empty() {
        if subject.kind() != PrincipalKind::User {
            return Err(PdpError::invalid(
                "a delegated request needs a `user` subject",
            ));
        }
        if actors.len() > MAX_ACTORS {
            return Err(PdpError::invalid("the act chain has more than 4 actors"));
        }
        if actors.iter().any(|a| a.kind() != PrincipalKind::Agent) {
            return Err(PdpError::invalid(
                "every actor must be an `agent` principal",
            ));
        }
    }
    Ok(Who { subject, actors })
}

impl Pdp {
    /// An empty PDP: no tenant loaded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads (or replaces) a tenant's bundle: its model and data at one
    /// revision.
    ///
    /// # Errors
    ///
    /// A [`LoadError`] when the revision is lower than one loaded before (no
    /// going back, PERMISSION-MODEL.md 16), above the JSON integer range, or
    /// when the data breaks a rule. The old bundle stays in place.
    pub fn load(
        &mut self,
        tenant: TenantKey,
        rev: u64,
        model: Arc<Model>,
        data: TenantData,
    ) -> Result<(), LoadError> {
        if rev > MAX_JSON_INT {
            return Err(LoadError::RevTooLarge);
        }
        if let Some(&have) = self.highest.get(&tenant)
            && rev < have
        {
            return Err(LoadError::LowerRevision { have, got: rev });
        }
        let index = Index::build(&model, data)?;
        self.highest.insert(tenant.clone(), rev);
        self.tenants.insert(tenant, Bundle { rev, model, index });
        Ok(())
    }

    /// The loaded revision of a tenant.
    #[must_use]
    pub fn rev(&self, tenant: &TenantKey) -> Option<u64> {
        self.tenants.get(tenant).map(|b| b.rev)
    }

    fn bundle(&self, tenant: &TenantKey, at_least: Option<u64>) -> Result<&Bundle, PdpError> {
        let b = self.tenants.get(tenant).ok_or(PdpError::NoBundle)?;
        if let Some(need) = at_least
            && b.rev < need
        {
            return Err(PdpError::StaleBundle {
                have_rev: b.rev,
                need_rev: need,
            });
        }
        Ok(b)
    }

    /// One decision for one action on one resource.
    ///
    /// # Errors
    ///
    /// A [`PdpError`] for an unknown tenant, a stale bundle, an unknown type
    /// or action, a path that is too long or malformed, or principals that
    /// break the delegation rules. Never an allow.
    pub fn check(&self, req: &CheckRequest) -> Result<Decision, PdpError> {
        let b = self.bundle(&req.tenant, req.at_least_revision)?;
        let who = who(&req.subject, &req.actors)?;
        if req.action.resource_type() != &req.resource.type_name {
            return Err(PdpError::invalid(
                "the action's type is not the resource's type",
            ));
        }
        let kind = action_kind(&b.model, &req.action)?;
        let this = this_entry(&req.resource)?;
        if !in_tenant(&b.index, &req.resource) {
            return Ok(tenant_mismatch(b.rev));
        }
        let ctx = b.ctx();
        let walk = Walk::new(&b.index, &this, &req.resource.path);
        let ty = &req.resource.type_name;
        let sides: Vec<Side<'_, '_>> = who
            .all()
            .map(|p| resolve(ctx, &walk, ty, &req.resource.attrs, p))
            .collect();

        // Fields: each one at the lowest level over the person and the
        // actors (the overlap), for the fields asked for.
        let keys = output_keys(&b.index, ty, req.fields.as_deref());
        let rules = rule_nodes(&walk);
        let mut levels: Vec<Level> = vec![Level::Full; keys.len()];
        let mut lowered: BTreeSet<RuleRef> = BTreeSet::new();
        for side in &sides {
            for (i, (l, by)) in field_levels(ctx, &rules, side, &keys)
                .into_iter()
                .enumerate()
            {
                if let Some(slot) = levels.get_mut(i) {
                    *slot = (*slot).min(l);
                }
                lowered.extend(by);
            }
        }
        let level = sides.iter().map(Side::item).min().unwrap_or(Level::None);
        let mask = mask(&keys, &levels, level);

        let allowed: Vec<bool> = sides
            .iter()
            .map(|s| side_allows(ctx, s, &req.action, kind, who.delegated()))
            .collect();
        let effect = if allowed.iter().all(|&a| a) {
            Effect::Allow
        } else {
            Effect::Deny
        };
        let reason = decision_reason(
            ctx,
            &walk,
            &sides,
            &allowed,
            &req.action,
            kind,
            who.delegated(),
        );
        let rule_ids = rule_ids(ctx, &sides, &lowered);
        let mut obligations = Vec::new();
        if effect == Effect::Allow {
            if who.delegated() {
                obligations.push(Obligation::Audit {
                    on_behalf_of: Some(req.subject.clone()),
                    reason_required: false,
                });
            }
            if let Some(label) = highest_label(&b.model, ty, &mask) {
                obligations.push(Obligation::Label { value: label });
            }
        }
        Ok(Decision {
            effect,
            level,
            field_mask: mask,
            rule_ids,
            reason,
            rev: b.rev,
            obligations,
        })
    }

    /// Many decisions, in the same order as `reqs`. If any request is
    /// invalid, the whole batch fails (fail closed).
    ///
    /// # Errors
    ///
    /// The first request's error; for [`PdpError::InvalidInput`], `index`
    /// names the request.
    pub fn batch(&self, reqs: &[CheckRequest]) -> Result<Vec<Decision>, PdpError> {
        reqs.iter()
            .enumerate()
            .map(|(i, r)| {
                self.check(r).map_err(|e| match e {
                    PdpError::InvalidInput { detail, .. } => PdpError::InvalidInput {
                        index: Some(i),
                        detail,
                    },
                    e => e,
                })
            })
            .collect()
    }

    /// A filter to list rows of one type inside SQL (CONTRACTS.md 6.6).
    ///
    /// `paths` gives the path of every scope the filter must place: the
    /// scopes where the principal has an assignment, and the tenant's
    /// private scopes (ADR-0011 F1). A row passes the filter exactly when
    /// `check` allows the action on it.
    ///
    /// # Errors
    ///
    /// A [`PdpError`] for an unknown tenant, a stale bundle, an unknown
    /// action, principals that break the delegation rules, a scope the
    /// provider cannot place ([`PdpError::ScopePath`]), or a filter above the
    /// limits ([`PdpError::FilterTooLarge`]). The caller then lists no rows.
    pub fn list_filter<P: ScopePaths + ?Sized>(
        &self,
        req: &ListFilterRequest,
        paths: &P,
    ) -> Result<ListFilter, PdpError> {
        let b = self.bundle(&req.tenant, req.at_least_revision)?;
        let who = who(&req.subject, &req.actors)?;
        let kind = action_kind(&b.model, &req.action)?;
        let listing = Listing {
            ctx: b.ctx(),
            tenant: &req.tenant,
            action: &req.action,
            kind,
            delegated: who.delegated(),
            rev: b.rev,
        };
        crate::filter::list_filter(&listing, who.subject, who.actors, paths)
    }

    /// Per-field verdicts for a write (CONTRACTS.md 6.7).
    ///
    /// Each changed field needs Write on that field (for the person and
    /// every actor). A field marked `grants_access` also needs the admin key
    /// `<type>:manage_access`, which never goes to agents or through
    /// delegation. A field the type does not declare is denied.
    ///
    /// # Errors
    ///
    /// As [`Pdp::check`]. Also [`PdpError::InvalidInput`] when nothing
    /// changes, and for a move (`new_path`): moves need boundary rules, which
    /// come with `tutela-store` (ROADMAP Phase A item 5). Until then a move
    /// is refused.
    pub fn write_check(&self, req: &WriteCheckRequest) -> Result<WriteDecision, PdpError> {
        let b = self.bundle(&req.tenant, req.at_least_revision)?;
        let who = who(&req.subject, &req.actors)?;
        if req.new_path.is_some() {
            return Err(PdpError::invalid(
                "moves are refused until boundary rules exist (ROADMAP Phase A item 5)",
            ));
        }
        if req.new_attrs.is_empty() {
            return Err(PdpError::invalid("a write must change at least one field"));
        }
        let ty = &req.resource.type_name;
        let write = ActionKey::builtin(ty.clone(), BuiltinAction::Write);
        let manage = ActionKey::builtin(ty.clone(), BuiltinAction::ManageAccess);
        let write_kind = action_kind(&b.model, &write)?;
        let manage_kind = action_kind(&b.model, &manage)?;
        let this = this_entry(&req.resource)?;
        let ctx = b.ctx();
        let changed: Vec<&FieldName> = req.new_attrs.keys().collect();
        let def = b.model.types().get(ty);
        let needs_for = |f: &FieldName| {
            if def
                .and_then(|d| d.fields.get(f))
                .is_some_and(|d| d.grants_access)
            {
                &manage
            } else {
                &write
            }
        };
        if !in_tenant(&b.index, &req.resource) {
            let r = reason(
                ReasonCode::TenantMismatch,
                "the resource is not in this tenant",
            );
            let fields = changed
                .into_iter()
                .map(|f| FieldVerdict {
                    field: f.clone(),
                    effect: Effect::Deny,
                    needs: needs_for(f).clone(),
                    reason: r.clone(),
                    rule_ids: Vec::new(),
                })
                .collect();
            return Ok(WriteDecision {
                effect: Effect::Deny,
                rev: b.rev,
                fields,
            });
        }
        let walk = Walk::new(&b.index, &this, &req.resource.path);
        let sides: Vec<Side<'_, '_>> = who
            .all()
            .map(|p| resolve(ctx, &walk, ty, &req.resource.attrs, p))
            .collect();
        let rules = rule_nodes(&walk);
        let delegated = who.delegated();
        let write_ok: Vec<bool> = sides
            .iter()
            .map(|s| side_allows(ctx, s, &write, write_kind, delegated))
            .collect();
        let manage_ok = sides
            .iter()
            .all(|s| side_allows(ctx, s, &manage, manage_kind, delegated));

        let mut verdicts = Vec::new();
        for f in changed {
            let key = FieldKey::new(ty.clone(), f.clone());
            let field_def = def.and_then(|d| d.fields.get(f));
            let grants_access = field_def.is_some_and(|d| d.grants_access);
            let needs = needs_for(f);
            let Some(_) = field_def else {
                verdicts.push(FieldVerdict {
                    field: f.clone(),
                    effect: Effect::Deny,
                    needs: needs.clone(),
                    reason: reason(
                        ReasonCode::NotAllowed,
                        &format!("{f} is not a declared data field of {ty}"),
                    ),
                    rule_ids: Vec::new(),
                });
                continue;
            };
            let mut level = Level::Full;
            let mut lowered = BTreeSet::new();
            let mut low: Vec<usize> = Vec::new();
            for (i, side) in sides.iter().enumerate() {
                let (l, by) = field_levels(ctx, &rules, side, &[&key])
                    .pop()
                    .unwrap_or((Level::None, Vec::new()));
                if !l.satisfies(Level::Write) {
                    low.push(i);
                }
                level = level.min(l);
                lowered.extend(by);
            }
            let field_ok = level.satisfies(Level::Write);
            let ok = field_ok && (!grants_access || manage_ok);
            let r = if ok {
                Reason::new(ReasonCode::Allowed)
            } else if !write_ok.iter().all(|&w| w) {
                decision_reason(ctx, &walk, &sides, &write_ok, &write, write_kind, delegated)
            } else if !field_ok {
                field_low_reason(ctx, &sides, &low, f, &lowered)
            } else {
                let manage_allowed: Vec<bool> = sides
                    .iter()
                    .map(|s| side_allows(ctx, s, &manage, manage_kind, delegated))
                    .collect();
                decision_reason(
                    ctx,
                    &walk,
                    &sides,
                    &manage_allowed,
                    &manage,
                    manage_kind,
                    delegated,
                )
            };
            verdicts.push(FieldVerdict {
                field: f.clone(),
                effect: if ok { Effect::Allow } else { Effect::Deny },
                needs: needs.clone(),
                reason: r,
                rule_ids: rule_ids(ctx, &sides, &lowered),
            });
        }
        let effect = if verdicts.iter().all(|v| v.effect == Effect::Allow) {
            Effect::Allow
        } else {
            Effect::Deny
        };
        Ok(WriteDecision {
            effect,
            rev: b.rev,
            fields: verdicts,
        })
    }
}

/// The resource as the first node of its walk, after checking its path:
/// at most [`MAX_PATH`] ancestors, the last one an org, no other org. An org
/// itself has no ancestors.
fn this_entry(res: &ResourceRef) -> Result<PathEntry, PdpError> {
    if res.path.len() > MAX_PATH {
        return Err(PdpError::PathTooLong);
    }
    let this = PathEntry::new(res.type_name.clone(), res.id.clone());
    if this.is_org() {
        if !res.path.is_empty() || this.org_id().is_none() {
            return Err(PdpError::invalid("an org has no path and an org id"));
        }
        return Ok(this);
    }
    let Some((last, rest)) = res.path.split_last() else {
        return Err(PdpError::invalid("the path must end at the org"));
    };
    if last.org_id().is_none() || rest.iter().any(PathEntry::is_org) {
        return Err(PdpError::invalid(
            "the path must end at the org, and only there",
        ));
    }
    Ok(this)
}

/// `true` if the resource's org is one of the tenant's orgs (step 2).
fn in_tenant(index: &Index, res: &ResourceRef) -> bool {
    let org = res
        .path
        .last()
        .map_or_else(|| res.id.as_str().parse().ok(), PathEntry::org_id);
    org.is_some_and(|o| index.orgs.contains(&o))
}

/// The deny for a resource of another tenant. There is no cross-tenant
/// grant, ever.
fn tenant_mismatch(rev: u64) -> Decision {
    Decision {
        effect: Effect::Deny,
        level: Level::None,
        field_mask: FieldMask::empty(),
        rule_ids: Vec::new(),
        reason: reason(
            ReasonCode::TenantMismatch,
            "the resource is not in this tenant",
        ),
        rev,
        obligations: Vec::new(),
    }
}

/// The fields and features the mask covers: every declared one of the type,
/// or the declared ones among those asked for. An unknown name is masked.
fn output_keys<'i>(
    index: &'i Index,
    ty: &ResourceType,
    asked: Option<&[FieldName]>,
) -> Vec<&'i FieldKey> {
    let all = index.type_fields.get(ty).map_or(&[][..], Vec::as_slice);
    match asked {
        None => all.iter().collect(),
        Some(names) => all.iter().filter(|k| names.contains(k.field())).collect(),
    }
}

/// The field mask: Read and above is readable, Write and above writable.
/// Empty at item level None.
fn mask(keys: &[&FieldKey], levels: &[Level], item: Level) -> FieldMask {
    if item == Level::None {
        return FieldMask::empty();
    }
    let at = |min: Level| {
        keys.iter()
            .zip(levels)
            .filter(move |(_, l)| l.satisfies(min))
            .map(|(k, _)| k.field().clone())
    };
    FieldMask::new(at(Level::Read), at(Level::Write)).unwrap_or_default()
}

/// The highest label among the readable data fields (PERMISSION-MODEL.md
/// 11.5).
fn highest_label(
    model: &Model,
    ty: &ResourceType,
    mask: &FieldMask,
) -> Option<tutela_contracts::keys::Label> {
    let def = model.types().get(ty)?;
    mask.read()
        .iter()
        .filter_map(|f| def.fields.get(f))
        .map(|d| d.sensitivity)
        .max()
        .map(crate::model::Sensitivity::label)
}

/// The rule ids of a decision: the deciding assignments, the conditions that
/// were false and the field rules that lowered a field, in that order,
/// without repeats.
fn rule_ids(ctx: Ctx<'_>, sides: &[Side<'_, '_>], lowered: &BTreeSet<RuleRef>) -> Vec<RuleId> {
    let mut out: Vec<RuleId> = Vec::new();
    let mut push = |id: Option<RuleId>| {
        if let Some(id) = id
            && !out.contains(&id)
        {
            out.push(id);
        }
    };
    for side in sides {
        if side.outcome != Outcome::Found {
            continue;
        }
        for r in &side.roles {
            push(ctx.index.bindings.get(r.binding).map(|b| b.id.clone()));
        }
    }
    for side in sides {
        for r in &side.roles {
            for &ci in &r.fired {
                push(condition_id(ci));
            }
        }
    }
    for &r in lowered {
        push(r.id(ctx.index));
    }
    out
}

/// The reason of a decision over the person and the actors
/// (CONTRACTS.md 6.4): the person's own reason when the person is denied;
/// `delegation_overlap` (or `outside_ai_reach`) when only an actor is.
fn decision_reason(
    ctx: Ctx<'_>,
    walk: &Walk<'_, '_>,
    sides: &[Side<'_, '_>],
    allowed: &[bool],
    action: &ActionKey,
    kind: ActionKind<'_>,
    delegated: bool,
) -> Reason {
    let mut it = sides.iter().zip(allowed);
    let Some((person, &person_ok)) = it.next() else {
        return Reason::new(ReasonCode::NotAllowed);
    };
    if !person_ok {
        return deny_reason(ctx, walk, person, action, kind, delegated);
    }
    for (actor, &ok) in it {
        if ok {
            continue;
        }
        let r = deny_reason(ctx, walk, actor, action, kind, delegated);
        if r.known_code() == Some(ReasonCode::OutsideAiReach)
            || r.known_code() == Some(ReasonCode::AdminOnly)
        {
            return r;
        }
        return reason(
            ReasonCode::DelegationOverlap,
            &format!(
                "{} is allowed, but actor {} is not ({})",
                person.principal,
                actor.principal,
                r.code()
            ),
        );
    }
    let detail = allow_reason(ctx, walk, person, action, kind);
    if delegated {
        reason(
            ReasonCode::Allowed,
            &format!("overlap of {detail}, and every actor"),
        )
    } else {
        reason(ReasonCode::Allowed, &detail)
    }
}

/// The reason a field is below Write while the item allows `write`.
fn field_low_reason(
    ctx: Ctx<'_>,
    sides: &[Side<'_, '_>],
    low: &[usize],
    field: &FieldName,
    lowered: &BTreeSet<RuleRef>,
) -> Reason {
    let by_rule = lowered
        .iter()
        .filter_map(|r| r.id(ctx.index))
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let rules = if by_rule.is_empty() {
        String::new()
    } else {
        format!(" (field rules: {by_rule})")
    };
    if !low.contains(&0) {
        let who = low
            .iter()
            .filter_map(|&i| sides.get(i))
            .map(|s| s.principal.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return reason(
            ReasonCode::DelegationOverlap,
            &format!("the person may write {field}, but {who} may not{rules}"),
        );
    }
    reason(
        ReasonCode::LevelTooLow,
        &format!("{field} is below write{rules}"),
    )
}
