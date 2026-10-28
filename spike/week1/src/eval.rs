//! The evaluator: `check` and `list_filter` from the same walk rules.
//! PERMISSION-MODEL.md §7 with the choices in docs/SPIKE-WEEK1.md §3.
//! THROWAWAY.

use crate::filter::{at_or_under, Cond, ListFilter, Val, Col};
use crate::model::*;
use crate::tree::ScopePaths;
use rustc_hash::FxHashMap;

pub const MAX_PATH: usize = 32;

/// Planted bugs, on the list side only, to show the differential test
/// catches them. 0 = none (the real run). Set with SPIKE_MUTATE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// One term per deciding scope (first version).
    Flat,
    /// One term per (nesting level, role). The default.
    Levels,
}

/// SPIKE_FORM=flat|levels
pub fn form() -> Form {
    static F: std::sync::OnceLock<Form> = std::sync::OnceLock::new();
    *F.get_or_init(|| match std::env::var("SPIKE_FORM").as_deref() {
        Ok("flat") => Form::Flat,
        _ => Form::Levels,
    })
}

pub fn mutate() -> u32 {
    static M: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *M.get_or_init(|| std::env::var("SPIKE_MUTATE").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

pub struct ResourceRef<'a> {
    pub id: NodeId,
    pub ty: TypeId,
    /// Ancestors, nearest first; the last is the org.
    pub path: &'a [NodeId],
    pub attrs: &'a Attrs,
}

pub struct CheckRequest<'a> {
    pub subject: Principal,
    pub actors: &'a [Principal],
    pub action: Action,
    pub resource: ResourceRef<'a>,
    /// Some(&[]) = no field mask wanted.
    pub fields: Option<&'a [u16]>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allow: bool,
    pub level: Level,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub rule_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug)]
pub enum PdpError {
    PathTooLong,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Why {
    #[default]
    NoRole,
    PrivateScope,
    Found,
}

/// The deciding role at one scope.
#[derive(Clone, Copy, Debug)]
pub struct Pick {
    pub role: RoleId,
    pub id: u32,
    pub via_group: bool,
    /// A direct assignment won over a group one at this scope.
    pub beat_group: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Resolved {
    pub level: Level,
    pub role: Option<RoleId>,
    pub scope: NodeId,
    pub assign_id: u32,
    pub why: Why,
    /// Conditions that were false.
    pub fired: Vec<u32>,
    pub conds_true: u32,
    pub via_group: bool,
    pub beat_group: bool,
    pub org_owner: bool,
}

pub struct Walk<'m> {
    pub n: usize,
    pub ids: [NodeId; MAX_PATH + 1],
    pub data: [Option<&'m NodeData>; MAX_PATH + 1],
}

impl Model {
    pub fn walk<'m>(&'m self, res: &ResourceRef) -> Result<Walk<'m>, PdpError> {
        if res.path.len() > MAX_PATH {
            return Err(PdpError::PathTooLong);
        }
        let mut w = Walk { n: res.path.len() + 1, ids: [0; MAX_PATH + 1], data: [None; MAX_PATH + 1] };
        w.ids[0] = res.id;
        w.data[0] = self.nodes.get(&res.id);
        for (i, &a) in res.path.iter().enumerate() {
            w.ids[i + 1] = a;
            w.data[i + 1] = self.nodes.get(&a);
        }
        Ok(w)
    }

    /// The deciding role for `p` at one scope: direct first, else the group
    /// role with the highest level for `ty`, ties to the lowest role id.
    pub fn role_at(&self, nd: &NodeData, p: Principal, ty: TypeId) -> Option<Pick> {
        let mut direct = None;
        let mut group: Option<(Level, RoleId, u32)> = None;
        for &(s, r, id) in &nd.assigns {
            match (s, p) {
                (Subject::User(u), Principal::User(q)) | (Subject::Agent(u), Principal::Agent(q)) if u == q => {
                    direct = Some((r, id))
                }
                (Subject::Group(g), Principal::User(q)) if self.in_group(q, g) => {
                    let l = self.roles[r as usize].type_level[ty as usize];
                    if group.is_none_or(|(bl, br, _)| l > bl || (l == bl && r < br)) {
                        group = Some((l, r, id));
                    }
                }
                _ => {}
            }
        }
        match direct {
            Some((role, id)) => Some(Pick { role, id, via_group: false, beat_group: group.is_some() }),
            None => group.map(|(_, role, id)| Pick { role, id, via_group: true, beat_group: false }),
        }
    }

    fn org_owner(&self, p: Principal, org: Option<&NodeData>, ty: TypeId) -> Option<Pick> {
        match p {
            Principal::User(_) => org.and_then(|nd| self.role_at(nd, p, ty)).filter(|pk| pk.role == OWNER),
            Principal::Agent(_) => None,
        }
    }

    /// Steps 3 and 4: walk up, closest assignment wins, private stops,
    /// then conditions narrow.
    pub fn resolve(&self, p: Principal, ty: TypeId, attrs: &Attrs, w: &Walk) -> Resolved {
        let mut r = Resolved::default();
        let last = w.n - 1;
        let mut found = self.org_owner(p, w.data[last], ty).map(|pk| (last, pk));
        r.org_owner = found.is_some();
        if found.is_none() {
            for i in 0..w.n {
                if let Some(nd) = w.data[i] {
                    if let Some(pk) = self.role_at(nd, p, ty) {
                        found = Some((i, pk));
                        break;
                    }
                    if nd.private {
                        r.why = Why::PrivateScope;
                        return r;
                    }
                }
            }
        }
        let Some((i, pk)) = found else {
            r.why = Why::NoRole;
            return r;
        };
        r.why = Why::Found;
        r.role = Some(pk.role);
        r.scope = w.ids[i];
        r.assign_id = pk.id;
        r.via_group = pk.via_group;
        r.beat_group = pk.beat_group;
        let mut level = self.roles[pk.role as usize].type_level[ty as usize];
        for j in 0..w.n {
            if let Some(nd) = w.data[j] {
                for &ci in &nd.conds {
                    let c = &self.conds[ci as usize];
                    if c.role == pk.role && c.ty == ty {
                        if self.eval_tpl(&c.tpl, attrs, p) {
                            r.conds_true += 1;
                        } else {
                            level = level.min(c.lif);
                            r.fired.push(c.id);
                        }
                    }
                }
            }
        }
        r.level = level;
        r
    }

    pub fn eval_tpl(&self, t: &Tpl, a: &Attrs, p: Principal) -> bool {
        match t {
            Tpl::StatusEq(s) => a.status == Some(*s),
            Tpl::StatusIn(v) => a.status.is_some_and(|x| v.contains(&x)),
            Tpl::PriorityEq(i) => a.priority == Some(*i),
            Tpl::FlagEq(b) => a.flag == Some(*b),
            Tpl::LabelsContain(l) => a.labels.is_some_and(|m| m & (1 << l) != 0),
            Tpl::AssigneeIsPrincipal => a.assignee == Some(p),
            Tpl::InGroup(g) => matches!(p, Principal::User(u) if self.in_group(u, *g)),
            Tpl::And(v) => v.iter().all(|x| self.eval_tpl(x, a, p)),
            Tpl::Or(v) => v.iter().any(|x| self.eval_tpl(x, a, p)),
            Tpl::Not(x) => !self.eval_tpl(x, a, p),
        }
    }

    /// The same template as a filter AST. Principal values are filled in.
    pub fn compile_tpl(&self, t: &Tpl, p: Principal) -> Cond {
        match t {
            Tpl::StatusEq(s) => Cond::Eq(Col::Status, Val::Str(STATUS[*s as usize])),
            Tpl::StatusIn(v) => Cond::In(Col::Status, v.iter().map(|s| Val::Str(STATUS[*s as usize])).collect()),
            Tpl::PriorityEq(i) => Cond::Eq(Col::Priority, Val::Int(*i)),
            Tpl::FlagEq(b) => Cond::Eq(Col::Flag, Val::Bool(*b)),
            Tpl::LabelsContain(l) => Cond::Contains(Col::Labels, LABELS[*l as usize]),
            Tpl::AssigneeIsPrincipal => Cond::Eq(Col::Assignee, Val::Principal(p)),
            Tpl::InGroup(g) => {
                if matches!(p, Principal::User(u) if self.in_group(u, *g)) {
                    Cond::True
                } else {
                    Cond::False
                }
            }
            Tpl::And(v) => Cond::and(v.iter().map(|x| self.compile_tpl(x, p)).collect()),
            Tpl::Or(v) => Cond::or(v.iter().map(|x| self.compile_tpl(x, p)).collect()),
            Tpl::Not(x) => Cond::not(self.compile_tpl(x, p)),
        }
    }

    fn allows(&self, r: &Resolved, ty: TypeId, action: Action) -> bool {
        match r.role {
            Some(role) => r.level >= action.need() && self.grant_ok(role, ty, action),
            None => false,
        }
    }

    /// Step 5: field level = min(role level capped by the item level,
    /// closest field rule). At one scope a rule for this role beats a rule
    /// for all roles.
    pub fn field_levels(&self, r: &Resolved, ty: TypeId, w: &Walk, out: &mut [Level], hits: &mut Vec<u32>) {
        let role = match r.role {
            Some(role) if r.level > Level::None => role,
            _ => {
                out.fill(Level::None);
                return;
            }
        };
        let rl = &self.roles[role as usize].field_level[ty as usize];
        for (k, o) in out.iter_mut().enumerate() {
            *o = rl[k].unwrap_or(r.level).min(r.level);
        }
        let mut decided: u64 = 0;
        for j in 0..w.n {
            let Some(nd) = w.data[j] else { continue };
            if nd.rules.is_empty() {
                continue;
            }
            let mut here: u64 = 0;
            for pass in 0..2 {
                for &ri in &nd.rules {
                    let fr = &self.rules[ri as usize];
                    let matches = if pass == 0 { fr.role == Some(role) } else { fr.role.is_none() };
                    if fr.ty != ty || !matches {
                        continue;
                    }
                    let b = 1u64 << fr.field;
                    if (decided | here) & b != 0 {
                        continue;
                    }
                    here |= b;
                    let f = fr.field as usize;
                    out[f] = out[f].min(fr.max);
                    hits.push(fr.id);
                }
            }
            decided |= here;
        }
    }

    pub fn check(&self, req: &CheckRequest) -> Result<Decision, PdpError> {
        let res = &req.resource;
        let ty = res.ty;
        let w = self.walk(res)?;
        let want_fields = !matches!(req.fields, Some(f) if f.is_empty());
        let nf = self.types[ty as usize].fields.len();
        let mut lv = [Level::None; 64];
        let mut lv2 = [Level::None; 64];
        let mut hits = Vec::new();
        let mut rule_ids = Vec::new();

        let r = self.resolve(req.subject, ty, res.attrs, &w);
        let person_allow = self.allows(&r, ty, req.action);
        let mut allow = person_allow;
        let mut level = r.level;
        if want_fields {
            self.field_levels(&r, ty, &w, &mut lv[..nf], &mut hits);
        }
        push_ids(&r, &mut rule_ids);
        let mut overlap = false;
        for &a in req.actors {
            let ra = self.resolve(a, ty, res.attrs, &w);
            let agent_allow = self.allows(&ra, ty, req.action);
            if want_fields {
                self.field_levels(&ra, ty, &w, &mut lv2[..nf], &mut hits);
                for k in 0..nf {
                    lv[k] = lv[k].min(lv2[k]);
                }
            }
            push_ids(&ra, &mut rule_ids);
            if allow != agent_allow {
                overlap = true;
            }
            allow = allow && agent_allow;
            level = level.min(ra.level);
        }
        for h in hits {
            rule_ids.push(format!("fr_{h}"));
        }
        let mut read = Vec::new();
        let mut write = Vec::new();
        if want_fields && level > Level::None {
            let names = &self.types[ty as usize].fields;
            let mut push = |k: usize| {
                if lv[k] >= Level::Read {
                    read.push(names[k].clone());
                }
                if lv[k] >= Level::Write {
                    write.push(names[k].clone());
                }
            };
            match req.fields {
                Some(fs) => fs.iter().for_each(|&k| push(k as usize)),
                None => (0..nf).for_each(push),
            }
        }
        let reason = if allow {
            format!("allowed: role assignment ra_{} at scope {}", r.assign_id, r.scope)
        } else if overlap && person_allow {
            "delegation_overlap".to_string()
        } else {
            match r.why {
                Why::NoRole => "no_role".to_string(),
                Why::PrivateScope => "private_scope".to_string(),
                Why::Found if !r.fired.is_empty() => "condition_failed".to_string(),
                Why::Found if r.level < req.action.need() => "level_too_low".to_string(),
                Why::Found => "missing_grant".to_string(),
            }
        };
        Ok(Decision { allow, level, read, write, rule_ids, reason })
    }

    /// The filter for one principal. PERMISSION-MODEL.md §12.2.
    pub fn list_filter_one(&self, p: Principal, ty: TypeId, action: Action, sp: &impl ScopePaths) -> ListFilter {
        let need = action.need();
        // 1. Deciding scopes: Some(pick) where the principal has a role,
        //    None for private scopes (inside them) that stop inheritance.
        let mut dec: FxHashMap<NodeId, Option<Pick>> = FxHashMap::default();
        if let Some(pk) = self.org_owner(p, self.nodes.get(&self.org), ty) {
            dec.insert(self.org, Some(pk));
        } else {
            let mut subjects = vec![match p {
                Principal::User(u) => Subject::User(u),
                Principal::Agent(a) => Subject::Agent(a),
            }];
            if let Principal::User(u) = p {
                subjects.extend(self.user_groups[u as usize].iter().map(|&g| Subject::Group(g)));
            }
            for s in subjects {
                for &n in self.by_subject.get(&s).map(|v| v.as_slice()).unwrap_or(&[]) {
                    if dec.contains_key(&n) {
                        continue;
                    }
                    if let Some(pk) = self.nodes.get(&n).and_then(|nd| self.role_at(nd, p, ty)) {
                        dec.insert(n, Some(pk));
                    }
                }
            }
            for &x in &self.private_list {
                if mutate() == 1 {
                    break; // bug 1: private scopes do not stop inheritance
                }
                if !dec.contains_key(&x) && sp.ancestors(x).iter().any(|a| matches!(dec.get(a), Some(Some(_)))) {
                    dec.insert(x, None);
                }
            }
        }
        if form() == Form::Levels {
            return self.levels_filter(p, ty, action, &dec, sp);
        }
        // 2. How they nest: each one's nearest deciding ancestor.
        let mut children: FxHashMap<NodeId, Vec<NodeId>> = FxHashMap::default();
        for &x in dec.keys() {
            if let Some(&par) = sp.ancestors(x).iter().find(|a| dec.contains_key(a)) {
                children.entry(par).or_default().push(x);
            }
        }
        // 3. A row passes if its deepest deciding scope allows it.
        let mut keys: Vec<NodeId> = dec.keys().copied().collect();
        keys.sort_unstable();
        let mut ids_in = Vec::new();
        let mut container_in = Vec::new();
        let mut terms = Vec::new();
        let mut pure = true;
        for d in keys {
            let Some(pk) = dec[&d] else { continue };
            if self.roles[pk.role as usize].type_level[ty as usize] < need || !self.grant_ok(pk.role, ty, action) {
                continue;
            }
            let mut parts = vec![at_or_under(&[(d, sp.ty(d) == ty)])];
            if let Some(ch) = children.get(&d).filter(|_| mutate() != 3) {
                let mut ch: Vec<(NodeId, bool)> = ch.iter().map(|&c| (c, sp.ty(c) == ty)).collect();
                ch.sort_unstable();
                parts.push(Cond::not(at_or_under(&ch)));
            }
            for &ci in self.conds_by_role_type.get(&(pk.role, ty)).map(|v| v.as_slice()).unwrap_or(&[]) {
                let c = &self.conds[ci as usize];
                if c.lif >= need {
                    continue;
                }
                let t = self.compile_tpl(&c.tpl, p);
                if c.scope == d || sp.ancestors(d).contains(&c.scope) {
                    if mutate() != 4 {
                        parts.push(t); // bug 4 drops conditions set above the deciding scope
                    }
                } else if sp.ancestors(c.scope).contains(&d) && mutate() == 2 {
                    parts.push(t); // bug 2: a condition below the scope applies to all its rows
                } else if sp.ancestors(c.scope).contains(&d) {
                    parts.push(Cond::or(vec![Cond::not(at_or_under(&[(c.scope, sp.ty(c.scope) == ty)])), t]));
                }
            }
            if parts.len() > 1 {
                pure = false;
            }
            if sp.ty(d) == ty {
                ids_in.push(d);
            }
            container_in.push(d);
            terms.push(Cond::and(parts));
        }
        ListFilter { ty, ids_in, container_in, condition: if pure { None } else { Some(Cond::or(terms)) } }
    }

    /// The merged form. A deciding scope's "level" is how many deciding
    /// scopes sit above it. A row's deepest deciding scope is at level k iff
    /// the row is at or under a level-k scope and not under any level-(k+1)
    /// scope (the row's deciding scopes form one chain). So one term per
    /// (level, role): at_or_under(allowed scopes of that level and role)
    /// AND NOT at_or_under(all level-(k+1) scopes) AND the role's
    /// conditions, each guarded by "at or under its scope".
    fn levels_filter(
        &self,
        p: Principal,
        ty: TypeId,
        action: Action,
        dec: &FxHashMap<NodeId, Option<Pick>>,
        sp: &impl ScopePaths,
    ) -> ListFilter {
        let need = action.need();
        let mut by_level: Vec<Vec<NodeId>> = Vec::new();
        let mut level_of: Vec<(NodeId, usize)> = Vec::new();
        for &x in dec.keys() {
            let k = sp.ancestors(x).iter().filter(|a| dec.contains_key(a)).count();
            if by_level.len() <= k {
                by_level.resize(k + 1, Vec::new());
            }
            by_level[k].push(x);
            level_of.push((x, k));
        }
        for v in &mut by_level {
            v.sort_unstable();
        }
        // (level, role with conditions that matter, or None) -> allowed scopes.
        // Roles with no condition below `need` share one term per level.
        let has_conds = |role: RoleId| {
            self.conds_by_role_type
                .get(&(role, ty))
                .is_some_and(|v| v.iter().any(|&ci| self.conds[ci as usize].lif < need))
        };
        let mut groups: std::collections::BTreeMap<(usize, Option<RoleId>), Vec<NodeId>> = Default::default();
        level_of.sort_unstable();
        for (x, k) in level_of {
            if let Some(pk) = dec[&x] {
                if self.roles[pk.role as usize].type_level[ty as usize] >= need && self.grant_ok(pk.role, ty, action) {
                    let key = if has_conds(pk.role) { Some(pk.role) } else { None };
                    groups.entry((k, key)).or_default().push(x);
                }
            }
        }
        let mut ids_in = Vec::new();
        let mut container_in = Vec::new();
        let mut terms = Vec::new();
        let mut pure = true;
        for ((k, role), scopes) in groups {
            let with_type: Vec<(NodeId, bool)> = scopes.iter().map(|&x| (x, sp.ty(x) == ty)).collect();
            let mut parts = vec![at_or_under(&with_type)];
            if let Some(next) = by_level.get(k + 1).filter(|_| mutate() != 3) {
                let next: Vec<(NodeId, bool)> = next
                    .iter()
                    // bug 7: exclude only the allowed scopes of the next level
                    .filter(|x| mutate() != 7 || dec[*x].is_some())
                    .map(|&x| (x, sp.ty(x) == ty))
                    .collect();
                parts.push(Cond::not(at_or_under(&next)));
            }
            let conds = match role {
                Some(role) => self.conds_by_role_type.get(&(role, ty)).map(|v| v.as_slice()).unwrap_or(&[]),
                None => &[],
            };
            for &ci in conds {
                let c = &self.conds[ci as usize];
                if c.lif >= need {
                    continue;
                }
                let t = self.compile_tpl(&c.tpl, p);
                if c.scope == self.org {
                    if mutate() != 4 {
                        parts.push(t);
                    }
                } else if mutate() == 2 {
                    parts.push(t);
                } else {
                    parts.push(Cond::or(vec![Cond::not(at_or_under(&[(c.scope, sp.ty(c.scope) == ty)])), t]));
                }
            }
            if parts.len() > 1 {
                pure = false;
            }
            for (x, same) in with_type {
                if same {
                    ids_in.push(x);
                }
                container_in.push(x);
            }
            terms.push(Cond::and(parts));
        }
        ids_in.sort_unstable();
        container_in.sort_unstable();
        ListFilter { ty, ids_in, container_in, condition: if pure { None } else { Some(Cond::or(terms)) } }
    }

    pub fn list_filter(
        &self,
        subject: Principal,
        actors: &[Principal],
        ty: TypeId,
        action: Action,
        sp: &impl ScopePaths,
    ) -> ListFilter {
        let mut f = self.list_filter_one(subject, ty, action, sp);
        for &a in actors {
            if mutate() == 5 {
                break; // bug 5: the agent side is ignored
            }
            f = f.and(self.list_filter_one(a, ty, action, sp));
        }
        f
    }
}

fn push_ids(r: &Resolved, out: &mut Vec<String>) {
    if r.role.is_some() {
        out.push(format!("ra_{}", r.assign_id));
    }
    for c in &r.fired {
        out.push(format!("cond_{c}"));
    }
}
