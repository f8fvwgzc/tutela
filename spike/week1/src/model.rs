//! The Tutela side of the data (what tutela-store would hold), compiled into
//! in-memory indexes. THROWAWAY spike code.

use rustc_hash::{FxHashMap, FxHashSet};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Level {
    #[default]
    None,
    Read,
    Write,
    Full,
}

impl Level {
    pub const ALL: [Level; 4] = [Level::None, Level::Read, Level::Write, Level::Full];
    pub fn name(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Read => "read",
            Level::Write => "write",
            Level::Full => "full",
        }
    }
}

pub type NodeId = u32;
pub type TypeId = u16;
pub type RoleId = u16;

/// The seeded Owner role.
pub const OWNER: RoleId = 0;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Principal {
    User(u32),
    Agent(u32),
}

impl Principal {
    pub fn text(self) -> String {
        match self {
            Principal::User(n) => format!("user:u{n}"),
            Principal::Agent(n) => format!("agent:a{n}"),
        }
    }
}

/// Who an assignment is for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Subject {
    User(u32),
    Agent(u32),
    Group(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Read,
    Write,
    Delete,
    Approve,
    Export,
}

impl Action {
    pub const ALL: [Action; 5] = [Action::Read, Action::Write, Action::Delete, Action::Approve, Action::Export];
    pub fn need(self) -> Level {
        match self {
            Action::Read | Action::Export => Level::Read,
            Action::Write | Action::Approve => Level::Write,
            Action::Delete => Level::Full,
        }
    }
    /// The grant bit a custom action needs on the role.
    pub fn grant(self) -> Option<u8> {
        match self {
            Action::Approve => Some(0),
            Action::Export => Some(1),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Approve => "approve",
            Action::Export => "export",
        }
    }
}

pub const STATUS: [&str; 3] = ["open", "closed", "review"];
pub const LABELS: [&str; 4] = ["a", "b", "c", "client_visible"];

/// Row attributes that conditions read. `None` = SQL NULL.
#[derive(Clone, Debug, Default)]
pub struct Attrs {
    pub assignee: Option<Principal>,
    pub status: Option<u8>,
    /// Bit mask over LABELS.
    pub labels: Option<u8>,
    pub priority: Option<i64>,
    pub flag: Option<bool>,
}

impl Attrs {
    pub fn has_null(&self) -> bool {
        self.assignee.is_none()
            || self.status.is_none()
            || self.labels.is_none()
            || self.priority.is_none()
            || self.flag.is_none()
    }
}

/// A vetted condition template (PERMISSION-MODEL open point 6).
#[derive(Clone, Debug)]
pub enum Tpl {
    StatusEq(u8),
    StatusIn(Vec<u8>),
    PriorityEq(i64),
    FlagEq(bool),
    LabelsContain(u8),
    AssigneeIsPrincipal,
    InGroup(u32),
    And(Vec<Tpl>),
    Or(Vec<Tpl>),
    Not(Box<Tpl>),
}

pub struct TypeDef {
    pub name: String,
    /// Field and feature names, sorted. At most 64.
    pub fields: Vec<String>,
}

pub struct Role {
    /// Per type.
    pub type_level: Vec<Level>,
    /// Per type, per field: the level the role sets, if any.
    pub field_level: Vec<Vec<Option<Level>>>,
    /// Per type: grant bits for custom actions.
    pub grants: Vec<u8>,
}

pub struct Condition {
    pub id: u32,
    pub role: RoleId,
    pub ty: TypeId,
    pub scope: NodeId,
    pub tpl: Tpl,
    pub lif: Level,
}

pub struct FieldRule {
    pub id: u32,
    pub scope: NodeId,
    pub ty: TypeId,
    pub field: u16,
    /// None = all roles.
    pub role: Option<RoleId>,
    pub max: Level,
}

pub struct Assignment {
    pub id: u32,
    pub subject: Subject,
    pub scope: NodeId,
    pub role: RoleId,
}

pub struct ModelInput {
    pub types: Vec<TypeDef>,
    pub roles: Vec<Role>,
    pub assignments: Vec<Assignment>,
    /// Per group: the groups it is a direct member of.
    pub group_parents: Vec<Vec<u32>>,
    /// Per user: the groups the user is a direct member of.
    pub user_groups: Vec<Vec<u32>>,
    pub private: Vec<NodeId>,
    pub rules: Vec<FieldRule>,
    pub conds: Vec<Condition>,
    pub org: NodeId,
}

/// Everything Tutela knows about one scope.
#[derive(Default)]
pub struct NodeData {
    pub assigns: Vec<(Subject, RoleId, u32)>,
    pub private: bool,
    /// Indexes into Model::conds.
    pub conds: Vec<u32>,
    /// Indexes into Model::rules.
    pub rules: Vec<u32>,
}

pub struct Model {
    pub types: Vec<TypeDef>,
    pub roles: Vec<Role>,
    pub rules: Vec<FieldRule>,
    pub conds: Vec<Condition>,
    pub nodes: FxHashMap<NodeId, NodeData>,
    pub by_subject: FxHashMap<Subject, Vec<NodeId>>,
    /// Per user: transitive groups as a bit set.
    group_bits: Vec<u64>,
    words: usize,
    /// Per user: transitive groups, sorted.
    pub user_groups: Vec<Vec<u32>>,
    /// Per group: transitive parent groups (not itself), sorted.
    pub group_ancestors: Vec<Vec<u32>>,
    pub private_list: Vec<NodeId>,
    pub conds_by_role_type: FxHashMap<(RoleId, TypeId), Vec<u32>>,
    pub org: NodeId,
}

impl Model {
    pub fn compile(input: ModelInput) -> Model {
        let groups = input.group_parents.len();
        // Transitive parents of each group (a DAG; memoised DFS).
        let mut anc: Vec<Option<Vec<u32>>> = vec![None; groups];
        fn up(g: usize, parents: &[Vec<u32>], anc: &mut Vec<Option<Vec<u32>>>) -> Vec<u32> {
            if let Some(a) = &anc[g] {
                return a.clone();
            }
            let mut set = FxHashSet::default();
            for &p in &parents[g] {
                set.insert(p);
                for x in up(p as usize, parents, anc) {
                    set.insert(x);
                }
            }
            let mut v: Vec<u32> = set.into_iter().collect();
            v.sort_unstable();
            anc[g] = Some(v.clone());
            v
        }
        for g in 0..groups {
            up(g, &input.group_parents, &mut anc);
        }
        let group_ancestors: Vec<Vec<u32>> = anc.into_iter().map(|a| a.unwrap_or_default()).collect();
        let words = groups.div_ceil(64).max(1);
        let mut group_bits = vec![0u64; words * input.user_groups.len()];
        let mut user_groups = Vec::with_capacity(input.user_groups.len());
        for (u, direct) in input.user_groups.iter().enumerate() {
            let mut set = FxHashSet::default();
            for &g in direct {
                set.insert(g);
                for &a in &group_ancestors[g as usize] {
                    set.insert(a);
                }
            }
            let mut v: Vec<u32> = set.into_iter().collect();
            v.sort_unstable();
            for &g in &v {
                group_bits[u * words + (g as usize / 64)] |= 1 << (g % 64);
            }
            user_groups.push(v);
        }

        let mut nodes: FxHashMap<NodeId, NodeData> = FxHashMap::default();
        let mut by_subject: FxHashMap<Subject, Vec<NodeId>> = FxHashMap::default();
        for a in &input.assignments {
            nodes.entry(a.scope).or_default().assigns.push((a.subject, a.role, a.id));
            by_subject.entry(a.subject).or_default().push(a.scope);
        }
        for &p in &input.private {
            nodes.entry(p).or_default().private = true;
        }
        let mut conds_by_role_type: FxHashMap<(RoleId, TypeId), Vec<u32>> = FxHashMap::default();
        for (i, c) in input.conds.iter().enumerate() {
            nodes.entry(c.scope).or_default().conds.push(i as u32);
            conds_by_role_type.entry((c.role, c.ty)).or_default().push(i as u32);
        }
        for (i, r) in input.rules.iter().enumerate() {
            nodes.entry(r.scope).or_default().rules.push(i as u32);
        }
        Model {
            types: input.types,
            roles: input.roles,
            rules: input.rules,
            conds: input.conds,
            nodes,
            by_subject,
            group_bits,
            words,
            user_groups,
            group_ancestors,
            private_list: input.private,
            conds_by_role_type,
            org: input.org,
        }
    }

    pub fn in_group(&self, user: u32, g: u32) -> bool {
        let w = self.group_bits[user as usize * self.words + (g as usize / 64)];
        w & (1 << (g % 64)) != 0
    }

    pub fn grant_ok(&self, role: RoleId, ty: TypeId, action: Action) -> bool {
        match action.grant() {
            None => true,
            Some(bit) => self.roles[role as usize].grants[ty as usize] & (1 << bit) != 0,
        }
    }
}
