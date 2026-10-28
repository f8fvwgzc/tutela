//! The list filter (CONTRACTS.md §6.6): `ids_in` + `container_in` + a
//! condition AST. Evaluated on rows in Rust, and compiled to SQL with bound
//! parameters only. THROWAWAY.

use crate::model::{Attrs, NodeId, Principal, TypeId, LABELS, STATUS};
use rustc_hash::FxHashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Col {
    Assignee,
    Status,
    Labels,
    Priority,
    Flag,
}

impl Col {
    fn sql(self) -> &'static str {
        match self {
            Col::Assignee => "assignee",
            Col::Status => "status",
            Col::Labels => "labels",
            Col::Priority => "priority",
            Col::Flag => "flag",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(&'static str),
    Principal(Principal),
    Int(i64),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub enum Cond {
    True,
    False,
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    Eq(Col, Val),
    In(Col, Vec<Val>),
    /// Array column holds the value.
    Contains(Col, &'static str),
    IdIn(Vec<NodeId>),
    /// One of the scopes is a (strict) ancestor of the row.
    Under(Vec<NodeId>),
}

impl Cond {
    pub fn and(mut v: Vec<Cond>) -> Cond {
        v.retain(|c| !matches!(c, Cond::True));
        if v.iter().any(|c| matches!(c, Cond::False)) {
            return Cond::False;
        }
        match v.len() {
            0 => Cond::True,
            1 => v.pop().unwrap_or(Cond::True),
            _ => Cond::And(v),
        }
    }
    pub fn or(mut v: Vec<Cond>) -> Cond {
        v.retain(|c| !matches!(c, Cond::False));
        if v.iter().any(|c| matches!(c, Cond::True)) {
            return Cond::True;
        }
        match v.len() {
            0 => Cond::False,
            1 => v.pop().unwrap_or(Cond::False),
            _ => Cond::Or(v),
        }
    }
    pub fn not(c: Cond) -> Cond {
        match c {
            Cond::True => Cond::False,
            Cond::False => Cond::True,
            c => Cond::Not(Box::new(c)),
        }
    }

    /// (nodes, depth)
    pub fn size(&self) -> (usize, usize) {
        match self {
            Cond::And(v) | Cond::Or(v) => {
                let mut n = 1;
                let mut d = 0;
                for c in v {
                    let (cn, cd) = c.size();
                    n += cn;
                    d = d.max(cd);
                }
                (n, d + 1)
            }
            Cond::Not(c) => {
                let (n, d) = c.size();
                (n + 1, d + 1)
            }
            _ => (1, 1),
        }
    }

    /// How many `not` nodes nest inside each other at most.
    pub fn not_nesting(&self) -> usize {
        match self {
            Cond::And(v) | Cond::Or(v) => v.iter().map(Cond::not_nesting).max().unwrap_or(0),
            Cond::Not(c) => 1 + c.not_nesting(),
            _ => 0,
        }
    }
}

/// "The row is this scope, or under it." Same-type scopes can be the row.
pub fn at_or_under(scopes: &[(NodeId, bool)]) -> Cond {
    let ids: Vec<NodeId> = scopes.iter().filter(|s| s.1).map(|s| s.0).collect();
    let all: Vec<NodeId> = scopes.iter().map(|s| s.0).collect();
    let mut v = Vec::new();
    if !ids.is_empty() {
        v.push(Cond::IdIn(ids));
    }
    if !all.is_empty() {
        v.push(Cond::Under(all));
    }
    Cond::or(v)
}

#[derive(Clone, Debug)]
pub struct ListFilter {
    pub ty: TypeId,
    pub ids_in: Vec<NodeId>,
    pub container_in: Vec<NodeId>,
    pub condition: Option<Cond>,
}

impl ListFilter {
    /// Both filters must pass (delegation: person AND agent).
    pub fn and(self, other: ListFilter) -> ListFilter {
        let mut pos = Vec::new();
        if !other.ids_in.is_empty() {
            pos.push(Cond::IdIn(other.ids_in));
        }
        if !other.container_in.is_empty() {
            pos.push(Cond::Under(other.container_in));
        }
        let mut parts = Vec::new();
        if let Some(c) = self.condition {
            parts.push(c);
        }
        parts.push(Cond::or(pos));
        if let Some(c) = other.condition {
            parts.push(c);
        }
        ListFilter { ty: self.ty, ids_in: self.ids_in, container_in: self.container_in, condition: Some(Cond::and(parts)) }
    }
}

// ---------- evaluation on a row (Rust) ----------

pub struct Row<'a> {
    pub id: NodeId,
    pub anc: &'a [NodeId],
    pub attrs: &'a Attrs,
}

enum P {
    True,
    False,
    And(Vec<P>),
    Or(Vec<P>),
    Not(Box<P>),
    Eq(Col, Val),
    In(Col, Vec<Val>),
    Contains(&'static str),
    IdIn(FxHashSet<NodeId>),
    Under(FxHashSet<NodeId>),
}

pub struct Prepared {
    ids_in: FxHashSet<NodeId>,
    container_in: FxHashSet<NodeId>,
    cond: Option<P>,
}

fn prep(c: &Cond) -> P {
    match c {
        Cond::True => P::True,
        Cond::False => P::False,
        Cond::And(v) => P::And(v.iter().map(prep).collect()),
        Cond::Or(v) => P::Or(v.iter().map(prep).collect()),
        Cond::Not(x) => P::Not(Box::new(prep(x))),
        Cond::Eq(c, v) => P::Eq(*c, v.clone()),
        Cond::In(c, v) => P::In(*c, v.clone()),
        Cond::Contains(_, s) => P::Contains(s),
        Cond::IdIn(v) => P::IdIn(v.iter().copied().collect()),
        Cond::Under(v) => P::Under(v.iter().copied().collect()),
    }
}

/// The row's value as a filter value, or None for SQL NULL.
fn value(a: &Attrs, c: Col) -> Option<Val> {
    match c {
        Col::Assignee => a.assignee.map(Val::Principal),
        Col::Status => a.status.map(|s| Val::Str(STATUS[s as usize])),
        Col::Priority => a.priority.map(Val::Int),
        Col::Flag => a.flag.map(Val::Bool),
        Col::Labels => None,
    }
}

fn eval(p: &P, r: &Row) -> bool {
    match p {
        P::True => true,
        P::False => false,
        P::And(v) => v.iter().all(|x| eval(x, r)),
        P::Or(v) => v.iter().any(|x| eval(x, r)),
        P::Not(x) => !eval(x, r),
        // Comparing with NULL is false.
        P::Eq(c, v) => value(r.attrs, *c).is_some_and(|x| &x == v),
        P::In(c, vs) => value(r.attrs, *c).is_some_and(|x| vs.contains(&x)),
        P::Contains(s) => r
            .attrs
            .labels
            .is_some_and(|m| LABELS.iter().enumerate().any(|(i, l)| l == s && m & (1 << i) != 0)),
        P::IdIn(set) => set.contains(&r.id),
        P::Under(set) => r.anc.iter().any(|a| set.contains(a)),
    }
}

impl Prepared {
    pub fn new(f: &ListFilter) -> Prepared {
        Prepared {
            ids_in: f.ids_in.iter().copied().collect(),
            container_in: f.container_in.iter().copied().collect(),
            cond: f.condition.as_ref().map(prep),
        }
    }
    pub fn matches(&self, r: &Row) -> bool {
        (self.ids_in.contains(&r.id) || r.anc.iter().any(|a| self.container_in.contains(a)))
            && self.cond.as_ref().is_none_or(|c| eval(c, r))
    }
}

// ---------- SQL ----------

#[derive(Debug)]
pub enum Param {
    I64s(Vec<i64>),
    Str(String),
    Strs(Vec<String>),
    I64(i64),
    Bool(bool),
}

fn val_param(v: &Val) -> Param {
    match v {
        Val::Str(s) => Param::Str((*s).to_string()),
        Val::Principal(p) => Param::Str(p.text()),
        Val::Int(i) => Param::I64(*i),
        Val::Bool(b) => Param::Bool(*b),
    }
}

/// `under` as SQL. `Ancestors::Array` uses the `bigint[]` column; `Closure`
/// uses an `item_ancestor` table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ancestors {
    Array,
    Closure,
}

struct Sql<'a> {
    params: &'a mut Vec<Param>,
    anc: Ancestors,
}

impl Sql<'_> {
    fn bind(&mut self, p: Param) -> String {
        self.params.push(p);
        format!("${}", self.params.len())
    }
    fn under(&mut self, ids: &[NodeId]) -> String {
        let n = self.bind(Param::I64s(ids.iter().map(|&x| x as i64).collect()));
        match self.anc {
            Ancestors::Array => format!("i.ancestors && {n}"),
            Ancestors::Closure => format!(
                "EXISTS (SELECT 1 FROM item_ancestor x WHERE x.tenant_id = i.tenant_id AND x.item_id = i.id AND x.ancestor_id = ANY({n}))"
            ),
        }
    }
    fn cond(&mut self, c: &Cond) -> String {
        match c {
            Cond::True => "TRUE".into(),
            Cond::False => "FALSE".into(),
            Cond::And(v) => format!("({})", v.iter().map(|x| self.cond(x)).collect::<Vec<_>>().join(" AND ")),
            Cond::Or(v) => format!("({})", v.iter().map(|x| self.cond(x)).collect::<Vec<_>>().join(" OR ")),
            Cond::Not(x) => format!("(NOT {})", self.cond(x)),
            // Every leaf is NOT NULL, so NOT and OR keep two-valued logic.
            Cond::Eq(col, v) if crate::eval::mutate() == 6 => {
                let n = self.bind(val_param(v));
                format!("i.{} = {n}", col.sql()) // bug 6: NULL leaks into NOT
            }
            Cond::Eq(col, v) => {
                let n = self.bind(val_param(v));
                format!("COALESCE(i.{} = {n}, FALSE)", col.sql())
            }
            Cond::In(col, vs) => {
                let p = match vs.first() {
                    Some(Val::Int(_)) => Param::I64s(
                        vs.iter().filter_map(|v| if let Val::Int(i) = v { Some(*i) } else { None }).collect(),
                    ),
                    _ => Param::Strs(
                        vs.iter()
                            .map(|v| match v {
                                Val::Str(s) => (*s).to_string(),
                                Val::Principal(p) => p.text(),
                                Val::Int(i) => i.to_string(),
                                Val::Bool(b) => b.to_string(),
                            })
                            .collect(),
                    ),
                };
                let n = self.bind(p);
                format!("COALESCE(i.{} = ANY({n}), FALSE)", col.sql())
            }
            Cond::Contains(col, s) => {
                let n = self.bind(Param::Str((*s).to_string()));
                format!("COALESCE({n} = ANY(i.{}), FALSE)", col.sql())
            }
            Cond::IdIn(ids) => {
                let n = self.bind(Param::I64s(ids.iter().map(|&x| x as i64).collect()));
                format!("i.id = ANY({n})")
            }
            Cond::Under(ids) => self.under(ids),
        }
    }
}

/// The WHERE clause after `tenant_id = $1 AND type = $2`. Params start at $3.
pub fn to_sql(f: &ListFilter, anc: Ancestors, params: &mut Vec<Param>) -> String {
    let mut s = Sql { params, anc };
    let ids = s.bind(Param::I64s(f.ids_in.iter().map(|&x| x as i64).collect()));
    let under = s.under(&f.container_in);
    let mut w = format!("(i.id = ANY({ids}) OR {under})");
    if let Some(c) = &f.condition {
        w.push_str(" AND ");
        w.push_str(&s.cond(c));
    }
    w
}
