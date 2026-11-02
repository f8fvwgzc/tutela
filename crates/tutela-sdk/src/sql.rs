//! The SQL adapter for [`ListFilter`] (CONTRACTS.md 6.6, PERMISSION-MODEL.md
//! 12.3, ADR-0011 F2).
//!
//! [`where_clause`] turns a filter into a `WHERE` fragment and its
//! parameters:
//! - every value is a **bound parameter**; no text is ever spliced in;
//! - column names come only from the product's [`Columns`] mapping, each
//!   checked as a plain identifier and quoted;
//! - the tenant predicate and the 32-ancestor bound are always added;
//! - each comparison is wrapped in `coalesce(..., false)`, so a `NULL`
//!   field never turns true under `not`;
//! - an op, a field or a value type the mapping cannot express is an error,
//!   and the caller fails closed (no rows).
//!
//! The ancestors column is a `text[]` of `type:id`, nearest first (the form
//! `tutela-store` keeps too). [`count`] and [`ids`] run the query with a
//! statement timeout; a timeout is an error, never a partial list.

use std::collections::HashMap;

use tokio_postgres::Transaction;
use tokio_postgres::types::ToSql;
use tutela_contracts::keys::FieldName;
use tutela_pdp::{FilterExpr, FilterValue, ListFilter, MAX_PATH, PathEntry};

/// Why a filter could not become SQL, or the query failed. The caller
/// fails closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqlError {
    /// A column name that is not a plain identifier.
    #[error("column `{0}` is not a plain SQL identifier")]
    Column(String),
    /// The filter reads a field the mapping has no column for.
    #[error("no column for field `{0}`")]
    UnmappedField(String),
    /// An op or a value this adapter does not know: refuse the filter.
    #[error("the filter has an op or value this adapter does not support")]
    Unsupported,
    /// The statement timed out, or failed.
    #[error("the list query failed")]
    Query(#[from] tokio_postgres::Error),
}

/// A bound parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    /// `text`.
    Text(String),
    /// `bigint`.
    Int(i64),
    /// `boolean`.
    Bool(bool),
    /// `text[]`.
    TextArray(Vec<String>),
    /// `bigint[]`.
    IntArray(Vec<i64>),
}

impl Param {
    pub(crate) fn as_sql(&self) -> &(dyn ToSql + Sync) {
        match self {
            Self::Text(v) => v,
            Self::Int(v) => v,
            Self::Bool(v) => v,
            Self::TextArray(v) => v,
            Self::IntArray(v) => v,
        }
    }
}

/// The product's table and columns.
#[derive(Clone, Debug)]
pub struct Columns {
    /// The table.
    pub table: String,
    /// The tenant's issuer.
    pub tenant_iss: String,
    /// The tenant id.
    pub tenant_tid: String,
    /// The row id.
    pub id: String,
    /// The ancestors, `text[]` of `type:id`, nearest first.
    pub ancestors: String,
    /// The column of each field a condition may read.
    pub fields: HashMap<FieldName, String>,
}

fn ident(name: &str) -> Result<String, SqlError> {
    if RESERVED.contains(&name) {
        return Err(SqlError::Column(name.to_owned()));
    }
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(format!("\"{name}\""))
    } else {
        Err(SqlError::Column(name.to_owned()))
    }
}

fn entry_text(e: &PathEntry) -> String {
    format!("{}:{}", e.type_name, e.id)
}

struct Builder<'a> {
    cols: &'a Columns,
    params: Vec<Param>,
    first: usize,
    /// Compile groups of same-shape terms as one lookup (ADR-0016).
    group: bool,
}

/// Groups smaller than this compile term by term.
const GROUP_MIN: usize = 4;

/// Scope lists longer than this are tested per ancestor with a hashed
/// `= ANY` (array overlap compares every pair and is far slower at the
/// limits); shorter ones keep `&&`, which a GIN index can serve.
const HASH_MIN: usize = 64;

/// "One of `scopes` (bound as `p`) is an ancestor", in the fast form for
/// its size. Never NULL when the ancestors column is not NULL.
fn under_sql(ancestors: &str, p: &str, len: usize) -> String {
    if len > HASH_MIN {
        format!(
            "EXISTS (SELECT 1 FROM unnest({ancestors}) AS tutela_anc(tutela_scope) \
             WHERE tutela_scope = ANY({p}))"
        )
    } else {
        format!("{ancestors} && {p}")
    }
}

/// Aliases the grouped form uses; product columns may not have these names.
const RESERVED: [&str; 4] = ["tutela_anc", "tutela_scope", "tutela_term", "tutela_vals"];

/// One term of an `or`: `under[scopes] AND rest`, where `rest` reads fields
/// only.
fn term(e: &FilterExpr) -> Option<(&[PathEntry], Vec<&FilterExpr>)> {
    let FilterExpr::And { args } = e else {
        return None;
    };
    let mut scopes = None;
    let mut rest = Vec::new();
    for a in args {
        match a {
            FilterExpr::Under { scopes: s } if scopes.is_none() => scopes = Some(s.as_slice()),
            other => rest.push(other),
        }
    }
    Some((scopes?, rest))
}

/// The shape of a condition that reads fields only: the AST with each value
/// replaced by a typed slot, and the values in slot order. `None` for a part
/// the grouped form cannot hold (`under`, `id_in`, `in`, an unknown op).
fn shape(e: &FilterExpr, values: &mut Vec<serde_json::Value>) -> Option<String> {
    fn slot(v: &FilterValue, values: &mut Vec<serde_json::Value>) -> &'static str {
        match v {
            FilterValue::String(s) => {
                values.push(serde_json::Value::String(s.clone()));
                "s"
            }
            FilterValue::Integer(i) => {
                values.push(serde_json::Value::from(*i));
                "i"
            }
            FilterValue::Boolean(b) => {
                values.push(serde_json::Value::Bool(*b));
                "b"
            }
        }
    }
    let list = |args: &[FilterExpr], values: &mut Vec<serde_json::Value>| {
        args.iter()
            .map(|a| shape(a, values))
            .collect::<Option<Vec<_>>>()
            .map(|v| v.join(","))
    };
    Some(match e {
        FilterExpr::True => "t".to_owned(),
        FilterExpr::False => "f".to_owned(),
        FilterExpr::And { args } => format!("and({})", list(args, values)?),
        FilterExpr::Or { args } => format!("or({})", list(args, values)?),
        FilterExpr::Not { arg } => format!("not({})", shape(arg, values)?),
        FilterExpr::Eq { attr, value } => format!("eq({attr},{})", slot(value, values)),
        FilterExpr::Ne { attr, value } => format!("ne({attr},{})", slot(value, values)),
        FilterExpr::Contains { attr, value } => {
            values.push(serde_json::Value::String(value.clone()));
            format!("contains({attr})")
        }
        FilterExpr::IsNull { attr } => format!("isnull({attr})"),
        _ => return None,
    })
}

/// A group of same-shape terms: one representative `rest`, and for each
/// scope the value lists of the terms that name it.
struct Group<'e> {
    rest: Vec<&'e FilterExpr>,
    by_scope: serde_json::Map<String, serde_json::Value>,
    terms: Vec<&'e FilterExpr>,
}

impl Builder<'_> {
    fn bind(&mut self, p: Param) -> String {
        self.params.push(p);
        format!("${}", self.first + self.params.len() - 1)
    }

    fn field(&self, f: &FieldName) -> Result<String, SqlError> {
        let col = self
            .cols
            .fields
            .get(f)
            .ok_or_else(|| SqlError::UnmappedField(f.to_string()))?;
        ident(col)
    }

    fn value(v: &FilterValue) -> Result<Param, SqlError> {
        Ok(match v {
            FilterValue::String(s) => Param::Text(s.clone()),
            FilterValue::Integer(i) => Param::Int(*i),
            FilterValue::Boolean(b) => Param::Bool(*b),
        })
    }

    /// `rest` with each value read from the term's slots (`tutela_vals`).
    fn slotted(&mut self, e: &FilterExpr, next: &mut usize) -> Result<String, SqlError> {
        let mut take = |v: Option<&FilterValue>| {
            let j = *next;
            *next += 1;
            let cast = match v {
                Some(FilterValue::Integer(_)) => "::bigint",
                Some(FilterValue::Boolean(_)) => "::boolean",
                _ => "",
            };
            format!("(tutela_vals ->> {j}){cast}")
        };
        Ok(match e {
            FilterExpr::True => "true".to_owned(),
            FilterExpr::False => "false".to_owned(),
            FilterExpr::And { args } | FilterExpr::Or { args } => {
                let op = if matches!(e, FilterExpr::And { .. }) {
                    " AND "
                } else {
                    " OR "
                };
                let mut parts = Vec::with_capacity(args.len());
                for a in args {
                    parts.push(self.slotted(a, next)?);
                }
                format!("({})", parts.join(op))
            }
            FilterExpr::Not { arg } => format!("(NOT {})", self.slotted(arg, next)?),
            FilterExpr::Eq { attr, value } => {
                let c = self.field(attr)?;
                format!("coalesce({c} = {}, false)", take(Some(value)))
            }
            FilterExpr::Ne { attr, value } => {
                let c = self.field(attr)?;
                format!("coalesce({c} <> {}, false)", take(Some(value)))
            }
            FilterExpr::Contains { attr, .. } => {
                let c = self.field(attr)?;
                format!("coalesce({} = ANY({c}), false)", take(None))
            }
            FilterExpr::IsNull { attr } => format!("({} IS NULL)", self.field(attr)?),
            _ => return Err(SqlError::Unsupported),
        })
    }

    /// An `or`: same-shape `under[S] AND rest` terms become one lookup per
    /// shape; everything else compiles as it is.
    fn or(&mut self, args: &[FilterExpr]) -> Result<String, SqlError> {
        if !self.group {
            return self.join(args, " OR ");
        }
        let mut groups: Vec<(String, Group<'_>)> = Vec::new();
        let mut parts = Vec::new();
        for a in args {
            let mut values = Vec::new();
            let grouped = term(a).and_then(|(scopes, rest)| {
                let key = rest
                    .iter()
                    .map(|r| shape(r, &mut values))
                    .collect::<Option<Vec<_>>>()?
                    .join("&");
                Some((scopes, rest, key))
            });
            let Some((scopes, rest, key)) = grouped else {
                parts.push(self.expr(a)?);
                continue;
            };
            let i = match groups.iter().position(|(k, _)| *k == key) {
                Some(i) => i,
                None => {
                    groups.push((
                        key,
                        Group {
                            rest,
                            by_scope: serde_json::Map::new(),
                            terms: Vec::new(),
                        },
                    ));
                    groups.len() - 1
                }
            };
            let Some((_, g)) = groups.get_mut(i) else {
                return Err(SqlError::Unsupported);
            };
            g.terms.push(a);
            for s in scopes {
                let slot = g
                    .by_scope
                    .entry(entry_text(s))
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                if let serde_json::Value::Array(list) = slot {
                    list.push(serde_json::Value::Array(values.clone()));
                }
            }
        }
        let ancestors = ident(&self.cols.ancestors)?;
        for (_, g) in groups {
            if g.terms.len() < GROUP_MIN {
                for t in g.terms {
                    parts.push(self.expr(t)?);
                }
                continue;
            }
            let mut next = 0;
            let mut rest = Vec::with_capacity(g.rest.len());
            for r in &g.rest {
                rest.push(self.slotted(r, &mut next)?);
            }
            let rest = if rest.is_empty() {
                "true".to_owned()
            } else {
                rest.join(" AND ")
            };
            let scopes = self.bind(Param::TextArray(g.by_scope.keys().cloned().collect()));
            let map = self.bind(Param::Text(
                serde_json::Value::Object(g.by_scope).to_string(),
            ));
            // Only an ancestor in the group's scope set (a hashed test) looks
            // its terms up in the map.
            parts.push(format!(
                "EXISTS (SELECT 1 FROM unnest({ancestors}) AS tutela_anc(tutela_scope) \
                 WHERE tutela_scope = ANY({scopes}) AND EXISTS (SELECT 1 FROM \
                 jsonb_array_elements(({map}::text::jsonb) -> tutela_scope) \
                 AS tutela_term(tutela_vals) WHERE {rest}))"
            ));
        }
        Ok(if parts.is_empty() {
            "false".to_owned()
        } else {
            format!("({})", parts.join(" OR "))
        })
    }

    fn expr(&mut self, e: &FilterExpr) -> Result<String, SqlError> {
        let ancestors = ident(&self.cols.ancestors)?;
        Ok(match e {
            FilterExpr::True => "true".to_owned(),
            FilterExpr::False => "false".to_owned(),
            FilterExpr::And { args } => self.join(args, " AND ")?,
            FilterExpr::Or { args } => self.or(args)?,
            FilterExpr::Not { arg } => format!("(NOT {})", self.expr(arg)?),
            FilterExpr::Eq { attr, value } => {
                let c = self.field(attr)?;
                let p = self.bind(Self::value(value)?);
                format!("coalesce({c} = {p}, false)")
            }
            FilterExpr::Ne { attr, value } => {
                let c = self.field(attr)?;
                let p = self.bind(Self::value(value)?);
                format!("coalesce({c} <> {p}, false)")
            }
            FilterExpr::In { attr, values } => {
                let c = self.field(attr)?;
                let array = match values.first() {
                    Some(FilterValue::String(_)) => Param::TextArray(
                        values
                            .iter()
                            .map(|v| match v {
                                FilterValue::String(s) => Ok(s.clone()),
                                _ => Err(SqlError::Unsupported),
                            })
                            .collect::<Result<_, _>>()?,
                    ),
                    Some(FilterValue::Integer(_)) => Param::IntArray(
                        values
                            .iter()
                            .map(|v| match v {
                                FilterValue::Integer(i) => Ok(*i),
                                _ => Err(SqlError::Unsupported),
                            })
                            .collect::<Result<_, _>>()?,
                    ),
                    _ => return Err(SqlError::Unsupported),
                };
                let p = self.bind(array);
                format!("coalesce({c} = ANY({p}), false)")
            }
            FilterExpr::Contains { attr, value } => {
                let c = self.field(attr)?;
                let p = self.bind(Param::Text(value.clone()));
                format!("coalesce({p} = ANY({c}), false)")
            }
            FilterExpr::IsNull { attr } => format!("({} IS NULL)", self.field(attr)?),
            FilterExpr::IdIn { ids } => {
                let id = ident(&self.cols.id)?;
                let p = self.bind(Param::TextArray(
                    ids.iter().map(ToString::to_string).collect(),
                ));
                format!("({id} = ANY({p}))")
            }
            FilterExpr::Under { scopes } => {
                let p = self.bind(Param::TextArray(scopes.iter().map(entry_text).collect()));
                format!(
                    "coalesce({}, false)",
                    under_sql(&ancestors, &p, scopes.len())
                )
            }
            _ => return Err(SqlError::Unsupported),
        })
    }

    fn join(&mut self, args: &[FilterExpr], op: &str) -> Result<String, SqlError> {
        let parts = args
            .iter()
            .map(|a| self.expr(a))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(format!("({})", parts.join(op)))
    }
}

/// The `WHERE` fragment of `filter` and its parameters, numbered from
/// `$first` (so the caller can add its own before).
///
/// # Errors
///
/// [`SqlError::Column`], [`SqlError::UnmappedField`] or
/// [`SqlError::Unsupported`]: the caller fails closed.
pub fn where_clause(
    filter: &ListFilter,
    cols: &Columns,
    first: usize,
) -> Result<(String, Vec<Param>), SqlError> {
    compile(filter, cols, first, true)
}

/// [`where_clause`] without grouping: every term compiles on its own. The
/// grouped form must list exactly the same rows (tested).
#[cfg(test)]
pub(crate) fn where_clause_plain(
    filter: &ListFilter,
    cols: &Columns,
    first: usize,
) -> Result<(String, Vec<Param>), SqlError> {
    compile(filter, cols, first, false)
}

fn compile(
    filter: &ListFilter,
    cols: &Columns,
    first: usize,
    group: bool,
) -> Result<(String, Vec<Param>), SqlError> {
    let mut b = Builder {
        cols,
        params: Vec::new(),
        first,
        group,
    };
    let iss = ident(&cols.tenant_iss)?;
    let tid = ident(&cols.tenant_tid)?;
    let id = ident(&cols.id)?;
    let ancestors = ident(&cols.ancestors)?;
    let p_iss = b.bind(Param::Text(filter.tenant.iss.as_str().to_owned()));
    let p_tid = b.bind(Param::Text(filter.tenant.tid.to_string()));
    let p_ids = b.bind(Param::TextArray(
        filter.ids_in.iter().map(ToString::to_string).collect(),
    ));
    let p_in = b.bind(Param::TextArray(
        filter.container_in.iter().map(entry_text).collect(),
    ));
    // The top-level test stays bare, so a GIN index on the ancestors can
    // serve it: here a NULL can only exclude a row, never let one through.
    // Inside the condition (under `not`) every test keeps its `coalesce`.
    let mut sql = format!(
        "{iss} = {p_iss} AND {tid} = {p_tid} AND cardinality({ancestors}) <= {MAX_PATH} \
         AND ({id} = ANY({p_ids}) OR {})",
        under_sql(&ancestors, &p_in, filter.container_in.len())
    );
    if let Some(c) = &filter.condition {
        sql.push_str(" AND ");
        sql.push_str(&b.expr(c)?);
    }
    Ok((sql, b.params))
}

async fn run(
    tx: &Transaction<'_>,
    filter: &ListFilter,
    cols: &Columns,
    timeout_ms: u32,
    select: &str,
) -> Result<Vec<tokio_postgres::Row>, SqlError> {
    tx.execute(&format!("SET LOCAL statement_timeout = {timeout_ms}"), &[])
        .await?;
    let (clause, params) = where_clause(filter, cols, 1)?;
    let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(Param::as_sql).collect();
    let sql = format!(
        "SELECT {select} FROM {} WHERE {clause}",
        ident(&cols.table)?
    );
    Ok(tx.query(&sql, &refs).await?)
}

/// The number of rows the filter lists, with a statement timeout.
///
/// # Errors
///
/// A [`SqlError`]; a timeout is [`SqlError::Query`], never a partial count.
pub async fn count(
    tx: &Transaction<'_>,
    filter: &ListFilter,
    cols: &Columns,
    timeout_ms: u32,
) -> Result<i64, SqlError> {
    let rows = run(tx, filter, cols, timeout_ms, "count(*)").await?;
    Ok(rows.first().map_or(Ok(0), |r| r.try_get(0))?)
}

/// The ids of the rows the filter lists, sorted, with a statement timeout.
///
/// # Errors
///
/// A [`SqlError`]; a timeout is [`SqlError::Query`], never a partial list.
pub async fn ids(
    tx: &Transaction<'_>,
    filter: &ListFilter,
    cols: &Columns,
    timeout_ms: u32,
) -> Result<Vec<String>, SqlError> {
    let id = ident(&cols.id)?;
    let mut out: Vec<String> = run(tx, filter, cols, timeout_ms, &id)
        .await?
        .iter()
        .map(|r| r.try_get(0))
        .collect::<Result<_, _>>()?;
    out.sort();
    Ok(out)
}
