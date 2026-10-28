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
    #[error("the list query failed: {0}")]
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
    fn as_sql(&self) -> &(dyn ToSql + Sync) {
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

    fn expr(&mut self, e: &FilterExpr) -> Result<String, SqlError> {
        let ancestors = ident(&self.cols.ancestors)?;
        Ok(match e {
            FilterExpr::True => "true".to_owned(),
            FilterExpr::False => "false".to_owned(),
            FilterExpr::And { args } => self.join(args, " AND ")?,
            FilterExpr::Or { args } => self.join(args, " OR ")?,
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
                format!("coalesce({ancestors} && {p}, false)")
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
    let mut b = Builder {
        cols,
        params: Vec::new(),
        first,
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
    let mut sql = format!(
        "{iss} = {p_iss} AND {tid} = {p_tid} AND cardinality({ancestors}) <= {MAX_PATH} \
         AND ({id} = ANY({p_ids}) OR coalesce({ancestors} && {p_in}, false))"
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
