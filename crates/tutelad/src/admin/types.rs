//! `PutResourceTypes` (PERMISSION-MODEL.md 15, INTEGRATION.md onto-intelli
//! step 6, CONTRACTS.md 7.13.3, ADR-0040).
//!
//! onto-intelli pushes its object, link and action types. They are merged
//! into the tenant's active model and stored as a **proposal**, never
//! published: a tenant admin approves it (POST
//! /v1/models/proposals/{id}/approve), with an approval token when it widens,
//! as for any proposal (ADR-0029). The push is additive: it may add types,
//! and add fields, actions, features and parents to a type; it never
//! removes or changes what the model has (409 `not_additive`). A new
//! confidential or secret field starts at None for every role, as the
//! compiler makes every such field (MANIFEST.md 4).
//!
//! The proposal's text is the active model, parsed and written again with
//! the new entries: the merged text keeps every value, not the comments.

use axum::http::StatusCode;
use serde_json::{Map, Value as Json};
use toml::{Table, Value as Toml};
use tutela_sdk::Identity;

use super::wire::ResourceTypesBody;
use super::{guard, required};
use crate::api::{AppState, Problem};
use crate::models::wire::{ProposalOut, PublishBody};
use crate::models::{self, WRITE_KEYS};
use crate::tenant::Tenant;

/// The most types one push may name.
const MAX_TYPES: usize = 512;

fn invalid(detail: String) -> Problem {
    Problem::invalid("invalid_request", detail)
}

fn not_additive(ty: &str, key: &str) -> Problem {
    Problem {
        detail: Some(format!("type `{ty}`, key `{key}`")),
        ..Problem::new(
            StatusCode::CONFLICT,
            "not_additive",
            "the push changes what the model has; only new types and entries are taken",
        )
    }
}

/// A JSON value as TOML: no `null`, whole numbers only.
fn to_toml(v: &Json) -> Option<Toml> {
    match v {
        Json::Null => None,
        Json::Bool(b) => Some(Toml::Boolean(*b)),
        Json::Number(n) => n.as_i64().map(Toml::Integer),
        Json::String(s) => Some(Toml::String(s.clone())),
        Json::Array(a) => a
            .iter()
            .map(to_toml)
            .collect::<Option<_>>()
            .map(Toml::Array),
        Json::Object(o) => o
            .iter()
            .map(|(k, v)| Some((k.clone(), to_toml(v)?)))
            .collect::<Option<Table>>()
            .map(Toml::Table),
    }
}

/// A string or a list of them, as a list.
fn as_list(v: Toml) -> Option<Vec<Toml>> {
    match v {
        Toml::String(_) => Some(vec![v]),
        Toml::Array(a) => Some(a),
        _ => None,
    }
}

/// `old` with the items of `new` it lacks. `true` when it grew.
fn union(ty: &str, key: &str, old: &mut Toml, new: Toml) -> Result<bool, Problem> {
    let mut list = as_list(old.clone()).ok_or_else(|| not_additive(ty, key))?;
    let mut grew = false;
    for item in as_list(new).ok_or_else(|| not_additive(ty, key))? {
        if !list.contains(&item) {
            list.push(item);
            grew = true;
        }
    }
    if grew {
        *old = Toml::Array(list);
    }
    Ok(grew)
}

/// Merges the pushed definition `new` of type `ty` into `have`. `true` when
/// something was added.
fn merge_type(ty: &str, have: &mut Table, new: Table) -> Result<bool, Problem> {
    let mut changed = false;
    for (key, value) in new {
        match (key.as_str(), have.get_mut(&key)) {
            (_, None) => {
                have.insert(key, value);
                changed = true;
            }
            ("parent" | "features", Some(old)) => changed |= union(ty, &key, old, value)?,
            ("fields" | "actions", Some(Toml::Table(old))) => {
                let Toml::Table(entries) = value else {
                    return Err(not_additive(ty, &key));
                };
                for (name, entry) in entries {
                    match old.get(&name) {
                        None => {
                            old.insert(name, entry);
                            changed = true;
                        }
                        Some(o) if *o == entry => {}
                        Some(_) => return Err(not_additive(ty, &format!("{key}.{name}"))),
                    }
                }
            }
            (_, Some(old)) if *old == value => {}
            _ => return Err(not_additive(ty, &key)),
        }
    }
    Ok(changed)
}

/// The active model `active` with `pushed` merged in, or `None` when the
/// push adds nothing.
///
/// # Errors
///
/// 400 for a push that is not an object of objects, 409 `not_additive`.
pub(crate) fn merge(active: &str, pushed: &Map<String, Json>) -> Result<Option<String>, Problem> {
    let mut doc: Table = active.parse().map_err(|_| {
        tracing::error!("the active model does not parse as TOML");
        Problem::stale("unavailable")
    })?;
    let types = doc
        .entry("types".to_owned())
        .or_insert_with(|| Toml::Table(Table::new()));
    let Toml::Table(types) = types else {
        return Err(Problem::stale("unavailable"));
    };
    let mut changed = false;
    for (name, def) in pushed {
        let Some(Toml::Table(def)) = to_toml(def) else {
            return Err(invalid(format!(
                "type `{name}` is not an object of strings, whole numbers, booleans, lists and objects"
            )));
        };
        match types.get_mut(name) {
            None => {
                types.insert(name.clone(), Toml::Table(def));
                changed = true;
            }
            Some(Toml::Table(have)) => changed |= merge_type(name, have, def)?,
            Some(_) => return Err(not_additive(name, name)),
        }
    }
    if !changed {
        return Ok(None);
    }
    toml::to_string(&doc).map(Some).map_err(|_| {
        tracing::error!("a merged model could not be written as TOML");
        Problem::stale("unavailable")
    })
}

/// `POST /v1/admin/resource-types`: merges the pushed types into the active
/// model and stores the result as a proposal, as `POST
/// /v1/models/proposals` does, with `origin: resource_types` in its audit
/// record. Needs what changing the model needs (ADR-0026 item 8).
///
/// # Errors
///
/// A [`Problem`]: 409 `version_conflict`, `not_additive` or `no_change`,
/// 400 `invalid_manifest` when the merged model does not compile.
pub async fn put_resource_types(
    state: &AppState,
    id: &Identity,
    body: ResourceTypesBody,
) -> Result<ProposalOut, Problem> {
    let tenant = Tenant::of(id);
    let types = required(body.types, "types")?;
    if types.is_empty() || types.len() > MAX_TYPES {
        return Err(invalid(format!("`types` names 1 to {MAX_TYPES} types")));
    }
    guard(
        state,
        id,
        &tenant,
        &WRITE_KEYS,
        "tutela_proposal:propose",
        ("tutela_proposal", "resource_types"),
    )
    .await?;
    let now = models::current(state, &tenant).await?;
    if body
        .expected_version
        .is_some_and(|v| v != now.active.version)
    {
        return Err(Problem::new(
            StatusCode::CONFLICT,
            "version_conflict",
            "a newer model; compare again",
        ));
    }
    let source = merge(&now.active.source, &types)?.ok_or_else(|| {
        Problem::new(
            StatusCode::CONFLICT,
            "no_change",
            "the model has every pushed type and entry",
        )
    })?;
    models::propose_from(
        state,
        id,
        PublishBody {
            source: Some(source),
            restore: None,
            expected_version: Some(now.active.version),
            approval: None,
        },
        Some("resource_types"),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASE: &str = "version = 1\n[app]\nname = \"crm\"\n\n[types.project]\nparent = \"org\"\ncontainer = true\n\n[types.invoice]\nparent = \"project\"\n[types.invoice.fields]\nstatus = { sensitivity = \"internal\" }\n";

    fn push(v: Json) -> Map<String, Json> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_new_type_and_new_entries_are_added() {
        let out = merge(
            BASE,
            &push(json!({
                "object": {"parent": "project", "fields": {"name": {"sensitivity": "internal"}}},
                "invoice": {"fields": {"total": {"sensitivity": "secret", "type": "integer"}},
                            "features": ["ai"]},
            })),
        )
        .unwrap()
        .unwrap();
        let t: Table = out.parse().unwrap();
        let types = t["types"].as_table().unwrap();
        assert!(types.contains_key("object"));
        let inv = types["invoice"].as_table().unwrap();
        assert!(inv["fields"].as_table().unwrap().contains_key("status"));
        assert!(inv["fields"].as_table().unwrap().contains_key("total"));
        assert_eq!(inv["features"].as_array().unwrap().len(), 1);
        tutela_pdp::model::Model::from_toml(&out).unwrap();
    }

    #[test]
    fn a_push_that_changes_an_entry_is_refused() {
        for bad in [
            json!({"invoice": {"fields": {"status": {"sensitivity": "public"}}}}),
            json!({"project": {"container": false}}),
            json!({"invoice": {"fields": "x"}}),
        ] {
            let e = merge(BASE, &push(bad.clone())).unwrap_err();
            assert_eq!(e.code, "not_additive", "{bad}");
        }
    }

    #[test]
    fn a_push_of_what_is_there_changes_nothing() {
        let same = json!({"invoice": {"parent": "project", "fields": {"status": {"sensitivity": "internal"}}}});
        assert_eq!(merge(BASE, &push(same)).unwrap(), None);
    }

    #[test]
    fn a_parent_list_grows_by_union() {
        let out = merge(
            BASE,
            &push(json!({"invoice": {"parent": ["project", "org"]}})),
        )
        .unwrap()
        .unwrap();
        let t: Table = out.parse().unwrap();
        let parents = t["types"]["invoice"]["parent"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
    }

    #[test]
    fn null_and_fractions_are_refused() {
        for bad in [
            json!({"x": {"parent": null}}),
            json!({"x": {"n": 1.5}}),
            json!({"x": 1}),
        ] {
            assert_eq!(merge(BASE, &push(bad)).unwrap_err().code, "invalid_request");
        }
    }
}
