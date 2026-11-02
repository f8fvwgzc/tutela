//! The JSON of the remote check API (CONTRACTS.md 7), and what it parses
//! into. HTTP deserializes these types and gRPC builds them, so both reach
//! the same code with the same input. Readers ignore unknown fields, and a
//! missing field is the same as `null` (CONTRACTS.md 0).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tutela_contracts::claims::Actor;
use tutela_contracts::decision::Decision;
use tutela_contracts::keys::{ActionKey, FieldName, ResourceId, ResourceType};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::{AttrValue, Attrs, CheckRequest, ListFilter, PathEntry, ResourceRef};

/// `subject`. `id` is optional here because a subject search leaves it out.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Subject {
    /// The principal kind.
    #[serde(rename = "type")]
    pub kind: String,
    /// The full principal string.
    pub id: Option<String>,
    /// `properties`.
    pub properties: Option<SubjectProperties>,
}

/// `subject.properties`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SubjectProperties {
    /// The actor chain, as in the token's `act` claim.
    pub act: Option<Actor>,
}

/// `action`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Action {
    /// An action key.
    pub name: String,
}

/// One node of a path.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Entry {
    /// A type name.
    #[serde(rename = "type")]
    pub kind: String,
    /// The product's own id.
    pub id: String,
}

/// `resource`. `id` is optional here because a resource search leaves it out.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Resource {
    /// A type name.
    #[serde(rename = "type")]
    pub kind: String,
    /// The product's own id.
    pub id: Option<String>,
    /// `properties`.
    pub properties: Option<ResourceProperties>,
}

/// `resource.properties`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ResourceProperties {
    /// The ancestors, nearest first; the last is the org.
    pub path: Option<Vec<Entry>>,
    /// The field values conditions read.
    pub attrs: Option<BTreeMap<String, serde_json::Value>>,
}

/// `context`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Context {
    /// Limits the field mask to these names.
    pub fields: Option<Vec<String>>,
    /// Sent after the caller's own write.
    pub at_least_revision: Option<u64>,
}

/// The body of `POST /access/v1/evaluation`, and one item of a batch.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EvaluationBody {
    /// Who.
    pub subject: Option<Subject>,
    /// What.
    pub action: Option<Action>,
    /// On what.
    pub resource: Option<Resource>,
    /// Extra input.
    pub context: Option<Context>,
}

/// `options` of a batch.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Options {
    /// `execute_all`, `deny_on_first_deny` or `permit_on_first_permit`.
    pub evaluations_semantic: Option<String>,
}

/// The body of `POST /access/v1/evaluations`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EvaluationsBody {
    /// The default subject.
    pub subject: Option<Subject>,
    /// The default action.
    pub action: Option<Action>,
    /// The default resource.
    pub resource: Option<Resource>,
    /// The default context.
    pub context: Option<Context>,
    /// The items.
    pub evaluations: Option<Vec<EvaluationBody>>,
    /// How to run them.
    pub options: Option<Options>,
}

impl EvaluationsBody {
    /// The top-level defaults, as one evaluation.
    #[must_use]
    pub fn defaults(&self) -> EvaluationBody {
        EvaluationBody {
            subject: self.subject.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
            context: self.context.clone(),
        }
    }
}

impl EvaluationBody {
    /// This item, with `defaults` for each key it does not set. A key in the
    /// item replaces the default as a whole.
    #[must_use]
    pub fn or(self, defaults: &EvaluationBody) -> Self {
        Self {
            subject: self.subject.or_else(|| defaults.subject.clone()),
            action: self.action.or_else(|| defaults.action.clone()),
            resource: self.resource.or_else(|| defaults.resource.clone()),
            context: self.context.or_else(|| defaults.context.clone()),
        }
    }
}

/// An item that could not be evaluated (AuthZEN 1.0 section 7).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ItemError {
    /// The status the item would have had alone.
    pub status: u16,
    /// What is wrong, in short English.
    pub message: String,
}

/// `context` of a result.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResultContext {
    /// The full Decision object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tutela: Option<Decision>,
    /// Why this item has no decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ItemError>,
}

/// One answer. `decision` is `true` exactly when the Decision allows.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EvaluationResult {
    /// The answer.
    pub decision: bool,
    /// The details.
    pub context: ResultContext,
}

impl EvaluationResult {
    /// The answer of `decision`. A decision with an obligation this build
    /// does not know is a deny.
    #[must_use]
    pub fn of(decision: Decision) -> Self {
        Self {
            decision: decision.is_allowed(),
            context: ResultContext {
                tutela: Some(decision),
                error: None,
            },
        }
    }

    /// An item with no decision. It never allows.
    #[must_use]
    pub const fn failed(error: ItemError) -> Self {
        Self {
            decision: false,
            context: ResultContext {
                tutela: None,
                error: Some(error),
            },
        }
    }
}

/// The answer of `POST /access/v1/evaluations`. With no items, the request
/// is one evaluation, and so is the answer (AuthZEN 1.0 section 7).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EvaluationsResult {
    /// The request had no items.
    One(EvaluationResult),
    /// One result per item that ran, in order.
    Many {
        /// The results.
        evaluations: Vec<EvaluationResult>,
    },
}

/// `page` of a search request (AuthZEN 1.0 section 8).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Page {
    /// The `next_token` of the page before.
    pub token: Option<String>,
    /// How many results. Missing or `0`: the default.
    pub limit: Option<u64>,
}

/// The body of a search.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SearchBody {
    /// Who, or for a subject search only the kind.
    pub subject: Option<Subject>,
    /// What.
    pub action: Option<Action>,
    /// On what, or for a resource search only the type.
    pub resource: Option<Resource>,
    /// Extra input.
    pub context: Option<Context>,
    /// Which page.
    pub page: Option<Page>,
}

/// `page` of a search response. `next_token` is empty on the last page.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PageOut {
    /// The next page's token.
    pub next_token: String,
    /// The results in this page.
    pub count: usize,
}

/// `context.tutela` of a resource search.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourceContext {
    /// The revision that was used.
    pub rev: u64,
    /// The CONTRACTS.md 6.6 filter, for the product's own SQL.
    pub filter: ListFilter,
}

/// `context` of a resource search.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourceContextOut {
    /// The details.
    pub tutela: ResourceContext,
}

/// The answer of `POST /access/v1/search/resource`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourceResults {
    /// The resources.
    pub results: Vec<Entry>,
    /// The page.
    pub page: PageOut,
    /// The revision and the filter.
    pub context: ResourceContextOut,
}

/// One principal in a subject search.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SubjectOut {
    /// The kind.
    #[serde(rename = "type")]
    pub kind: String,
    /// The principal string.
    pub id: String,
}

/// `context.tutela` of a subject search.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SubjectContext {
    /// The revision that was used.
    pub rev: u64,
}

/// `context` of a subject search.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SubjectContextOut {
    /// The details.
    pub tutela: SubjectContext,
}

/// The answer of `POST /access/v1/search/subject`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SubjectResults {
    /// The principals.
    pub results: Vec<SubjectOut>,
    /// The page.
    pub page: PageOut,
    /// The revision.
    pub context: SubjectContextOut,
}

/// A request that does not parse. The text is short English with no values
/// from the request, so it is safe to send and to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

/// A parsed question.
#[derive(Clone, Debug)]
pub struct Ask {
    /// Who.
    pub subject: Principal,
    /// The actor chain, current actor first.
    pub actors: Vec<Principal>,
    /// What.
    pub action: ActionKey,
    /// On what.
    pub resource: ResourceRef,
    /// `context.fields`.
    pub fields: Option<Vec<FieldName>>,
    /// `context.at_least_revision`.
    pub at_least: Option<u64>,
}

impl Ask {
    /// Parses one evaluation.
    ///
    /// # Errors
    ///
    /// [`Invalid`] when a field is missing or does not parse.
    pub fn parse(body: EvaluationBody) -> Result<Self, Invalid> {
        let (subject, actors) = principal(&body.subject.ok_or(Invalid("`subject` is missing"))?)?;
        let action = action(&body.action.ok_or(Invalid("`action` is missing"))?)?;
        let resource = resource(body.resource.ok_or(Invalid("`resource` is missing"))?)?;
        let context = body.context.unwrap_or_default();
        Ok(Self {
            subject,
            actors,
            action,
            resource,
            fields: context.fields.as_deref().map(field_names).transpose()?,
            at_least: context.at_least_revision,
        })
    }

    /// The evaluator's request. `tenant` comes from the token, and `need` is
    /// the revision floor of the whole call.
    #[must_use]
    pub fn request(self, tenant: TenantKey, need: Option<u64>) -> CheckRequest {
        CheckRequest {
            tenant,
            subject: self.subject,
            actors: self.actors,
            action: self.action,
            resource: self.resource,
            fields: self.fields,
            at_least_revision: need,
        }
    }
}

/// The subject and its actors. The kind in `type` must be the kind in `id`.
///
/// # Errors
///
/// [`Invalid`] for a missing or bad id, or a kind that does not match.
pub fn principal(s: &Subject) -> Result<(Principal, Vec<Principal>), Invalid> {
    let id = s.id.as_deref().ok_or(Invalid("`subject.id` is missing"))?;
    let p: Principal = id
        .parse()
        .map_err(|_| Invalid("`subject.id` is not a principal"))?;
    if p.kind().as_str() != s.kind {
        return Err(Invalid("`subject.type` is not the kind of `subject.id`"));
    }
    let actors = s
        .properties
        .as_ref()
        .and_then(|p| p.act.as_ref())
        .map_or_else(Vec::new, |a| a.chain().into_iter().cloned().collect());
    Ok((p, actors))
}

/// The action key.
///
/// # Errors
///
/// [`Invalid`] when it does not parse.
pub fn action(a: &Action) -> Result<ActionKey, Invalid> {
    ActionKey::parse(&a.name).map_err(|_| Invalid("`action.name` is not an action key"))
}

/// A type name.
///
/// # Errors
///
/// [`Invalid`] when it does not parse.
pub fn type_name(t: &str) -> Result<ResourceType, Invalid> {
    ResourceType::parse(t).map_err(|_| Invalid("a resource type is not a type name"))
}

/// A path.
///
/// # Errors
///
/// [`Invalid`] when an entry does not parse.
pub fn path(entries: &[Entry]) -> Result<Vec<PathEntry>, Invalid> {
    entries
        .iter()
        .map(|e| {
            Ok(PathEntry::new(
                type_name(&e.kind)?,
                ResourceId::parse(&e.id).map_err(|_| Invalid("a path id is not a resource id"))?,
            ))
        })
        .collect()
}

/// The field values.
///
/// # Errors
///
/// [`Invalid`] for a bad name or a value of a kind conditions cannot read.
pub fn attrs(values: BTreeMap<String, serde_json::Value>) -> Result<Attrs, Invalid> {
    values
        .into_iter()
        .map(|(name, value)| {
            let name = FieldName::parse(&name).map_err(|_| Invalid("an attr is not a field"))?;
            Ok((name, attr(value)?))
        })
        .collect()
}

fn attr(v: serde_json::Value) -> Result<AttrValue, Invalid> {
    use serde_json::Value;
    match v {
        Value::Null => Ok(AttrValue::Null),
        Value::Bool(b) => Ok(AttrValue::Boolean(b)),
        Value::String(s) => Ok(AttrValue::String(s)),
        Value::Number(n) => n
            .as_i64()
            .map(AttrValue::Integer)
            .ok_or(Invalid("an attr number must be an integer")),
        Value::Array(items) => items
            .into_iter()
            .map(|i| match i {
                Value::String(s) => Ok(s),
                _ => Err(Invalid("an attr array must hold strings only")),
            })
            .collect::<Result<_, _>>()
            .map(AttrValue::Strings),
        Value::Object(_) => Err(Invalid("an attr cannot be an object")),
    }
}

/// Field and feature names.
///
/// # Errors
///
/// [`Invalid`] for a bad name.
pub fn field_names(names: &[String]) -> Result<Vec<FieldName>, Invalid> {
    names
        .iter()
        .map(|n| FieldName::parse(n).map_err(|_| Invalid("a name in `fields` is not a field")))
        .collect()
}

/// A kind name.
///
/// # Errors
///
/// [`Invalid`] for an unknown kind.
pub fn kind(s: &Subject) -> Result<PrincipalKind, Invalid> {
    PrincipalKind::ALL
        .into_iter()
        .find(|k| k.as_str() == s.kind)
        .ok_or(Invalid("`subject.type` is not a principal kind"))
}

/// A resource, parsed in full.
///
/// # Errors
///
/// [`Invalid`] when a field is missing or does not parse.
pub fn resource(r: Resource) -> Result<ResourceRef, Invalid> {
    let type_name = type_name(&r.kind)?;
    let id = r.id.as_deref().ok_or(Invalid("`resource.id` is missing"))?;
    let id = ResourceId::parse(id).map_err(|_| Invalid("`resource.id` is not a resource id"))?;
    let properties = r.properties.unwrap_or_default();
    Ok(ResourceRef {
        type_name,
        id,
        path: path(properties.path.as_deref().unwrap_or_default())?,
        attrs: attrs(properties.attrs.unwrap_or_default())?,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";

    fn body(v: serde_json::Value) -> Result<Ask, Invalid> {
        Ask::parse(serde_json::from_value(v).unwrap())
    }

    fn good() -> serde_json::Value {
        json!({
            "subject": {"type": "user", "id": USER},
            "action": {"name": "invoice:read"},
            "resource": {"type": "invoice", "id": "inv-1", "properties": {
                "path": [{"type": "project", "id": "p-1"}],
                "attrs": {"status": "open", "amount": 5, "ok": true, "none": null, "labels": ["a"]}
            }},
            "context": {"fields": ["status"], "at_least_revision": 7}
        })
    }

    #[test]
    fn a_full_body_parses() {
        let a = body(good()).unwrap();
        assert_eq!(a.subject.to_string(), USER);
        assert!(a.actors.is_empty());
        assert_eq!(a.action.to_string(), "invoice:read");
        assert_eq!(a.resource.path.len(), 1);
        assert_eq!(a.resource.attrs.len(), 5);
        assert_eq!(a.at_least, Some(7));
    }

    #[test]
    fn a_subject_type_must_be_the_kind_of_its_id() {
        let mut v = good();
        v["subject"]["type"] = json!("sa");
        assert!(body(v).is_err());
    }

    #[test]
    fn a_missing_field_or_a_bad_value_is_invalid_and_never_guessed() {
        for bad in ["subject", "action", "resource"] {
            let mut v = good();
            v.as_object_mut().unwrap().remove(bad);
            assert!(body(v).is_err(), "{bad}");
        }
        for (key, value) in [
            ("amount", json!(1.5)),
            ("amount", json!({"a": 1})),
            ("labels", json!([1])),
        ] {
            let mut v = good();
            v["resource"]["properties"]["attrs"][key] = value;
            assert!(body(v).is_err(), "{key}");
        }
    }

    #[test]
    fn a_batch_item_replaces_a_default_as_a_whole() {
        let defaults: EvaluationBody = serde_json::from_value(good()).unwrap();
        let item: EvaluationBody =
            serde_json::from_value(json!({"action": {"name": "invoice:write"}})).unwrap();
        let merged = item.or(&defaults);
        assert_eq!(merged.action.unwrap().name, "invoice:write");
        assert!(merged.subject.is_some());
    }
}
