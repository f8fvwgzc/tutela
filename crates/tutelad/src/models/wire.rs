//! The JSON of the model API (CONTRACTS.md 7.10).

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tutela_contracts::timestamp::Timestamp;
use tutela_store::ModelVersion;

/// The body of `POST /v1/models/publish`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PublishBody {
    /// The new manifest. Or `restore`.
    pub source: Option<String>,
    /// A kept version to publish again. Or `source`.
    pub restore: Option<i64>,
    /// The version the caller compared against.
    pub expected_version: Option<i64>,
    /// An approval token, for a widening change.
    pub approval: Option<String>,
}

/// The answer of a publish.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PublishResult {
    /// The new version.
    pub version: i64,
    /// The tenant revision it took effect at.
    pub rev: u64,
    /// SHA-256 of the text.
    pub digest: String,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The version it copies, for a rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restores: Option<i64>,
}

/// The model a tenant runs on.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ActiveOut {
    /// The newest version number. 0 when the tenant has none.
    pub version: i64,
    /// SHA-256 of the text.
    pub digest: String,
    /// `true` when the tenant published it itself, `false` when it follows
    /// the app's manifest.
    pub own: bool,
}

/// One version.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VersionOut {
    /// The number.
    pub version: i64,
    /// The tenant revision at publish.
    pub rev: u64,
    /// SHA-256 of the text.
    pub digest: String,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The diff, one change per line.
    pub diff: String,
    /// Who published it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Who approved it.
    pub approvers: Vec<String>,
    /// `app` or `tenant`.
    pub origin: String,
    /// The version it copies, for a rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restores: Option<i64>,
    /// When, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// The impact report, as it was then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<serde_json::Value>,
    /// The text, when one version was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

fn time(t: SystemTime) -> Option<String> {
    let ms = t.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_millis();
    Timestamp::from_unix_millis(i64::try_from(ms).ok()?)
        .ok()
        .map(|t| t.to_string())
}

impl VersionOut {
    /// The answer for a stored version.
    #[must_use]
    pub fn of(v: ModelVersion) -> Self {
        Self {
            version: v.version,
            rev: v.rev,
            digest: v.digest,
            class: v.class,
            diff: v.diff,
            author: v.author,
            approvers: v.approvers,
            origin: v.origin,
            restores: v.restores,
            published_at: v.published_at.and_then(time),
            impact: v.impact.and_then(|i| serde_json::from_str(&i).ok()),
            source: v.source,
        }
    }
}

/// The answer of `GET /v1/models`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VersionsOut {
    /// What runs now.
    pub active: ActiveOut,
    /// Newest first.
    pub versions: Vec<VersionOut>,
    /// `before` for the next page. Missing on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<i64>,
}
