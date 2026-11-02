//! The JSON of the model API (CONTRACTS.md 7.9).

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

/// One line of an impact report as it is sent: the count and some names.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineOut {
    /// `gain` or `lose`.
    pub change: String,
    /// The principal kind, or `role`.
    pub kind: String,
    /// The type, field, feature or action.
    pub key: String,
    /// Before.
    pub from: String,
    /// After.
    pub to: String,
    /// It depends on field values Tutela does not have.
    pub conditional: bool,
    /// How many principals.
    pub count: usize,
    /// In how many scopes.
    pub scopes: usize,
    /// The first principals, sorted.
    pub examples: Vec<String>,
}

/// An impact report as it is sent (CONTRACTS.md 7.9).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactOut {
    /// `false` when the report stopped at its bound.
    pub complete: bool,
    /// `true` only for a complete report with no line.
    pub no_impact: bool,
    /// One sentence per line.
    pub summary: Vec<String>,
    /// The lines.
    pub lines: Vec<LineOut>,
    /// Lines left out past the limit of a response.
    pub omitted_lines: usize,
    /// SHA-256 of the whole report, every principal included.
    pub digest: String,
}

/// The most lines a response holds.
pub const MAX_LINES: usize = 1_000;

/// The most names a line holds.
pub const MAX_EXAMPLES: usize = 20;

impl ImpactOut {
    /// The response form of `report`.
    #[must_use]
    pub fn of(report: &tutela_pdp::ImpactReport) -> Self {
        let digest = tutela_store::digest(&serde_json::to_string(report).unwrap_or_default());
        let mut summary = report.summary();
        summary.truncate(MAX_LINES);
        Self {
            complete: report.complete,
            no_impact: report.no_impact(),
            summary,
            lines: report
                .lines
                .iter()
                .take(MAX_LINES)
                .map(|l| LineOut {
                    change: match l.change {
                        tutela_pdp::Change::Gain => "gain",
                        tutela_pdp::Change::Lose => "lose",
                    }
                    .to_owned(),
                    kind: l.kind.clone(),
                    key: l.key.clone(),
                    from: l.from.clone(),
                    to: l.to.clone(),
                    conditional: l.conditional,
                    count: l.principals.len(),
                    scopes: l.scopes.len(),
                    examples: l.principals.iter().take(MAX_EXAMPLES).cloned().collect(),
                })
                .collect(),
            omitted_lines: report.lines.len().saturating_sub(MAX_LINES),
            digest,
        }
    }
}

/// The answer of `POST /v1/models/impact`: what a publish of this text
/// would do, now.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ChangeOut {
    /// The active version, to send as `expected_version`.
    pub version: i64,
    /// The active model's digest: an approval token's `from`.
    pub from: String,
    /// The new text's digest: an approval token's `to`.
    pub to: String,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The diff, one change per line.
    pub diff: String,
    /// Who gains or loses what.
    pub impact: ImpactOut,
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
    /// What it did, as reported just before.
    pub impact: ImpactOut,
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

pub(crate) fn time(t: SystemTime) -> Option<String> {
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

/// The body of `PUT /v1/models/settings`.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct SettingsBody {
    /// On or off.
    pub two_person: Option<bool>,
}

/// A tenant's model settings.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SettingsOut {
    /// Two-person publish is on.
    pub two_person: bool,
    /// Who asked to turn it off; a second person must agree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off_requested_by: Option<String>,
}

impl SettingsOut {
    /// The answer for a stored setting.
    #[must_use]
    pub fn of(t: tutela_store::TwoPerson) -> Self {
        Self {
            two_person: t.on,
            off_requested_by: t.off_requested_by,
        }
    }
}

/// The body of an approval.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ApproveBody {
    /// An approval token, for a widening change.
    pub approval: Option<String>,
}

/// A proposal.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProposalOut {
    /// `mpr_<uuidv7>`.
    pub id: String,
    /// `proposed`, `published`, `rejected` or `stale`.
    pub state: String,
    /// The version it was compared against.
    pub base_version: i64,
    /// Its digest: an approval token's `from`.
    pub from: String,
    /// The new text's digest: an approval token's `to`.
    pub to: String,
    /// The version it copies, for a rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restores: Option<i64>,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The diff.
    pub diff: String,
    /// The impact report the proposer saw.
    pub impact: Option<ImpactOut>,
    /// The revision it was made at.
    pub rev: u64,
    /// Who proposed it.
    pub proposed_by: String,
    /// Who decided it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// The version it became.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When it was decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    /// The text, when one proposal was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl ProposalOut {
    /// The answer for a stored proposal.
    #[must_use]
    pub fn of(p: tutela_store::Proposal) -> Self {
        Self {
            id: p.id,
            state: p.state,
            base_version: p.base_version,
            from: p.base_digest,
            to: p.digest,
            restores: p.restores,
            class: p.class,
            diff: p.diff,
            impact: serde_json::from_str(&p.impact).ok(),
            rev: p.rev,
            proposed_by: p.proposed_by,
            decided_by: p.decided_by,
            version: p.version,
            created_at: time(p.created_at),
            decided_at: p.decided_at.and_then(time),
            source: p.source,
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
