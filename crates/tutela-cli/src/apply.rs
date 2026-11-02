//! `tutela apply` in library mode (PERMISSION-MODEL.md 15.2).
//!
//! 1. Compile the new manifest.
//! 2. Compare it with the applied one (or with an empty model of the same
//!    app for a first apply) and print the diff.
//! 3. A widening diff needs an approval token for exactly this change
//!    (ADR-0015); without one it is refused.
//! 4. Publish: one transaction stores the manifest and bumps every
//!    tenant's revision.

use std::io::Write;

use tutela_pdp::model::{Class, Model, diff};
use tutela_store::tokio_postgres::Client;

use crate::approval::{self, NO_MANIFEST};
use crate::{CliError, print_issues};

/// What `apply` should do.
#[derive(Clone, Copy, Debug)]
pub struct Options<'a> {
    /// The new manifest text.
    pub source: &'a str,
    /// An approval token, for a widening diff.
    pub approval: Option<&'a str>,
    /// Who applies it (for the record).
    pub author: Option<&'a str>,
    /// Show the diff only.
    pub dry_run: bool,
    /// Now, Unix seconds.
    pub now: u64,
}

/// What `apply` did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// The new manifest is the applied one.
    NoChange,
    /// `--dry-run`: the diff was shown, nothing was written.
    DryRun(Class),
    /// Published: the app's new version and the number of tenants bumped.
    Applied {
        /// The class of the diff.
        class: Class,
        /// The app's manifest version now.
        version: i64,
        /// How many tenants got a new revision.
        tenants: usize,
    },
    /// A widening diff without a valid approval token. Nothing was written.
    Refused,
}

/// Runs `apply` against the store behind `client`.
///
/// # Errors
///
/// [`CliError::Compile`] if the manifest does not compile (the problems are
/// printed), or a store error.
pub async fn apply(
    client: &mut Client,
    opts: &Options<'_>,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let new = match Model::from_toml(opts.source) {
        Ok(m) => m,
        Err(issues) => {
            print_issues(out, &issues)?;
            return Err(CliError::Compile);
        }
    };
    let app = new.app().clone();
    let to = tutela_store::digest(opts.source);

    let tx = client.transaction().await?;
    let stored = tutela_store::manifest(&tx, &app).await?;
    let from = stored
        .as_ref()
        .map_or_else(|| NO_MANIFEST.to_owned(), |s| s.digest.clone());
    writeln!(out, "app:     {app}")?;
    match &stored {
        Some(s) => writeln!(out, "applied: version {} (sha256 {})", s.version, s.digest)?,
        None => writeln!(out, "applied: none (first apply)")?,
    }
    writeln!(out, "new:     sha256 {to}")?;
    if from == to {
        writeln!(out, "nothing to apply: the manifest is already applied")?;
        return Ok(Outcome::NoChange);
    }

    // The old model. One that no longer compiles (a stricter compiler) is
    // compared as if nothing were applied: every grant then counts as new,
    // which can only make the diff more widening.
    let old = match &stored {
        Some(s) => Model::from_toml(&s.source).ok(),
        None => None,
    };
    if stored.is_some() && old.is_none() {
        writeln!(
            out,
            "note: the applied manifest no longer compiles; comparing against an empty model"
        )?;
    }
    let old = match old {
        Some(m) => m,
        None => empty(&app)?,
    };
    let d = diff(&old, &new)?;
    writeln!(
        out,
        "diff:    {} change(s), {}",
        d.changes().len() + d.omitted(),
        d.class()
    )?;
    let mut text = String::new();
    for c in d.changes() {
        writeln!(out, "  {c}")?;
        text.push_str(&c.to_string());
        text.push('\n');
    }
    if d.omitted() > 0 {
        writeln!(out, "  and {} more", d.omitted())?;
        text.push_str(&format!("and {} more\n", d.omitted()));
    }
    if opts.dry_run {
        writeln!(out, "dry run: nothing written")?;
        return Ok(Outcome::DryRun(d.class()));
    }

    let mut approvers = Vec::new();
    if d.is_widening() {
        let checked = match opts.approval {
            None => Err(None),
            Some(t) => check_approval(&tx, t, app.as_str(), &from, &to, opts.now)
                .await
                .map_err(Some),
        };
        match checked {
            Ok(kid) => {
                writeln!(out, "approved by {kid}")?;
                approvers.push(kid);
            }
            Err(why) => {
                if let Some(e) = why {
                    writeln!(out, "refused: {}", e.report())?;
                } else {
                    writeln!(
                        out,
                        "refused: this diff is WIDENING and needs an approval token"
                    )?;
                }
                writeln!(
                    out,
                    "An approver reviews the diff above, then runs:\n  \
                     tutela approve --app {app} --from {from} --to {to} --key <approver key file>\n\
                     Then run: tutela apply --approval <token>"
                )?;
                return Ok(Outcome::Refused);
            }
        }
    }

    let tenants = tutela_store::publish_manifest(
        &tx,
        &tutela_store::Publish {
            app: &app,
            source: opts.source,
            expected: stored.as_ref().map(|s| s.version),
            class: d.class(),
            diff: &text,
            author: opts.author,
            approvers: &approvers,
        },
    )
    .await?;
    tx.commit().await?;
    let version = stored.as_ref().map_or(1, |s| s.version.saturating_add(1));
    writeln!(
        out,
        "applied: version {version}, {} tenant revision(s) bumped",
        tenants.len()
    )?;
    Ok(Outcome::Applied {
        class: d.class(),
        version,
        tenants: tenants.len(),
    })
}

/// Checks an approval token against the database's approver keys.
async fn check_approval(
    tx: &tutela_store::tokio_postgres::Transaction<'_>,
    token: &str,
    app: &str,
    from: &str,
    to: &str,
    now: u64,
) -> Result<String, CliError> {
    let kid = approval::peek(token)?.kid;
    let key = tutela_store::approver(tx, &kid)
        .await?
        .ok_or(approval::ApprovalError::UnknownKey)?;
    if key.revoked {
        return Err(approval::ApprovalError::RevokedKey.into());
    }
    approval::verify(token, &key.public_key, app, from, to, now)?;
    Ok(kid)
}

/// An empty model of `app`: the baseline of a first apply.
fn empty(app: &tutela_pdp::model::AppName) -> Result<Model, CliError> {
    Model::from_toml(&format!("version = 1\n[app]\nname = \"{app}\"\n"))
        .map_err(|_| CliError::Internal("the empty baseline model does not compile"))
}
