//! The `tutela` CLI (ROADMAP Phase A item 9), library mode.
//!
//! The binary is a thin layer over these functions, so they can be tested.
//! Commands: `init`, `check`, `codegen`, `migrate`, `apply`, `approve` and
//! `approvers keygen | add | list | revoke`. The database is
//! `TUTELA_DATABASE_URL` (a key=value or a `postgresql://` connection
//! string).
//!
//! Exit codes: 0 done, 1 error, 3 refused (a widening diff without a valid
//! approval token).

pub mod apply;
pub mod approval;
pub mod codegen;
pub mod init;

use std::io::Write;
use std::str::FromStr;

use tutela_pdp::model::{Issues, Model};
use tutela_store::tokio_postgres::config::Host;
use tutela_store::tokio_postgres::{Client, Config, NoTls};

/// The environment variable that names the database.
pub const DATABASE_ENV: &str = "TUTELA_DATABASE_URL";

/// The default manifest file name.
pub const DEFAULT_MANIFEST: &str = "tutela.resources.toml";

/// Why a command failed. Messages never hold tokens, keys or the database
/// password.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// Reading or writing a file or the terminal failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The manifest does not compile; its problems were printed.
    #[error("the manifest does not compile")]
    Compile,
    /// The database is not configured or may not be used.
    #[error("{0}")]
    Database(&'static str),
    /// The database connection or a statement failed.
    #[error("database error: {0}")]
    Postgres(#[from] tutela_store::tokio_postgres::Error),
    /// The store refused a call.
    #[error("{0}")]
    Store(#[from] tutela_store::StoreError),
    /// The diff could not be computed.
    #[error("{0}")]
    Diff(#[from] tutela_pdp::model::DiffError),
    /// An approval token or a key was refused.
    #[error("{0}")]
    Approval(#[from] approval::ApprovalError),
    /// Bad command-line input.
    #[error("{0}")]
    Usage(String),
    /// A bug in the CLI.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Prints a manifest's problems, one per line.
///
/// # Errors
///
/// An i/o error.
pub fn print_issues(out: &mut dyn Write, issues: &Issues) -> std::io::Result<()> {
    writeln!(out, "the manifest has {} problem(s):", issues.0.len())?;
    for i in &issues.0 {
        writeln!(out, "  {i}")?;
    }
    Ok(())
}

/// `tutela check`: compiles a manifest and prints a summary or its
/// problems.
///
/// # Errors
///
/// [`CliError::Compile`] if it does not compile.
pub fn check(source: &str, out: &mut dyn Write) -> Result<Model, CliError> {
    match Model::from_toml(source) {
        Ok(m) => {
            writeln!(
                out,
                "ok: app {}, {} type(s), {} role(s), {} UI key(s); sha256 {}",
                m.app(),
                m.types().len(),
                m.roles().len(),
                m.ui().len(),
                tutela_store::digest(source)
            )?;
            Ok(m)
        }
        Err(issues) => {
            print_issues(out, &issues)?;
            Err(CliError::Compile)
        }
    }
}

/// How the CLI connects to the database.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// Plain text: only to a Unix socket or a loopback host.
    Local,
    /// TLS with a verified certificate (`sslmode=require`).
    Tls,
}

/// Parses a database connection string and picks the transport.
///
/// - `sslmode=require` connects over TLS (rustls on aws-lc-rs, the
///   platform verifier) and **always verifies the certificate**, which is
///   stricter than libpq's `require`.
/// - Without it, only a Unix socket or a loopback host is accepted, so a
///   password and the manifest never cross a network in plain text.
///   `sslmode=prefer` (the default) could fall back to plain text, so it
///   does not count.
///
/// # Errors
///
/// [`CliError::Database`] for a string that does not parse, or for a
/// remote host without `sslmode=require`.
pub fn database_config(url: &str) -> Result<(Config, Transport), CliError> {
    use tutela_store::tokio_postgres::config::SslMode;
    let config = Config::from_str(url)
        .map_err(|_| CliError::Database("TUTELA_DATABASE_URL does not parse"))?;
    if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
        return Err(CliError::Database("TUTELA_DATABASE_URL names no host"));
    }
    if config.get_ssl_mode() == SslMode::Require {
        return Ok((config, Transport::Tls));
    }
    let loopback_host = |h: &Host| match h {
        Host::Tcp(name) => {
            name == "localhost"
                || name
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        Host::Unix(_) => true,
    };
    if !config.get_hosts().iter().all(loopback_host)
        || !config
            .get_hostaddrs()
            .iter()
            .all(std::net::IpAddr::is_loopback)
    {
        return Err(CliError::Database(
            "a database that is not on this machine needs TLS: add sslmode=require \
             (the certificate is always verified)",
        ));
    }
    Ok((config, Transport::Local))
}

/// Connects to the database in `TUTELA_DATABASE_URL`.
///
/// # Errors
///
/// [`CliError::Database`] if it is unset or not allowed, or a connection
/// error.
pub async fn connect(url: Option<&str>) -> Result<Client, CliError> {
    let url = url.filter(|u| !u.is_empty()).ok_or(CliError::Database(
        "set TUTELA_DATABASE_URL to the product's database",
    ))?;
    let (config, transport) = database_config(url)?;
    let client = match transport {
        Transport::Local => {
            let (client, conn) = config.connect(NoTls).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        }
        Transport::Tls => {
            let tls = tutela_safenet::tls_client_config()
                .map_err(|_| CliError::Database("the TLS setup failed"))?;
            let (client, conn) = config
                .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                .await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        }
    };
    Ok(client)
}

/// `tutela migrate`.
///
/// # Errors
///
/// A store error.
pub async fn migrate(client: &mut Client, out: &mut dyn Write) -> Result<(), CliError> {
    let applied = tutela_store::migrate(client).await?;
    if applied.is_empty() {
        writeln!(
            out,
            "the schema is current (migration {})",
            tutela_store::latest_migration()
        )?;
    } else {
        writeln!(out, "applied migration(s) {applied:?}")?;
    }
    Ok(())
}

/// `tutela approvers add`: registers a public key. Prints its id.
///
/// # Errors
///
/// A bad public key, or a store error.
pub async fn approvers_add(
    client: &mut Client,
    name: &str,
    public_key: &str,
    out: &mut dyn Write,
) -> Result<String, CliError> {
    let key = approval::parse_public_key(public_key)?;
    let tx = client.transaction().await?;
    let id = tutela_store::add_approver(&tx, name, &key).await?;
    tx.commit().await?;
    writeln!(out, "added approver {id} ({name})")?;
    Ok(id)
}

/// `tutela approvers list`.
///
/// # Errors
///
/// A store error.
pub async fn approvers_list(client: &mut Client, out: &mut dyn Write) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let all = tutela_store::approvers(&tx).await?;
    tx.commit().await?;
    if all.is_empty() {
        writeln!(out, "no approver keys")?;
    }
    for a in all {
        let state = if a.revoked { "revoked" } else { "active" };
        writeln!(out, "{}  {state:<7}  {}", a.id, a.name)?;
    }
    Ok(())
}

/// `tutela approvers revoke`.
///
/// # Errors
///
/// A store error.
pub async fn approvers_revoke(
    client: &mut Client,
    id: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    tutela_store::revoke_approver(&tx, id).await?;
    tx.commit().await?;
    writeln!(out, "revoked {id}")?;
    Ok(())
}

/// Seconds since the Unix epoch.
///
/// # Errors
///
/// [`CliError::Internal`] if the clock is before 1970.
pub fn now() -> Result<u64, CliError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| CliError::Internal("the system clock is before 1970"))
}

#[cfg(test)]
mod tests_pg;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_database_needs_tls_and_a_local_one_may_skip_it() {
        for ok in [
            "host=127.0.0.1 port=5432 user=u dbname=d",
            "host=localhost user=u",
            "host=::1 user=u",
            "host=/var/run/postgresql user=u",
            "postgresql://u@localhost/d",
            "postgresql://u@[::1]:5432/d",
        ] {
            assert!(
                matches!(database_config(ok), Ok((_, Transport::Local))),
                "{ok}"
            );
        }
        for tls in [
            "host=db.example.com user=u sslmode=require",
            "postgresql://u@db.example.com/d?sslmode=require",
            "host=127.0.0.1,db.example.com user=u sslmode=require",
            "host=localhost user=u sslmode=require",
        ] {
            assert!(
                matches!(database_config(tls), Ok((_, Transport::Tls))),
                "{tls}"
            );
        }
        for bad in [
            "host=db.example.com user=u",
            "host=db.example.com user=u sslmode=prefer",
            "host=db.example.com user=u sslmode=disable",
            "host=10.0.0.5 user=u",
            "host=127.0.0.1,db.example.com user=u",
            "host=localhost hostaddr=10.0.0.5 user=u",
            "postgresql://u@db.example.com/d",
            "user=u",
            "not a connection string = = =",
        ] {
            assert!(database_config(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn check_names_every_problem() {
        let mut out = Vec::new();
        assert!(check(&init::starter("crm"), &mut out).is_ok());
        assert!(String::from_utf8_lossy(&out).starts_with("ok: app crm, 2 type(s)"));
        let mut out = Vec::new();
        assert!(matches!(
            check("version = 1\n[app]\nname = \"crm\"\nnope = 1\n", &mut out),
            Err(CliError::Compile)
        ));
        assert!(String::from_utf8_lossy(&out).contains("problem"));
    }
}
