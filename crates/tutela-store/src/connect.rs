//! How Tutela's binaries reach the database: the rule for TLS.

use std::str::FromStr as _;

use tokio_postgres::Config;
use tokio_postgres::config::{Host, SslMode};

use crate::StoreError;

/// How a connection travels.
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
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a string that does not
/// parse, or for a remote host without `sslmode=require`. The error never
/// holds the string, which may hold a password.
pub fn database_config(url: &str) -> Result<(Config, Transport), StoreError> {
    let config = Config::from_str(url)
        .map_err(|_| StoreError::invalid("TUTELA_DATABASE_URL does not parse"))?;
    if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
        return Err(StoreError::invalid("TUTELA_DATABASE_URL names no host"));
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
        return Err(StoreError::invalid(
            "a database that is not on this machine needs TLS: add sslmode=require \
             (the certificate is always verified)",
        ));
    }
    Ok((config, Transport::Local))
}
