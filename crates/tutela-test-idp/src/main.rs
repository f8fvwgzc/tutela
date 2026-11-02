//! `tutela-test-idp`: the test OpenID provider as a program, for running
//! the Tutela Console locally (docs/JS-SDK.md, "The Console"). Loopback
//! only; never for production.
//!
//! ```text
//! tutela-test-idp --listen 127.0.0.1:18555 \
//!   --redirect-uri http://127.0.0.1:8080/console/callback \
//!   --person kc-owner="Olivia Owner" --person kc-member="Max Member"
//! ```
//!
//! It prints `{"issuer", "jwks_uri"}` and serves until Ctrl-C.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use tutela_test_idp::{Person, Settings};

/// A test OpenID provider shaped like Keycloak 26, on loopback only.
#[derive(Debug, Parser)]
#[command(name = "tutela-test-idp", version)]
struct Args {
    /// Where to listen: a loopback address.
    #[arg(long, default_value = "127.0.0.1:18555")]
    listen: SocketAddr,
    /// The realm's name.
    #[arg(long, default_value = "tutela")]
    realm: String,
    /// The `aud` of access tokens: tutelad's `TUTELA_AUDIENCE`.
    #[arg(long, default_value = "tutela-authz")]
    audience: String,
    /// The Console's client id (`TUTELA_CONSOLE_CLIENT_ID`).
    #[arg(long, default_value = "tutela-console")]
    client_id: String,
    /// The Console's redirect URI: `<tutelad>/console/callback`.
    #[arg(long, default_value = "http://127.0.0.1:8080/console/callback")]
    redirect_uri: Vec<String>,
    /// A person, as `sub=Name`. Repeat it.
    #[arg(long = "person", value_parser = person)]
    people: Vec<Person>,
    /// The `acr` after MFA: one of tutelad's `TUTELA_ADMIN_ACR`.
    #[arg(long, default_value = "mfa")]
    step_up_acr: String,
    /// The life of an access token, in seconds.
    #[arg(long, default_value_t = 300)]
    access_ttl_secs: u64,
}

fn person(s: &str) -> Result<Person, String> {
    let (sub, name) = s.split_once('=').ok_or("a person is sub=Name")?;
    if sub.is_empty() || name.is_empty() {
        return Err("a person is sub=Name".to_owned());
    }
    Ok(Person::new(sub, name))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let people = if a.people.is_empty() {
        vec![
            Person::new("kc-owner", "Olivia Owner"),
            Person::new("kc-member", "Max Member"),
        ]
    } else {
        a.people
    };
    let post_logout = a
        .redirect_uri
        .iter()
        .map(|u| u.trim_end_matches("callback").to_owned())
        .collect();
    let settings = Settings {
        listen: a.listen,
        realm: a.realm,
        audience: a.audience,
        client_id: a.client_id,
        redirect_uris: a.redirect_uri,
        post_logout_redirect_uris: post_logout,
        people,
        step_up_acr: a.step_up_acr,
        plain_acr: "1".to_owned(),
        access_ttl: Duration::from_secs(a.access_ttl_secs),
    };
    let running = tutela_test_idp::start(settings).await?;
    println!(
        "{}",
        serde_json::json!({"issuer": running.issuer(), "jwks_uri": running.jwks_uri()})
    );
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    running.stop().await;
    Ok(())
}
