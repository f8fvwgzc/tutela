//! The `tutela` command. See the `tutela_cli` crate docs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tutela_cli::apply::{self, Outcome};
use tutela_cli::approval::{self, Approval};
use tutela_cli::{CliError, DATABASE_ENV, DEFAULT_MANIFEST};

/// Tutela's CLI: the manifest, its diff and approvals, in library mode and
/// against `tutelad`; apps; `tutelad`'s keys.
#[derive(Parser)]
#[command(name = "tutela", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a starter tutela.resources.toml (never overwrites a file).
    Init {
        /// The app name (the model namespace).
        #[arg(long, default_value = "app")]
        app: String,
        /// Where to write it.
        #[arg(long, default_value = DEFAULT_MANIFEST)]
        file: PathBuf,
    },
    /// Compile a manifest and list every problem.
    Check {
        /// The manifest.
        #[arg(long, default_value = DEFAULT_MANIFEST)]
        file: PathBuf,
    },
    /// Generate Rust and TypeScript constants and the route table.
    Codegen {
        /// The manifest.
        #[arg(long, default_value = DEFAULT_MANIFEST)]
        file: PathBuf,
        /// Where to write the Rust module.
        #[arg(long)]
        rust: Option<PathBuf>,
        /// Where to write the TypeScript module.
        #[arg(long)]
        ts: Option<PathBuf>,
        /// Write nothing; fail if a file is missing or out of date (for CI).
        #[arg(long)]
        check: bool,
    },
    /// Create or update the tutela schema (run as the database owner).
    Migrate,
    /// Show the diff against the applied manifest, then apply it. A widening
    /// diff needs an approval token.
    Apply {
        /// The manifest.
        #[arg(long, default_value = DEFAULT_MANIFEST)]
        file: PathBuf,
        /// An approval token from `tutela approve` (or TUTELA_APPROVAL).
        #[arg(long, env = "TUTELA_APPROVAL", hide_env_values = true)]
        approval: Option<String>,
        /// Who applies it (for the record).
        #[arg(long)]
        author: Option<String>,
        /// Show the diff only; write nothing.
        #[arg(long)]
        dry_run: bool,
        /// `tutelad`'s URL (or TUTELA_URL): apply to the caller's tenant
        /// there, with the impact report. Without it, library mode.
        #[arg(long, env = "TUTELA_URL")]
        server: Option<String>,
        /// The caller's token for `tutelad` (or TUTELA_TOKEN): a pipeline's
        /// service token or a person's admin token.
        #[arg(long, env = "TUTELA_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },
    /// Apps of the caller's tenant on `tutelad` (the tenant's owner only).
    Apps {
        /// `tutelad`'s URL (or TUTELA_URL).
        #[arg(long, env = "TUTELA_URL")]
        server: String,
        /// The caller's token (or TUTELA_TOKEN).
        #[arg(long, env = "TUTELA_TOKEN", hide_env_values = true)]
        token: String,
        #[command(subcommand)]
        command: AppsCommand,
    },
    /// `tutelad`'s signing keys and audit producer key, through the key store
    /// (TUTELA_DATABASE_URL, TUTELA_MASTER_KEY, TUTELA_ISSUER).
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Sign an approval for one change (run by an approver, after reviewing
    /// the diff that `tutela apply` printed).
    Approve {
        /// The app.
        #[arg(long)]
        app: String,
        /// The applied manifest's digest (`none` for a first apply).
        #[arg(long)]
        from: String,
        /// The new manifest's digest.
        #[arg(long)]
        to: String,
        /// The approver's private key file.
        #[arg(long)]
        key: PathBuf,
        /// The one tenant this approves the change for (`tutelad`). Leave it
        /// out for the app's manifest (library mode).
        #[arg(long)]
        tenant: Option<String>,
        /// How long the token is valid, in minutes (at most 1440).
        #[arg(long, default_value_t = 60)]
        valid_for: u64,
    },
    /// Manage approver keys.
    Approvers {
        #[command(subcommand)]
        command: ApproversCommand,
    },
}

#[derive(Subcommand)]
enum AppsCommand {
    /// Make an app. Its client secret is printed this once.
    Create {
        /// The app's display name.
        #[arg(long)]
        name: String,
    },
    /// List the apps.
    List,
    /// A new client secret, printed this once; the old ones keep working
    /// for the overlap.
    Rotate {
        /// The client id, `app_<uuidv7>`.
        id: String,
        /// How long the old secrets keep working, in seconds (default 3600).
        #[arg(long)]
        overlap_secs: Option<u64>,
    },
    /// Disable an app: its secrets and tokens stop.
    Disable {
        /// The client id.
        id: String,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List the signing keys and the audit keys.
    List,
    /// Make the next signing key (or, with --audit, the next audit producer
    /// key).
    Rotate {
        /// Rotate the audit producer key instead.
        #[arg(long)]
        audit: bool,
        /// The JWKS cache time of the replicas, in seconds.
        #[arg(long, env = "TUTELA_JWKS_CACHE_SECS", default_value_t = 300)]
        jwks_cache_secs: u64,
    },
    /// Deny a signing key at once; a new key signs.
    Deny {
        /// The key's `kid`.
        kid: String,
    },
    /// Seal every key again under the current master key
    /// (TUTELA_MASTER_KEY_PREVIOUS opens the old ones).
    Rewrap,
}

#[derive(Subcommand)]
enum ApproversCommand {
    /// Make a new key pair. The private key file is readable by you only.
    Keygen {
        /// Where to write the private key (never overwrites a file).
        #[arg(long)]
        out: PathBuf,
    },
    /// Register an approver's public key in the database.
    Add {
        /// Who holds the key.
        #[arg(long)]
        name: String,
        /// The public key that `keygen` printed.
        #[arg(long)]
        public_key: String,
    },
    /// List the approver keys.
    List,
    /// Revoke a key: it approves nothing any more.
    Revoke {
        /// The key id (`apk_...`).
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Every Tutela binary installs the one crypto provider itself.
    if tutela_safenet::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("error: a crypto provider is already installed");
        return ExitCode::from(1);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let mut out = std::io::stdout().lock();
    match runtime.block_on(run(cli.command, &mut out)) {
        Ok(code) => code,
        Err(e) => {
            let _ = out.flush();
            eprintln!("error: {}", e.report());
            ExitCode::from(1)
        }
    }
}

async fn run(command: Command, out: &mut dyn Write) -> Result<ExitCode, CliError> {
    let db = || std::env::var(DATABASE_ENV).ok();
    match command {
        Command::Init { app, file } => {
            tutela_pdp::model::AppName::parse(&app)
                .map_err(|_| CliError::Usage(format!("`{app}` is not an app name")))?;
            write_new(&file, tutela_cli::init::starter(&app).as_bytes(), false)?;
            writeln!(out, "wrote {}", file.display())?;
        }
        Command::Check { file } => {
            tutela_cli::check(&read(&file)?, out)?;
        }
        Command::Codegen {
            file,
            rust,
            ts,
            check,
        } => {
            if rust.is_none() && ts.is_none() {
                return Err(CliError::Usage("give --rust, --ts or both".into()));
            }
            let source = read(&file)?;
            let model = tutela_cli::check(&source, &mut std::io::sink()).map_err(|_| {
                CliError::Usage(format!(
                    "{} does not compile; run tutela check",
                    file.display()
                ))
            })?;
            let digest = tutela_store::digest(&source);
            let outputs = [
                (rust, tutela_cli::codegen::rust(&model, &digest)),
                (ts, tutela_cli::codegen::typescript(&model, &digest)),
            ];
            let mut stale = false;
            for (path, text) in outputs {
                let Some(path) = path else { continue };
                if check {
                    let current = std::fs::read_to_string(&path).unwrap_or_default();
                    if current != text {
                        writeln!(out, "out of date: {}", path.display())?;
                        stale = true;
                    }
                } else {
                    std::fs::write(&path, text)?;
                    writeln!(out, "wrote {}", path.display())?;
                }
            }
            if stale {
                writeln!(out, "run tutela codegen to update")?;
                return Ok(ExitCode::from(1));
            }
        }
        Command::Migrate => {
            let mut client = tutela_cli::connect(db().as_deref()).await?;
            tutela_cli::migrate(&mut client, out).await?;
        }
        Command::Apply {
            file,
            approval,
            author: _,
            dry_run,
            server: Some(server),
            token,
        } => {
            let source = read(&file)?;
            let svc =
                tutela_cli::service::Service::new(&server, token.as_deref().unwrap_or_default())?;
            let outcome = tutela_cli::service::apply(
                &svc,
                &tutela_cli::service::ApplyOptions {
                    source: &source,
                    approval: approval.as_deref(),
                    dry_run,
                },
                out,
            )
            .await?;
            if outcome == tutela_cli::service::Applied::Refused {
                return Ok(ExitCode::from(3));
            }
        }
        Command::Apply {
            file,
            approval,
            author,
            dry_run,
            server: None,
            token: _,
        } => {
            let source = read(&file)?;
            let mut client = tutela_cli::connect(db().as_deref()).await?;
            let outcome = apply::apply(
                &mut client,
                &apply::Options {
                    source: &source,
                    approval: approval.as_deref(),
                    author: author.as_deref(),
                    dry_run,
                    now: tutela_cli::now()?,
                },
                out,
            )
            .await?;
            if outcome == Outcome::Refused {
                return Ok(ExitCode::from(3));
            }
        }
        Command::Approve {
            app,
            from,
            to,
            key,
            tenant,
            valid_for,
        } => {
            let signing = approval::parse_key_file(&read(&key)?)?;
            let iat = tutela_cli::now()?;
            let exp = valid_for
                .checked_mul(60)
                .and_then(|s| iat.checked_add(s))
                .ok_or_else(|| CliError::Usage("--valid-for is too large".into()))?;
            let kid = tutela_store::approver_id(&signing.verifying_key().to_bytes());
            let token = approval::mint(
                &signing,
                &Approval {
                    app,
                    from,
                    to,
                    kid,
                    iat,
                    exp,
                    tid: tenant,
                },
            )?;
            writeln!(out, "{token}")?;
        }
        Command::Apps {
            server,
            token,
            command,
        } => {
            let svc = tutela_cli::service::Service::new(&server, &token)?;
            match command {
                AppsCommand::Create { name } => {
                    tutela_cli::service::apps_create(&svc, &name, out).await?;
                }
                AppsCommand::List => tutela_cli::service::apps_list(&svc, out).await?,
                AppsCommand::Rotate { id, overlap_secs } => {
                    tutela_cli::service::apps_rotate(&svc, &id, overlap_secs, out).await?;
                }
                AppsCommand::Disable { id } => {
                    tutela_cli::service::apps_disable(&svc, &id, out).await?;
                }
            }
        }
        Command::Keys { command } => {
            let mut client = tutela_cli::connect(db().as_deref()).await?;
            if let KeysCommand::List = command {
                tutela_cli::keys::list(&mut client, out).await?;
                return Ok(ExitCode::SUCCESS);
            }
            let vault = tutela_vault::Vault::from_env().map_err(|_| {
                CliError::Usage("TUTELA_MASTER_KEY is not set or not 32 bytes".into())
            })?;
            let iss: tutela_contracts::tenant::Issuer = std::env::var("TUTELA_ISSUER")
                .ok()
                .and_then(|i| i.parse().ok())
                .ok_or_else(|| {
                    CliError::Usage("TUTELA_ISSUER is not set or not an issuer".into())
                })?;
            match command {
                KeysCommand::List => {}
                KeysCommand::Rotate { audit: true, .. } => {
                    tutela_cli::keys::rotate_audit(&mut client, &vault, &iss, out).await?;
                }
                KeysCommand::Rotate {
                    audit: false,
                    jwks_cache_secs,
                } => {
                    let cache = std::time::Duration::from_secs(jwks_cache_secs);
                    tutela_cli::keys::rotate(&mut client, &vault, &iss, cache, out).await?;
                }
                KeysCommand::Deny { kid } => {
                    tutela_cli::keys::deny(&mut client, &vault, &iss, &kid, out).await?;
                }
                KeysCommand::Rewrap => {
                    tutela_cli::keys::rewrap(&mut client, &vault, &iss, out).await?
                }
            }
        }
        Command::Approvers { command } => match command {
            ApproversCommand::Keygen { out: path } => {
                let key = approval::generate()?;
                write_new(&path, approval::key_file_text(&key).as_bytes(), true)?;
                let vk = key.verifying_key();
                writeln!(out, "wrote the private key to {}", path.display())?;
                writeln!(
                    out,
                    "key id:     {}",
                    tutela_store::approver_id(&vk.to_bytes())
                )?;
                writeln!(out, "public key: {}", approval::public_key_text(&vk))?;
                writeln!(
                    out,
                    "register it: tutela approvers add --name <who> --public-key <public key>"
                )?;
            }
            ApproversCommand::Add { name, public_key } => {
                let mut client = tutela_cli::connect(db().as_deref()).await?;
                tutela_cli::approvers_add(&mut client, &name, &public_key, out).await?;
            }
            ApproversCommand::List => {
                let mut client = tutela_cli::connect(db().as_deref()).await?;
                tutela_cli::approvers_list(&mut client, out).await?;
            }
            ApproversCommand::Revoke { id } => {
                let mut client = tutela_cli::connect(db().as_deref()).await?;
                tutela_cli::approvers_revoke(&mut client, &id, out).await?;
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}

/// Reads a manifest or a key file (at most 4 MiB).
fn read(path: &Path) -> Result<String, CliError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > 4 * 1024 * 1024 {
        return Err(CliError::Usage(format!(
            "{} is larger than 4 MiB",
            path.display()
        )));
    }
    Ok(std::fs::read_to_string(path)?)
}

/// Writes a new file; never replaces one. `secret` makes it readable by the
/// owner only.
fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<(), CliError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Usage(format!("{} exists; not overwriting it", path.display()))
        } else {
            CliError::Io(e)
        }
    })?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
