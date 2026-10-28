//! The `tutela` command. See the `tutela_cli` crate docs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tutela_cli::apply::{self, Outcome};
use tutela_cli::approval::{self, Approval};
use tutela_cli::{CliError, DATABASE_ENV, DEFAULT_MANIFEST};

/// Tutela's CLI for library mode: the manifest, its diff and approvals.
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
            eprintln!("error: {e}");
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
            author,
            dry_run,
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
                },
            )?;
            writeln!(out, "{token}")?;
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
