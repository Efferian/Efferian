use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, error::ErrorKind};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::config::{self, Authority, Config, Origin, Overrides};
use crate::egress::EgressClient;
use crate::http::{self, AppState};
use crate::http_transport;
use crate::node_bridge::OfflineNodeBridge;
use crate::operations;
use crate::storage::{OpenMode, ShutdownReport, StorageClock, SystemStorageClock};

#[derive(Parser)]
#[command(version, about = "Run and administer an Efferian Hub")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new Hub and issue the first administrator token.
    Init {
        #[arg(long, value_name = "DIR")]
        state_dir: Option<PathBuf>,
        #[arg(long, default_value = "admin")]
        admin_name: String,
        /// Write the token to a new private file, or use - for stdout.
        #[arg(long, default_value = "-", value_name = "PATH|-")]
        admin_token_out: PathBuf,
    },
    /// Serve the Hub over HTTP/1.
    Serve {
        #[command(flatten)]
        settings: Settings,
        #[arg(long, value_name = "ADDR")]
        listen: Option<std::net::SocketAddr>,
        /// Allow these exact Host authorities (comma-separated).
        #[arg(long, value_name = "LIST", value_parser = config::parse_csv::<Authority>)]
        allowed_hosts: Option<Vec<Authority>>,
        /// Allow these HTTP or HTTPS origins (comma-separated).
        #[arg(long, value_name = "LIST", value_parser = config::parse_csv::<Origin>)]
        allowed_origins: Option<Vec<Origin>>,
    },
    /// Recover access to a stopped Hub.
    Admin {
        #[command(subcommand)]
        command: Admin,
    },
    /// Back up the live SQLite database to a new file.
    SqliteSnapshot {
        #[arg(long, value_name = "DIR")]
        state_dir: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Args)]
struct Settings {
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Read settings from this TOML file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_active_tokens_per_principal: Option<usize>,
}

#[derive(Subcommand)]
enum Admin {
    /// Issue an unrestricted token for an active global administrator.
    CreateToken {
        #[command(flatten)]
        settings: Settings,
        #[arg(long, value_name = "NAME")]
        principal: String,
        /// Write the token to a new private file, or use - for stdout.
        #[arg(long, default_value = "-", value_name = "PATH|-")]
        out: PathBuf,
        #[arg(long, default_value = "offline-admin")]
        label: String,
    },
}

type CommandResult = Result<(), Box<dyn std::error::Error>>;

pub fn run_cli() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(_) => {
            eprintln!(
                "error: invalid command line. See efferian-hub --help or the subcommand's --help."
            );
            return ExitCode::from(2);
        }
    };
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("error: a TLS provider was already installed at startup");
        return ExitCode::FAILURE;
    }
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> CommandResult {
    match command {
        Command::Init {
            state_dir,
            admin_name,
            admin_token_out,
        } => {
            let config = Config::load(
                None,
                Overrides {
                    state_dir,
                    ..Overrides::default()
                },
            )?;
            operations::init(
                config.state_dir()?,
                &admin_name,
                &admin_token_out,
                &config.storage_config(),
            )?;
        }
        Command::Serve {
            settings,
            listen,
            allowed_hosts,
            allowed_origins,
        } => {
            let config = Config::load(
                settings.config.as_deref(),
                Overrides {
                    state_dir: settings.state_dir,
                    listen,
                    allowed_hosts,
                    allowed_origins,
                    max_active_tokens_per_principal: settings.max_active_tokens_per_principal,
                },
            )?;
            config.validate_listen()?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(config))?;
        }
        Command::Admin {
            command:
                Admin::CreateToken {
                    settings,
                    principal,
                    out,
                    label,
                },
        } => {
            let config = Config::load(
                settings.config.as_deref(),
                Overrides {
                    state_dir: settings.state_dir,
                    max_active_tokens_per_principal: settings.max_active_tokens_per_principal,
                    ..Overrides::default()
                },
            )?;
            operations::create_token(
                config.state_dir()?,
                &principal,
                &out,
                &label,
                &config.storage_config(),
                config.max_active_tokens_per_principal,
            )?;
        }
        Command::SqliteSnapshot { state_dir, out } => {
            operations::snapshot(&config::state_dir(state_dir)?, &out)?;
        }
    }
    Ok(())
}

async fn serve(config: Config) -> CommandResult {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let state_dir = config.state_dir()?.to_path_buf();
    let storage_config = config.storage_config();
    let egress = EgressClient::new(config.egress_policy()?)?;
    let clock: Arc<dyn StorageClock> = Arc::new(SystemStorageClock::new()?);
    let startup_clock = Arc::clone(&clock);
    let (opened, vault) = tokio::task::spawn_blocking(move || {
        operations::open_existing(
            &state_dir,
            OpenMode::ServeAutoMigrate,
            &storage_config,
            startup_clock,
        )
    })
    .await??;
    let listener = TcpListener::bind(config.listen).await?;
    let bound = listener.local_addr()?;
    let (storage, runtime) =
        tokio::task::spawn_blocking(move || opened.migrate_and_start_runtime()).await??;
    let config = Arc::new(config);
    let mut writer_stopped = false;
    let app = AppState {
        storage,
        vault,
        clock,
        config: Arc::clone(&config),
        bridge: Arc::new(OfflineNodeBridge),
        egress,
    };
    let server_result: CommandResult = match http::router(app, bound.port()) {
        Ok(router) => {
            eprintln!("Hub listening on {bound}");
            let shutdown = async {
                tokio::select! {
                    biased;
                    _ = runtime.wait_stopped() => writer_stopped = true,
                    _ = interrupt.recv() => {}
                    _ = terminate.recv() => {}
                }
            };
            http_transport::serve(listener, router, config.max_tcp_connections, shutdown)
                .await
                .map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    };
    match runtime.shutdown().await {
        ShutdownReport::Complete => {}
        ShutdownReport::WalCheckpointIncomplete {
            busy,
            log,
            checkpointed,
        } => {
            eprintln!(
                "warning: Hub stopped with an incomplete WAL checkpoint (busy={busy}, log={log}, checkpointed={checkpointed})"
            );
        }
        ShutdownReport::Failed(error) => return Err(error.into()),
    }
    if writer_stopped {
        return Err("Hub database writer stopped unexpectedly".into());
    }
    server_result
}
