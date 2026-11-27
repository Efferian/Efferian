use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, error::ErrorKind};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;

use crate::config::{self, Authority, Config, CsvList, Origin, Overrides};
use crate::egress::EgressClient;
use crate::execution::state::{finish_upstreams_for_shutdown, recover_upstreams, sweep_deadlines};
use crate::http::{self, AppState};
use crate::http_transport;
use crate::node_bridge::OfflineNodeBridge;
use crate::operations;
use crate::storage::{OpenMode, ShutdownReport, StorageClock, StorageRuntime, SystemStorageClock};

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
        #[arg(long, value_name = "LIST")]
        allowed_hosts: Option<CsvList<Authority>>,
        /// Allow these HTTP or HTTPS origins (comma-separated).
        #[arg(long, value_name = "LIST")]
        allowed_origins: Option<CsvList<Origin>>,
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
                    allowed_hosts: allowed_hosts.map(|list| list.0),
                    allowed_origins: allowed_origins.map(|list| list.0),
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
    let interrupt = signal(SignalKind::interrupt())?;
    let terminate = signal(SignalKind::terminate())?;
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
    let (storage, runtime) =
        tokio::task::spawn_blocking(move || opened.migrate_and_start_runtime()).await??;
    let app = AppState::new(
        storage,
        vault,
        clock,
        Arc::new(config),
        Arc::new(OfflineNodeBridge),
        egress,
    );
    let server_result = serve_running(app, &runtime, interrupt, terminate).await;
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
    server_result
}

async fn serve_running(
    app: AppState,
    runtime: &StorageRuntime,
    mut interrupt: tokio::signal::unix::Signal,
    mut terminate: tokio::signal::unix::Signal,
) -> CommandResult {
    recover_upstreams(&app.storage).await?;
    let listener = TcpListener::bind(app.config.listen).await?;
    let bound = listener.local_addr()?;
    let router = http::router(app.clone(), bound.port())?;
    let (stop_http, http_stop) = oneshot::channel();
    let server = http_transport::serve(listener, router, app.config.max_tcp_connections, async {
        let _ = http_stop.await;
    });
    tokio::pin!(server);
    let sweeper = tokio::spawn(deadline_sweeper(app.clone()));
    eprintln!("Hub listening on {bound}");

    let (writer_healthy, already_stopped) = tokio::select! {
        biased;
        _ = runtime.wait_stopped() => (false, None),
        _ = interrupt.recv() => (true, None),
        _ = terminate.recv() => (true, None),
        result = &mut server => (true, Some(result)),
    };
    app.execution.stop();
    let _ = stop_http.send(());

    let (server_result, cleanup_result) = tokio::join!(
        async {
            match already_stopped {
                Some(result) => result,
                None => server.await,
            }
        },
        async {
            let _ = sweeper.await;
            cleanup_dispatchers(&app, writer_healthy).await
        },
    );
    if !writer_healthy {
        return Err("Hub database writer stopped unexpectedly".into());
    }
    server_result?;
    cleanup_result?;
    Ok(())
}

async fn cleanup_dispatchers(app: &AppState, writer_healthy: bool) -> CommandResult {
    let barrier = if writer_healthy {
        app.storage.work_barrier().await
    } else {
        Ok(())
    };
    let can_flush_receipts = writer_healthy && barrier.is_ok();
    tokio::join!(
        drain_dispatcher(app.bridge.shutdown_graceful(can_flush_receipts)),
        drain_dispatcher(app.upstream.shutdown()),
    );
    barrier?;
    if writer_healthy {
        finish_upstreams_for_shutdown(app).await?;
    }
    Ok(())
}

async fn drain_dispatcher(shutdown: impl std::future::Future<Output = ()>) {
    if tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .is_err()
    {
        tracing::warn!("Dispatcher shutdown deadline elapsed");
    }
}

async fn deadline_sweeper(app: AppState) {
    let mut shutdown = app.execution.shutdown_receiver();
    let period = Duration::from_secs(10);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = async { let _ = shutdown.wait_for(|&stopping| stopping).await; } => return,
            _ = interval.tick() => {
                if let Err(error) = sweep_deadlines(&app).await {
                    tracing::warn!(%error, "Execution deadline sweep did not complete");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    mod shutdown;

    use super::*;

    #[test]
    fn serve_parses_csv_allowed_hosts_and_allowed_origins_without_panicking()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = Cli::try_parse_from([
            "efferian-hub",
            "serve",
            "--state-dir",
            "/tmp/state",
            "--listen",
            "0.0.0.0:8080",
            "--allowed-hosts",
            "hub.example:443,[::1]:8080",
            "--allowed-origins",
            "https://console.example:443,http://app.example:80",
        ])?;
        let Command::Serve {
            allowed_hosts,
            allowed_origins,
            ..
        } = parsed.command
        else {
            return Err("expected serve subcommand".into());
        };
        assert_eq!(
            allowed_hosts.map(|list| list.0),
            Some(vec!["hub.example:443".parse()?, "[::1]:8080".parse()?,])
        );
        assert_eq!(
            allowed_origins.map(|list| list.0),
            Some(vec![
                "https://console.example".parse()?,
                "http://app.example".parse()?,
            ])
        );

        let single = Cli::try_parse_from([
            "efferian-hub",
            "serve",
            "--allowed-hosts",
            "hub.example:443",
            "--allowed-origins",
            "https://console.example",
        ])?;
        assert!(matches!(
            single.command,
            Command::Serve {
                allowed_hosts: Some(_),
                allowed_origins: Some(_),
                ..
            }
        ));

        for bad in [
            [
                "efferian-hub",
                "serve",
                "--allowed-hosts",
                "hub.example:0443",
            ],
            ["efferian-hub", "serve", "--allowed-hosts", "hub.example,"],
            [
                "efferian-hub",
                "serve",
                "--allowed-origins",
                "https://console.example/",
            ],
        ] {
            assert!(Cli::try_parse_from(bad).is_err(), "{bad:?}");
        }
        Ok(())
    }
}
