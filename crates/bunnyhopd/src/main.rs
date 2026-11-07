mod daemon;
mod ipc;

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use bunnyhop_config::DaemonConfig;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "bunnyhopd",
    version,
    about = "The bunnyhop daemon: a mesh client, a lighthouse, or both"
)]
struct Cli {
    #[arg(
        short,
        long,
        default_value = "/etc/bunnyhop/bunnyhopd.toml",
        help = "The config file to run with"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Validate bunnyhopd.toml and exit")]
    CheckConfig {
        #[arg(help = "Defaults to --config")]
        path: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let default_level = if cli.command.is_none() {
        "info,hickory_server=warn,rtc_ice=warn"
    } else {
        "warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .with_writer(io::stderr)
        .init();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe) =>
        {
            ExitCode::SUCCESS
        },
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "error: {error:#}");
            ExitCode::FAILURE
        },
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        None => daemon::run(&cli.config).await,
        Some(Command::CheckConfig { path }) => {
            let path = path.unwrap_or(cli.config);
            DaemonConfig::load(&path).with_context(|| format!("loading {}", path.display()))?;
            writeln!(io::stdout().lock(), "{} is valid", path.display())?;
            Ok(())
        },
    }
}
