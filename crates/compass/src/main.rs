mod control;
mod ctl;

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::control::Control;
use clap::{Args, Parser, Subcommand};
use compass_config::DEFAULT_SOCKET;
use compass_proto::{AuthKey, DnsName, ExitNodeChoice, PrivateKey};

#[derive(Parser)]
#[command(
    name = "compass",
    version,
    about = "Control compassd and manage compass keys"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "COMPASS_SOCKET",
        default_value = DEFAULT_SOCKET,
        help = "compassd's control socket"
    )]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Show the connection and peers")]
    Status {
        #[command(flatten)]
        output: Output,
    },
    #[command(about = "List this node's DNS records and whether the lighthouse accepted them")]
    Dns {
        #[command(flatten)]
        output: Output,
    },
    #[command(about = "Change the exit node until compassd restarts or reloads")]
    ExitNode {
        #[command(subcommand)]
        command: ExitNodeCommand,
        #[command(flatten)]
        output: Output,
    },
    #[command(about = "Generate a WireGuard private key for a node or a hub")]
    Genkey,
    #[command(about = "Generate a pre-auth key secret")]
    Authkey,
}

#[derive(Args)]
struct Output {
    #[arg(long, global = true, help = "Print JSON instead of text")]
    json: bool,
}

#[derive(Subcommand)]
enum ExitNodeCommand {
    #[command(about = "Send internet traffic through this peer")]
    Use { peer: DnsName },
    #[command(about = "Send internet traffic directly")]
    Off,
    #[command(about = "Go back to the exit node in the config")]
    Reset,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

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
    let control = Control::new(cli.socket);

    match cli.command {
        Command::Status { output } => ctl::status(&control, output.json).await,
        Command::Dns { output } => ctl::dns(&control, output.json).await,
        Command::ExitNode { command, output } => {
            let choice = match command {
                ExitNodeCommand::Use { peer } => ExitNodeChoice::Peer(peer),
                ExitNodeCommand::Off => ExitNodeChoice::Off,
                ExitNodeCommand::Reset => ExitNodeChoice::Config,
            };

            ctl::set_exit_node(&control, choice, output.json).await
        },
        Command::Genkey => {
            let key = PrivateKey::generate().to_base64();
            writeln!(io::stdout().lock(), "{}", key.as_str())?;
            Ok(())
        },
        Command::Authkey => {
            writeln!(io::stdout().lock(), "{}", AuthKey::generate().expose())?;
            Ok(())
        },
    }
}
