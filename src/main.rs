pub mod alloc;

mod config;
#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod serve;
mod track;

use clap::{Parser, Subcommand};
use config::Config;

type Result<T, E = error::Error> = std::result::Result<T, E>;

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Opt {
    #[clap(subcommand)]
    pub commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run TLS/HTTP2 tracking server
    Run(Config),

    /// Start TLS/HTTP2 tracking server daemon
    #[cfg(target_family = "unix")]
    Start(Config),

    /// Restart TLS/HTTP2 tracking server daemon
    #[cfg(target_family = "unix")]
    Restart(Config),

    /// Stop TLS/HTTP2 tracking server daemon
    #[cfg(target_family = "unix")]
    Stop,

    /// Show the TLS/HTTP2 tracking server daemon log
    #[cfg(target_family = "unix")]
    Log,

    /// Show the TLS/HTTP2 tracking server daemon process
    #[cfg(target_family = "unix")]
    PS,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    match opt.commands {
        Commands::Run(config) => serve::run(config),
        #[cfg(target_family = "unix")]
        Commands::Start(config) => daemon::start(config),
        #[cfg(target_family = "unix")]
        Commands::Restart(config) => daemon::restart(config),
        #[cfg(target_family = "unix")]
        Commands::Stop => daemon::stop(),
        #[cfg(target_family = "unix")]
        Commands::PS => daemon::status(),
        #[cfg(target_family = "unix")]
        Commands::Log => daemon::log(),
    }
}
