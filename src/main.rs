mod client;
mod cover;
mod config;
mod crypto;
mod obfuscation;
mod peer;
mod protocol;
mod server;
mod tls;

use std::{path::PathBuf,sync::Arc};
use anyhow::Result;
use clap::{Parser,Subcommand};
use tokio::net::TcpStream;
use tokio::time::{Duration,timeout};
use config::{Config,Role};

#[derive(Parser)]
#[command(name="rustine",version,about="Rustine | Vibe VPN — two-hop TLS tunnel")]
struct Cli {
    #[arg(long,env="RUSTINE_CONFIG",global=true)]
    config:Option<PathBuf>,
    #[command(subcommand)]
    command:Option<Command>,
}
#[derive(Subcommand)] enum Command {
    /// Checks TCP reachability of a service without using its credentials.
    Health{#[arg(long)] target:String},
    /// Validates configuration, certificate file paths and feature flags.
    Check,
}
#[tokio::main]
async fn main()->Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_|"rustine=info".into())).init();
    let cli=Cli::parse();
    if let Some(Command::Health{target})=&cli.command {
        timeout(Duration::from_secs(3),TcpStream::connect(target)).await??;
        println!("healthy"); return Ok(());
    }
    let cfg=Arc::new(Config::load(cli.config.as_deref())?);
    if matches!(cli.command,Some(Command::Check)) {
        match cfg.role {
            Role::Client => { tls::connector(&cfg)?; }
            Role::Relay => { tls::acceptor(&cfg)?; tls::connector(&cfg)?; }
            Role::Exit => { tls::acceptor(&cfg)?; }
        }
        println!("configuration and TLS material valid");
        return Ok(());
    }
    match cfg.role {
        Role::Client=>client::run(cfg).await,
        Role::Relay|Role::Exit=>server::run(cfg).await,
    }
}
