use clap::Args;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Args, Clone)]
pub struct Config {
    /// Debug mode
    #[clap(long, env = "PINGLY_DEBUG")]
    pub debug: bool,

    /// Bind address
    #[clap(short, long, default_value = "0.0.0.0:8181")]
    pub bind: SocketAddr,

    /// Concurrent connections
    #[clap(short, long, default_value = "1024")]
    pub concurrent: usize,

    /// TLS certificate file path
    #[clap(short = 'C', long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    #[clap(short = 'K', long)]
    pub tls_key: Option<PathBuf>,
}
