//! `warren-natpmp-request` - CLI tool to request a NAT-PMP mapping
//! from the Warren exit and log the result.
//!
//! Typical usage (from an active tunnel client):
//!
//! ```sh
//! warren-natpmp-request --server 10.66.0.1:5351 \
//!     --proto udp --internal-port 8080 --lifetime 60
//! ```
//!
//! Stdout: `external_port=49152` or non-zero exit code + error log.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;
use warrenguard_natpmp_client::{NatPmpClientError, default_server_addr, request_map};
use warrenguard_natpmp_protocol::MapProto;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliProto {
    Tcp,
    Udp,
}

impl From<CliProto> for MapProto {
    fn from(p: CliProto) -> Self {
        match p {
            CliProto::Tcp => MapProto::Tcp,
            CliProto::Udp => MapProto::Udp,
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Warren NAT-PMP request CLI")]
struct Args {
    /// Address of the NAT-PMP server (typically the exit tunnel
    /// gateway `10.66.0.1:5351`). If absent, uses the default value.
    #[arg(long)]
    server: Option<SocketAddr>,

    /// TCP or UDP protocol.
    #[arg(long, value_enum)]
    proto: CliProto,

    /// Internal port on the client side (the one to expose).
    #[arg(long)]
    internal_port: u16,

    /// Suggested external port (`0` = server picks).
    #[arg(long, default_value_t = 0)]
    suggested_external_port: u16,

    /// Requested lifetime in seconds. The server may grant less.
    /// `0` = delete-mapping (RFC 6886 §3.3.2).
    #[arg(long, default_value_t = 3600)]
    lifetime_secs: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let server = args.server.unwrap_or_else(default_server_addr);

    tracing::info!(
        ?server,
        proto = ?args.proto,
        internal_port = args.internal_port,
        suggested_external_port = args.suggested_external_port,
        lifetime_secs = args.lifetime_secs,
        "sending NAT-PMP map request"
    );

    let res = request_map(
        server,
        args.proto.into(),
        args.internal_port,
        args.suggested_external_port,
        args.lifetime_secs,
    )
    .await;

    match res {
        Ok(mapping) => {
            tracing::info!(
                external_port = mapping.external_port,
                internal_port = mapping.internal_port,
                lifetime_secs = mapping.lifetime_secs,
                epoch_secs = mapping.epoch_secs,
                "NAT-PMP mapping established"
            );
            // Machine-readable output for scripts.
            println!("external_port={}", mapping.external_port);
            println!("lifetime_secs={}", mapping.lifetime_secs);
            println!("epoch_secs={}", mapping.epoch_secs);
            Ok(())
        }
        Err(NatPmpClientError::Server(rc)) => {
            anyhow::bail!("NAT-PMP server returned error code: {rc:?}")
        }
        Err(e) => Err(e).context("NAT-PMP request failed"),
    }
}
