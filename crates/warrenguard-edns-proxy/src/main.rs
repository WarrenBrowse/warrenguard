//! `warren-edns-proxy`: run the Encrypted DNS proxy server, or encode the
//! `AAAA` record an operator must publish for a given proxy endpoint.
//!
//! Production usage:
//! ```text
//! # Run a XorV2 proxy forwarding to the Warren API:
//! warren-edns-proxy serve --listen 0.0.0.0:443 \
//!     --upstream api.warrenbrowse.com:443 --xor-key aabbcc
//!
//! # Compute the AAAA record to publish for that proxy's public address:
//! warren-edns-proxy encode --proxy-addr 203.0.113.7:443 --xor-key aabbcc
//! ```
//!
//! Binding a privileged port (e.g. 443) requires `CAP_NET_BIND_SERVICE`
//! (`setcap 'cap_net_bind_service=+ep' warren-edns-proxy`) or a port-forward;
//! do not run the binary as root just to bind 443.

use std::fmt::Write as _;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use warrenguard_edns_proxy::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS, DEFAULT_PER_IP_BURST,
    DEFAULT_PER_IP_MAX_CONCURRENT, DEFAULT_PER_IP_PER_SECOND, DEFAULT_PREFIX, Metrics,
    ObfuscationConfig, PerIpLimit, ProxyConfig, ProxyServer, ServerConfig, XorKey,
};

// mimalloc as global allocator, matching the relay/exit server binaries: this binary
// forwards every byte of the client's TLS session on the API hot path.
#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Warren Encrypted DNS proxy server and record encoder.
#[derive(Debug, Parser)]
#[command(
    name = "warren-edns-proxy",
    version,
    about = "Warren Encrypted DNS proxy: XOR-deobfuscating TCP forwarder to the Warren API",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the proxy server.
    Serve(ServeArgs),
    /// Encode the AAAA record to publish for a proxy endpoint.
    Encode(EncodeArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Address to listen on. Binding a privileged port needs
    /// `CAP_NET_BIND_SERVICE`.
    #[arg(short, long, value_name = "ADDR", default_value = "0.0.0.0:443")]
    listen: SocketAddr,
    /// Upstream `host:port` to forward the recovered stream to.
    #[arg(
        short,
        long,
        value_name = "HOST:PORT",
        default_value = "api.warrenbrowse.com:443"
    )]
    upstream: String,
    /// XOR key as hex (1..=6 bytes), e.g. `aabbcc`. Omit with `--plain`.
    #[arg(short = 'k', long, value_name = "HEX")]
    xor_key: Option<String>,
    /// Run an unobfuscated (plain) proxy instead of XorV2.
    #[arg(long, conflicts_with = "xor_key")]
    plain: bool,
    /// Maximum concurrent client connections.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    /// Upstream connect timeout, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_CONNECT_TIMEOUT.as_secs())]
    connect_timeout_secs: u64,
    /// Per-direction idle timeout, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_IDLE_TIMEOUT.as_secs())]
    idle_timeout_secs: u64,
    /// Sustained new connections per second per source IP. `0` disables per-IP
    /// rate limiting (IPv6 is keyed by /64). Keep generous for CGNAT users.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_PER_IP_PER_SECOND)]
    per_ip_per_second: u32,
    /// Per-source-IP connection burst allowance.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_PER_IP_BURST)]
    per_ip_burst: u32,
    /// Maximum concurrently active relay sessions per source IP. `0` disables
    /// the per-IP concurrency cap (IPv6 is keyed by /64). Distinct from
    /// `--per-ip-per-second` (which bounds new-connection rate, not standing
    /// session count).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_PER_IP_MAX_CONCURRENT)]
    per_ip_max_concurrent: u32,
    /// Address for the `/health`, `/readyz` and `/metrics` HTTP endpoints.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:19092")]
    health_addr: SocketAddr,
}

#[derive(Debug, Args)]
struct EncodeArgs {
    /// Public `IPv4:port` where this proxy listens.
    #[arg(short, long, value_name = "IPV4:PORT")]
    proxy_addr: SocketAddrV4,
    /// XOR key as hex (1..=6 bytes). Omit with `--plain`.
    #[arg(short = 'k', long, value_name = "HEX")]
    xor_key: Option<String>,
    /// Encode a plain (unobfuscated) proxy instead of XorV2.
    #[arg(long, conflicts_with = "xor_key")]
    plain: bool,
    /// Leading IPv6 prefix hextet (free, ignored by the client). 4 hex chars.
    #[arg(long, value_name = "HEX", default_value = "2001")]
    prefix: String,
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(args),
        Command::Encode(args) => encode(&args),
    }
}

fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let obfuscation = build_obfuscation(args.xor_key.as_deref(), args.plain)?;
    let per_ip_limit = build_per_ip_limit(args.per_ip_per_second, args.per_ip_burst);
    let per_ip_max_concurrent =
        (args.per_ip_max_concurrent > 0).then_some(args.per_ip_max_concurrent);
    let config = ServerConfig {
        upstream: args.upstream.clone(),
        obfuscation,
        max_connections: args.max_connections,
        connect_timeout: Duration::from_secs(args.connect_timeout_secs),
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
        per_ip_limit,
        per_ip_max_concurrent,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async move {
        let server = ProxyServer::bind(args.listen, config)
            .await
            .with_context(|| format!("binding listener on {}", args.listen))?;
        let local = server.local_addr().context("reading local addr")?;
        let metrics = server.metrics();
        tracing::info!(
            bind = %local,
            upstream = %args.upstream,
            max_connections = args.max_connections,
            per_ip_limit = per_ip_limit.map_or(0, |l| l.per_second.get()),
            mode = if obfuscation.is_some() { "xorv2" } else { "plain" },
            "warren-edns-proxy listening",
        );

        if !args.health_addr.ip().is_loopback() {
            tracing::warn!(
                addr = %args.health_addr,
                "health/metrics endpoint is NOT on loopback - /metrics exposes operational counters publicly",
            );
        }

        let cancel = CancellationToken::new();
        spawn_signal_handler(cancel.clone());
        spawn_health_server(args.health_addr, metrics.clone(), cancel.clone());

        server.run(cancel).await;
        tracing::info!(
            accepted = metrics.accepted.load(Ordering::Relaxed),
            "warren-edns-proxy stopped",
        );
        Ok(())
    })
}

fn encode(args: &EncodeArgs) -> anyhow::Result<()> {
    let obfuscation = build_obfuscation(args.xor_key.as_deref(), args.plain)?;
    let prefix = parse_prefix(&args.prefix)?;
    let cfg = ProxyConfig {
        addr: args.proxy_addr,
        obfuscation,
    };
    let aaaa = cfg.to_ipv6(prefix);
    println!("{aaaa}");
    eprintln!("publish as: <name>  IN  AAAA  {aaaa}");
    Ok(())
}

/// Build the obfuscation config from CLI flags. Exactly one of `xor_key` or
/// `plain` must be provided.
fn build_obfuscation(
    xor_key: Option<&str>,
    plain: bool,
) -> anyhow::Result<Option<ObfuscationConfig>> {
    match (xor_key, plain) {
        (Some(hex), false) => Ok(Some(ObfuscationConfig::XorV2(parse_xor_key(hex)?))),
        (None, true) => Ok(None),
        (None, false) => bail!("provide --xor-key <HEX> or --plain"),
        (Some(_), true) => unreachable!("clap conflicts_with prevents this"),
    }
}

/// Build the per-IP rate limit from CLI values. `per_second == 0` disables it;
/// a zero burst is clamped to 1 so the limiter is always well-formed.
fn build_per_ip_limit(per_second: u32, burst: u32) -> Option<PerIpLimit> {
    let per_second = std::num::NonZeroU32::new(per_second)?;
    let burst = std::num::NonZeroU32::new(burst.max(1)).expect("max(1) is non-zero");
    Some(PerIpLimit { per_second, burst })
}

/// Parse a 1..=6 byte XOR key from hex, zero-padding to 6 bytes.
fn parse_xor_key(hex_str: &str) -> anyhow::Result<XorKey> {
    let bytes = hex::decode(hex_str).context("xor key is not valid hex")?;
    if bytes.is_empty() || bytes.len() > 6 {
        bail!("xor key must be 1..=6 bytes ({} given)", bytes.len());
    }
    if bytes.iter().all(|b| *b == 0) {
        bail!("xor key must not be all zeros");
    }
    let mut padded = [0u8; 6];
    padded[..bytes.len()].copy_from_slice(&bytes);
    XorKey::try_from(padded).context("invalid xor key")
}

/// Parse the 2-byte IPv6 prefix hextet from exactly 4 hex chars (e.g. `2001`).
fn parse_prefix(hex_str: &str) -> anyhow::Result<[u8; 2]> {
    if hex_str.is_empty() {
        return Ok(DEFAULT_PREFIX);
    }
    if hex_str.len() != 4 {
        bail!("prefix must be exactly 4 hex chars (2 bytes), e.g. 2001");
    }
    let bytes = hex::decode(hex_str).context("prefix is not valid hex")?;
    <[u8; 2]>::try_from(bytes.as_slice()).context("prefix must be a 2-byte hextet, e.g. 2001")
}

/// Install SIGINT/SIGTERM handlers that trigger graceful shutdown.
fn spawn_signal_handler(cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(error) => {
                tracing::error!(%error, "failed to install SIGINT handler");
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => tracing::info!("SIGINT received"),
            _ = sigterm.recv() => tracing::info!("SIGTERM received"),
        }
        cancel.cancel();
    });
}

/// Serve `/health`, `/readyz` and `/metrics` until `cancel` fires.
fn spawn_health_server(addr: SocketAddr, metrics: Arc<Metrics>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let metrics_for_route = metrics.clone();
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/readyz",
                axum::routing::get(|| async { (axum::http::StatusCode::OK, "ready") }),
            )
            .route(
                "/metrics",
                axum::routing::get(move || {
                    let m = metrics_for_route.clone();
                    async move { prometheus(&m) }
                }),
            );
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(%addr, %error, "health server failed to bind");
                return;
            }
        };
        tracing::info!(%addr, "health server listening");
        let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
            cancel.cancelled().await;
        });
        if let Err(error) = serve.await {
            tracing::warn!(%error, "health server exited");
        }
    });
}

/// Render the metrics in Prometheus text exposition format.
fn prometheus(m: &Metrics) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let mut body = String::with_capacity(512);
    let _ = writeln!(body, "# TYPE warren_edns_accepted_total counter");
    let _ = writeln!(
        body,
        "warren_edns_accepted_total {}",
        m.accepted.load(Ordering::Relaxed)
    );
    let _ = writeln!(body, "# TYPE warren_edns_completed_total counter");
    let _ = writeln!(
        body,
        "warren_edns_completed_total {}",
        m.completed.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "# TYPE warren_edns_rejected_at_capacity_total counter"
    );
    let _ = writeln!(
        body,
        "warren_edns_rejected_at_capacity_total {}",
        m.rejected_at_capacity.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "# TYPE warren_edns_rejected_rate_limited_total counter"
    );
    let _ = writeln!(
        body,
        "warren_edns_rejected_rate_limited_total {}",
        m.rejected_rate_limited.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "# TYPE warren_edns_rejected_per_ip_concurrency_total counter"
    );
    let _ = writeln!(
        body,
        "warren_edns_rejected_per_ip_concurrency_total {}",
        m.rejected_per_ip_concurrency.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "# TYPE warren_edns_upstream_connect_failures_total counter"
    );
    let _ = writeln!(
        body,
        "warren_edns_upstream_connect_failures_total {}",
        m.upstream_connect_failures.load(Ordering::Relaxed)
    );
    let _ = writeln!(body, "# TYPE warren_edns_active gauge");
    let _ = writeln!(body, "warren_edns_active {}", m.active());
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Default to `info`, NOT debug: this service handles at-risk users and the
    // debug level is where connection-level detail lives. Operators opt in
    // explicitly via `RUST_LOG`.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
