//! `warrenguard` - reference CLI driving the WarrenGuard engine as a generic
//! VPN-over-QUIC tool, with no Warren backend in the path ("like WireGuard").
//!
//! Subcommands:
//! - `keygen`  - print a fresh node key: a 32-byte seed (the secret to keep) and
//!   its `ed25519:<base64>` public key (the value a peer pins, like WireGuard's
//!   `PublicKey=`).
//! - `serve`   - bind a generic exit (`AllowAll`: any peer that completes the RPK
//!   TLS handshake is admitted) and serve until interrupted.
//! - `connect` - dial a server pinned by its public key + endpoint, complete the
//!   handshake, and print the tunnel IP the server allocated.
//!
//! The identity layer is pulled with `default-features = false` (no BIP39): keys
//! are raw seeds, so a deployer can source them from a file / KMS / `keygen`.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use warrenguard_identity::derive_node_key;
use warrenguard_server::{AllowlistHandle, ExitBindOpts, ExitListener};
use warrenguard_transport::ClientTunnel;
use warrenguard_wire::{WarrenExitAddr, WarrenPubkey};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(name = "warrenguard", about = "Generic WarrenGuard VPN-over-QUIC tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a fresh node key (seed + public key).
    Keygen,
    /// Run an exit server. Open (`AllowAll`) by default; pass `--peer` one or
    /// more times to enforce a closed static roster (the WireGuard `AllowedIPs`
    /// analog at the peer-identity level).
    Serve {
        /// Address to bind the QUIC server on.
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        /// 32-byte node seed as hex (64 chars). Omit for an ephemeral identity.
        #[arg(long)]
        seed: Option<String>,
        /// Authorized peer public key, `ed25519:<base64>` (a peer's `keygen`
        /// output). Repeatable. When given, ONLY these peers may handshake;
        /// every other key is refused before any tunnel IP is assigned. Omit
        /// for the open `AllowAll` policy.
        #[arg(long = "peer", value_name = "ed25519:<base64>")]
        peers: Vec<String>,
        /// Path to a PEM certificate chain (leaf-first, e.g. ACME
        /// `fullchain.pem`). Enables v6 X.509 mode: the exit presents this
        /// real certificate so the TLS handshake looks like an ordinary
        /// HTTPS/h3 server, and its Warren identity is proven in-band. Must
        /// be paired with `--tls-key`. Omit for the RPK-via-SNI default.
        #[arg(long = "tls-cert", value_name = "PEM", env = "WARREN_TLS_CERT")]
        tls_cert: Option<String>,
        /// Path to the PEM private key for `--tls-cert` (e.g. ACME
        /// `privkey.pem`). Required when `--tls-cert` is given.
        #[arg(long = "tls-key", value_name = "PEM", env = "WARREN_TLS_KEY")]
        tls_key: Option<String>,
    },
    /// Connect to a server and print the allocated tunnel IP.
    Connect {
        /// Server public key, `ed25519:<base64>` (from the server's `serve` log).
        #[arg(long)]
        server_key: String,
        /// Server endpoint `host:port`.
        #[arg(long)]
        server_addr: SocketAddr,
        /// 32-byte client node seed as hex. Omit for an ephemeral identity.
        #[arg(long)]
        seed: Option<String>,
        /// Cover-domain SNI to dial in v6 X.509 mode (the domain on the
        /// exit's real certificate, e.g. `cover.example.com`). When set, the
        /// client validates the exit's X.509 chain via WebPKI instead of
        /// pinning its raw public key in the SNI; the exit's Warren identity
        /// is still verified in-band against `--server-key`. Omit for the
        /// RPK-via-SNI default.
        #[arg(long = "cover-domain", value_name = "DOMAIN")]
        cover_domain: Option<String>,
        /// Path to a PEM CA bundle to validate the exit certificate against
        /// (a self-hosted CA). Only meaningful with `--cover-domain`. Omit to
        /// validate against the bundled Mozilla root program (public ACME).
        #[arg(long = "ca", value_name = "PEM")]
        ca: Option<String>,
    },
}

/// Loads a PEM cert chain + key into the DER shape `ExitBindOpts` expects.
/// Both paths must be present (enforced by the caller); a load failure names
/// the offending file so the operator can fix the right path.
fn load_tls_certificate(cert_path: &str, key_path: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("reading --tls-cert {cert_path}"))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("reading --tls-key {key_path}"))?;
    let chain = warrenguard_tls::load_cert_chain_pem(&cert_pem)
        .with_context(|| format!("parsing --tls-cert {cert_path}"))?;
    let key = warrenguard_tls::load_private_key_pem(&key_pem)
        .with_context(|| format!("parsing --tls-key {key_path}"))?;
    let chain_der = chain.iter().map(|c| c.as_ref().to_vec()).collect();
    let key_der = key.secret_der().to_vec();
    Ok((chain_der, key_der))
}

/// Resolves the `--tls-cert` / `--tls-key` flag pair, enforcing that both are
/// supplied together. One without the other is a config error, never a silent
/// fall-back to the RPK default (which would defeat the operator's intent to
/// run X.509 mode).
fn resolve_tls_flags(
    cert: Option<String>,
    key: Option<String>,
) -> Result<Option<(String, String)>> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c, k))),
        (None, None) => Ok(None),
        (Some(_), None) => bail!("--tls-cert requires --tls-key"),
        (None, Some(_)) => bail!("--tls-key requires --tls-cert"),
    }
}

/// Loads a PEM CA bundle into the DER trust-anchor shape `with_x509` expects.
fn load_ca_roots(ca_path: &str) -> Result<Vec<Vec<u8>>> {
    let ca_pem = std::fs::read(ca_path).with_context(|| format!("reading --ca {ca_path}"))?;
    let certs = warrenguard_tls::load_cert_chain_pem(&ca_pem)
        .with_context(|| format!("parsing --ca {ca_path}"))?;
    Ok(certs.iter().map(|c| c.as_ref().to_vec()).collect())
}

/// `ed25519:<base64>` is the WireGuard-analog public-key display: a short,
/// copy-pasteable identity a peer pins.
fn format_pubkey(pk: &[u8; 32]) -> String {
    format!("ed25519:{}", data_encoding::BASE64.encode(pk))
}

fn parse_pubkey(s: &str) -> Result<[u8; 32]> {
    let b64 = s
        .strip_prefix("ed25519:")
        .context("public key must be `ed25519:<base64>`")?;
    let raw = data_encoding::BASE64
        .decode(b64.as_bytes())
        .context("public key base64 is invalid")?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("public key must decode to exactly 32 bytes"))
}

fn parse_seed(hex_seed: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut raw = hex::decode(hex_seed.trim()).context("seed must be hex")?;
    let seed: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed must be exactly 32 bytes (64 hex chars)"))?;
    raw.zeroize();
    Ok(Zeroizing::new(seed))
}

/// True if `ip` falls within the shared tunnel IP pool
/// (`warrenguard_config::TUNNEL_POOL_NETWORK`/`TUNNEL_POOL_PREFIX`). Derived
/// from those constants rather than a hardcoded octet pattern so the CLI's
/// sanity check and the pool definition it is validating against cannot
/// drift apart.
fn is_in_tunnel_pool(ip: Ipv4Addr) -> bool {
    let prefix = u32::from(warrenguard_config::TUNNEL_POOL_PREFIX);
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(warrenguard_config::TUNNEL_POOL_NETWORK) & mask)
}

/// Turns the `--peer` flags into the exit's admission policy.
///
/// `None` (no peers) keeps the open `AllowAll` policy. Otherwise every value is
/// parsed as an `ed25519:<base64>` key and folded into a closed static roster.
/// A single malformed entry fails the whole roster: a typo must never silently
/// widen admission (fail-closed).
fn parse_peer_roster(peers: &[String]) -> Result<Option<AllowlistHandle>> {
    if peers.is_empty() {
        return Ok(None);
    }
    let mut keys = Vec::with_capacity(peers.len());
    for p in peers {
        let raw = parse_pubkey(p).with_context(|| format!("invalid --peer value: {p}"))?;
        keys.push(WarrenPubkey::from_bytes(raw));
    }
    Ok(Some(AllowlistHandle::from_static_keys(keys)))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Command::Keygen => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::fill(&mut *seed);
            let key = derive_node_key(&seed);
            let pubkey = key.verifying_key().to_bytes();
            // The seed is deliberately printed (that is the whole point of
            // `keygen`: it is the secret the operator must save); only the
            // in-process buffer is zeroized on drop.
            println!("seed       {}", hex::encode(*seed));
            println!("public key {}", format_pubkey(&pubkey));
        }

        Command::Serve {
            listen,
            seed,
            peers,
            tls_cert,
            tls_key,
        } => {
            let signing_key = match seed {
                Some(s) => Some(derive_node_key(&*parse_seed(&s)?)),
                None => None,
            };
            // An empty `--peer` list keeps the open AllowAll policy; one or more
            // turns the exit into a closed static roster.
            let allowlist = parse_peer_roster(&peers)?;
            let policy = match &allowlist {
                Some(_) => format!("StaticAllowlist ({} authorized peer(s))", peers.len()),
                None => "AllowAll (any handshaking peer is admitted)".to_owned(),
            };
            // X.509 mode requires both flags together; one without the other
            // is a config error, not a silent fall-back to RPK.
            let tls_certificate = match resolve_tls_flags(tls_cert, tls_key)? {
                Some((cert, key)) => Some(load_tls_certificate(&cert, &key)?),
                None => None,
            };
            let tls_mode = if tls_certificate.is_some() {
                "X.509 (in-band Warren identity)"
            } else {
                "RPK-via-SNI"
            };
            let opts = ExitBindOpts {
                signing_key,
                allowlist,
                tls_certificate,
                ..Default::default()
            };
            let exit = ExitListener::bind_with_opts(listen, opts)
                .await
                .context("bind the exit server")?;
            println!("public key {}", format_pubkey(exit.pubkey().as_bytes()));
            println!("listening  {listen}");
            println!("policy     {policy}");
            println!("tls        {tls_mode}");
            exit.accept_forever().await.context("serve loop")?;
        }

        Command::Connect {
            server_key,
            server_addr,
            seed,
            cover_domain,
            ca,
        } => {
            let server_pk = parse_pubkey(&server_key)?;
            let target =
                WarrenExitAddr::new(WarrenPubkey::from_bytes(server_pk)).with_ip_addr(server_addr);
            let client = match seed {
                Some(s) => ClientTunnel::with_signing_key(&derive_node_key(&*parse_seed(&s)?)),
                None => ClientTunnel::new(),
            };
            // `--ca` only makes sense paired with `--cover-domain` (X.509 mode);
            // flag it rather than silently ignore a misplaced trust anchor.
            if ca.is_some() && cover_domain.is_none() {
                bail!("--ca requires --cover-domain (it is only used in X.509 mode)");
            }
            let client = match cover_domain {
                Some(domain) => match ca {
                    Some(ca_path) => client.with_x509(load_ca_roots(&ca_path)?, domain),
                    None => client.with_x509_webpki(domain),
                },
                None => client,
            };
            let session = client
                .connect(target)
                .await
                .context("handshake with the server")?;
            println!("connected");
            println!("tunnel ipv4 {}", session.assigned_ipv4());
            if let Some(v6) = session.assigned_ipv6() {
                println!("tunnel ipv6 {v6}");
            }
            if is_in_tunnel_pool(session.assigned_ipv4()) {
                Ok::<(), anyhow::Error>(())
            } else {
                bail!("server returned an unexpected tunnel IP")
            }?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_display_round_trips_through_parse() {
        let raw = [0x9au8; 32];
        let shown = format_pubkey(&raw);
        assert!(shown.starts_with("ed25519:"), "WireGuard-style prefix");
        assert_eq!(parse_pubkey(&shown).expect("parse own output"), raw);
    }

    #[test]
    fn parse_pubkey_rejects_bad_input() {
        assert!(
            parse_pubkey("no-prefix").is_err(),
            "missing ed25519: prefix"
        );
        assert!(
            parse_pubkey("ed25519:not base64!!").is_err(),
            "invalid base64"
        );
        // Valid base64 but the wrong length (16 bytes, not 32).
        let short = format!("ed25519:{}", data_encoding::BASE64.encode(&[0u8; 16]));
        assert!(parse_pubkey(&short).is_err(), "wrong decoded length");
    }

    #[test]
    fn parse_seed_requires_exactly_32_bytes() {
        assert_eq!(
            *parse_seed(&hex::encode([7u8; 32])).expect("32 bytes"),
            [7u8; 32]
        );
        assert!(parse_seed(&hex::encode([0u8; 31])).is_err(), "too short");
        assert!(parse_seed("zz").is_err(), "not hex");
    }

    #[test]
    fn parse_seed_returns_zeroizing_seed() {
        // Minor defect fix: a 32-byte node seed is secret material, so
        // `parse_seed` must hand it back wrapped in `Zeroizing` (scrubbed on
        // drop) rather than a bare `[u8; 32]`. The explicit type annotation
        // makes this a compile-time check.
        let seed: Zeroizing<[u8; 32]> =
            parse_seed(&hex::encode([9u8; 32])).expect("32 bytes parses");
        assert_eq!(*seed, [9u8; 32]);
    }

    #[test]
    fn is_in_tunnel_pool_accepts_the_shared_pool_network() {
        // Minor defect fix: the tunnel-IP sanity check must be derived from
        // `warrenguard_config::TUNNEL_POOL_NETWORK`/`TUNNEL_POOL_PREFIX`, not
        // a hardcoded `[10, 66, _, _]` pattern, so the two cannot drift.
        assert!(is_in_tunnel_pool(warrenguard_config::TUNNEL_POOL_NETWORK));
        assert!(is_in_tunnel_pool(warrenguard_config::TUNNEL_GATEWAY_IP));
        assert!(is_in_tunnel_pool(Ipv4Addr::new(10, 66, 255, 255)));
    }

    #[test]
    fn is_in_tunnel_pool_rejects_ips_outside_the_pool() {
        assert!(!is_in_tunnel_pool(Ipv4Addr::new(10, 67, 0, 1)));
        assert!(!is_in_tunnel_pool(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_in_tunnel_pool(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn no_peer_flags_means_open_allow_all() {
        assert!(
            parse_peer_roster(&[]).expect("empty roster ok").is_none(),
            "no --peer must keep the open AllowAll policy (None)"
        );
    }

    #[test]
    fn peer_flags_build_a_closed_roster_that_admits_only_listed_keys() {
        let listed = [0x11u8; 32];
        let other = [0x22u8; 32];
        let roster = parse_peer_roster(&[format_pubkey(&listed)])
            .expect("valid peer")
            .expect("a roster, not AllowAll");
        // `now` is irrelevant: a static roster never expires locally.
        assert!(
            roster.is_allowed_at(&WarrenPubkey::from_bytes(listed), 1_000),
            "the listed peer is admitted"
        );
        assert!(
            !roster.is_allowed_at(&WarrenPubkey::from_bytes(other), 1_000),
            "an unlisted peer is refused (closed roster)"
        );
    }

    #[test]
    fn multiple_peers_all_admitted_others_refused() {
        // The roster is inherently multi-peer (the WireGuard analog). Exercise
        // the parse loop with N>1 so a "first-peer-only" / off-by-one bug cannot
        // hide: every listed key must be admitted, an unlisted one refused.
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        let unlisted = [0x44u8; 32];
        let roster = parse_peer_roster(&[format_pubkey(&a), format_pubkey(&b), format_pubkey(&c)])
            .expect("valid peers")
            .expect("a roster, not AllowAll");
        for listed in [a, b, c] {
            assert!(
                roster.is_allowed_at(&WarrenPubkey::from_bytes(listed), 1_000),
                "every listed peer must be admitted"
            );
        }
        assert!(
            !roster.is_allowed_at(&WarrenPubkey::from_bytes(unlisted), 1_000),
            "an unlisted peer must be refused even with a multi-peer roster"
        );
    }

    #[test]
    fn serve_parses_tls_cert_and_key_flags() {
        let cli = Cli::try_parse_from([
            "warrenguard",
            "serve",
            "--tls-cert",
            "/etc/le/fullchain.pem",
            "--tls-key",
            "/etc/le/privkey.pem",
        ])
        .expect("valid serve invocation");
        match cli.cmd {
            Command::Serve {
                tls_cert, tls_key, ..
            } => {
                assert_eq!(tls_cert.as_deref(), Some("/etc/le/fullchain.pem"));
                assert_eq!(tls_key.as_deref(), Some("/etc/le/privkey.pem"));
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn connect_parses_cover_domain_and_ca_flags() {
        let cli = Cli::try_parse_from([
            "warrenguard",
            "connect",
            "--server-key",
            "ed25519:AAAA",
            "--server-addr",
            "127.0.0.1:443",
            "--cover-domain",
            "cover.example.com",
            "--ca",
            "/tmp/ca.pem",
        ])
        .expect("valid connect invocation");
        match cli.cmd {
            Command::Connect {
                cover_domain, ca, ..
            } => {
                assert_eq!(cover_domain.as_deref(), Some("cover.example.com"));
                assert_eq!(ca.as_deref(), Some("/tmp/ca.pem"));
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn resolve_tls_flags_requires_both_or_neither() {
        // Both: X.509 mode.
        assert_eq!(
            resolve_tls_flags(Some("c".into()), Some("k".into())).expect("both ok"),
            Some(("c".to_owned(), "k".to_owned()))
        );
        // Neither: RPK default.
        assert_eq!(resolve_tls_flags(None, None).expect("neither ok"), None);
        // One without the other: fail closed, do not silently drop to RPK.
        assert!(
            resolve_tls_flags(Some("c".into()), None).is_err(),
            "--tls-cert without --tls-key must error"
        );
        assert!(
            resolve_tls_flags(None, Some("k".into())).is_err(),
            "--tls-key without --tls-cert must error"
        );
    }

    #[test]
    fn one_malformed_peer_fails_the_whole_roster() {
        // Fail-closed: a typo in one --peer must not silently drop to a
        // narrower-or-wider roster; the whole serve invocation errors out.
        let good = format_pubkey(&[0x33u8; 32]);
        let bad = "ed25519:not-base64!!";
        let err = parse_peer_roster(&[good, bad.to_owned()])
            .expect_err("a malformed peer must fail the roster");
        // The diagnostic must name the offending value so the operator can fix
        // the right flag (a bare error would be unactionable with many peers).
        assert!(
            format!("{err:#}").contains(bad),
            "the error must name the bad --peer value, got: {err:#}"
        );
    }
}
