//! `warrenguard` - reference CLI driving the WarrenGuard engine as a generic
//! VPN-over-QUIC tool, with no Warren backend in the path ("like WireGuard").
//!
//! Subcommands:
//! - `keygen` - print a fresh node key: a 32-byte seed (the secret to keep) and
//!   its `ed25519:<base64>` public key (the value a peer pins, like WireGuard's
//!   `PublicKey=`).
//! - `serve`  - bind a multi-hop exit (the datapath the Warren desktop app
//!   dials), admit every peer that completes the handshake (no control-plane),
//!   allocate one tunnel IP per connection, and serve until interrupted.
//!
//! The identity layer is pulled with `default-features = false` (no BIP39): keys
//! are raw seeds, so a deployer can source them from a file / KMS / `keygen`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use quinn::Endpoint;
use warrenguard_identity::derive_node_key;
use warrenguard_multihop::ExitId;
use warrenguard_multihop_server::ip_pool::IpAllocator;
use warrenguard_multihop_server::multihop::{
    derive_x25519_ikm_from_ed25519, derive_x25519_keypair, format_x25519_pubkey_hex,
    serve_multihop_with_tun_and_daita,
};
use warrenguard_transport::RealTun;
use warrenguard_transport_core::warren_transport_config_exit_multihop_with_gso;
use zeroize::{Zeroize, Zeroizing};

/// Default multi-hop client subnet: every accepted 1-hop connection draws one
/// host from here. A deployer overrides it with `--multihop-subnet`.
const DEFAULT_MULTIHOP_SUBNET: &str = "10.66.0.0/24";
/// Default multi-hop gateway (the exit-side TUN address), inside
/// [`DEFAULT_MULTIHOP_SUBNET`].
const DEFAULT_MULTIHOP_GATEWAY: &str = "10.66.0.1";

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
    /// Run a multi-hop exit server (what the Warren desktop app dials): the
    /// node terminates the HPKE-sealed multi-hop `/v1` frames, admits every
    /// peer that completes the handshake (no control-plane), and allocates one
    /// tunnel IP per connection. Requires `--seed` (the stable identity the
    /// multi-hop pubkey is bound to) and `--multihop-exit-id`.
    Serve {
        /// Address to bind the QUIC server on.
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        /// 32-byte node seed as hex (64 chars). Required: the multi-hop pubkey
        /// is derived from this stable Ed25519 identity, so an ephemeral one
        /// would rotate the published pubkey on every restart.
        #[arg(long)]
        seed: Option<String>,
        /// 16-byte exit identifier as 32 hex chars. Bound into every sealed
        /// frame so a client's packets target this exit.
        #[arg(long = "multihop-exit-id", value_name = "32-hex")]
        multihop_exit_id: Option<String>,
        /// Path to a raw 32-byte X25519 IKM file. When omitted, the multi-hop
        /// IKM is derived deterministically from the same Ed25519 identity as
        /// `--seed`, so the published pubkey rotates only when the identity
        /// does. Supply a file to rotate the multi-hop key independently.
        #[arg(long = "multihop-x25519-ikm", value_name = "FILE")]
        multihop_x25519_ikm: Option<String>,
        /// Client subnet the exit allocates tunnel IPs from, `A.B.C.D/prefix`.
        #[arg(long = "multihop-subnet", value_name = "CIDR", default_value = DEFAULT_MULTIHOP_SUBNET)]
        multihop_subnet: String,
        /// Gateway address (the exit-side TUN host) inside `--multihop-subnet`.
        #[arg(long = "multihop-gateway", value_name = "IP", default_value = DEFAULT_MULTIHOP_GATEWAY)]
        multihop_gateway: Ipv4Addr,
    },
}

/// `ed25519:<base64>` is the WireGuard-analog public-key display: a short,
/// copy-pasteable identity a peer pins.
fn format_pubkey(pk: &[u8; 32]) -> String {
    format!("ed25519:{}", data_encoding::BASE64.encode(pk))
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

/// Parse a `--multihop-exit-id` (32 hex chars = 16 bytes) into an [`ExitId`].
/// A malformed value fails the whole serve invocation rather than silently
/// binding a zero or truncated id.
fn parse_multihop_exit_id(hex_id: &str) -> Result<ExitId> {
    ExitId::from_hex(hex_id.trim())
        .with_context(|| format!("--multihop-exit-id must be 32 hex chars, got: {hex_id}"))
}

/// Parse `A.B.C.D/prefix` into its network address and prefix length. The exit
/// uses these to size both the IP pool and its TUN.
fn parse_multihop_subnet(subnet: &str) -> Result<(Ipv4Addr, u8)> {
    let (net_str, prefix_str) = subnet
        .split_once('/')
        .with_context(|| format!("--multihop-subnet must be A.B.C.D/prefix, got: {subnet}"))?;
    let network: Ipv4Addr = net_str
        .parse()
        .with_context(|| format!("--multihop-subnet network is not a valid IPv4: {net_str}"))?;
    let prefix_len: u8 = prefix_str
        .parse()
        .with_context(|| format!("--multihop-subnet prefix is not a number: {prefix_str}"))?;
    Ok((network, prefix_len))
}

/// Build the multi-hop IP pool over `network/prefix_len` with `gateway`
/// reserved for the exit-side TUN, wrapped for shared access across the
/// per-connection spawn loop.
fn build_multihop_ip_allocator(
    network: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<Arc<Mutex<IpAllocator>>> {
    let allocator = IpAllocator::new(network, prefix_len, gateway).with_context(|| {
        format!("build IP allocator for {network}/{prefix_len} gateway {gateway}")
    })?;
    Ok(Arc::new(Mutex::new(allocator)))
}

/// Resolve the 32-byte X25519 multi-hop IKM: read it from `ikm_file` when
/// given (independent rotation), otherwise derive it deterministically from
/// the exit's Ed25519 identity so the published pubkey is bound to it.
fn resolve_multihop_ikm(ikm_file: Option<&str>, signing_key: &SigningKey) -> Result<[u8; 32]> {
    match ikm_file {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read --multihop-x25519-ikm {path}"))?;
            bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "--multihop-x25519-ikm file must be exactly 32 bytes, got {}",
                    v.len()
                )
            })
        }
        None => Ok(derive_x25519_ikm_from_ed25519(signing_key)),
    }
}

/// The four values a self-hoster pastes into a client's custom-exit form: the
/// exit id, the X25519 multi-hop pubkey, the Ed25519 RPK pubkey, and the bind
/// endpoint. Rendered as a block so the exact shape is directly testable.
fn multihop_identity_block(
    exit_id: &ExitId,
    x25519_pubkey_hex: &str,
    ed25519_pubkey: &[u8; 32],
    listen: SocketAddr,
) -> String {
    format!(
        "multihop exit-id  {}\nmultihop pubkey   {}\npublic key        {}\nlistening         {}\n",
        exit_id.to_hex(),
        x25519_pubkey_hex,
        format_pubkey(ed25519_pubkey),
        listen,
    )
}

/// Build the QUIC server endpoint for the multi-hop exit: an Ed25519 raw-public
/// key TLS config (same RPK-via-SNI shape the single-hop path serves) with ALPN
/// `h3`, plus the exit multi-hop inbound transport profile (no Initial padding,
/// which stalls the handshake on a low-PMTU path).
fn build_multihop_endpoint(listen: SocketAddr, signing_key: &SigningKey) -> Result<Endpoint> {
    let provider = warrenguard_tls::default_crypto_provider();
    let mut server_cfg =
        warrenguard_tls::make_server_config(signing_key, provider, &[warrenguard_config::ALPN_H3])
            .map_err(|e| anyhow::anyhow!("build multi-hop TLS server config: {e}"))?;
    server_cfg.transport_config(warren_transport_config_exit_multihop_with_gso(true));
    Endpoint::server(server_cfg, listen)
        .with_context(|| format!("bind the multi-hop exit on {listen}"))
}

/// Serve a multi-hop-1-hop exit until interrupted: derive and print the node's
/// multi-hop identity, then terminate the HPKE multi-hop datapath onto a real
/// TUN, admitting every peer and drawing one tunnel IP per connection.
async fn serve_multihop(
    listen: SocketAddr,
    signing_key: SigningKey,
    exit_id: ExitId,
    x25519_ikm: [u8; 32],
    network: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<()> {
    let (exit_priv, exit_pub) =
        derive_x25519_keypair(&x25519_ikm).context("derive the X25519 multi-hop keypair")?;
    let x25519_pubkey_hex = format_x25519_pubkey_hex(&exit_pub);
    let rpk = signing_key.verifying_key().to_bytes();

    let endpoint = build_multihop_endpoint(listen, &signing_key)?;
    let ip_allocator = build_multihop_ip_allocator(network, prefix_len, gateway)?;
    let tun = RealTun::create_with_ipv4(gateway, prefix_len)
        .await
        .context("create the exit-side TUN (need root / CAP_NET_ADMIN)")?;

    // This print is the point of the mode: it hands the operator the four
    // values a client needs to dial this self-hosted node.
    print!(
        "{}",
        multihop_identity_block(&exit_id, &x25519_pubkey_hex, &rpk, listen)
    );

    // Admit-all (no allowlist), no token admitter, no DAITA: a self-host serve
    // has no control-plane. The terminator loops until the endpoint closes.
    serve_multihop_with_tun_and_daita(
        endpoint,
        exit_priv,
        exit_id,
        tun,
        None,
        None,
        Some(ip_allocator),
        None,
    )
    .await
    .context("multi-hop serve loop")?;
    Ok(())
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
            multihop_exit_id,
            multihop_x25519_ikm,
            multihop_subnet,
            multihop_gateway,
        } => {
            // The multi-hop identity (QUIC RPK + the derived X25519 key) must be
            // stable, so a self-host serve requires a seed: an ephemeral
            // identity would rotate the published pubkey on every restart and
            // break every client pinning it.
            let signing_key = match seed {
                Some(s) => derive_node_key(&*parse_seed(&s)?),
                None => bail!(
                    "serve requires --seed: the multi-hop pubkey is derived from a stable \
                     Ed25519 identity, so an ephemeral one would break client pins"
                ),
            };
            let exit_id_hex = multihop_exit_id.ok_or_else(|| {
                anyhow::anyhow!("serve requires --multihop-exit-id <32 hex chars>")
            })?;
            let exit_id = parse_multihop_exit_id(&exit_id_hex)?;
            let x25519_ikm = resolve_multihop_ikm(multihop_x25519_ikm.as_deref(), &signing_key)?;
            let (network, prefix_len) = parse_multihop_subnet(&multihop_subnet)?;
            serve_multihop(
                listen,
                signing_key,
                exit_id,
                x25519_ikm,
                network,
                prefix_len,
                multihop_gateway,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn serve_parses_the_multihop_flags() {
        let cli = Cli::try_parse_from([
            "warrenguard",
            "serve",
            "--multihop-exit-id",
            "aabbccddeeff00112233445566778899",
            "--multihop-subnet",
            "10.9.0.0/24",
            "--multihop-gateway",
            "10.9.0.1",
        ])
        .expect("valid serve invocation");
        match cli.cmd {
            Command::Serve {
                multihop_exit_id,
                multihop_subnet,
                multihop_gateway,
                ..
            } => {
                assert_eq!(
                    multihop_exit_id.as_deref(),
                    Some("aabbccddeeff00112233445566778899")
                );
                assert_eq!(multihop_subnet, "10.9.0.0/24");
                assert_eq!(multihop_gateway, Ipv4Addr::new(10, 9, 0, 1));
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn serve_defaults_the_subnet_and_gateway() {
        // The self-hoster gets a working pool without naming a subnet.
        let cli = Cli::try_parse_from([
            "warrenguard",
            "serve",
            "--multihop-exit-id",
            "aabbccddeeff00112233445566778899",
        ])
        .expect("valid serve invocation");
        match cli.cmd {
            Command::Serve {
                multihop_subnet,
                multihop_gateway,
                ..
            } => {
                assert_eq!(multihop_subnet, DEFAULT_MULTIHOP_SUBNET);
                assert_eq!(multihop_gateway, Ipv4Addr::new(10, 66, 0, 1));
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn parse_multihop_exit_id_accepts_32_hex_and_rejects_bad_length() {
        let id =
            parse_multihop_exit_id("aabbccddeeff00112233445566778899").expect("32 hex chars parse");
        assert_eq!(
            id.as_bytes(),
            &[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99
            ]
        );
        assert!(parse_multihop_exit_id("aabb").is_err(), "too short");
        assert!(parse_multihop_exit_id("zz").is_err(), "not hex");
    }

    #[test]
    fn parse_multihop_subnet_splits_network_and_prefix() {
        let (net, prefix) = parse_multihop_subnet("10.66.0.0/24").expect("valid CIDR");
        assert_eq!(net, Ipv4Addr::new(10, 66, 0, 0));
        assert_eq!(prefix, 24);
        assert!(
            parse_multihop_subnet("10.66.0.0").is_err(),
            "missing prefix"
        );
        assert!(
            parse_multihop_subnet("not-an-ip/24").is_err(),
            "bad network"
        );
    }

    #[test]
    fn build_multihop_ip_allocator_builds_a_usable_pool_and_rejects_a_bad_gateway() {
        let alloc = build_multihop_ip_allocator(
            Ipv4Addr::new(10, 66, 0, 0),
            24,
            Ipv4Addr::new(10, 66, 0, 1),
        )
        .expect("/24 pool builds");
        {
            let mut guard = alloc.lock();
            let ip = guard.allocate(1).expect("pool hands out a host");
            assert_ne!(ip, Ipv4Addr::new(10, 66, 0, 1), "never the gateway");
        }
        // A gateway outside the subnet must fail closed, not silently pick one.
        assert!(
            build_multihop_ip_allocator(
                Ipv4Addr::new(10, 66, 0, 0),
                24,
                Ipv4Addr::new(192, 168, 1, 1)
            )
            .is_err(),
            "a gateway outside the subnet must be rejected"
        );
    }

    #[test]
    fn resolve_multihop_ikm_derives_from_identity_when_no_file() {
        // No file: the IKM must equal the identity-bound derivation, so the
        // published pubkey is stable across restarts of the same identity.
        let sk = derive_node_key(&[0x51u8; 32]);
        let ikm = resolve_multihop_ikm(None, &sk).expect("derive from identity");
        assert_eq!(
            ikm,
            derive_x25519_ikm_from_ed25519(&sk),
            "the no-file path must reuse the identity-bound IKM"
        );
        assert_ne!(ikm, [0u8; 32], "a real derivation is never all zero");
    }

    #[test]
    fn multihop_identity_block_carries_all_four_values() {
        // The block is the operator's whole payload; a missing line would leave
        // a self-hoster unable to dial. Assert every value is present.
        let exit_id = ExitId::from_bytes([0xAB; 16]);
        let x25519_hex = "1".repeat(64);
        let rpk = [0x22u8; 32];
        let listen: SocketAddr = "203.0.113.7:443".parse().expect("addr");
        let block = multihop_identity_block(&exit_id, &x25519_hex, &rpk, listen);
        assert!(block.contains(&exit_id.to_hex()), "exit id present");
        assert!(
            block.contains(&x25519_hex),
            "x25519 multihop pubkey present"
        );
        assert!(block.contains(&format_pubkey(&rpk)), "ed25519 RPK present");
        assert!(block.contains("203.0.113.7:443"), "bind endpoint present");
    }

    #[test]
    fn multihop_identity_derivation_is_a_stable_nonzero_golden_pubkey() {
        // Frozen crypto vector: a fixed Ed25519 seed must always derive this
        // exact X25519 multi-hop pubkey through the same pipeline the operator
        // helper `warren-exit-multihop-pubkey` runs (derive_node_key -> HKDF
        // IKM -> RFC 9180 DeriveKeyPair). Any change to a frozen derivation
        // constant flips this hex, so it is a real regression anchor, not a
        // tautology.
        let sk = derive_node_key(&[0x51u8; 32]);
        let ikm = derive_x25519_ikm_from_ed25519(&sk);
        let (_priv, pubk) = derive_x25519_keypair(&ikm).expect("derive keypair from a 32-byte IKM");
        let got = format_x25519_pubkey_hex(&pubk);
        assert_eq!(got.len(), 64, "x25519 pubkey renders as 64 lowercase hex");
        assert_ne!(got, "0".repeat(64), "derived pubkey must be non-zero");
        assert_eq!(
            got, "934d5d7fcc1e60dd66f59a243908b279eb3fe683a1ba9d00e0dedec1f3cdd067",
            "frozen multi-hop identity derivation regression anchor"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn multihop_serve_hands_a_dialing_client_a_valid_ip_assign() {
        use std::time::Duration;

        use rand_core::{OsRng, UnwrapErr};
        use warrenguard_multihop::{ClientSession, decode_frame, encode_frame};
        use warrenguard_transport_core::FakeTun;
        use warrenguard_wire::WarrenPubkey;

        // The multi-hop setup handshake rides a reliable bidi stream (seq 0),
        // not a datagram: the client writes the sealed IpRequest, finishes the
        // send side, and reads the sealed reply off the same stream.
        async fn setup_ip_assign(
            conn: &quinn::Connection,
            session: &ClientSession,
        ) -> warrenguard_multihop::IpAssignment {
            let request = session
                .seal_setup_request(None, None, false, false, 0, 0)
                .expect("seal the setup IpRequest");
            let bytes = encode_frame(&request).expect("encode request");
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            send.write_all(&bytes).await.expect("write setup request");
            send.finish().expect("finish setup send");
            let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
                .await
                .expect("setup reply must arrive")
                .expect("read the setup reply bytes");
            let reply_frame = decode_frame(&reply).expect("decode the reply frame");
            session
                .open_setup_reply(&reply_frame)
                .expect("the exit must grant an IpAssign")
        }

        // Exit identity + multi-hop keypair, exactly as `serve --multihop`
        // derives them from a seed.
        let signing_key = derive_node_key(&[0x51u8; 32]);
        let exit_id = ExitId::from_bytes([0xAA; 16]);
        let ikm = derive_x25519_ikm_from_ed25519(&signing_key);
        let (exit_priv, exit_pub) =
            derive_x25519_keypair(&ikm).expect("derive the exit multi-hop keypair");

        // Bind the exit server through the very builder the CLI uses, then run
        // the terminator against a FakeTun (no root needed) with an IP pool.
        let listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = build_multihop_endpoint(listen, &signing_key).expect("bind loopback exit");
        let addr = endpoint.local_addr().expect("exit local addr");
        let ip_allocator = build_multihop_ip_allocator(
            Ipv4Addr::new(10, 66, 0, 0),
            24,
            Ipv4Addr::new(10, 66, 0, 1),
        )
        .expect("/24 pool builds");

        let serve = tokio::spawn(serve_multihop_with_tun_and_daita(
            endpoint,
            exit_priv,
            exit_id,
            FakeTun::new(),
            None,
            None,
            Some(ip_allocator),
            None,
        ));

        // A real multi-hop client dials the exit's RPK-via-SNI endpoint.
        let provider = warrenguard_tls::default_crypto_provider();
        let client_cfg =
            warrenguard_tls::make_client_config(provider, &[warrenguard_config::ALPN_H3])
                .expect("client config builds");
        let mut client_ep = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())
            .expect("loopback client endpoint binds");
        client_ep.set_default_client_config(client_cfg);
        let exit_rpk = WarrenPubkey::from_bytes(signing_key.verifying_key().to_bytes());
        let sni = warrenguard_tls::name::encode(exit_rpk);
        let conn = client_ep
            .connect(addr, &sni)
            .expect("connect call accepted")
            .await
            .expect("handshake completes against the multi-hop exit");

        // Admit-all setup (no signing key, no PoP): the exit must still grant
        // an IpAssign because it runs with no allowlist.
        let mut rng = UnwrapErr(OsRng);
        let session = ClientSession::new(&exit_pub, exit_id, &mut rng)
            .expect("client HPKE setup against the freshly derived exit pubkey");
        let assign = setup_ip_assign(&conn, &session).await;

        let assigned = Ipv4Addr::from(assign.ipv4);
        assert_eq!(assign.prefix_len, 24, "the assign echoes the pool prefix");
        assert_eq!(
            Ipv4Addr::from(assign.gateway_ipv4),
            Ipv4Addr::new(10, 66, 0, 1),
            "the assign carries the pool gateway"
        );
        // The address is a real host of the configured pool, never the gateway.
        assert_eq!(assigned.octets()[0..3], [10, 66, 0], "inside 10.66.0.0/24");
        assert_ne!(
            assigned,
            Ipv4Addr::new(10, 66, 0, 1),
            "the allocator never hands out the gateway"
        );

        serve.abort();
        drop(conn);
    }
}
