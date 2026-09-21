//! `masque-forward`: a local forwarder through an HTTP/3 proxy ingress, the
//! reference client of `warrenguard-masque` and the tool a bench drives
//! `iperf3` through. Each `--tcp local=host:port` accepts local TCP
//! connections and carries each one as a CONNECT tunnel; each
//! `--udp local=host:port` accepts local UDP datagrams and carries each local
//! source address as a CONNECT-UDP tunnel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use quinn::Endpoint;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use warrenguard_masque::client::{MasqueClient, UdpSender};

/// One `local=host:port` mapping.
#[derive(Debug, Clone)]
pub(crate) struct Mapping {
    pub(crate) local: SocketAddr,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl std::str::FromStr for Mapping {
    type Err = anyhow::Error;

    fn from_str(spec: &str) -> Result<Self> {
        let (local, target) = spec
            .split_once('=')
            .with_context(|| format!("mapping must be local=host:port, got: {spec}"))?;
        let local: SocketAddr = local
            .parse()
            .with_context(|| format!("local side is not an address: {local}"))?;
        let (host, port) = target
            .rsplit_once(':')
            .with_context(|| format!("target must be host:port, got: {target}"))?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port: u16 = port
            .parse()
            .with_context(|| format!("target port is not a number: {port}"))?;
        Ok(Self { local, host, port })
    }
}

/// The `proxy-authorization` value for a browser-proxy credential: the token
/// rides as the Basic password under the fixed username.
fn basic_credential(password: &str) -> String {
    format!(
        "Basic {}",
        data_encoding::BASE64.encode(
            format!(
                "{}:{password}",
                warrenguard_connect_proxy::CREDENTIAL_USERNAME
            )
            .as_bytes()
        )
    )
}

/// Runs the forwarder until interrupted. `proxy_addr` dials that address
/// while still validating the certificate for the `proxy` host, for a proxy
/// whose name is not published in DNS yet (a bench node).
pub(crate) async fn run(
    proxy: String,
    proxy_addr: Option<SocketAddr>,
    credential: String,
    tcp: Vec<Mapping>,
    udp: Vec<Mapping>,
    ca: Option<PathBuf>,
) -> Result<()> {
    if tcp.is_empty() && udp.is_empty() {
        bail!("nothing to forward: give at least one --tcp or --udp mapping");
    }
    let (host, port) = proxy
        .rsplit_once(':')
        .context("--proxy must be host:port")?;
    let port: u16 = port.parse().context("--proxy port is not a number")?;
    let addr = match proxy_addr {
        Some(addr) => addr,
        None => tokio::net::lookup_host((host, port))
            .await
            .context("resolve the proxy host")?
            .next()
            .context("the proxy host resolves to nothing")?,
    };

    let mut roots = quinn::rustls::RootCertStore::empty();
    match ca {
        Some(path) => {
            let pem = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            for cert in rustls_pemfile_certs(&pem)? {
                roots.add(cert).context("add the --ca certificate")?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut client_cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .context("client TLS config")?;
    // The ingress sends no keep-alive of its own (its clients drive it, as a
    // browser does), so an idle forwarder must keep the connection up itself
    // or lose it between two bursts of local traffic.
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)))
        .max_idle_timeout(Some(
            std::time::Duration::from_secs(120)
                .try_into()
                .context("idle timeout")?,
        ))
        .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
        .datagram_send_buffer_size(4 * 1024 * 1024);
    client_cfg.transport_config(Arc::new(transport));
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let mut endpoint = Endpoint::client(bind).context("bind the client endpoint")?;
    endpoint.set_default_client_config(client_cfg);
    let client = Arc::new(Proxy {
        endpoint,
        addr,
        host: host.to_owned(),
        client: Mutex::new(None),
    });
    client
        .get()
        .await
        .context("first connection to the proxy")?;
    let credential = Arc::new(basic_credential(&credential));
    eprintln!("connected to {proxy} over HTTP/3");

    let mut tasks = tokio::task::JoinSet::new();
    for mapping in tcp {
        let listener = TcpListener::bind(mapping.local)
            .await
            .with_context(|| format!("bind {}", mapping.local))?;
        eprintln!("tcp {} -> {}:{}", mapping.local, mapping.host, mapping.port);
        let client = client.clone();
        let credential = credential.clone();
        tasks.spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                let client = client.clone();
                let credential = credential.clone();
                let target = format!("{}:{}", mapping.host, mapping.port);
                tokio::spawn(async move {
                    let proxy = match client.get().await {
                        Ok(proxy) => proxy,
                        Err(e) => return eprintln!("proxy unreachable: {e}"),
                    };
                    match proxy.connect_tcp(&target, Some(&credential)).await {
                        Ok(tunnel) => tunnel.pump(socket).await,
                        Err(e) => eprintln!("tcp tunnel refused: {e}"),
                    }
                });
            }
        });
    }
    for mapping in udp {
        let socket = Arc::new(
            UdpSocket::bind(mapping.local)
                .await
                .with_context(|| format!("bind {}", mapping.local))?,
        );
        eprintln!("udp {} -> {}:{}", mapping.local, mapping.host, mapping.port);
        let client = client.clone();
        let credential = credential.clone();
        tasks.spawn(async move {
            forward_udp(socket, client, credential, mapping).await;
        });
    }
    tasks.join_next().await;
    Ok(())
}

/// The proxy connection, re-dialed when it is lost: the ingress closes an
/// admitted connection at the credential epoch boundary, and a browser
/// reconnects by itself, so the forwarder does too.
struct Proxy {
    endpoint: Endpoint,
    addr: SocketAddr,
    host: String,
    client: Mutex<Option<Arc<MasqueClient>>>,
}

impl Proxy {
    /// The live client, dialing a new connection when the last one is gone.
    async fn get(&self) -> Result<Arc<MasqueClient>> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref()
            && client.connection().close_reason().is_none()
        {
            return Ok(client.clone());
        }
        let conn = self
            .endpoint
            .connect(self.addr, &self.host)
            .context("connect builds")?
            .await
            .context("QUIC handshake with the proxy")?;
        let client = Arc::new(
            MasqueClient::open(conn)
                .await
                .context("HTTP/3 opening with the proxy")?,
        );
        *slot = Some(client.clone());
        Ok(client)
    }
}

/// Carries each local source address as its own CONNECT-UDP tunnel.
async fn forward_udp(
    socket: Arc<UdpSocket>,
    client: Arc<Proxy>,
    credential: Arc<String>,
    mapping: Mapping,
) {
    let tunnels: Arc<Mutex<HashMap<SocketAddr, UdpSender>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok((n, from)) = socket.recv_from(&mut buf).await {
        let existing = tunnels.lock().await.get(&from).cloned();
        let sender = match existing {
            Some(sender) => sender,
            None => {
                let proxy = match client.get().await {
                    Ok(proxy) => proxy,
                    Err(e) => {
                        eprintln!("proxy unreachable: {e}");
                        continue;
                    }
                };
                let tunnel = match proxy
                    .connect_udp(&mapping.host, mapping.port, Some(&credential))
                    .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("udp tunnel refused: {e}");
                        continue;
                    }
                };
                let (sender, mut receiver) = tunnel.split();
                tunnels.lock().await.insert(from, sender.clone());
                let socket = socket.clone();
                let tunnels = tunnels.clone();
                tokio::spawn(async move {
                    while let Some(payload) = receiver.recv().await {
                        let _ = socket.send_to(&payload, from).await;
                    }
                    tunnels.lock().await.remove(&from);
                });
                sender
            }
        };
        if sender.send(&buf[..n]).is_err() {
            // The connection behind this tunnel is gone; the next packet from
            // this source opens a fresh tunnel on a fresh connection.
            tunnels.lock().await.remove(&from);
        }
    }
}

/// Parses every certificate of a PEM bundle.
fn rustls_pemfile_certs(
    pem: &[u8],
) -> Result<Vec<quinn::rustls::pki_types::CertificateDer<'static>>> {
    use quinn::rustls::pki_types::CertificateDer;
    let text = std::str::from_utf8(pem).context("--ca is not text")?;
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block
            .split("-----END CERTIFICATE-----")
            .next()
            .context("unterminated certificate")?;
        let der = data_encoding::BASE64
            .decode(body.split_whitespace().collect::<String>().as_bytes())
            .context("certificate is not base64")?;
        out.push(CertificateDer::from(der));
    }
    if out.is_empty() {
        bail!("--ca holds no certificate");
    }
    Ok(out)
}
