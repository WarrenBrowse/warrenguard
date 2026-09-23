//! HTTP/3 proxy ingress for browser clients: CONNECT and CONNECT-UDP (MASQUE).
//!
//! A browser handed an HTTP/3 proxy opens one QUIC connection to it and
//! tunnels every destination inside: a plain `CONNECT` request stream carries
//! a TCP connection as DATA frames (RFC 9114 section 4.4), and an extended
//! `CONNECT` with `:protocol connect-udp` carries a UDP flow as HTTP Datagrams
//! (RFC 9297, RFC 9298). This crate serves such a connection once the deployer
//! has recognised the peer as HTTP/3: it speaks the server side of HTTP/3
//! (control stream, SETTINGS, static-only QPACK), classifies each request with
//! [`warrenguard_edge`], admits the connection through the deployer's
//! credential admitter, filters destinations through its egress policy, dials
//! through its dialers, and pumps bytes. Nothing here is Warren-specific.
//!
//! # Admission is a connection state
//!
//! A browser presents its proxy credential on plain CONNECT requests only:
//! Firefox sends none on CONNECT-UDP and treats a `407` there as fatal. So a
//! credential that verifies admits the whole QUIC connection, and a
//! CONNECT-UDP is served only on an admitted connection (or when it carries a
//! verifying credential itself). The admission lives exactly as long as the
//! connection, in memory: no session ticket carries it, a resumed connection
//! is a new connection, and path migration keeps it because it names a
//! session, never an address. It ends at the credential epoch boundary plus a
//! grace ([`MasqueConfig::admission_period`], [`MasqueConfig::admission_grace`]),
//! when the connection is closed and the browser reconnects with the next
//! credential. A single connection never admits for longer than one period
//! plus the grace.
//!
//! # What is bounded
//!
//! Tunnels per connection ([`MasqueConfig::max_tunnels_per_connection`]), the
//! request head (16 KiB, and a deadline), the capsule stream a CONNECT-UDP
//! peer may leave unparsed, and the datagram queue per tunnel. Pre-auth
//! budgets (per-IP rate, in-flight connections) are the deployer's, applied
//! before a connection reaches [`MasqueIngress::serve_connection`].
//!
//! # No-log discipline
//!
//! No destination, credential or peer address reaches a log or an error here.

#![forbid(unsafe_code)]

pub mod client;
mod connection;
mod frames;
mod tunnel;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use warrenguard_connect_proxy::{
    Authority, ConnectDialer, EgressPolicy, ProxyCredential, admit_credential,
    parse_proxy_authorization,
};
use warrenguard_edge::{
    FRAME_HEADERS, ProxyRequest, STREAM_CONTROL, classify_proxy_request,
    connect_established_response, connect_udp_established_response, encode_response_headers,
    encode_varint, masque_control_stream_prelude, parse_connect_udp_target, parse_settings,
    proxy_challenge_response, read_frame, read_uni_stream_type,
};
pub use warrenguard_server::{SessionTokenAdmitter, TokenAdmission};

use connection::ConnState;
use frames::{FrameReader, MAX_CONTROL_FRAME_BYTES};
use tunnel::{UdpRoute, abort, pump_tcp, pump_udp, respond_and_close};

/// QPACK encoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_ENCODER: u64 = 0x02;
/// QPACK decoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_DECODER: u64 = 0x03;

/// Opens the upstream UDP flow a CONNECT-UDP asked for: a socket connected to
/// `target`, so `send`/`recv` talk to it alone. Injected so the deployer owns
/// the egress socket and re-checks what the name resolved to.
pub trait ConnectUdpDialer: Send + Sync {
    /// Binds and connects a socket to `target`, or reports that it will not.
    fn dial(
        &self,
        target: &Authority,
    ) -> impl std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>> + Send;
}

/// A shared dialer dials like the dialer it shares.
impl<T: ConnectUdpDialer> ConnectUdpDialer for Arc<T> {
    fn dial(
        &self,
        target: &Authority,
    ) -> impl std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>> + Send {
        T::dial(self, target)
    }
}

/// Knobs a deployer sets on the ingress.
#[derive(Debug, Clone)]
pub struct MasqueConfig {
    /// Live tunnels (request streams) one connection may hold. A browser
    /// multiplexes every origin it talks to onto the one proxy connection.
    pub max_tunnels_per_connection: u32,
    /// How long a request stream may take to deliver its complete head.
    pub request_deadline: Duration,
    /// The credential epoch: an admission ends at the next multiple of this
    /// period on the wall clock, plus [`Self::admission_grace`].
    pub admission_period: Duration,
    /// Slack past the epoch boundary before an admitted connection is closed,
    /// so a client whose clock runs slightly behind still has its next
    /// credential by then.
    pub admission_grace: Duration,
    /// The complete HTTP/3 response (HEADERS frame, then DATA frames) written
    /// to a request that is not a proxy request, so the endpoint answers a
    /// plain GET like the web server it appears to be.
    pub other_response: Bytes,
}

impl Default for MasqueConfig {
    fn default() -> Self {
        Self {
            max_tunnels_per_connection: 256,
            request_deadline: Duration::from_secs(10),
            admission_period: Duration::from_secs(3600),
            admission_grace: Duration::from_secs(300),
            other_response: Bytes::from(encode_response_headers(404, &[])),
        }
    }
}

/// A request stream the deployer accepted and partly read before it knew the
/// peer was HTTP/3.
pub struct PendingRequest {
    /// Send half of the stream.
    pub send: SendStream,
    /// Receive half, positioned after `bytes`.
    pub recv: RecvStream,
    /// The bytes already read off the stream.
    pub bytes: Bytes,
}

/// The streams the deployer's dispatcher had already accepted on an HTTP/3
/// connection when it handed the connection over.
#[derive(Default)]
pub struct Http3Handoff {
    /// The peer's first unidirectional stream, unread.
    pub uni: Option<RecvStream>,
    /// The peer's first request stream, when it had already arrived.
    pub request: Option<PendingRequest>,
}

/// An HTTP/3 server a dispatcher can hand a connection to once it has
/// recognised the peer as HTTP/3, without naming the ingress's seam types.
pub trait Http3Service: Send + Sync {
    /// Serves `conn` until it closes.
    fn serve(
        self: Arc<Self>,
        conn: Connection,
        handoff: Http3Handoff,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

impl<A, P, D, U> Http3Service for MasqueIngress<A, P, D, U>
where
    A: SessionTokenAdmitter + ?Sized + 'static,
    P: EgressPolicy + 'static,
    D: ConnectDialer + 'static,
    U: ConnectUdpDialer + 'static,
{
    fn serve(
        self: Arc<Self>,
        conn: Connection,
        handoff: Http3Handoff,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(self.serve_connection(conn, handoff))
    }
}

/// The ingress: the deployer's four seams plus the config, shared by every
/// connection it serves.
pub struct MasqueIngress<A: ?Sized, P, D, U> {
    admitter: Arc<A>,
    policy: P,
    tcp: D,
    udp: U,
    config: MasqueConfig,
}

impl<A, P, D, U> MasqueIngress<A, P, D, U>
where
    A: SessionTokenAdmitter + ?Sized + 'static,
    P: EgressPolicy + 'static,
    D: ConnectDialer + 'static,
    U: ConnectUdpDialer + 'static,
{
    /// Builds the ingress around the deployer's admitter, egress policy and
    /// dialers.
    pub fn new(admitter: Arc<A>, policy: P, tcp: D, udp: U, config: MasqueConfig) -> Self {
        Self {
            admitter,
            policy,
            tcp,
            udp,
            config,
        }
    }

    /// Serves `conn` as an HTTP/3 proxy connection until it closes: writes the
    /// server control stream, reads the peer's, and serves every request
    /// stream, the ones in `handoff` first.
    pub async fn serve_connection(self: Arc<Self>, conn: Connection, handoff: Http3Handoff) {
        conn.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(
            self.config.max_tunnels_per_connection,
        ));
        let state = Arc::new(ConnState::new(
            conn.clone(),
            self.config.max_tunnels_per_connection,
        ));

        // Speak first, as a real HTTP/3 server does: the control stream with
        // our SETTINGS, then the two QPACK streams. A browser sends no
        // CONNECT-UDP until it has read that we allow extended CONNECT.
        let Ok(mut control) = conn.open_uni().await else {
            return;
        };
        if control
            .write_all(&masque_control_stream_prelude())
            .await
            .is_err()
        {
            return;
        }
        let mut qpack_encoder = match conn.open_uni().await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = qpack_encoder
            .write_all(&encode_varint(QPACK_STREAM_ENCODER))
            .await;
        let mut qpack_decoder = match conn.open_uni().await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = qpack_decoder
            .write_all(&encode_varint(QPACK_STREAM_DECODER))
            .await;

        // The peer's unidirectional streams: read its SETTINGS off the control
        // stream, and keep every one open and drained for the connection's
        // life (resetting a critical stream aborts the whole connection).
        {
            let state = state.clone();
            let conn = conn.clone();
            let first = handoff.uni;
            tokio::spawn(async move {
                let _hold = (control, qpack_encoder, qpack_decoder);
                if let Some(recv) = first {
                    tokio::spawn(drain_peer_uni(recv, state.clone()));
                }
                while let Ok(recv) = conn.accept_uni().await {
                    tokio::spawn(drain_peer_uni(recv, state.clone()));
                }
            });
        }

        // HTTP Datagrams arrive on the connection, tagged with the stream they
        // belong to; one task routes them to the tunnel pumps.
        {
            let state = state.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Ok(datagram) = conn.read_datagram().await {
                    state.routes().route(&datagram);
                }
            });
        }

        if let Some(pending) = handoff.request {
            tokio::spawn(self.clone().serve_request(
                state.clone(),
                pending.send,
                pending.recv,
                pending.bytes,
            ));
        }
        while let Ok((send, recv)) = conn.accept_bi().await {
            tokio::spawn(
                self.clone()
                    .serve_request(state.clone(), send, recv, Bytes::new()),
            );
        }
    }

    /// Serves one request stream to completion.
    async fn serve_request(
        self: Arc<Self>,
        state: Arc<ConnState>,
        mut send: SendStream,
        recv: RecvStream,
        prefix: Bytes,
    ) {
        let mut reader = FrameReader::new(recv, prefix);
        let head = tokio::time::timeout(
            self.config.request_deadline,
            reader.next_frame(FRAME_HEADERS),
        )
        .await;
        let field_section = match head {
            Ok(Ok(Some(payload))) => payload,
            // The stream ended before a request head: nothing to answer.
            Ok(Ok(None)) => return,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "masque: request head unreadable");
                return abort(&mut send, reader.recv_mut(), e);
            }
            Err(_elapsed) => {
                return abort(&mut send, reader.recv_mut(), frames::FrameError::Malformed);
            }
        };
        let request = match classify_proxy_request(&field_section) {
            Ok(request) => {
                tracing::trace!(
                    conn = state.id(),
                    kind = match &request {
                        ProxyRequest::Connect(_) => "connect",
                        ProxyRequest::ConnectUdp(_) => "connect-udp",
                        ProxyRequest::Other => "other",
                    },
                    admitted = state.is_admitted(),
                    "masque: request"
                );
                request
            }
            Err(e) => {
                tracing::debug!(error = %e, "masque: request head undecodable");
                return abort(&mut send, reader.recv_mut(), frames::FrameError::Malformed);
            }
        };

        let _tunnel = match request {
            ProxyRequest::Other => {
                let response = self.config.other_response.clone();
                return respond_and_close(&mut send, reader.recv_mut(), &response).await;
            }
            ProxyRequest::Connect(_) | ProxyRequest::ConnectUdp(_) => {
                match state.try_acquire_tunnel() {
                    Some(permit) => permit,
                    None => {
                        let response = encode_response_headers(503, &[]);
                        return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                    }
                }
            }
        };

        match request {
            ProxyRequest::Connect(connect) => {
                let Ok(target) = Authority::parse(&connect.authority) else {
                    let response = encode_response_headers(400, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                };
                // The destination is judged BEFORE the credential, so an
                // unusable request spends no token and learns nothing about it.
                if !self.policy.permits(&target) {
                    let response = encode_response_headers(403, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                }
                let credential = header_credential(connect.proxy_authorization.as_ref());
                if let Some(response) = self.admit(&state, credential).await {
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                }
                let Ok(upstream) = self.tcp.dial(&target).await else {
                    let response = encode_response_headers(502, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                };
                if send
                    .write_all(&connect_established_response())
                    .await
                    .is_err()
                {
                    return;
                }
                tracing::trace!(conn = state.id(), "masque: tcp tunnel opened");
                pump_tcp(send, reader, upstream).await;
            }
            ProxyRequest::ConnectUdp(connect) => {
                // A peer that never advertised HTTP Datagrams cannot receive
                // the tunnel's replies; it is refused rather than served with a
                // capsule fallback it did not ask for.
                if !state
                    .peer_supports_h3_datagram(self.config.request_deadline)
                    .await
                {
                    let response = encode_response_headers(400, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                }
                let Some((target, path_credential)) = parse_connect_udp_target(&connect.path)
                    .and_then(|t| Some((udp_authority(&t.host, t.port)?, t.credential)))
                else {
                    let response = encode_response_headers(400, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                };
                if !self.policy.permits(&target) {
                    let response = encode_response_headers(403, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                }
                // A browser sends no header on CONNECT-UDP and opens a
                // dedicated connection for it, so the credential in the
                // template's query is the one that admits that connection.
                let credential =
                    header_credential(connect.proxy_authorization.as_ref()).or_else(|| {
                        path_credential.map(|c| ProxyCredential::from_password(c.as_bytes()))
                    });
                if let Some(response) = self.admit(&state, credential).await {
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                }
                let stream_id = u64::from(send.id());
                let route = UdpRoute::open(&state, stream_id);
                let Ok(socket) = self.udp.dial(&target).await else {
                    drop(route);
                    let response = encode_response_headers(502, &[]);
                    return respond_and_close(&mut send, reader.recv_mut(), &response).await;
                };
                if send
                    .write_all(&connect_udp_established_response())
                    .await
                    .is_err()
                {
                    return;
                }
                tracing::trace!(conn = state.id(), "masque: udp tunnel opened");
                pump_udp(state, stream_id, send, reader, socket, route).await;
            }
            ProxyRequest::Other => {}
        }
    }

    /// Admits the connection if it is not yet, from `credential`. Returns the
    /// response to write when the request cannot proceed: a `407` challenge
    /// when no credential verified, a `403` when one verified but is spent
    /// elsewhere.
    async fn admit(
        &self,
        state: &ConnState,
        credential: Option<ProxyCredential>,
    ) -> Option<Vec<u8>> {
        state
            .admit_once(|| async {
                let Some(credential) = credential else {
                    return Err(proxy_challenge_response());
                };
                match admit_credential(self.admitter.as_ref(), &credential).await {
                    TokenAdmission::Admit { .. } => {
                        let ttl = admission_ttl(
                            unix_now(),
                            self.config.admission_period,
                            self.config.admission_grace,
                        );
                        // Value-free: one line per admitted connection, no
                        // peer, no destination, no credential.
                        tracing::debug!(
                            conn = state.id(),
                            ttl_secs = ttl.as_secs(),
                            "masque: connection admitted"
                        );
                        Ok(ttl)
                    }
                    // Challenge rather than refuse: a stale credential is the
                    // ordinary case at an epoch boundary, and the client
                    // answers a 407 with a fresh one.
                    TokenAdmission::Reject => Err(proxy_challenge_response()),
                    TokenAdmission::Denied => Err(encode_response_headers(403, &[])),
                }
            })
            .await
            .err()
    }
}

/// The credential a `proxy-authorization` header carries, when it parses.
fn header_credential(
    header: Option<&warrenguard_edge::ProxyAuthorization>,
) -> Option<ProxyCredential> {
    header
        .and_then(|c| core::str::from_utf8(c.as_bytes()).ok())
        .and_then(|c| parse_proxy_authorization(c.trim()).ok())
}

/// The `host:port` authority of a CONNECT-UDP target, bracketing an IPv6
/// literal (the template carries it bare).
fn udp_authority(host: &str, port: u16) -> Option<Authority> {
    let raw = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Authority::parse(&raw).ok()
}

/// How long an admission granted at `now` (seconds since the Unix epoch)
/// lasts: to the end of the current `period` on the wall clock, plus `grace`.
/// Never longer than one period plus the grace.
#[must_use]
pub fn admission_ttl(now_unix_secs: u64, period: Duration, grace: Duration) -> Duration {
    let period_secs = period.as_secs().max(1);
    let remaining = period_secs - (now_unix_secs % period_secs);
    Duration::from_secs(remaining) + grace
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Drains one peer-initiated unidirectional stream for the connection's
/// lifetime, reading the SETTINGS off the control stream. Never resets it: a
/// reset of a critical HTTP/3 stream aborts the whole connection.
async fn drain_peer_uni(mut recv: RecvStream, state: Arc<ConnState>) {
    let mut header = Vec::new();
    let mut settled = false;
    let mut scratch = [0u8; 4096];
    while let Ok(Some(n)) = recv.read(&mut scratch).await {
        if settled {
            continue;
        }
        if header.len() < MAX_CONTROL_FRAME_BYTES as usize {
            header.extend_from_slice(&scratch[..n]);
        }
        settled = match read_uni_stream_type(&header) {
            None => false,
            Some((ty, _)) if ty != STREAM_CONTROL => true,
            Some((_, after_ty)) => match read_frame(after_ty) {
                Some((frame, _)) => {
                    state.set_h3_datagram(parse_settings(frame.payload).h3_datagram);
                    true
                }
                None => header.len() >= MAX_CONTROL_FRAME_BYTES as usize,
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_ends_at_the_period_boundary_plus_the_grace() {
        let period = Duration::from_secs(3600);
        let grace = Duration::from_secs(300);
        // Ten minutes into an epoch: fifty minutes remain, plus the grace.
        assert_eq!(
            admission_ttl(3600 * 7 + 600, period, grace),
            Duration::from_secs(3000 + 300)
        );
        // Exactly at a boundary the whole period remains: the maximum.
        assert_eq!(admission_ttl(3600 * 7, period, grace), period + grace);
        // One second before the boundary: the minimum, one second plus grace.
        assert_eq!(
            admission_ttl(3600 * 8 - 1, period, grace),
            Duration::from_secs(1) + grace
        );
    }

    #[test]
    fn udp_authority_brackets_an_ipv6_literal() {
        let v6 = udp_authority("2001:db8::1", 53).expect("valid");
        assert_eq!((v6.host(), v6.port()), ("2001:db8::1", 53));
        let name = udp_authority("example.com", 443).expect("valid");
        assert_eq!((name.host(), name.port()), ("example.com", 443));
        assert!(udp_authority("bad host", 1).is_none());
    }
}
