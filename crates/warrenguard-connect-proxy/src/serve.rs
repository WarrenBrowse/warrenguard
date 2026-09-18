//! Serving one CONNECT request over an already-established byte stream.

use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use warrenguard_server::{SessionTokenAdmitter, TokenAdmission};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

use crate::head::{
    Authority, ConnectHead, HeadError, MAX_HEAD_BYTES, ProxyCredential, challenge_response,
    established_response, method_not_allowed_response, parse_connect_head, refused_response,
};

/// Opens the upstream connection a CONNECT asked for. Injected so the deployer
/// owns the egress socket (its interface, its bind address, its policy).
pub trait ConnectDialer: Send + Sync {
    /// The upstream stream type this dialer produces.
    type Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Dials `target`, or reports that it will not.
    fn dial(
        &self,
        target: &Authority,
    ) -> impl std::future::Future<Output = std::io::Result<Self::Upstream>> + Send;
}

/// Whether a destination may be dialed at all. Runs BEFORE the credential is
/// examined, so a refused destination costs no token verification and reveals
/// nothing about the credential.
pub trait EgressPolicy: Send + Sync {
    /// `true` when this ingress may open a connection to `target`.
    fn permits(&self, target: &Authority) -> bool;
}

/// Why a request did not become a tunnel. Carries no destination and no
/// credential, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRefusal {
    /// The head never completed, or was not an acceptable CONNECT.
    Head(HeadError),
    /// The peer closed before sending a complete head.
    Closed,
    /// The peer sent no complete head within the deadline.
    Timeout,
    /// The destination is outside what this ingress will dial.
    EgressDenied,
    /// No credential was presented; the client was challenged.
    Challenged,
    /// A credential was presented and did not verify.
    CredentialRejected,
    /// A credential verified but its serial is already spent elsewhere.
    CredentialSpent,
    /// The upstream refused or was unreachable.
    UpstreamUnreachable,
}

/// How one CONNECT ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// The tunnel ran to completion.
    Tunnelled {
        /// Bytes the client sent to the destination.
        to_upstream: u64,
        /// Bytes the destination sent back.
        to_client: u64,
    },
    /// A response was written and the connection is finished.
    Refused(ProxyRefusal),
}

/// Knobs a deployer sets on the ingress.
#[derive(Debug, Clone)]
pub struct ConnectProxyConfig {
    /// How long a peer may take to deliver a complete request head. A browser
    /// sends it immediately; this denies a stalled peer a cheap held slot.
    pub head_deadline: Duration,
}

impl Default for ConnectProxyConfig {
    fn default() -> Self {
        Self {
            head_deadline: Duration::from_secs(10),
        }
    }
}

/// Serves one CONNECT exchange on `stream`.
///
/// `prefix` is any bytes the caller already read off the stream while deciding
/// this was an HTTP request, so a shared listener can sniff without consuming.
///
/// Order of checks, and why: the head is parsed, then the destination is passed
/// through `policy`, then the credential is verified. Refusing a destination
/// before touching the credential keeps an unusable request from spending a
/// token, and keeps the expensive check behind the cheap one.
///
/// # Errors
/// An I/O error on the client stream. A refusal is not an error: it is reported
/// as [`ProxyOutcome::Refused`] after the matching response has been written.
pub async fn serve_connect<S, D, P, A>(
    mut stream: S,
    prefix: &[u8],
    config: &ConnectProxyConfig,
    policy: &P,
    admitter: &A,
    dialer: &D,
) -> std::io::Result<ProxyOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    D: ConnectDialer,
    P: EgressPolicy,
    A: SessionTokenAdmitter + ?Sized,
{
    let head = match read_head(&mut stream, prefix, config.head_deadline).await? {
        Ok(head) => head,
        Err(refusal) => {
            let response = match refusal {
                ProxyRefusal::Head(HeadError::NotConnect) => method_not_allowed_response(),
                _ => refused_response(),
            };
            // A peer that already vanished cannot be told why.
            let _ = stream.write_all(response).await;
            let _ = stream.flush().await;
            return Ok(ProxyOutcome::Refused(refusal));
        }
    };

    if !policy.permits(&head.target) {
        stream.write_all(refused_response()).await?;
        stream.flush().await?;
        return Ok(ProxyOutcome::Refused(ProxyRefusal::EgressDenied));
    }

    let Some(credential) = head.credential else {
        stream.write_all(challenge_response()).await?;
        stream.flush().await?;
        return Ok(ProxyOutcome::Refused(ProxyRefusal::Challenged));
    };

    match admit(admitter, &credential).await {
        TokenAdmission::Admit { .. } => {}
        TokenAdmission::Reject => {
            // Challenge rather than refuse: a stale credential is the ordinary
            // case at an epoch boundary, and the client answers a 407 with a
            // fresh one without the user seeing anything.
            stream.write_all(challenge_response()).await?;
            stream.flush().await?;
            return Ok(ProxyOutcome::Refused(ProxyRefusal::CredentialRejected));
        }
        TokenAdmission::Denied => {
            stream.write_all(refused_response()).await?;
            stream.flush().await?;
            return Ok(ProxyOutcome::Refused(ProxyRefusal::CredentialSpent));
        }
    }

    let mut upstream = match dialer.dial(&head.target).await {
        Ok(upstream) => upstream,
        Err(_) => {
            // The reason an upstream refused is the client's destination
            // talking; it is answered generically and never logged here.
            stream.write_all(refused_response()).await?;
            stream.flush().await?;
            return Ok(ProxyOutcome::Refused(ProxyRefusal::UpstreamUnreachable));
        }
    };

    stream.write_all(established_response()).await?;
    stream.flush().await?;

    let (to_upstream, to_client) =
        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(ProxyOutcome::Tunnelled {
        to_upstream,
        to_client,
    })
}

/// Hands the credential to the admitter under the engine's v7 token type.
///
/// The password half of a Basic credential travels through a browser as a
/// string, so it carries the token base64url-encoded rather than raw. A
/// credential that does not decode to exactly one token is rejected here, before
/// any crypto runs.
async fn admit<A>(admitter: &A, credential: &ProxyCredential) -> TokenAdmission
where
    A: SessionTokenAdmitter + ?Sized,
{
    let Ok(decoded) = BASE64URL_NOPAD.decode(credential.as_bytes()) else {
        return TokenAdmission::Reject;
    };
    let Ok(bytes) = <[u8; SESSION_TOKEN_LEN]>::try_from(decoded.as_slice()) else {
        return TokenAdmission::Reject;
    };
    let tokens = [SessionToken(bytes)];
    admitter.admit(&tokens).await
}

/// Reads until a complete head has arrived, the deadline passes, or the peer
/// goes away. The outer result is an I/O failure on the client stream; the inner
/// one separates an acceptable head from a refusal the caller must answer.
async fn read_head<S>(
    stream: &mut S,
    prefix: &[u8],
    deadline: Duration,
) -> std::io::Result<Result<ConnectHead, ProxyRefusal>>
where
    S: AsyncRead + Unpin + Send,
{
    let mut buf = prefix.to_vec();
    loop {
        match parse_connect_head(&buf) {
            Ok(Some(head)) => return Ok(Ok(head)),
            Ok(None) => {}
            Err(e) => return Ok(Err(ProxyRefusal::Head(e))),
        }
        let mut chunk = [0u8; 1024];
        let read = match tokio::time::timeout(deadline, stream.read(&mut chunk)).await {
            Err(_elapsed) => return Ok(Err(ProxyRefusal::Timeout)),
            Ok(Err(e)) => return Err(e),
            Ok(Ok(0)) => return Ok(Err(ProxyRefusal::Closed)),
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(Err(ProxyRefusal::Head(HeadError::TooLarge)));
        }
    }
}
