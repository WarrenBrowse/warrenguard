//! The client side of the ingress: what a browser does with an HTTP/3 proxy,
//! as a library, so the ingress can be driven end to end from a test, a bench
//! tool or a forwarder without a browser in the loop.
//!
//! [`MasqueClient::open`] speaks the HTTP/3 opening on an established QUIC
//! connection (control stream with SETTINGS, QPACK streams, draining the
//! server's). [`MasqueClient::connect_tcp`] and [`MasqueClient::connect_udp`]
//! send one request stream each and hand back the tunnel once the ingress
//! answered `200`, or the status it answered instead.

use std::sync::Arc;

use bytes::Bytes;
use quinn::{Connection, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use warrenguard_edge::{
    CONNECT_UDP_CREDENTIAL_PARAM, CONNECT_UDP_PATH_PREFIX, FRAME_HEADERS, FRAME_SETTINGS,
    SETTINGS_H3_DATAGRAM, SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    STREAM_CONTROL, decode_field_section, encode_field_section, encode_frame,
    encode_masque_datagram, encode_varint,
};

use crate::connection::DatagramRoutes;
use crate::frames::{FrameError, FrameReader, data_frame_header};
use crate::tunnel::{H3_NO_ERROR, pump_tcp};

/// QPACK encoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_ENCODER: u64 = 0x02;
/// QPACK decoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_DECODER: u64 = 0x03;

/// Why a request did not become a tunnel. Carries no destination and no
/// credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A QUIC stream or connection operation failed.
    #[error("QUIC connection failed")]
    Connection,
    /// The ingress answered with malformed HTTP/3.
    #[error("malformed HTTP/3 from the proxy")]
    Malformed,
    /// The ingress answered something other than `200`.
    #[error("proxy answered {status}")]
    Status {
        /// The `:status` it answered.
        status: u16,
        /// Every response field, name and value.
        fields: Vec<(String, String)>,
    },
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Stream => Self::Connection,
            FrameError::Malformed => Self::Malformed,
        }
    }
}

/// One HTTP/3 proxy connection, opened and ready for requests.
pub struct MasqueClient {
    conn: Connection,
    routes: Arc<DatagramRoutes>,
}

impl MasqueClient {
    /// Performs the HTTP/3 opening on `conn`: writes the control stream with
    /// SETTINGS (static-only QPACK, HTTP Datagrams) and the QPACK streams, and
    /// drains whatever unidirectional streams the server opens.
    ///
    /// # Errors
    /// [`ClientError::Connection`] when a stream cannot be opened or written.
    pub async fn open(conn: Connection) -> Result<Self, ClientError> {
        let mut settings = Vec::new();
        for (id, value) in [
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_H3_DATAGRAM, 1),
        ] {
            settings.extend_from_slice(&encode_varint(id));
            settings.extend_from_slice(&encode_varint(value));
        }
        let mut prelude = encode_varint(STREAM_CONTROL);
        prelude.extend_from_slice(&encode_frame(FRAME_SETTINGS, &settings));
        let mut control = conn.open_uni().await.map_err(|_| ClientError::Connection)?;
        control
            .write_all(&prelude)
            .await
            .map_err(|_| ClientError::Connection)?;
        let mut encoder = conn.open_uni().await.map_err(|_| ClientError::Connection)?;
        encoder
            .write_all(&encode_varint(QPACK_STREAM_ENCODER))
            .await
            .map_err(|_| ClientError::Connection)?;
        let mut decoder = conn.open_uni().await.map_err(|_| ClientError::Connection)?;
        decoder
            .write_all(&encode_varint(QPACK_STREAM_DECODER))
            .await
            .map_err(|_| ClientError::Connection)?;

        let routes = Arc::new(DatagramRoutes::default());
        {
            let conn = conn.clone();
            tokio::spawn(async move {
                let _hold = (control, encoder, decoder);
                while let Ok(mut recv) = conn.accept_uni().await {
                    tokio::spawn(async move {
                        let mut scratch = [0u8; 4096];
                        while let Ok(Some(_)) = recv.read(&mut scratch).await {}
                    });
                }
            });
        }
        {
            let conn = conn.clone();
            let routes = routes.clone();
            tokio::spawn(async move {
                while let Ok(datagram) = conn.read_datagram().await {
                    routes.route(&datagram);
                }
            });
        }
        Ok(Self { conn, routes })
    }

    /// The underlying QUIC connection.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Sends a `CONNECT` for `authority` (`host:port`), with `credential` as
    /// the `proxy-authorization` value when given.
    ///
    /// # Errors
    /// [`ClientError::Status`] when the ingress answered anything but `200`;
    /// the connection and framing errors otherwise.
    pub async fn connect_tcp(
        &self,
        authority: &str,
        credential: Option<&str>,
    ) -> Result<TcpTunnel, ClientError> {
        let mut fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":authority", authority.as_bytes()),
        ];
        if let Some(c) = credential {
            fields.push((b"proxy-authorization", c.as_bytes()));
        }
        let (send, reader) = self.request(&fields).await?;
        Ok(TcpTunnel { send, reader })
    }

    /// Sends a `CONNECT` with `:protocol connect-udp` for `host:port` on the
    /// well-known template, with `credential` when given.
    ///
    /// # Errors
    /// As [`Self::connect_tcp`].
    pub async fn connect_udp(
        &self,
        host: &str,
        port: u16,
        credential: Option<&str>,
    ) -> Result<UdpTunnel, ClientError> {
        self.request_udp(host, port, credential, None).await
    }

    /// As [`Self::connect_udp`], with the credential's password half carried
    /// in the template's query rather than in a header: what a browser's
    /// expanded `masqueTemplate` sends.
    ///
    /// # Errors
    /// As [`Self::connect_tcp`].
    pub async fn connect_udp_with_path_credential(
        &self,
        host: &str,
        port: u16,
        password: &str,
    ) -> Result<UdpTunnel, ClientError> {
        self.request_udp(host, port, None, Some(password)).await
    }

    async fn request_udp(
        &self,
        host: &str,
        port: u16,
        credential: Option<&str>,
        path_credential: Option<&str>,
    ) -> Result<UdpTunnel, ClientError> {
        let mut path = format!("{CONNECT_UDP_PATH_PREFIX}{}/{port}/", percent_encode(host));
        if let Some(password) = path_credential {
            path.push('?');
            path.push_str(CONNECT_UDP_CREDENTIAL_PARAM);
            path.push('=');
            path.push_str(password);
        }
        let mut fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"connect-udp"),
            (b":scheme", b"https"),
            (b":authority", b"proxy"),
            (b":path", path.as_bytes()),
            (b"capsule-protocol", b"?1"),
        ];
        if let Some(c) = credential {
            fields.push((b"proxy-authorization", c.as_bytes()));
        }
        let (send, reader) = self.request(&fields).await?;
        let stream_id = u64::from(send.id());
        let (tx, rx) = mpsc::channel(256);
        self.routes.register(stream_id >> 2, tx);
        Ok(UdpTunnel {
            sender: UdpSender {
                conn: self.conn.clone(),
                stream_id,
            },
            receiver: UdpReceiver {
                routes: self.routes.clone(),
                stream_id,
                send,
                reader,
                rx,
            },
        })
    }

    /// Writes one request head and reads the response head; `Ok` only on a
    /// `200`, with the stream ready to carry the tunnel.
    async fn request(
        &self,
        fields: &[(&[u8], &[u8])],
    ) -> Result<(SendStream, FrameReader), ClientError> {
        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|_| ClientError::Connection)?;
        send.write_all(&encode_frame(FRAME_HEADERS, &encode_field_section(fields)))
            .await
            .map_err(|_| ClientError::Connection)?;
        let mut reader = FrameReader::new(recv, Bytes::new());
        let head = reader
            .next_frame(FRAME_HEADERS)
            .await?
            .ok_or(ClientError::Malformed)?;
        let fields: Vec<(String, String)> = decode_field_section(&head)
            .map_err(|_| ClientError::Malformed)?
            .into_iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).into_owned(),
                    String::from_utf8_lossy(&f.value).into_owned(),
                )
            })
            .collect();
        let status: u16 = fields
            .iter()
            .find(|(n, _)| n == ":status")
            .and_then(|(_, v)| v.parse().ok())
            .ok_or(ClientError::Malformed)?;
        if status != 200 {
            let _ = send.finish();
            let _ = reader.recv_mut().stop(H3_NO_ERROR);
            return Err(ClientError::Status { status, fields });
        }
        Ok((send, reader))
    }
}

/// Percent-encodes the characters of a host that the path template cannot
/// carry bare (the colons of an IPv6 literal).
fn percent_encode(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for b in host.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// An open TCP tunnel: the CONNECT stream after the `200`.
pub struct TcpTunnel {
    send: SendStream,
    reader: FrameReader,
}

impl TcpTunnel {
    /// Sends `bytes` to the destination as one DATA frame.
    ///
    /// # Errors
    /// [`ClientError::Connection`] when the stream is gone.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let mut chunks = [
            data_frame_header(bytes.len()),
            Bytes::copy_from_slice(bytes),
        ];
        self.send
            .write_all_chunks(&mut chunks)
            .await
            .map_err(|_| ClientError::Connection)
    }

    /// Receives the next bytes from the destination; `None` once the
    /// destination closed.
    ///
    /// # Errors
    /// The framing errors of the stream.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ClientError> {
        Ok(self.reader.next_data().await?)
    }

    /// Half-closes toward the destination.
    pub fn finish(&mut self) {
        let _ = self.send.finish();
    }

    /// Pipes the tunnel and `io` into each other until both directions end,
    /// exactly as the ingress pipes its side: the shape of a local forwarder.
    pub async fn pump<T>(self, io: T)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        pump_tcp(self.send, self.reader, io).await;
    }
}

/// An open UDP tunnel: the CONNECT-UDP stream after the `200`, and the HTTP
/// Datagrams tagged for it. Splits into a cloneable sender and the receiver
/// that owns the stream, so a forwarder can send from one task and receive on
/// another.
pub struct UdpTunnel {
    sender: UdpSender,
    receiver: UdpReceiver,
}

impl UdpTunnel {
    /// The request stream's ID, whose quarter tags this tunnel's datagrams.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.sender.stream_id
    }

    /// Sends one UDP payload to the destination as an HTTP Datagram.
    ///
    /// # Errors
    /// [`ClientError::Connection`] when the connection is gone.
    pub fn send(&self, payload: &[u8]) -> Result<(), ClientError> {
        self.sender.send(payload)
    }

    /// Receives the next UDP payload from the destination; `None` once the
    /// tunnel is gone.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.receiver.recv().await
    }

    /// Splits the tunnel into its sending and receiving halves.
    #[must_use]
    pub fn split(self) -> (UdpSender, UdpReceiver) {
        (self.sender, self.receiver)
    }
}

/// The sending half of a [`UdpTunnel`]: cheap to clone, usable from any task.
#[derive(Clone)]
pub struct UdpSender {
    conn: Connection,
    stream_id: u64,
}

impl UdpSender {
    /// Sends one UDP payload to the destination as an HTTP Datagram. A
    /// payload too large for the path is dropped, as UDP would.
    ///
    /// # Errors
    /// [`ClientError::Connection`] when the connection is gone.
    pub fn send(&self, payload: &[u8]) -> Result<(), ClientError> {
        use quinn::SendDatagramError as E;
        match self
            .conn
            .send_datagram(Bytes::from(encode_masque_datagram(self.stream_id, payload)))
        {
            Ok(()) | Err(E::TooLarge) => Ok(()),
            Err(E::UnsupportedByPeer | E::Disabled | E::ConnectionLost(_)) => {
                Err(ClientError::Connection)
            }
        }
    }
}

/// The receiving half of a [`UdpTunnel`]: owns the request stream, so
/// dropping it ends the tunnel at the ingress.
pub struct UdpReceiver {
    routes: Arc<DatagramRoutes>,
    stream_id: u64,
    send: SendStream,
    reader: FrameReader,
    rx: mpsc::Receiver<Bytes>,
}

impl UdpReceiver {
    /// Receives the next UDP payload from the destination; `None` once the
    /// tunnel is gone.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    /// Resolves once the ingress has ended the tunnel (finished or reset the
    /// request stream).
    pub async fn closed(&mut self) {
        while let Ok(Some(_)) = self.reader.next_data().await {}
    }
}

impl Drop for UdpReceiver {
    fn drop(&mut self) {
        self.routes.unregister(self.stream_id >> 2);
        let _ = self.send.finish();
        let _ = self.reader.recv_mut().stop(H3_NO_ERROR);
    }
}

// Value-free renderings: a tunnel names a destination the client asked for,
// which must not reach a log through a stray `{:?}`.
impl core::fmt::Debug for TcpTunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TcpTunnel")
    }
}

impl core::fmt::Debug for UdpTunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpTunnel")
            .field("stream_id", &self.sender.stream_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn percent_encodes_an_ipv6_literal_for_the_template() {
        assert_eq!(percent_encode("2001:db8::1"), "2001%3Adb8%3A%3A1");
        assert_eq!(percent_encode("example.com"), "example.com");
    }
}
