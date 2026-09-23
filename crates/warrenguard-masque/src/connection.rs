//! Per-connection state of the ingress: the admission a verified credential
//! grants, the tunnel budget, and the HTTP Datagram routes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::{Connection, VarInt};
use tokio::sync::{OnceCell, Semaphore, mpsc, watch};
use warrenguard_edge::read_masque_datagram;

/// What one HTTP/3 connection knows about itself while the ingress serves it.
pub(crate) struct ConnState {
    conn: Connection,
    /// Set once a credential verified on this connection, to the instant the
    /// admission ends. It is never extended: the connection is closed at that
    /// instant and the client reconnects with a fresh credential.
    admitted_until: OnceCell<Instant>,
    /// One permit per live tunnel.
    tunnels: Arc<Semaphore>,
    /// The HTTP Datagram routes of the connection's CONNECT-UDP tunnels.
    routes: DatagramRoutes,
    /// Whether the peer's SETTINGS advertised HTTP Datagram support. `None`
    /// until its control stream has been read.
    h3_datagram: watch::Sender<Option<bool>>,
}

impl ConnState {
    pub(crate) fn new(conn: Connection, max_tunnels: u32) -> Self {
        Self {
            conn,
            admitted_until: OnceCell::new(),
            tunnels: Arc::new(Semaphore::new(max_tunnels as usize)),
            routes: DatagramRoutes::default(),
            h3_datagram: watch::Sender::new(None),
        }
    }

    /// Whether a credential has admitted this connection. Expiry is not
    /// checked here: the timer armed by [`Self::admit_once`] closes the
    /// connection at the deadline, so an open connection with an admission is
    /// admitted.
    pub(crate) fn is_admitted(&self) -> bool {
        self.admitted_until.initialized()
    }

    /// Admits the connection through `verify` unless it is admitted already,
    /// and arms the close that ends the admission after the `ttl` `verify`
    /// grants.
    ///
    /// One verification at a time: a request arriving while another is being
    /// verified waits for that outcome, and runs its own only if that one did
    /// not admit. Verifying spends the credential, so concurrent first
    /// requests carrying the same one would otherwise spend it twice and see
    /// the second attempt refused.
    ///
    /// # Errors
    ///
    /// What `verify` refused with, when the connection is still not admitted.
    pub(crate) async fn admit_once<F, Fut, E>(&self, verify: F) -> Result<(), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Duration, E>>,
    {
        self.admitted_until
            .get_or_try_init(|| async {
                let ttl = verify().await?;
                let conn = self.conn.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(ttl).await;
                    // A neutral code: the client reconnects and presents the
                    // next epoch's credential on its first CONNECT.
                    conn.close(VarInt::from_u32(0), b"");
                });
                Ok(Instant::now() + ttl)
            })
            .await
            .map(|_| ())
    }

    /// Reserves a tunnel slot, or `None` when the connection is at its cap.
    pub(crate) fn try_acquire_tunnel(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.tunnels.clone().try_acquire_owned().ok()
    }

    /// A process-local identifier of the connection, for correlating log
    /// lines; it names no peer.
    pub(crate) fn id(&self) -> usize {
        self.conn.stable_id()
    }

    pub(crate) fn routes(&self) -> &DatagramRoutes {
        &self.routes
    }

    /// Sends one HTTP Datagram to the peer. A datagram too large for the path
    /// is dropped (UDP semantics); `false` only when the connection is gone or
    /// the peer does not accept datagrams at all, so the tunnel ends.
    pub(crate) fn send_datagram(&self, datagram: Bytes) -> bool {
        use quinn::SendDatagramError as E;
        match self.conn.send_datagram(datagram) {
            Ok(()) | Err(E::TooLarge) => true,
            Err(E::UnsupportedByPeer | E::Disabled | E::ConnectionLost(_)) => false,
        }
    }

    /// Records what the peer's SETTINGS said about HTTP Datagrams.
    pub(crate) fn set_h3_datagram(&self, supported: bool) {
        self.h3_datagram.send_replace(Some(supported));
    }

    /// Waits until the peer's SETTINGS have been read, up to `deadline`, and
    /// reports whether they advertised HTTP Datagrams. `false` when they did
    /// not, or never arrived: a peer that cannot receive datagrams gets no UDP
    /// tunnel.
    pub(crate) async fn peer_supports_h3_datagram(&self, deadline: Duration) -> bool {
        let mut rx = self.h3_datagram.subscribe();
        let wait = rx.wait_for(|v| v.is_some());
        match tokio::time::timeout(deadline, wait).await {
            Ok(Ok(value)) => value.unwrap_or(false),
            _ => false,
        }
    }
}

/// Quarter Stream ID of each live CONNECT-UDP stream on one connection, to the
/// channel that feeds its pump the HTTP Datagrams received for it. Shared by
/// the ingress and the client: both ends demultiplex datagrams the same way.
#[derive(Default)]
pub(crate) struct DatagramRoutes {
    routes: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
}

impl DatagramRoutes {
    pub(crate) fn register(&self, quarter_stream_id: u64, tx: mpsc::Sender<Bytes>) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(quarter_stream_id, tx);
        }
    }

    pub(crate) fn unregister(&self, quarter_stream_id: u64) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.remove(&quarter_stream_id);
        }
    }

    /// Hands one received HTTP Datagram to the tunnel it names. A datagram for
    /// an unknown stream, a foreign context, or a pump whose queue is full is
    /// dropped: UDP semantics, no backpressure onto the connection.
    pub(crate) fn route(&self, datagram: &Bytes) {
        let Some((quarter_stream_id, context_id, payload)) = read_masque_datagram(datagram) else {
            return;
        };
        if context_id != warrenguard_edge::CONNECT_UDP_CONTEXT_ID {
            return;
        }
        let payload = datagram.slice_ref(payload);
        if let Ok(routes) = self.routes.lock()
            && let Some(tx) = routes.get(&quarter_stream_id)
        {
            let _ = tx.try_send(payload);
        }
    }
}
