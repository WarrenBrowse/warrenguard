//! Engine seam for handling connections that are NOT authenticated Warren
//! clients (the active-probe decoy hook).

/// Handler for a connection that completed the QUIC + TLS handshake but did
/// not present a valid, authenticated Warren `Setup`: the setup frame was
/// absent or undecodable, the channel binding could not be exported, or the
/// in-band auth proof did not verify. With a handler configured on
/// [`crate::ExitBindOpts::unauthenticated_handler`], the exit hands such a
/// connection to it instead of closing - the seam a deployer uses to mount an
/// active-probe decoy (a real HTTP/3 site, a reverse proxy, ...).
///
/// The engine stays policy-free: it carries no HTTP/3 dependency and bundles
/// no decoy. WHAT to serve is the deployer's choice; the
/// engine only decides WHEN to hand off.
///
/// This is NOT called for authorization failures. A connection that DID present
/// a valid, channel-bound auth proof but whose pubkey the allowlist or device
/// cap rejects is a genuine Warren client; it keeps its structured rejection
/// close code (e.g. `WARREN_AUTH_FAILED`) so the client app can act, and is
/// never routed here.
///
/// Hand-off contract: by the time `handle` is called the engine has already
/// accepted the peer's first bidi stream and read its first message (which did
/// not decode as a valid Warren `Setup`). Rather than dropping that stream, the
/// engine hands it back in [`UnauthenticatedProbe`] (its send half plus the
/// bytes already read), so a decoy can answer the probe's own request - an
/// active prober that GETs the cover domain expects an HTTP/3 response on the
/// request stream, not an abrupt close. The handler owns the connection and the
/// probe from this point and may open or accept further streams, send
/// datagrams, or simply hold it. It MUST NOT block the accept loop: spawn if the
/// work is not instantaneous.
pub trait UnauthenticatedHandler: Send + Sync {
    /// Takes ownership of the live, handshake-complete but unauthenticated
    /// connection and the consumed first stream (see [`UnauthenticatedProbe`]).
    fn handle(&self, conn: quinn::Connection, probe: UnauthenticatedProbe);
}

/// The first bidi stream the engine accepted on an unauthenticated connection,
/// handed to an [`UnauthenticatedHandler`] so a decoy can reply on it.
#[non_exhaustive]
pub struct UnauthenticatedProbe {
    /// Send half of the peer's first bidi stream (the request stream of an
    /// HTTP/3 prober). The decoy writes its response here.
    pub send: quinn::SendStream,
    /// The bytes the peer already sent on that stream before the engine
    /// determined it was not a Warren client (e.g. the prober's HTTP/3
    /// request). A decoy may inspect them to shape a plausible reply.
    pub request: Vec<u8>,
}

impl UnauthenticatedProbe {
    /// Builds a probe from the consumed stream half and the bytes read off it.
    #[must_use]
    pub fn new(send: quinn::SendStream, request: Vec<u8>) -> Self {
        Self { send, request }
    }
}
