//! Shared protocol constants: the QUIC application close codes that are part of
//! the `/v1` wire contract and read by **both** the client and the exit.
//!
//! They live in a neutral module so the client decode path never reaches into
//! the server `exit` module just to recognise a close code.
//!
//! Each value is frozen: the client matches it byte-for-byte on
//! `Connection::close_reason()`, so changing one breaks recognition across
//! mixed-version deployments. Bump the protocol version instead of mutating a
//! value.

use quinn::VarInt;

/// Application-level QUIC error code the exit uses to close a connection when an
/// AUTHENTICATED Warren client is refused: its in-band auth proof verified but
/// its pubkey is not authorized (allowlist), or its session was revoked
/// mid-tunnel. "WARR" in ASCII = `0x57415252`.
///
/// Part of the wire contract (`/v1`): the **client** matches this exact code on
/// `Connection::close_reason()` to map an otherwise-generic "connection lost"
/// into [`crate::TunnelError::AuthRejected`].
///
/// It is NOT sent to an UNAUTHENTICATED peer (absent or undecodable `Setup`,
/// channel-binding failure, or an auth proof that did not verify): such a peer
/// is indistinguishable from an active prober and gets
/// [`H3_GENERAL_PROTOCOL_ERROR`], so the exit leaks no Warren-specific
/// close-code tell.
pub const WARREN_AUTH_FAILED: VarInt = VarInt::from_u32(0x5741_5252);

/// Application-level QUIC error code the exit uses to close a PRIMARY connection
/// refused by the global per-account device cap (v2): the account already has
/// the server-configured maximum of distinct devices live. "WLIM" in
/// ASCII = `0x574c494d`.
///
/// Distinct from [`WARREN_AUTH_FAILED`] so the client can map this to a clear
/// "device limit reached" reason rather than a generic auth rejection.
pub const WARREN_DEVICE_LIMIT: VarInt = VarInt::from_u32(0x574c_494d);

/// Human-readable close reason string paired with [`WARREN_DEVICE_LIMIT`].
pub const WARREN_DEVICE_LIMIT_REASON: &[u8] = b"device limit reached";

/// Application-level QUIC error code the exit uses to close a connection when IP
/// attribution fails because the tunnel pool has no free address left. "WFUL" in
/// ASCII = `0x5746554c`. Advisory (the client maps it to a generic connection
/// error today); distinct from [`WARREN_AUTH_FAILED`] so an exhausted exit is
/// never mistaken for an auth rejection in packet captures and exit logs.
pub const WARREN_NO_CAPACITY: VarInt = VarInt::from_u32(0x5746_554c);

/// Human-readable close reason string paired with [`WARREN_NO_CAPACITY`].
pub const WARREN_NO_CAPACITY_REASON: &[u8] = b"ip pool exhausted";

/// Application-level QUIC error code the exit uses when it is DRAINING for
/// planned maintenance: new authenticated handshakes are refused with this
/// code (fail-fast, so a reconnecting client immediately re-selects another
/// exit instead of landing on a dying one), and still-attached sessions are
/// hard-closed with it once the drain deadline passes. "WDRN" in
/// ASCII = `0x5744524e`.
///
/// Distinct from [`WARREN_AUTH_FAILED`] (the client's identity is fine, only
/// this exit is going away) and from [`WARREN_NO_CAPACITY`] (the exit is not
/// full, it is leaving). Like the other codes it is only ever sent to an
/// AUTHENTICATED peer; an unauthenticated prober still sees the decoy /
/// [`H3_GENERAL_PROTOCOL_ERROR`] behaviour and learns nothing.
pub const WARREN_EXIT_DRAINING: VarInt = VarInt::from_u32(0x5744_524e);

/// Human-readable close reason string paired with [`WARREN_EXIT_DRAINING`].
pub const WARREN_EXIT_DRAINING_REASON: &[u8] = b"exit draining";

/// Close code for a handshake-complete but UNAUTHENTICATED connection when no
/// decoy handler is configured: absent or undecodable `Setup`, channel-binding
/// export failure, or an in-band auth proof that did not verify. It is the
/// standard HTTP/3 `H3_GENERAL_PROTOCOL_ERROR` (RFC 9114), paired with an empty
/// reason, so an active prober sees exactly what a real HTTP/3 endpoint emits
/// for a malformed request rather than a Warren-specific tell (the ALPN is
/// `h3`).
pub const H3_GENERAL_PROTOCOL_ERROR: VarInt = VarInt::from_u32(0x0101);
