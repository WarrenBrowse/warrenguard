//! HTTP CONNECT proxy ingress for browser clients.
//!
//! A browser configured with a remote HTTPS proxy completes TLS to that proxy
//! and then speaks ordinary HTTP/1.1 CONNECT inside it. This crate owns that
//! exchange and nothing else: it parses the request head, challenges for a
//! credential, hands the credential to an injected admitter, asks an injected
//! dialer for the upstream, and pipes bytes. Admission policy, egress policy and
//! transport all live in the deployer.
//!
//! # Why this exists next to the WebTransport edge
//!
//! The edge (`warrenguard-edge-server`) carries a sealed Warren session inside
//! a browser WebTransport session, which only the extension's own code can use.
//! A CONNECT ingress is what a browser can be *configured* to send all of its
//! traffic through, so it is the shape that turns a store-installed extension
//! into a whole-browser VPN with nothing installed on the machine.
//!
//! # What this ingress is not
//!
//! It serves CONNECT only. A plain-http request through a proxy arrives in
//! absolute form (`GET http://host/`), which would make the ingress the
//! cleartext terminator for that request; it is refused with `405` instead.
//!
//! In the single-hop deployment the node that terminates this TLS also dials the
//! destination, so it sees the client address and the destination together. That
//! is an ordinary single-hop VPN and the deployer must label it as one.
//!
//! # No-log discipline
//!
//! The request head carries the client's destination, and the credential is
//! bearer material. Neither appears in an error value here: every [`HeadError`]
//! variant is value-free, and [`ProxyCredential`] renders redacted and zeroizes
//! on drop.

mod head;
mod serve;

pub use head::{
    Authority, CREDENTIAL_USERNAME, ConnectHead, HeadError, MAX_HEAD_BYTES, ProxyCredential,
    challenge_response, established_response, looks_like_connect_request,
    method_not_allowed_response, parse_connect_head, parse_proxy_authorization, refused_response,
};
pub use serve::{
    ConnectDialer, ConnectProxyConfig, EgressPolicy, ProxyOutcome, ProxyRefusal, admit_credential,
    serve_connect,
};
