//! Minimal TLS ClientHello parsing: extracts only the fields JA4 needs
//! (RFC 8446 s4.1.2).

use crate::error::Ja4Error;
use crate::ja4::is_grease;

/// JA4-relevant fields extracted from a TLS ClientHello.
pub struct ClientHelloInfo {
    /// Effective TLS version: the highest non-GREASE value from the
    /// `supported_versions` extension, else the `legacy_version` field.
    pub tls_version: u16,
    /// Whether a `server_name` (SNI, ext `0x0000`) extension is present.
    pub has_sni: bool,
    /// Cipher suites in wire order (GREASE not yet filtered).
    pub cipher_suites: Vec<u16>,
    /// Extension types in wire order (GREASE not yet filtered).
    pub extensions: Vec<u16>,
    /// ALPN protocol strings (ext `0x0010`) in order.
    pub alpn: Vec<Vec<u8>>,
    /// Signature algorithms (ext `0x000d`) in order.
    pub sig_algs: Vec<u16>,
}

/// Cursor over a byte buffer with fallible big-endian reads.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn u8(&mut self) -> Result<u8, Ja4Error> {
        let v = *self.b.get(self.p).ok_or(Ja4Error::MalformedClientHello)?;
        self.p += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, Ja4Error> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn u24(&mut self) -> Result<u32, Ja4Error> {
        Ok(u32::from_be_bytes([0, self.u8()?, self.u8()?, self.u8()?]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Ja4Error> {
        let s = self
            .b
            .get(self.p..self.p + n)
            .ok_or(Ja4Error::MalformedClientHello)?;
        self.p += n;
        Ok(s)
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
}

/// Parses the JA4-relevant fields of a ClientHello handshake message.
///
/// # Errors
///
/// [`Ja4Error::NoClientHello`] if the handshake is not a ClientHello;
/// [`Ja4Error::MalformedClientHello`] on a structural parse failure.
pub fn parse_client_hello(hs: &[u8]) -> Result<ClientHelloInfo, Ja4Error> {
    let mut r = Reader::new(hs);
    if r.u8()? != 0x01 {
        return Err(Ja4Error::NoClientHello); // handshake type != ClientHello
    }
    let _body_len = r.u24()?;
    let legacy_version = r.u16()?;
    r.take(32)?; // random
    let sid_len = usize::from(r.u8()?);
    r.take(sid_len)?; // session_id
    let cs_len = usize::from(r.u16()?);
    let cipher_suites = u16_list(r.take(cs_len)?)?;
    let cm_len = usize::from(r.u8()?);
    r.take(cm_len)?; // compression_methods

    let mut extensions = Vec::new();
    let mut has_sni = false;
    let mut alpn = Vec::new();
    let mut sig_algs = Vec::new();
    let mut tls_version = legacy_version;

    if r.remaining() >= 2 {
        let ext_total = usize::from(r.u16()?);
        let mut e = Reader::new(r.take(ext_total)?);
        while e.remaining() >= 4 {
            let ext_type = e.u16()?;
            let ext_len = usize::from(e.u16()?);
            let data = e.take(ext_len)?;
            extensions.push(ext_type);
            match ext_type {
                0x0000 => has_sni = true,
                0x0010 => alpn = parse_alpn(data)?,
                // signature_algorithms: 2-byte list length, then the u16 list.
                0x000d => sig_algs = u16_list(data.get(2..).unwrap_or_default())?,
                0x002b => {
                    tls_version = highest_supported_version(data).unwrap_or(legacy_version);
                }
                _ => {}
            }
        }
    }

    Ok(ClientHelloInfo {
        tls_version,
        has_sni,
        cipher_suites,
        extensions,
        alpn,
        sig_algs,
    })
}

fn u16_list(b: &[u8]) -> Result<Vec<u16>, Ja4Error> {
    if !b.len().is_multiple_of(2) {
        return Err(Ja4Error::MalformedClientHello);
    }
    Ok(b.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, Ja4Error> {
    // ALPN ext: u16 list length, then [u8 proto_len + proto bytes]*.
    let mut r = Reader::new(data);
    let list_len = usize::from(r.u16()?);
    let mut inner = Reader::new(r.take(list_len)?);
    let mut out = Vec::new();
    while inner.remaining() >= 1 {
        let l = usize::from(inner.u8()?);
        out.push(inner.take(l)?.to_vec());
    }
    Ok(out)
}

fn highest_supported_version(data: &[u8]) -> Option<u16> {
    // supported_versions (ClientHello form): u8 list length, then [u16]*.
    let list_len = usize::from(*data.first()?);
    let list = data.get(1..1 + list_len)?;
    list.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .max()
}
