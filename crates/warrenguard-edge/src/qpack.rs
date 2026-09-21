//! QPACK (RFC 9204) request-side field-section decoding, static table only.
//!
//! The edge advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so a
//! conformant peer never uses the dynamic table: every field line a browser
//! sends is decodable from the static table plus literals. That lets this
//! decoder stay stateless. Dynamic-table (post-base) representations are
//! rejected rather than half-supported.
//!
//! Huffman-coded literals (RFC 7541 Appendix B) are decoded via
//! [`crate::huffman`], since real browsers Huffman-code their header names and
//! values; a literal that fails to Huffman-decode is
//! [`EdgeError::InvalidHuffman`].
//!
//! The encoder ([`encode_field_section`]) is the mirror image for the responses
//! the edge writes: static-only, never Huffman, so a peer that disabled its own
//! dynamic table (every peer, given our SETTINGS) decodes it with no state.

use crate::EdgeError;

/// One decoded header field: name and value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// The subset of the RFC 9204 Appendix A static table the edge classifier needs
/// (request pseudo-headers and `authorization`), as `(index, name, value)`.
/// A name-reference to any index here resolves the name; an indexed field line
/// resolves the whole pair. Indices outside this subset are rejected: the edge
/// only ever needs to understand a WebTransport CONNECT, and anything exotic is
/// treated as "not a WebTransport request" upstream.
const STATIC_TABLE: &[(u64, &[u8], &[u8])] = &[
    (0, b":authority", b""),
    (1, b":path", b"/"),
    (15, b":method", b"CONNECT"),
    (16, b":method", b"DELETE"),
    (17, b":method", b"GET"),
    (18, b":method", b"HEAD"),
    (19, b":method", b"OPTIONS"),
    (20, b":method", b"POST"),
    (21, b":method", b"PUT"),
    (22, b":scheme", b"http"),
    (23, b":scheme", b"https"),
    // Response status lines, used by the encoder: a status in this list is one
    // indexed byte, any other status is a literal against the `:status` name.
    (24, b":status", b"103"),
    (25, b":status", b"200"),
    (26, b":status", b"304"),
    (27, b":status", b"404"),
    (28, b":status", b"503"),
    (52, b"content-type", b"text/html; charset=utf-8"),
    (63, b":status", b"100"),
    (64, b":status", b"204"),
    (65, b":status", b"206"),
    (66, b":status", b"302"),
    (67, b":status", b"400"),
    (68, b":status", b"403"),
    (69, b":status", b"421"),
    (70, b":status", b"425"),
    (71, b":status", b"500"),
    // `authorization` (name only; value is always a literal in practice).
    (84, b"authorization", b""),
];

fn static_entry(index: u64) -> Option<(&'static [u8], &'static [u8])> {
    STATIC_TABLE
        .iter()
        .find(|(i, _, _)| *i == index)
        .map(|(_, n, v)| (*n, *v))
}

/// Decodes a QPACK prefixed integer (RFC 7541 section 5.1) whose first byte's
/// low `prefix_bits` are the integer prefix. Returns the value and bytes
/// consumed, or `None` on truncation.
fn read_prefixed_int(input: &[u8], prefix_bits: u32) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let mask = (1u16 << prefix_bits) as u64 - 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut used = 1;
    let mut shift = 0u32;
    loop {
        let byte = *input.get(used)?;
        used += 1;
        value = value.checked_add(u64::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 62 {
            return None; // absurdly long integer; refuse
        }
    }
    Some((value, used))
}

/// Reads a QPACK string literal: a Huffman bit + prefixed length + bytes. The
/// Huffman bit occupies the bit just above `len_prefix_bits` in the first byte.
fn read_string(input: &[u8], len_prefix_bits: u32) -> Result<(Vec<u8>, usize), EdgeError> {
    let first = *input.first().ok_or(EdgeError::MalformedFieldSection)?;
    let huffman = first & (1 << len_prefix_bits) != 0;
    let (len, n) =
        read_prefixed_int(input, len_prefix_bits).ok_or(EdgeError::MalformedFieldSection)?;
    let start = n;
    let end = start
        .checked_add(len as usize)
        .ok_or(EdgeError::MalformedFieldSection)?;
    let bytes = input
        .get(start..end)
        .ok_or(EdgeError::MalformedFieldSection)?;
    let decoded = if huffman {
        crate::huffman::decode(bytes)?
    } else {
        bytes.to_vec()
    };
    Ok((decoded, end))
}

/// Decodes a full encoded field section (prefix + field lines) into its header
/// fields. Rejects dynamic-table references and post-base representations.
pub fn decode_field_section(input: &[u8]) -> Result<Vec<Field>, EdgeError> {
    // Encoded Field Section Prefix: Required Insert Count (8-bit prefix) then
    // Sign + Delta Base (7-bit prefix). We require RIC == 0 (static only).
    let (ric, n1) = read_prefixed_int(input, 8).ok_or(EdgeError::MalformedFieldSection)?;
    if ric != 0 {
        return Err(EdgeError::MalformedFieldSection);
    }
    let (_base, n2) = read_prefixed_int(&input[n1..], 7).ok_or(EdgeError::MalformedFieldSection)?;
    let mut rest = &input[n1 + n2..];
    let mut fields = Vec::new();

    while let Some(&first) = rest.first() {
        if first & 0x80 != 0 {
            // Indexed Field Line: 1 T index(6+). T (bit 6) selects the table.
            let static_table = first & 0x40 != 0;
            if !static_table {
                return Err(EdgeError::MalformedFieldSection); // dynamic table
            }
            let (index, used) =
                read_prefixed_int(rest, 6).ok_or(EdgeError::MalformedFieldSection)?;
            // A fully-indexed static line carries no extra bytes, so an index
            // outside the classifier's subset is skippable: emit an empty-named
            // placeholder the header lookup will never match, rather than
            // failing the whole section. A real browser sends static-indexed
            // headers (e.g. `origin`) the edge does not care about; those must
            // not abort parsing of the pseudo-headers it does need.
            let (name, value) = static_entry(index).unwrap_or((b"", b""));
            fields.push(Field {
                name: name.to_vec(),
                value: value.to_vec(),
            });
            rest = &rest[used..];
        } else if first & 0x40 != 0 {
            // Literal Field Line With Name Reference: 01 N T index(4+).
            let static_table = first & 0x10 != 0;
            if !static_table {
                return Err(EdgeError::MalformedFieldSection); // dynamic name ref
            }
            let (index, used) =
                read_prefixed_int(rest, 4).ok_or(EdgeError::MalformedFieldSection)?;
            // The value string is length-delimited, so it can be read past even
            // when the referenced static name is outside the classifier's
            // subset; use an empty placeholder name in that case (see the
            // indexed-line note above).
            let name = static_entry(index).map(|(n, _)| n).unwrap_or(b"");
            let (value, vused) = read_string(&rest[used..], 7)?;
            fields.push(Field {
                name: name.to_vec(),
                value,
            });
            rest = &rest[used + vused..];
        } else if first & 0x20 != 0 {
            // Literal Field Line With Literal Name: 001 N H namelen(3+).
            let (name, nused) = read_string(rest, 3)?;
            let (value, vused) = read_string(&rest[nused..], 7)?;
            fields.push(Field { name, value });
            rest = &rest[nused + vused..];
        } else {
            // 0001 xxxx (indexed post-base) or 0000 xxxx (literal post-base):
            // both are dynamic-table representations we do not support.
            return Err(EdgeError::MalformedFieldSection);
        }
    }
    Ok(fields)
}

/// Appends a QPACK prefixed integer (RFC 7541 section 5.1): `flags` carries the
/// representation bits above the `prefix_bits`-wide prefix of the first byte.
fn write_prefixed_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u32, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Appends a raw (non-Huffman) string literal with a 7-bit length prefix.
fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_prefixed_int(out, 0x00, 7, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Encodes `fields` as a static-only QPACK field section: the two-byte prefix
/// (RIC=0, Base=0), then one field line per entry. A `(name, value)` pair that
/// is in the static table is an indexed line; a name that is in it is a literal
/// with a name reference; anything else is a literal with a literal name.
/// Strings are never Huffman-coded, so the output needs no decoder table and no
/// dynamic state on the peer.
#[must_use]
pub fn encode_field_section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for &(name, value) in fields {
        if let Some((index, _, _)) = STATIC_TABLE
            .iter()
            .find(|(_, n, v)| *n == name && *v == value)
        {
            // Indexed field line: 1 T=1 index(6+).
            write_prefixed_int(&mut out, 0xc0, 6, *index);
        } else if let Some((index, _, _)) = STATIC_TABLE.iter().find(|(_, n, _)| *n == name) {
            // Literal with name reference: 01 N=0 T=1 index(4+), then the value.
            write_prefixed_int(&mut out, 0x50, 4, *index);
            write_string(&mut out, value);
        } else {
            // Literal with literal name: 001 N=0 H=0 namelen(3+), name, value.
            write_prefixed_int(&mut out, 0x20, 3, name.len() as u64);
            out.extend_from_slice(name);
            write_string(&mut out, value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the two-byte static-only prefix (RIC=0, Base=0).
    fn prefix() -> Vec<u8> {
        vec![0x00, 0x00]
    }

    fn literal_string(bytes: &[u8], prefix_bits: u32) -> Vec<u8> {
        // Huffman bit 0, length in the prefix, then raw bytes.
        let mut out = vec![bytes.len() as u8]; // fits since our test strings are short
        // For a plain length under the prefix max, one byte suffices; ensure the
        // Huffman bit (just above the prefix) is 0 (it is, len is small).
        let _ = prefix_bits;
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn decodes_an_indexed_static_field() {
        // Indexed static ` :method GET` is index 17: 0x80 | 0x40 | 17 = 0xd1.
        let mut buf = prefix();
        buf.push(0xc0 | 17);
        let fields = decode_field_section(&buf).expect("decodes");
        assert_eq!(
            fields,
            vec![Field {
                name: b":method".to_vec(),
                value: b"GET".to_vec()
            }]
        );
    }

    #[test]
    fn decodes_a_literal_with_static_name_reference() {
        // `:authority example.com` via name ref to index 0: 01 N=0 T=1 index=0
        // => 0x50, then a literal value string.
        let mut buf = prefix();
        buf.push(0x50);
        buf.extend_from_slice(&literal_string(b"example.com", 7));
        let fields = decode_field_section(&buf).expect("decodes");
        assert_eq!(
            fields,
            vec![Field {
                name: b":authority".to_vec(),
                value: b"example.com".to_vec()
            }]
        );
    }

    #[test]
    fn decodes_a_literal_with_literal_name() {
        // `:protocol webtransport`: 001 N=0 H=0 namelen(3+). Name len 9 exceeds
        // the 3-bit prefix (max 7), so it continues: 0x20 | 0x07 then (9-7)=2.
        let mut buf = prefix();
        buf.push(0x20 | 0x07);
        buf.push(0x02); // 7 + 2 = 9
        buf.extend_from_slice(b":protocol");
        buf.extend_from_slice(&literal_string(b"webtransport", 7));
        let fields = decode_field_section(&buf).expect("decodes");
        assert_eq!(
            fields,
            vec![Field {
                name: b":protocol".to_vec(),
                value: b"webtransport".to_vec()
            }]
        );
    }

    #[test]
    fn skips_unknown_static_indices_instead_of_failing() {
        // A browser sends static-indexed headers the edge does not model (e.g.
        // `origin`, index 90). Such a line must be skipped, not abort the parse:
        // here `:method GET` (index 17, known) precedes an indexed line to an
        // out-of-subset index, and both parse.
        let mut buf = prefix();
        buf.push(0xc0 | 17); // known: :method GET
        buf.push(0xc0 | 60); // unknown static index (outside the subset)
        let fields = decode_field_section(&buf).expect("decodes past the unknown index");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, b":method");
        assert_eq!(
            fields[1].name, b"",
            "the unknown index yields a placeholder"
        );
    }

    #[test]
    fn skips_an_unknown_name_reference_but_reads_its_value() {
        // Literal with name reference to an out-of-subset index: the value is
        // still read (length-delimited), the name is a placeholder.
        let mut buf = prefix();
        buf.push(0x50 | 0x0e); // name ref, static, index 14 (outside the subset)
        buf.extend_from_slice(&literal_string(b"whatever", 7));
        let fields = decode_field_section(&buf).expect("decodes");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, b"");
        assert_eq!(fields[0].value, b"whatever");
    }

    #[test]
    fn rejects_a_dynamic_table_indexed_line() {
        // Indexed field line with T=0 (dynamic table): 0x80 | index.
        let mut buf = prefix();
        buf.push(0x80 | 0x01);
        assert_eq!(
            decode_field_section(&buf),
            Err(EdgeError::MalformedFieldSection)
        );
    }

    #[test]
    fn decodes_a_huffman_coded_literal_name_and_value() {
        // RFC 7541 C.6.2: "custom-key" -> 25a849e95ba97d7f (8 bytes Huffman),
        // "custom-value" -> 25a849e95bb8e8b4bf (9 bytes). Literal-with-literal-
        // name, Huffman bit set on both strings.
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let name_h = hex("25a849e95ba97d7f"); // len 8
        let value_h = hex("25a849e95bb8e8b4bf"); // len 9
        let mut buf = prefix();
        // 001 N=0 H=1 namelen(3+): 8 exceeds the 3-bit max (7), continue by 1.
        buf.push(0x20 | 0x08 | 0x07);
        buf.push(0x01); // 7 + 1 = 8
        buf.extend_from_slice(&name_h);
        // value string: H=1 (bit 7), len 9 fits the 7-bit prefix: 0x80 | 9.
        buf.push(0x80 | 0x09);
        buf.extend_from_slice(&value_h);
        let fields = decode_field_section(&buf).expect("decodes");
        assert_eq!(
            fields,
            vec![Field {
                name: b"custom-key".to_vec(),
                value: b"custom-value".to_vec()
            }]
        );
    }

    #[test]
    fn rejects_an_invalid_huffman_literal() {
        // Huffman bit set but the bytes are not a valid code + padding.
        let mut buf = prefix();
        buf.push(0x20 | 0x08 | 0x03);
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // zero bits: bad padding
        assert_eq!(decode_field_section(&buf), Err(EdgeError::InvalidHuffman));
    }

    #[test]
    fn rejects_a_nonzero_required_insert_count() {
        // RIC != 0 means the encoder used the dynamic table.
        let buf = vec![0x05, 0x00];
        assert_eq!(
            decode_field_section(&buf),
            Err(EdgeError::MalformedFieldSection)
        );
    }

    #[test]
    fn prefixed_int_decodes_multi_byte_values() {
        // 7-bit prefix value 1337: prefix all-ones (127) then continuation.
        // 1337 - 127 = 1210 = 0x4BA -> 0xBA(with cont) , 0x09
        let (v, used) = read_prefixed_int(&[0x7f, 0xba, 0x09], 7).expect("int");
        assert_eq!((v, used), (1337, 3));
    }
    /// Coerces array literals to the slice pair the encoder takes.
    fn field<'a>(name: &'a [u8], value: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        (name, value)
    }

    #[test]
    fn encodes_a_static_pair_as_one_indexed_line() {
        // `:status 200` is static index 25: 0xc0 | 25 = 0xd9, after the prefix.
        assert_eq!(
            encode_field_section(&[field(b":status", b"200")]),
            vec![0x00, 0x00, 0xd9]
        );
    }

    #[test]
    fn encodes_a_static_index_past_the_six_bit_prefix() {
        // `:status 403` is index 68: prefix all-ones (63) then 68 - 63 = 5.
        assert_eq!(
            encode_field_section(&[field(b":status", b"403")]),
            vec![0x00, 0x00, 0xff, 0x05]
        );
    }

    #[test]
    fn encodes_an_unlisted_value_as_a_literal_with_a_name_reference() {
        // `:status 407` is not in the table, `:status` is (index 24): 01 N=0 T=1
        // index=24 needs the 4-bit continuation (15, then 9), then the value.
        let encoded = encode_field_section(&[field(b":status", b"407")]);
        assert_eq!(&encoded[..2], &[0x00, 0x00]);
        assert_eq!(&encoded[2..4], &[0x5f, 0x09]);
        assert_eq!(&encoded[4..], &[0x03, b'4', b'0', b'7']);
    }

    #[test]
    fn encodes_an_unlisted_name_as_a_literal_name_and_round_trips() {
        // The field lines the MASQUE ingress writes decode through our own
        // request-side decoder, which pins the representation bits.
        let encoded = encode_field_section(&[
            field(b":status", b"200"),
            field(b"capsule-protocol", b"?1"),
            field(b"proxy-authenticate", b"Basic realm=\"proxy\""),
        ]);
        let fields = decode_field_section(&encoded).expect("our own encoding decodes");
        assert_eq!(fields[0].name, b":status");
        assert_eq!(fields[0].value, b"200");
        assert_eq!(fields[1].name, b"capsule-protocol");
        assert_eq!(fields[1].value, b"?1");
        assert_eq!(fields[2].name, b"proxy-authenticate");
        assert_eq!(fields[2].value, b"Basic realm=\"proxy\"");
    }

    #[test]
    fn encodes_a_long_literal_with_the_seven_bit_continuation() {
        // A 200-byte value overflows the 7-bit length prefix: 127, then 73.
        let value = vec![b'x'; 200];
        let encoded = encode_field_section(&[field(b"x-long", &value)]);
        let fields = decode_field_section(&encoded).expect("decodes");
        assert_eq!(fields[0].value, value);
        // 0x20 | 6 (name len), name, then 0x7f 0x49 (200 - 127 = 73).
        assert_eq!(&encoded[2..3], &[0x26]);
        assert_eq!(&encoded[9..11], &[0x7f, 0x49]);
    }
}
