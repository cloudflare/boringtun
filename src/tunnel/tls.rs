//! TLS ClientHello inspection helpers for tunnel traffic.
//!
//! These helpers inspect the first bytes of a TLS handshake without consuming
//! the stream, extracting lightweight fingerprint fields used for heuristics
//! and audit output. They do not terminate TLS or modify the connection.

use std::fmt::Write;

/// Hold parsed TLS fingerprint details for a prospective tunnel.
#[derive(Clone, Default)]
pub(crate) struct TlsInfo {
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Option<String>,
    pub(crate) tls_ver: Option<String>,
    pub(crate) cipher_suites_count: Option<u8>,
    pub(crate) ja3_lite: Option<String>,
}

/// Peek at the first bytes of a TCP stream and parse TLS metadata.
pub(crate) async fn peek_tls_info(stream: &mut tokio::net::TcpStream) -> TlsInfo {
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_millis(500),
        stream.peek(&mut buf),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(0);
    parse_tls_info(&buf[..n])
}

/// Parse ClientHello metadata from a TLS record without panicking.
pub(crate) fn parse_tls_info(buf: &[u8]) -> TlsInfo {
    let mut info = TlsInfo::default();
    if buf.len() < 5 || buf[0] != 22 {
        return info;
    }
    info.tls_ver = match (buf[1], buf[2]) {
        (3, 3) => Some("TLS1.2".into()),
        (3, 1) => Some("TLS1.0".into()),
        _ => None,
    };
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hs = match buf.get(5..5 + record_len.min(buf.len().saturating_sub(5))) {
        Some(s) => s,
        None => return info,
    };
    if hs.first() != Some(&1) || hs.len() < 6 {
        return info;
    }
    let mut pos = 4 + 2 + 32;
    let sid_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return info,
    };
    pos += 1 + sid_len;
    let cs_len = match hs.get(pos..pos + 2) {
        Some(s) => u16::from_be_bytes([s[0], s[1]]) as usize,
        None => return info,
    };
    info.cipher_suites_count = Some((cs_len / 2).min(255) as u8);
    let cs_start = pos + 2;
    let cs_end = cs_start + cs_len;
    pos += 2 + cs_len;
    let cm_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return info,
    };
    pos += 1 + cm_len;
    if pos + 2 > hs.len() {
        return info;
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hs.len());

    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut point_fmts: Vec<u8> = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        let ext_data = match hs.get(pos..pos + ext_len) {
            Some(s) => s,
            None => break,
        };
        if ext_type & 0x0f0f != 0x0a0a {
            ext_types.push(ext_type);
        }
        match ext_type {
            0 if ext_len >= 5 => {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if ext_data.len() >= 5 + name_len {
                    info.sni = String::from_utf8(ext_data[5..5 + name_len].to_vec()).ok();
                }
            }
            16 if ext_len >= 4 => {
                let proto_len = ext_data[2] as usize;
                if ext_data.len() >= 3 + proto_len {
                    info.alpn = String::from_utf8(ext_data[3..3 + proto_len].to_vec()).ok();
                }
            }
            43 if ext_len >= 3 => {
                let list_len = ext_data[0] as usize;
                let mut i = 1;
                while i + 2 <= (1 + list_len).min(ext_data.len()) {
                    if ext_data[i] == 0x03 && ext_data[i + 1] == 0x04 {
                        info.tls_ver = Some("TLS1.3".into());
                        break;
                    }
                    i += 2;
                }
            }
            10 if ext_len >= 4 => {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut i = 2;
                while i + 2 <= (2 + list_len).min(ext_data.len()) {
                    let g = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                    if g & 0x0f0f != 0x0a0a {
                        curves.push(g);
                    }
                    i += 2;
                }
            }
            11 if ext_len >= 2 => {
                let list_len = ext_data[0] as usize;
                for &b in ext_data.get(1..1 + list_len).unwrap_or(&[]) {
                    point_fmts.push(b);
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    let tls_ver_num: u16 = match info.tls_ver.as_deref() {
        Some("TLS1.3") => 772,
        Some("TLS1.2") => 771,
        Some("TLS1.0") => 769,
        _ => 0,
    };
    let cs_nums: Vec<u16> = hs
        .get(cs_start..cs_end)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| v & 0x0f0f != 0x0a0a)
        .collect();

    let mut ja3 = String::with_capacity(128);
    append_joined_u16(&mut ja3, &[tls_ver_num]);
    ja3.push(',');
    append_joined_u16(&mut ja3, &cs_nums);
    ja3.push(',');
    append_joined_u16(&mut ja3, &ext_types);
    ja3.push(',');
    append_joined_u16(&mut ja3, &curves);
    ja3.push(',');
    append_joined_u8(&mut ja3, &point_fmts);
    info.ja3_lite = Some(ja3);
    info
}

fn append_joined_u16(out: &mut String, values: &[u16]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push('-');
        }
        let _ = write!(out, "{value}");
    }
}

fn append_joined_u8(out: &mut String, values: &[u8]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push('-');
        }
        let _ = write!(out, "{value}");
    }
}

#[cfg(test)]
mod tests {
    use super::parse_tls_info;

    #[test]
    fn parses_crafted_client_hello() {
        let client_hello: &[u8] = &[
            0x16, // ContentType: Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x5e, // Record length
            0x01, // HandshakeType: ClientHello
            0x00, 0x00, 0x5a, // Handshake length
            0x03, 0x03, // Client version TLS 1.2
            // Random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length
            0x00, 0x04, // Cipher suites length (2 suites)
            0x13, 0x01, // TLS_AES_256_GCM_SHA384
            0x13, 0x02, // TLS_CHACHA20_POLY1305_SHA256
            0x01, // Compression methods length
            0x00, // NULL compression
            0x00, 0x1f, // Extensions length
            // SNI extension
            0x00, 0x00, // Extension type: SNI
            0x00, 0x10, // Extension length
            0x00, 0x0e, // Server name list length
            0x00, // Name type: host_name
            0x00, 0x0b, // Name length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            // ALPN extension
            0x00, 0x10, // Extension type: ALPN
            0x00, 0x05, // Extension length
            0x00, 0x03, // Protocol list length
            0x02, // Protocol length
            b'h', b'2',
        ];

        let info = parse_tls_info(client_hello);

        assert_eq!(info.sni, Some("example.com".to_string()));
        assert_eq!(info.alpn, Some("h2".to_string()));
        assert_eq!(info.tls_ver, Some("TLS1.2".to_string()));
        assert_eq!(info.cipher_suites_count, Some(2));
        assert!(info.ja3_lite.is_some());
    }

    #[test]
    fn handles_invalid_input() {
        let info = parse_tls_info(&[]);
        assert_eq!(info.sni, None);
        assert_eq!(info.alpn, None);
        assert_eq!(info.tls_ver, None);

        let info = parse_tls_info(&[0x17, 0x03, 0x03, 0x00, 0x00]);
        assert_eq!(info.tls_ver, None);
    }
}
