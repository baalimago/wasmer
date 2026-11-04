//! One HTTP request as data, for a guest that cannot terminate TLS: the host carries it with
//! its own HTTP client and hands back the response as it arrives (ext's `http-open`).
//!
//! Both directions are one encoding, little-endian `u32` counts and then the bytes: the method,
//! the URL, a header count and the pairs, then the body. The response adds a status before its
//! header count. (2026-11-04 research/http-host-call/PROMPT.md)

use std::sync::Arc;

use crate::ByteSource;

/// One request from a guest.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A response head and the body that follows it, which the host streams.
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Arc<dyn ByteSource>,
}

/// Why a guest's bytes are not a request. The kernel reports them as `-errno`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Not the encoding, or a method or URL that is empty.
    Malformed,
    /// A URL whose scheme is not `http` or `https`.
    Scheme,
}

/// Headers the host refuses to send: it sets `host` and `content-length` itself, and the rest
/// describe a connection an HTTP client of its own does not have.
const REFUSED: [&str; 5] = [
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "user-agent",
];

/// Decodes a request, dropping the headers the host sends itself.
pub fn decode(bytes: &[u8]) -> Result<HttpRequest, Bad> {
    let mut cursor = Cursor { bytes, at: 0 };
    let method = cursor.string()?;
    let url = cursor.string()?;
    if method.is_empty() || url.is_empty() {
        return Err(Bad::Malformed);
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(Bad::Scheme);
    }
    let count = cursor.u32()?;
    let mut headers = Vec::new();
    for _ in 0..count {
        let name = cursor.string()?;
        let value = cursor.string()?;
        if !REFUSED.iter().any(|refused| name.eq_ignore_ascii_case(refused)) {
            headers.push((name, value));
        }
    }
    Ok(HttpRequest {
        method,
        url,
        headers,
        body: bytes[cursor.at..].to_vec(),
    })
}

/// The response head a `read` returns before the body: the status, then the headers.
pub fn head(status: u16, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::from(status).to_le_bytes());
    out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for (name, value) in headers {
        push(&mut out, name);
        push(&mut out, value);
    }
    out
}

fn push(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Result<u32, Bad> {
        let word = self.take(4)?;
        Ok(u32::from_le_bytes(word.try_into().expect("four bytes")))
    }

    fn string(&mut self) -> Result<String, Bad> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Bad::Malformed)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Bad> {
        let end = self.at.checked_add(len).ok_or(Bad::Malformed)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Bad::Malformed)?;
        self.at = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push(&mut out, method);
        push(&mut out, url);
        out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        for (name, value) in headers {
            push(&mut out, name);
            push(&mut out, value);
        }
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_request_decodes_into_its_parts() {
        let bytes = request(
            "POST",
            "https://api.openai.com/v1/chat",
            &[("authorization", "Bearer k"), ("content-type", "application/json")],
            br#"{"model":"m"}"#,
        );

        assert_eq!(
            decode(&bytes).unwrap(),
            HttpRequest {
                method: "POST".into(),
                url: "https://api.openai.com/v1/chat".into(),
                headers: vec![
                    ("authorization".into(), "Bearer k".into()),
                    ("content-type".into(), "application/json".into()),
                ],
                body: br#"{"model":"m"}"#.to_vec(),
            }
        );
    }

    #[test]
    fn the_hosts_own_headers_are_dropped() {
        let bytes = request(
            "GET",
            "http://example.com/",
            &[("Host", "example.com"), ("User-Agent", "go"), ("accept", "*/*")],
            b"",
        );

        assert_eq!(
            decode(&bytes).unwrap().headers,
            vec![("accept".to_string(), "*/*".to_string())]
        );
    }

    #[test]
    fn a_broken_request_says_which_way_it_broke() {
        assert_eq!(decode(&[]), Err(Bad::Malformed));
        assert_eq!(decode(&[2, 0, 0, 0, b'G']), Err(Bad::Malformed));
        assert_eq!(
            decode(&request("GET", "ftp://example.com/", &[], b"")),
            Err(Bad::Scheme)
        );
        assert_eq!(
            decode(&request("", "http://example.com/", &[], b"")),
            Err(Bad::Malformed)
        );
        assert_eq!(
            decode(&request("GET", "http://example.com/", &[], b"")[..6]),
            Err(Bad::Malformed)
        );
    }

    #[test]
    fn a_response_head_is_its_status_then_its_headers() {
        let head = head(404, &[("content-type".into(), "text/plain".into())]);

        assert_eq!(
            head,
            [
                148, 1, 0, 0, // 404
                1, 0, 0, 0, // one header
                12, 0, 0, 0, b'c', b'o', b'n', b't', b'e', b'n', b't', b'-', b't', b'y', b'p', b'e',
                10, 0, 0, 0, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n',
            ]
        );
    }
}