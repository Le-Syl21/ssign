//! Shared HTTP client and the SCS async-task helper.
//!
//! Certum's card/key/certificate/signature endpoints are all asynchronous:
//!   POST …/tasks            -> 202 {"atom:link": <poll url>, "ping-after": ms}
//!   GET  <poll url>         -> 303 {"atom:link": <result url>}  (when ready)
//!   GET  <result url>       -> 200 <the payload>
//! `run_task` drives that loop, following `atom:link` until the 200 result.

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::Url;
use std::time::Duration;

pub const API_BASE: &str = "https://cloudsign.webnotarius.pl";

pub fn is_certum_origin(url: &Url) -> bool {
    let certum = Url::parse(API_BASE).expect("API_BASE is a URL");
    url.origin() == certum.origin() && url.username().is_empty() && url.password().is_none()
}

/// A bearer-authenticated client with automatic redirects disabled (we follow
/// `atom:link` ourselves, so a 303 must not be swallowed).
pub fn client() -> Result<Client> {
    // The SCS endpoints reject requests without an Accept header (400), and the
    // certificate result is multipart while the rest is JSON — so accept both.
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        // Prefer multipart: the certificate/key results are multipart and the
        // JSON variant of those resources carries a broken self-link.
        reqwest::header::HeaderValue::from_static("multipart/form-data, application/json"),
    );
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .user_agent("ssign")
        .default_headers(headers)
        .build()
        .context("building API client")
}

/// Resolve an `atom:link` that may be absolute or root-relative.
fn abs(link: &str) -> Result<Url> {
    let url = Url::parse(API_BASE)
        .and_then(|base| base.join(link))
        .context("task link is not a URL")?;
    if !is_certum_origin(&url) {
        bail!("task link points outside {API_BASE}; refusing to send the token there");
    }
    Ok(url)
}

/// Send `initial` (a POST already carrying auth + body), then follow `atom:link`
/// until a response no longer carries one — that final response IS the result.
/// Returns its content-type and raw body.
///
/// The task states surface as 202 (created), 303 (ready → redirect) and even a
/// 200 that is still just a status object with an `atom:link`; only a body
/// without `atom:link` (the array/multipart result) ends the loop.
pub fn run_task(
    client: &Client,
    token: &str,
    initial: RequestBuilder,
) -> Result<(String, Vec<u8>)> {
    let mut resp = initial.send().context("task request")?;
    for _ in 0..120 {
        let status = resp.status().as_u16();
        let url = resp.url().clone();
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.bytes().context("reading task response")?.to_vec();

        if status >= 400 {
            bail!(
                "task failed (HTTP {status}) at {url}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        // A result resource is JSON without an `atom:link` (array/object) or a
        // multipart body; a task still in progress is JSON *with* an `atom:link`
        // to follow. A "failed" state means the cloud rejected the operation.
        if !ct.contains("multipart") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                if v.get("state").and_then(|s| s.as_str()) == Some("failed") {
                    bail!("cloud task failed: {}", String::from_utf8_lossy(&body));
                }
                if let Some(link) = v.get("atom:link").and_then(|x| x.as_str()) {
                    let ping = v.get("ping-after").and_then(|x| x.as_u64()).unwrap_or(0);
                    std::thread::sleep(Duration::from_millis(ping.clamp(200, 2000)));
                    resp = client
                        .get(abs(link)?)
                        .bearer_auth(token)
                        .send()
                        .context("task poll")?;
                    continue;
                }
            }
        }
        return Ok((ct, body));
    }
    bail!("task did not complete after 120 polls")
}

/// Extract the raw bytes of a named part from a `multipart/form-data` body.
pub fn multipart_part(body: &[u8], name: &str) -> Result<Vec<u8>> {
    // The opening delimiter is the body's first line (handles boundaries that
    // themselves begin with '--').
    let first_line_end = body
        .windows(2)
        .position(|w| w == b"\r\n")
        .context("multipart body has no CRLF")?;
    let delim = &body[..first_line_end];
    if !delim.starts_with(b"--") {
        bail!("multipart body does not start with a boundary");
    }
    let needle = format!("name=\"{name}\"");
    for chunk in split_on(body, delim) {
        let chunk = trim_crlf(chunk);
        if chunk.is_empty() || chunk == b"--" {
            continue;
        }
        let Some(sep) = find(chunk, b"\r\n\r\n") else {
            continue;
        };
        let headers = &chunk[..sep];
        let value = &chunk[sep + 4..];
        if find(headers, needle.as_bytes()).is_some() {
            return Ok(trim_crlf(value).to_vec());
        }
    }
    bail!("multipart part `{name}` not found")
}

fn split_on<'a>(hay: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + sep.len() <= hay.len() {
        if &hay[i..i + sep.len()] == sep {
            out.push(&hay[start..i]);
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&hay[start..]);
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn trim_crlf(b: &[u8]) -> &[u8] {
    let mut s = b;
    while s.first() == Some(&b'\r') || s.first() == Some(&b'\n') {
        s = &s[1..];
    }
    while s.last() == Some(&b'\r') || s.last() == Some(&b'\n') {
        s = &s[..s.len() - 1];
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_certum_task_links() {
        let task = "/scs1/card/v1/cards/123/certificates/signature/task/abc";
        for link in [
            task.to_string(),
            task.trim_start_matches('/').to_string(),
            format!("{API_BASE}{task}"),
            format!("https://CLOUDSIGN.webnotarius.pl:443{task}"),
        ] {
            let url = abs(&link).unwrap();
            assert_eq!(url.as_str(), format!("{API_BASE}{task}"), "{link}");
        }
    }

    #[test]
    fn refuses_task_links_outside_certum() {
        for link in [
            "https://evil.example/poll",
            "http://cloudsign.webnotarius.pl/poll",
            "//evil.example/poll",
            "https:\\\\evil.example/poll",
            "https://cloudsign.webnotarius.pl.evil.com/poll",
            "https://evil.com/cloudsign.webnotarius.pl/poll",
            "https://x@evil.example/poll",
            "https://cloudsign.webnotarius.pl@evil.example/poll",
            "https://user:pw@cloudsign.webnotarius.pl/poll",
            "https://cloudsign.webnotarius.pl:8443/poll",
            "https://cloudsign.webnotarius.pl./poll",
            "https://cloudsign.webnotarius.pl%2Eevil.com/poll",
            "https://cloudsign%2Ewebnotarius%2Epl%2Eevil%2Ecom/poll",
            "https://xn--cloudsign-webnotarius-pl.example/poll",
            "ftp://cloudsign.webnotarius.pl/poll",
        ] {
            assert!(abs(link).is_err(), "{link} was accepted");
        }
    }

    #[test]
    fn extracts_named_part() {
        let body = b"----BND\r\nContent-Disposition: form-data; name=\"certificate\"; filename=\"x.cer\"\r\nContent-Type: application/octet-stream\r\n\r\n\x01\x02\x03DER\r\n----BND\r\nContent-Disposition: form-data; name=\"res\"\r\nContent-Type: application/json\r\n\r\n[{}]\r\n----BND--\r\n";
        let cert = multipart_part(body, "certificate").unwrap();
        assert_eq!(cert, b"\x01\x02\x03DER");
        let res = multipart_part(body, "res").unwrap();
        assert_eq!(res, b"[{}]");
    }
}
