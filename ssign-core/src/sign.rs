//! Step 3a — the remote signature (SCS1_ATOM async protocol).
//!
//!   POST /card/v1/cards/{serial}/certificates/signature
//!        multipart: req = {"digests":[<sha256 hex>],"digesttype":"SHA256"}
//!                   certificate = <DER blob>
//!     -> 202, then poll -> 200 [{"<digest hex>":"<hex RSA-4096 signature>"}]

use crate::card::Card;
use crate::client::{run_task, API_BASE};
use anyhow::{Context, Result};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;

/// Ask the cloud HSM to sign one SHA-256 digest; returns the raw RSA signature.
pub fn request(client: &Client, token: &str, card: &Card, sha256: &[u8; 32]) -> Result<Vec<u8>> {
    let digest_hex = hex::encode(sha256);
    let req_json = format!(r#"{{"digests":["{digest_hex}"],"digesttype":"SHA256"}}"#);

    let form = Form::new()
        .part(
            "req",
            Part::text(req_json)
                .mime_str("application/json")
                .context("req part mime")?,
        )
        .part(
            "certificate",
            // Send the certificate exactly as issued (PEM); the endpoint rejects
            // a DER re-encoding.
            Part::bytes(card.certificate_pem.clone())
                .file_name("blob")
                .mime_str("application/octet-stream")
                .context("certificate part mime")?,
        );

    let resp = run_task(
        client,
        token,
        client
            .post(format!(
                "{API_BASE}/card/v1/cards/{}/certificates/signature",
                card.serial
            ))
            .bearer_auth(token)
            .multipart(form),
    )
    .context("signature task")?
    .1;

    parse_signature_response(&resp, &digest_hex)
}

fn parse_signature_response(resp: &[u8], digest_hex: &str) -> Result<Vec<u8>> {
    let arr: serde_json::Value =
        serde_json::from_slice(resp).context("signature result was not JSON")?;
    // Result shape: [ { "<digest hex>": "<signature hex>" } ]
    let sig_hex = arr
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .and_then(|m| {
            m.iter()
                .find(|(digest, _)| digest.eq_ignore_ascii_case(digest_hex))
                .map(|(_, signature)| signature)
        })
        .and_then(|v| v.as_str())
        .with_context(|| {
            let snip: String = String::from_utf8_lossy(resp).chars().take(300).collect();
            format!("no signature for requested digest {digest_hex}; got: {snip}")
        })?;
    hex::decode(sig_hex).context("signature was not valid hex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_signature_for_the_requested_digest() {
        let response = br#"[{"other":"aa","wanted":"bb"}]"#;
        assert_eq!(
            parse_signature_response(response, "wanted").unwrap(),
            vec![0xbb]
        );
    }

    #[test]
    fn selects_a_realistic_digest_regardless_of_hex_case() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let response =
            br#"[{"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF":"bb"}]"#;
        assert_eq!(
            parse_signature_response(response, digest).unwrap(),
            vec![0xbb]
        );
    }

    #[test]
    fn rejects_a_response_without_the_requested_digest() {
        let response = br#"[{"other":"aa"}]"#;
        assert!(parse_signature_response(response, "wanted").is_err());
    }
}
