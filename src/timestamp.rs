//! RFC 3161 timestamping: hash the signature, ask the TSA to countersign it,
//! and return the TimeStampToken to embed as an unauthenticated attribute.

use crate::asn1;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// Validate the timestamp authority before sending a signature to it. A TSA
/// response must be authenticated by the TSA itself, but HTTP still lets a
/// network attacker tamper with or deny the response, so it needs an explicit
/// acknowledgement.
pub fn validate_url(url: &str, allow_insecure_http: bool) -> Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    let parsed = reqwest::Url::parse(url).context("invalid timestamp URL")?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_http => Ok(()),
        "http" => bail!(
            "refusing plaintext timestamp authority; pass --allow-insecure-timestamp to acknowledge the risk"
        ),
        scheme => bail!("timestamp URL must use HTTPS (or explicitly acknowledged HTTP), not {scheme}"),
    }
}

/// Request a timestamp over `signature` from the RFC3161 TSA at `url`; returns
/// the DER `TimeStampToken` (a PKCS#7 ContentInfo).
pub fn fetch(url: &str, signature: &[u8], allow_insecure_http: bool) -> Result<Vec<u8>> {
    validate_url(url, allow_insecure_http)?;
    let imprint: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(signature);
        h.finalize().into()
    };

    // TimeStampReq ::= SEQUENCE { version INTEGER(1),
    //   messageImprint SEQUENCE { hashAlgorithm AlgId, hashedMessage OCTET STRING },
    //   certReq BOOLEAN TRUE }
    let tsq = asn1::seq(&[
        &asn1::int_one(),
        &asn1::seq(&[
            &asn1::seq(&[&asn1::oid(OID_SHA256), &asn1::null()]),
            &asn1::octet_string(&imprint),
        ]),
        &asn1::bool_true(),
    ]);

    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building TSA client")?
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/timestamp-query")
        .body(tsq)
        .send()
        .context("timestamp request")?;
    if !resp.status().is_success() {
        bail!("timestamp HTTP {}", resp.status());
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/timestamp-reply")
    {
        bail!("timestamp response had unexpected content type {content_type:?}");
    }
    let tsr = resp.bytes().context("reading timestamp reply")?;

    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TST OPTIONAL }
    let top = asn1::children(&tsr).map_err(|e| anyhow::anyhow!("bad TSR: {e}"))?;
    let status_info = top.first().context("TSR has no status")?;
    let status = asn1::children(status_info)
        .ok()
        .and_then(|c| c.first().and_then(|s| s.get(2)).copied())
        .unwrap_or(255);
    if status != 0 && status != 1 {
        bail!("TSA rejected the request (status {status})");
    }
    let token = top.get(1).context("TSR has no timeStampToken")?;
    validate_timestamp_token(token)?;
    Ok(token.to_vec())
}

/// Ensure the token is structurally a CMS SignedData ContentInfo before it is
/// embedded. Certificate-chain and signature validation remains the verifier's
/// responsibility; this avoids writing arbitrary TSA response bytes into PE.
fn validate_timestamp_token(token: &[u8]) -> Result<()> {
    if token.first() != Some(&0x30) {
        bail!("timeStampToken is not a DER SEQUENCE");
    }
    let children =
        asn1::children(token).map_err(|err| anyhow::anyhow!("bad timeStampToken: {err}"))?;
    if children.len() != 2 || children[0] != asn1::oid(OID_PKCS7_SIGNED_DATA).as_slice() {
        bail!("timeStampToken is not CMS SignedData");
    }
    let wrapped = children[1];
    if wrapped.first() != Some(&0xa0) {
        bail!("CMS SignedData is missing its explicit wrapper");
    }
    let signed_data = asn1::children(wrapped)
        .map_err(|err| anyhow::anyhow!("bad CMS SignedData wrapper: {err}"))?;
    if signed_data.len() != 1 || signed_data[0].first() != Some(&0x30) {
        bail!("CMS SignedData wrapper did not contain SignedData");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_tsa_requires_explicit_opt_in() {
        assert!(validate_url("http://time.certum.pl/", false).is_err());
        assert!(validate_url("http://time.certum.pl/", true).is_ok());
        assert!(validate_url("https://example.test/tsa", false).is_ok());
        assert!(validate_url("ftp://example.test/tsa", true).is_err());
    }

    #[test]
    fn accepts_only_cms_signed_data_tokens() {
        let signed_data = asn1::seq(&[]);
        let token = asn1::seq(&[
            &asn1::oid(OID_PKCS7_SIGNED_DATA),
            &asn1::ctx(0, &signed_data),
        ]);
        assert!(validate_timestamp_token(&token).is_ok());
        assert!(validate_timestamp_token(&asn1::seq(&[])).is_err());
    }
}
