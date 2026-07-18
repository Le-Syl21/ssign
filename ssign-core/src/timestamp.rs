//! RFC 3161 timestamping: hash the signature, ask the TSA to countersign it,
//! and return the TimeStampToken to embed as an unauthenticated attribute.

use crate::asn1;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// Request a timestamp over `signature` from the RFC3161 TSA at `url`; returns
/// the DER `TimeStampToken` (a PKCS#7 ContentInfo).
pub fn fetch(url: &str, signature: &[u8]) -> Result<Vec<u8>> {
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

fn validate_timestamp_token(token: &[u8]) -> Result<()> {
    if token.first() != Some(&0x30) {
        bail!("timeStampToken is not a DER SEQUENCE");
    }
    let children = asn1::children(token).map_err(|e| anyhow::anyhow!("bad timeStampToken: {e}"))?;
    if children.len() != 2 || children[0] != asn1::oid(OID_PKCS7_SIGNED_DATA).as_slice() {
        bail!("timeStampToken is not CMS SignedData");
    }
    let wrapped = children[1];
    if wrapped.first() != Some(&0xa0) {
        bail!("CMS SignedData is missing its explicit wrapper");
    }
    let signed_data = asn1::children(wrapped)
        .map_err(|e| anyhow::anyhow!("bad CMS SignedData wrapper: {e}"))?;
    if signed_data.len() != 1 || signed_data[0].first() != Some(&0x30) {
        bail!("CMS SignedData wrapper did not contain SignedData");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_cms_signed_data_tokens() {
        let signed_data = asn1::seq(&[]);
        let token = asn1::seq(&[
            &asn1::oid("1.2.840.113549.1.7.2"),
            &asn1::ctx(0, &signed_data),
        ]);
        assert!(validate_timestamp_token(&token).is_ok());
        assert!(validate_timestamp_token(&asn1::seq(&[])).is_err());
    }
}
