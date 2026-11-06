//! RFC 3161 timestamping: hash the signature, ask the TSA to countersign it,
//! and return the TimeStampToken to embed as an unauthenticated attribute.

use crate::asn1;
use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::time::Duration;

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Request a timestamp over `signature` from the RFC3161 TSA at `url`; returns
/// the DER `TimeStampToken` (a PKCS#7 ContentInfo).
/// The TSA's own signature is left to Windows, which checks it on every file.
pub fn fetch(url: &str, signature: &[u8]) -> Result<Vec<u8>> {
    let imprint: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(signature);
        h.finalize().into()
    };
    let nonce = new_nonce()?;

    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building TSA client")?
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/timestamp-query")
        .body(request(&imprint, &nonce))
        .send()
        .context("timestamp request")?;
    if !resp.status().is_success() {
        bail!("timestamp HTTP {}", resp.status());
    }
    let tsr = resp.bytes().context("reading timestamp reply")?;
    parse_response(&tsr, &imprint, &nonce)
}

fn new_nonce() -> Result<Vec<u8>> {
    let mut n = [0u8; 8];
    SystemRandom::new()
        .fill(&mut n)
        .map_err(|_| anyhow!("no randomness for the timestamp nonce"))?;
    // A positive, minimal INTEGER, so the echoed nonce compares byte for byte.
    n[0] = (n[0] & 0x7f).max(1);
    Ok(asn1::tlv(0x02, &n))
}

// TimeStampReq ::= SEQUENCE { version INTEGER(1),
//   messageImprint SEQUENCE { hashAlgorithm AlgId, hashedMessage OCTET STRING },
//   nonce INTEGER, certReq BOOLEAN TRUE }
fn request(imprint: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    asn1::seq(&[
        &asn1::int_one(),
        &asn1::seq(&[
            &asn1::seq(&[&asn1::oid(OID_SHA256), &asn1::null()]),
            &asn1::octet_string(imprint),
        ]),
        nonce,
        &asn1::bool_true(),
    ])
}

fn parse_response(tsr: &[u8], imprint: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>> {
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TST OPTIONAL }
    let top = asn1::children(tsr).map_err(|e| anyhow::anyhow!("bad TSR: {e}"))?;
    let status_info = top.first().context("TSR has no status")?;
    let status = asn1::children(status_info)
        .ok()
        .and_then(|c| c.first().and_then(|s| s.get(2)).copied())
        .unwrap_or(255);
    if status != 0 && status != 1 {
        bail!("TSA rejected the request (status {status})");
    }
    let token = top.get(1).context("TSR has no timeStampToken")?;
    let signed_data = validate_timestamp_token(token)?;
    check_tst_info(tst_info(signed_data)?, imprint, nonce)?;
    Ok(token.to_vec())
}

fn der<T>(r: std::result::Result<T, &'static str>) -> Result<T> {
    r.map_err(|e| anyhow!("bad timeStampToken: {e}"))
}

fn tst_info(signed_data: &[u8]) -> Result<&[u8]> {
    let encap = *der(asn1::children(signed_data))?
        .get(2)
        .context("SignedData is truncated")?;
    let encap = der(asn1::children(encap))?;
    if encap.first() != Some(&asn1::oid(OID_TST_INFO).as_slice()) {
        bail!("timeStampToken does not carry a TSTInfo");
    }
    let wrapped = encap
        .get(1)
        .filter(|e| e.first() == Some(&0xa0))
        .context("TSTInfo is missing its explicit wrapper")?;
    let octets = der(asn1::children(wrapped))?;
    match octets.as_slice() {
        [o] if o.first() == Some(&0x04) => der(asn1::content(o)),
        _ => bail!("TSTInfo is not a DER OCTET STRING"),
    }
}

// TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
//   accuracy SEQUENCE OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
//   tsa [0] OPTIONAL, extensions [1] OPTIONAL }
fn check_tst_info(tst_info: &[u8], imprint: &[u8; 32], nonce: &[u8]) -> Result<()> {
    let fields = der(asn1::children(tst_info))?;
    let message_imprint = der(asn1::children(
        fields.get(2).context("TSTInfo has no messageImprint")?,
    ))?;
    let [alg, hashed] = message_imprint.as_slice() else {
        bail!("malformed messageImprint");
    };
    let alg_oid = der(asn1::children(alg))?.first().copied();
    if alg_oid != Some(asn1::oid(OID_SHA256).as_slice())
        || hashed.first() != Some(&0x04)
        || der(asn1::content(hashed))? != imprint
    {
        bail!("timestamp is for a different signature (messageImprint mismatch)");
    }
    // After genTime only the nonce is an INTEGER.
    match fields.iter().skip(5).find(|f| f.first() == Some(&0x02)) {
        Some(n) if *n == nonce => Ok(()),
        Some(_) => bail!("timestamp reply does not match this request (nonce mismatch)"),
        None => bail!("timestamp reply has no nonce"),
    }
}

fn validate_timestamp_token(token: &[u8]) -> Result<&[u8]> {
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
    let signed_data =
        asn1::children(wrapped).map_err(|e| anyhow::anyhow!("bad CMS SignedData wrapper: {e}"))?;
    if signed_data.len() != 1 || signed_data[0].first() != Some(&0x30) {
        bail!("CMS SignedData wrapper did not contain SignedData");
    }
    Ok(signed_data[0])
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

    const IMPRINT: [u8; 32] = [7; 32];

    fn make_tst_info(imprint: &[u8], alg: &str, nonce: Option<&[u8]>) -> Vec<u8> {
        let mut fields = vec![
            asn1::int_one(),
            asn1::oid("1.2.616.1.113527.2.5.1.7"),
            asn1::seq(&[
                &asn1::seq(&[&asn1::oid(alg), &asn1::null()]),
                &asn1::octet_string(imprint),
            ]),
            asn1::tlv(0x02, &[0x42]),
            asn1::tlv(0x18, b"20261106120000Z"),
            asn1::seq(&[&asn1::int_one()]),
        ];
        fields.extend(nonce.map(<[u8]>::to_vec));
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        asn1::seq(&refs)
    }

    fn reply(tst_info: &[u8]) -> Vec<u8> {
        let encap = asn1::seq(&[
            &asn1::oid(OID_TST_INFO),
            &asn1::ctx(0, &asn1::octet_string(tst_info)),
        ]);
        let signed_data = asn1::seq(&[&asn1::int_one(), &asn1::set(&[]), &encap, &asn1::set(&[])]);
        let token = asn1::seq(&[
            &asn1::oid(OID_PKCS7_SIGNED_DATA),
            &asn1::ctx(0, &signed_data),
        ]);
        asn1::seq(&[&asn1::seq(&[&[0x02, 0x01, 0x00]]), &token])
    }

    #[test]
    fn the_request_carries_the_nonce_before_cert_req() {
        let nonce = new_nonce().unwrap();
        let tsq = request(&IMPRINT, &nonce);
        let fields = asn1::children(&tsq).unwrap();
        assert_eq!(fields[2], nonce.as_slice());
        assert_eq!(fields[3], asn1::bool_true().as_slice());
        assert!((0x01..=0x7f).contains(&nonce[2]));
        assert_ne!(new_nonce().unwrap(), nonce);
    }

    #[test]
    fn accepts_a_reply_that_echoes_the_nonce_and_imprint() {
        let nonce = new_nonce().unwrap();
        let tsr = reply(&make_tst_info(&IMPRINT, OID_SHA256, Some(&nonce)));
        let token = parse_response(&tsr, &IMPRINT, &nonce).unwrap();
        assert_eq!(token.as_slice(), asn1::children(&tsr).unwrap()[1]);
    }

    #[test]
    fn rejects_a_reply_with_another_nonce() {
        let nonce = new_nonce().unwrap();
        let other = new_nonce().unwrap();
        let tsr = reply(&make_tst_info(&IMPRINT, OID_SHA256, Some(&other)));
        let err = parse_response(&tsr, &IMPRINT, &nonce).unwrap_err();
        assert!(err.to_string().contains("nonce mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_reply_without_a_nonce() {
        let nonce = new_nonce().unwrap();
        let tsr = reply(&make_tst_info(&IMPRINT, OID_SHA256, None));
        assert!(parse_response(&tsr, &IMPRINT, &nonce).is_err());
    }

    #[test]
    fn rejects_a_reply_for_another_imprint() {
        let nonce = new_nonce().unwrap();
        let tsr = reply(&make_tst_info(&[8; 32], OID_SHA256, Some(&nonce)));
        let err = parse_response(&tsr, &IMPRINT, &nonce).unwrap_err();
        assert!(err.to_string().contains("messageImprint"), "{err}");
    }

    #[test]
    fn rejects_an_imprint_made_with_another_hash() {
        let nonce = new_nonce().unwrap();
        let tsr = reply(&make_tst_info(&IMPRINT, "1.3.14.3.2.26", Some(&nonce)));
        assert!(parse_response(&tsr, &IMPRINT, &nonce).is_err());
    }

    #[test]
    #[ignore = "network: asks http://time.certum.pl/ for a real timestamp"]
    fn real_tsa_reply_passes_the_nonce_and_imprint_checks() {
        let token = fetch("http://time.certum.pl/", b"ssign timestamp self-test").unwrap();
        assert!(validate_timestamp_token(&token).is_ok());
    }
}
