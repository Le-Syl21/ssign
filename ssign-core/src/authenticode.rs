//! Step 3b — the local Authenticode work, all cross-platform (no Windows APIs).
//!
//! - `pe_hash`  : Authenticode SHA-256 of a PE.
//! - `prepare`  : build the SpcIndirectData + signed attributes and return the
//!   SHA-256 that Certum must sign (over the signed attrs).
//! - `finalize` : wrap [attrs + signature + cert] into a PKCS#7 SignedData and
//!   splice it into the PE's certificate table.

use crate::asn1;
use anyhow::{bail, Context, Result};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use std::path::Path;

// ---- OIDs -----------------------------------------------------------------
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SPC_STATEMENT_TYPE: &str = "1.3.6.1.4.1.311.2.1.11";
const OID_SPC_SP_OPUS_INFO: &str = "1.3.6.1.4.1.311.2.1.12";
const OID_SPC_INDIVIDUAL: &str = "1.3.6.1.4.1.311.2.1.21";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_TIMESTAMP_TOKEN: &str = "1.3.6.1.4.1.311.3.3.1";

/// The `SpcAttributeTypeAndOptionalValue` is identical for every PE signature
/// (SPC_PE_IMAGE_DATA + the "<<<Obsolete>>>" moniker); captured verbatim.
const SPC_ATTR_CONST: &[u8] = &[
    0x30, 0x34, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f, 0x30, 0x26,
    0x03, 0x02, 0x07, 0x80, 0xa0, 0x20, 0xa2, 0x1e, 0x80, 0x1c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c,
    0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65,
    0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ---- PE hashing -----------------------------------------------------------

fn u32le(b: &[u8], off: usize) -> Result<u32> {
    let s = b.get(off..off + 4).context("PE truncated")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct PeLayout {
    checksum_off: usize,
    sec_dir_entry_off: usize,
    cert_table_off: usize,
    cert_table_size: usize,
}

fn pe_layout(pe: &[u8]) -> Result<PeLayout> {
    if pe.get(..2) != Some(b"MZ") {
        bail!("not a PE (no MZ signature)");
    }
    let pe_off = u32le(pe, 0x3c)? as usize;
    if pe.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        bail!("not a PE (no PE signature)");
    }
    let opt_off = pe_off + 24;
    let is_pe32plus = match pe.get(opt_off..opt_off + 2).context("PE truncated")? {
        [0x0b, 0x01] => false,
        [0x0b, 0x02] => true,
        _ => bail!("unknown optional-header magic"),
    };
    let checksum_off = opt_off + 64;
    let data_dir_off = opt_off + if is_pe32plus { 112 } else { 96 };
    let sec_dir_entry_off = data_dir_off + 4 * 8;
    Ok(PeLayout {
        checksum_off,
        sec_dir_entry_off,
        cert_table_off: u32le(pe, sec_dir_entry_off)? as usize,
        cert_table_size: u32le(pe, sec_dir_entry_off + 4)? as usize,
    })
}

/// Compute the Authenticode SHA-256 hash of a PE image.
pub fn pe_hash(pe: &[u8]) -> Result<[u8; 32]> {
    let l = pe_layout(pe)?;
    let (cert_start, cert_end) = if l.cert_table_size == 0 {
        (pe.len(), pe.len())
    } else {
        (l.cert_table_off, l.cert_table_off + l.cert_table_size)
    };
    let mut h = Sha256::new();
    h.update(&pe[..l.checksum_off]);
    h.update(&pe[l.checksum_off + 4..l.sec_dir_entry_off]);
    h.update(&pe[l.sec_dir_entry_off + 8..cert_start]);
    if cert_end < pe.len() {
        h.update(&pe[cert_end..]);
    }
    Ok(h.finalize().into())
}

// ---- prepare / finalize ---------------------------------------------------

/// The Certum "Code Signing 2021 CA" intermediate, embedded so the chain to the
/// (widely trusted) root is complete in the signature itself.
const INTERMEDIATE_DER: &[u8] = include_bytes!("certs/ccsca2021.der");

/// Decode a PEM certificate to DER (pass-through if already DER).
pub fn pem_to_der(cert: &[u8]) -> Result<Vec<u8>> {
    if cert.starts_with(b"-----BEGIN") {
        let pem = std::str::from_utf8(cert).context("certificate PEM not UTF-8")?;
        Ok(der::Document::from_pem(pem)
            .context("decoding certificate PEM")?
            .1
            .into_vec())
    } else {
        Ok(cert.to_vec())
    }
}

/// Everything needed to finish a signature once Certum returns the RSA bytes.
pub struct Prepared {
    /// SHA-256 over the DER-encoded signed attributes — this is what Certum signs.
    pub to_be_signed: [u8; 32],
    /// The whole file bytes (with any pre-existing signature stripped).
    pe: Vec<u8>,
    /// SpcIndirectData eContent (full SEQUENCE).
    spc_indirect: Vec<u8>,
    /// Signed attributes, encoded as a SET OF (0x31) — hashed and embedded.
    signed_attrs_set: Vec<u8>,
}

/// Build the SpcIndirectData and signed attributes for `pe`, returning the
/// digest Certum must sign plus the context needed to finalize.
pub fn prepare(
    pe: &[u8],
    name: Option<&str>,
    url: Option<&str>,
    signing_time: &str,
) -> Result<Prepared> {
    let h_pe = pe_hash(pe)?;

    // SpcIndirectDataContent = SEQUENCE { SpcAttr(const), DigestInfo(sha256, H_pe) }
    let digest_info = asn1::seq(&[
        &asn1::seq(&[&asn1::oid(OID_SHA256), &asn1::null()]),
        &asn1::octet_string(&h_pe),
    ]);
    let mut spc_content = SPC_ATTR_CONST.to_vec();
    spc_content.extend_from_slice(&digest_info);
    let spc_indirect = asn1::tlv(0x30, &spc_content);
    // Authenticode quirk: messageDigest is the hash of the SEQUENCE *content*.
    let message_digest = sha256(&spc_content);

    // Signed attributes (each: SEQUENCE { OID, SET { value } }).
    let mut attrs: Vec<Vec<u8>> = vec![
        asn1::seq(&[
            &asn1::oid(OID_CONTENT_TYPE),
            &asn1::set(&[&asn1::oid(OID_SPC_INDIRECT_DATA)]),
        ]),
        asn1::seq(&[
            &asn1::oid(OID_SIGNING_TIME),
            &asn1::set(&[&asn1::utc_time(signing_time)]),
        ]),
        asn1::seq(&[
            &asn1::oid(OID_SPC_STATEMENT_TYPE),
            &asn1::set(&[&asn1::seq(&[&asn1::oid(OID_SPC_INDIVIDUAL)])]),
        ]),
        asn1::seq(&[
            &asn1::oid(OID_MESSAGE_DIGEST),
            &asn1::set(&[&asn1::octet_string(&message_digest)]),
        ]),
    ];
    if name.is_some() || url.is_some() {
        attrs.push(asn1::seq(&[
            &asn1::oid(OID_SPC_SP_OPUS_INFO),
            &asn1::set(&[&opus_info(name, url)]),
        ]));
    }
    // DER SET OF: members sorted ascending by their encoding.
    attrs.sort();
    let refs: Vec<&[u8]> = attrs.iter().map(|a| a.as_slice()).collect();
    let signed_attrs_set = asn1::set(&refs);

    Ok(Prepared {
        to_be_signed: sha256(&signed_attrs_set),
        pe: pe.to_vec(),
        spc_indirect,
        signed_attrs_set,
    })
}

/// SpcSpOpusInfo ::= SEQUENCE { programName [0] EXPLICIT SpcString OPTIONAL,
///                              moreInfo    [1] EXPLICIT SpcLink   OPTIONAL }
fn opus_info(name: Option<&str>, url: Option<&str>) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if let Some(n) = name {
        // programName = [0] { SpcString ascii = [1] IMPLICIT }
        parts.push(asn1::ctx(0, &asn1::ctx_prim(1, n.as_bytes())));
    }
    if let Some(u) = url {
        // moreInfo = [1] { SpcLink url = [0] IMPLICIT }
        parts.push(asn1::ctx(1, &asn1::ctx_prim(0, u.as_bytes())));
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    asn1::seq(&refs)
}

/// Assemble the PKCS#7 SignedData with Certum's `signature` and splice it into
/// the PE; returns the signed image bytes.
pub fn finalize(
    prep: Prepared,
    signature: &[u8],
    cert_der: &[u8],
    timestamp_token: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert_der).context("parsing signing certificate")?;
    let issuer = cert
        .tbs_certificate
        .issuer
        .to_der()
        .context("encoding issuer")?;
    let serial = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .context("encoding serial")?;
    let issuer_and_serial = asn1::seq(&[&issuer, &serial]);

    let sha256_algid = asn1::seq(&[&asn1::oid(OID_SHA256), &asn1::null()]);
    let rsa_algid = asn1::seq(&[&asn1::oid(OID_RSA), &asn1::null()]);

    // authenticatedAttributes as [0] IMPLICIT (0xa0) — same content we hashed.
    let auth_attrs_ctx = {
        // signed_attrs_set is 0x31|len|content; re-tag to 0xa0.
        let content = &prep.signed_attrs_set[1 + der_len_size(&prep.signed_attrs_set)..];
        asn1::ctx(0, content)
    };

    // unauthenticatedAttributes [1] IMPLICIT SET OF — carries the RFC3161 token.
    let unauth = timestamp_token.map(|tok| {
        let attr = asn1::seq(&[&asn1::oid(OID_TIMESTAMP_TOKEN), &asn1::set(&[tok])]);
        asn1::ctx(1, &attr)
    });

    let one = asn1::int_one();
    let sig_octet = asn1::octet_string(signature);
    let mut si_parts: Vec<&[u8]> = vec![
        &one,
        &issuer_and_serial,
        &sha256_algid,
        &auth_attrs_ctx,
        &rsa_algid,
        &sig_octet,
    ];
    if let Some(u) = &unauth {
        si_parts.push(u);
    }
    let signer_info = asn1::seq(&si_parts);

    // encapContentInfo = SEQUENCE { OID SPC_INDIRECT_DATA, [0] { SpcIndirectData } }
    let encap = asn1::seq(&[
        &asn1::oid(OID_SPC_INDIRECT_DATA),
        &asn1::ctx(0, &prep.spc_indirect),
    ]);

    // certificates [0] IMPLICIT SET OF: the leaf plus the Certum intermediate,
    // so the chain to the trusted root is complete.
    let mut certs = cert_der.to_vec();
    certs.extend_from_slice(INTERMEDIATE_DER);

    let signed_data = asn1::seq(&[
        &asn1::int_one(),
        &asn1::set(&[&sha256_algid]),
        &encap,
        &asn1::ctx(0, &certs),
        &asn1::set(&[&signer_info]),
    ]);

    let pkcs7 = asn1::seq(&[
        &asn1::oid(OID_PKCS7_SIGNED_DATA),
        &asn1::ctx(0, &signed_data),
    ]);

    embed(prep.pe, &pkcs7)
}

/// Number of length octets in a DER TLV starting at `tlv[0]`.
fn der_len_size(tlv: &[u8]) -> usize {
    if tlv[1] < 0x80 {
        1
    } else {
        1 + (tlv[1] & 0x7f) as usize
    }
}

/// Splice a PKCS#7 blob into the PE's attribute certificate table.
fn embed(mut pe: Vec<u8>, pkcs7: &[u8]) -> Result<Vec<u8>> {
    let l = pe_layout(&pe)?;
    if l.cert_table_size != 0 {
        bail!("file already has a signature");
    }
    while !pe.len().is_multiple_of(8) {
        pe.push(0);
    }
    let table_off = pe.len();
    let win_cert_len = 8 + pkcs7.len();
    pe.extend_from_slice(&(win_cert_len as u32).to_le_bytes());
    pe.extend_from_slice(&[0x00, 0x02]); // wRevision  = WIN_CERT_REVISION_2_0
    pe.extend_from_slice(&[0x02, 0x00]); // wCertType  = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    pe.extend_from_slice(pkcs7);
    while !(pe.len() - table_off).is_multiple_of(8) {
        pe.push(0);
    }
    let table_size = pe.len() - table_off;

    pe[l.sec_dir_entry_off..l.sec_dir_entry_off + 4]
        .copy_from_slice(&(table_off as u32).to_le_bytes());
    pe[l.sec_dir_entry_off + 4..l.sec_dir_entry_off + 8]
        .copy_from_slice(&(table_size as u32).to_le_bytes());

    let checksum = pe_checksum(&pe, l.checksum_off);
    pe[l.checksum_off..l.checksum_off + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(pe)
}

/// The PE image checksum (16-bit ones-complement sum + file length).
fn pe_checksum(pe: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < pe.len() {
        if i == checksum_off {
            i += 4; // the checksum field counts as zero
            continue;
        }
        let w = u16::from_le_bytes([pe[i], pe[i + 1]]) as u64;
        sum += w;
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    if i < pe.len() {
        sum += pe[i] as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32) + pe.len() as u32
}

// ---- public helpers used by main ------------------------------------------

/// Authenticode SHA-256 of a file on disk.
pub fn digest(file: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    pe_hash(&bytes)
}

/// Format a Unix timestamp as an ASN.1 UTCTime (`YYMMDDhhmmssZ`).
pub fn utc_time(unix: u64) -> String {
    // civil-from-days (Howard Hinnant's algorithm).
    let days = (unix / 86400) as i64;
    let secs = unix % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        y.rem_euclid(100),
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_hash_matches_osslsigncode() {
        let pe = include_bytes!("../tests/fixtures/hello.exe");
        assert_eq!(
            hex::encode_upper(pe_hash(pe).unwrap()),
            "BC17B1C98515D63F366BCD9F472054AE49CD5E839043265CE060B38B33CA2A43"
        );
    }

    #[test]
    fn message_digest_uses_sequence_content() {
        // Rebuild the SpcIndirectData for the fixture's known H_pe and check the
        // messageDigest matches what osslsigncode embedded.
        let h_pe = hex::decode("BC17B1C98515D63F366BCD9F472054AE49CD5E839043265CE060B38B33CA2A43")
            .unwrap();
        let digest_info = asn1::seq(&[
            &asn1::seq(&[&asn1::oid(OID_SHA256), &asn1::null()]),
            &asn1::octet_string(&h_pe),
        ]);
        let mut spc_content = SPC_ATTR_CONST.to_vec();
        spc_content.extend_from_slice(&digest_info);
        assert_eq!(
            hex::encode_upper(sha256(&spc_content)),
            "320623882B0DBD238471A6E7DC3C1F3177D2DD38C0DC166FB12109BA89698E4B"
        );
    }

    #[test]
    fn utc_time_format() {
        assert_eq!(utc_time(0), "700101000000Z");
        // 1783667881 == 2026-07-10 07:18:01 UTC (the fixture's signingTime).
        assert_eq!(utc_time(1783667881), "260710071801Z");
    }

    /// End-to-end assembly check with a local self-signed key: prepare -> sign
    /// the digest ourselves (exactly as Certum would) -> finalize -> write a PE.
    /// Run with `cargo test -- --ignored`, then `osslsigncode verify` the output.
    #[test]
    #[ignore = "writes /tmp/ssign_selftest.exe for external osslsigncode verify"]
    fn selftest_assembles_verifiable_pe() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};

        let pe = include_bytes!("../tests/fixtures/hello.exe");
        let cert_der = include_bytes!("../tests/fixtures/selftest_cert.der");
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!("../tests/fixtures/selftest_key.pem"))
            .unwrap();

        let prep = prepare(
            pe,
            Some("ssign selftest"),
            Some("https://github.com/Le-Syl21"),
            &utc_time(1783667881),
        )
        .unwrap();
        // Certum returns RSASSA-PKCS1-v1_5 over the signed-attrs digest; do the same.
        let signature = key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &prep.to_be_signed)
            .unwrap();
        let ts = crate::timestamp::fetch("http://time.certum.pl/", &signature).ok();
        let signed = finalize(prep, &signature, cert_der, ts.as_deref()).unwrap();
        std::fs::write("/tmp/ssign_selftest.exe", &signed).unwrap();
        assert!(pe_layout(&signed).unwrap().cert_table_size > 0);
    }
}
