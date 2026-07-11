//! A live cloud signing session — the [`auth`] → [`card`] → [`sign`] steps
//! bundled behind one object.
//!
//! Both the CLI and the `ssign-pkcs11` module log in once and then sign many
//! digests through this handle. It also precomputes the pieces a PKCS#11 module
//! needs to describe the key to osslsigncode/signtool: the certificate (DER),
//! its public key (SPKI DER), and a stable id linking the two.

use crate::{auth, card, client, sign};
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use sha1::{Digest, Sha1};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// An authenticated Certum cloud session ready to sign SHA-256 digests.
pub struct CloudSession {
    http: Client,
    token: String,
    card: card::Card,
    cert_der: Vec<u8>,
    pubkey_der: Vec<u8>,
    key_id: Vec<u8>,
}

impl CloudSession {
    /// Log in (email + current 6-digit code) and materialize the card,
    /// certificate and the derived key descriptors.
    pub fn open(email: &str, otp_code: &str) -> Result<Self> {
        let token = auth::login(email, otp_code)?.0;
        let http = client::client()?;
        let card = card::fetch(&http, &token)?;

        let cert_der = crate::authenticode::pem_to_der(&card.certificate_pem)
            .context("decoding the signing certificate")?;
        let cert = Certificate::from_der(&cert_der).context("parsing the signing certificate")?;
        // The PKCS#1 `RSAPublicKey` (modulus + exponent) — the bare content of
        // the SPKI's BIT STRING, which is the shape PKCS#11 clients expect from
        // a public-key object's CKA_VALUE.
        let pubkey_der = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        // Conventional CKA_ID: a stable hash tying the certificate to its key so
        // a PKCS#11 client that finds the cert can find the matching key.
        let key_id = Sha1::digest(&cert_der).to_vec();

        Ok(Self {
            http,
            token,
            card,
            cert_der,
            pubkey_der,
            key_id,
        })
    }

    /// The signing certificate (DER).
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The certificate's public key as a PKCS#1 `RSAPublicKey` DER
    /// (modulus + exponent) — the shape PKCS#11 clients parse.
    pub fn public_key_der(&self) -> &[u8] {
        &self.pubkey_der
    }

    /// A stable id linking the certificate and its private key (CKA_ID).
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// Ask the cloud HSM to sign one SHA-256 digest; returns the raw RSA
    /// PKCS#1 v1.5 signature.
    pub fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        sign::request(&self.http, &self.token, &self.card, digest)
    }
}
