//! A live cloud signing session — the [`auth`] → [`card`] → [`sign`] steps
//! bundled behind one object.
//!
//! Both the CLI and the `ssign-pkcs11` module log in once and then sign many
//! digests through this handle. It also precomputes the pieces a PKCS#11 module
//! needs to describe the key to osslsigncode/signtool: the certificate (DER),
//! its public key (PKCS#1 RSAPublicKey DER), and a stable id linking the two.
//!
//! # Session cache
//!
//! A PKCS#11 caller like osslsigncode reloads the module — and thus logs in
//! again — for every file it signs. Certum rejects a reused TOTP code, so
//! signing several files in a row would fail after the first. To avoid that,
//! [`CloudSession::save`] persists the OAuth token (valid ~30 min) and
//! [`CloudSession::load_cached`] reuses it, so only the first sign needs an OTP.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{auth, card, client, sign};
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use sha1::{Digest, Sha1};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// How long a cached token is trusted before we log in again. The real token
/// lives ~30 min; we stay well inside that so a sign never starts on a token
/// about to expire.
const CACHE_TTL_SECS: u64 = 20 * 60;

/// An authenticated Certum cloud session ready to sign SHA-256 digests.
pub struct CloudSession {
    http: Client,
    token: String,
    card: card::Card,
    cert_der: Vec<u8>,
    pubkey_der: Vec<u8>,
    key_id: Vec<u8>,
    /// Memoized last `(digest, signature)`. PKCS#11 clients call `C_Sign` twice
    /// per signature — once with a null buffer to learn the length, once to get
    /// the bytes — which would otherwise be two cloud round-trips for the same
    /// digest. RSA PKCS#1 v1.5 is deterministic, so caching by digest is always
    /// correct.
    last: Mutex<Option<([u8; 32], Vec<u8>)>>,
}

impl CloudSession {
    /// Log in (email + current 6-digit code) and materialize the card,
    /// certificate and the derived key descriptors.
    pub fn open(email: &str, otp_code: &str) -> Result<Self> {
        let token = auth::login(email, otp_code)?.0;
        let http = client::client()?;
        let card = card::fetch(&http, &token)?;
        Self::from_parts(http, token, card)
    }

    /// Build a session from an already-issued token and card (no login).
    fn from_parts(http: Client, token: String, card: card::Card) -> Result<Self> {
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
            last: Mutex::new(None),
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
    /// PKCS#1 v1.5 signature. The result is memoized per digest so the twin
    /// `C_Sign` calls a PKCS#11 client makes cost a single cloud round-trip.
    pub fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        if let Some((cached_digest, signature)) = self.last.lock().unwrap().as_ref() {
            if cached_digest == digest {
                return Ok(signature.clone());
            }
        }
        let signature = sign::request(&self.http, &self.token, &self.card, digest)?;
        *self.last.lock().unwrap() = Some((*digest, signature.clone()));
        Ok(signature)
    }

    // --- session cache -----------------------------------------------------

    /// Reuse a previously saved session for `email`, if the cached token is
    /// still valid. Best-effort: any problem (missing file, wrong account,
    /// expired token, parse error) yields `None` so the caller logs in afresh.
    pub fn load_cached(email: &str) -> Option<Self> {
        let raw = fs::read(cache_path()?).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        if v.get("email")?.as_str()? != email {
            return None;
        }
        let expires_at = v.get("expires_at")?.as_u64()?;
        if now() + 120 >= expires_at {
            return None;
        }
        let token = v.get("token")?.as_str()?.to_string();
        let serial = v.get("serial")?.as_str()?.to_string();
        let certificate_pem = v.get("cert_pem")?.as_str()?.as_bytes().to_vec();
        let card = card::Card {
            serial,
            certificate_pem,
        };
        Self::from_parts(client::client().ok()?, token, card).ok()
    }

    /// Persist this session's token + card so the next process can reuse it
    /// without an OTP. Best-effort; a failure to write is not fatal.
    pub fn save(&self, email: &str) {
        let Some(path) = cache_path() else { return };
        let doc = serde_json::json!({
            "v": 1,
            "email": email,
            "token": self.token,
            "expires_at": now() + CACHE_TTL_SECS,
            "serial": self.card.serial,
            "cert_pem": String::from_utf8_lossy(&self.card.certificate_pem),
        });
        let _ = write_private(&path, doc.to_string().as_bytes());
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `$XDG_RUNTIME_DIR/ssign/session.json`, falling back to `$HOME/.cache` then
/// the system temp dir. The token here can sign for ~30 min, so the file is
/// written user-private (see [`write_private`]).
fn cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    Some(base.join("ssign").join("session.json"))
}

/// Write `data` to `path` with owner-only permissions, creating the parent
/// directory (also owner-only on Unix).
fn write_private(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
    }
    fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
