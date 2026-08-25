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
use std::path::{Path, PathBuf};
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
            .tbs_certificate()
            .subject_public_key_info()
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

    /// The card serial this session signs with (`cardno`).
    pub fn card_serial(&self) -> &str {
        &self.card.serial
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
        Self::load_cached_from(&cache_path()?, email)
    }

    /// [`load_cached`](Self::load_cached) against an explicit path.
    fn load_cached_from(path: &Path, email: &str) -> Option<Self> {
        let raw = fs::read(path).ok()?;
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
        self.save_to(&path, email);
    }

    /// [`save`](Self::save) against an explicit path.
    fn save_to(&self, path: &Path, email: &str) {
        let doc = serde_json::json!({
            "v": 1,
            "email": email,
            "token": self.token,
            "expires_at": now() + CACHE_TTL_SECS,
            "serial": self.card.serial,
            "cert_pem": String::from_utf8_lossy(&self.card.certificate_pem),
        });
        let _ = write_private(path, doc.to_string().as_bytes());
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
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A session built straight from parts, with no network involved.
    fn fake_session() -> CloudSession {
        use x509_cert::der::pem::LineEnding;
        use x509_cert::der::EncodePem;
        let cert_der = include_bytes!("../tests/fixtures/selftest_cert.der");
        let pem = Certificate::from_der(cert_der)
            .expect("parse test certificate")
            .to_pem(LineEnding::LF)
            .expect("encode test certificate");
        let card = card::Card {
            serial: "1234567890".into(),
            certificate_pem: pem.into_bytes(),
        };
        CloudSession::from_parts(client::client().unwrap(), "token-abc".into(), card)
            .expect("build session from parts")
    }

    fn temp_cache(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ssign-cache-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir.join("session.json")
    }

    #[test]
    fn a_saved_session_is_reloaded_without_a_new_login() {
        // The bug this guards: the CLI used to call `auth::login` directly and
        // never write the cache, so `ssign-pkcs11` logged in a second time and
        // replayed a Certum code that is only accepted once.
        let path = temp_cache("roundtrip");
        fake_session().save_to(&path, "user@example.com");

        let loaded = CloudSession::load_cached_from(&path, "user@example.com")
            .expect("cached session should reload");
        assert_eq!(loaded.token, "token-abc");
        assert_eq!(loaded.card_serial(), "1234567890");
        assert_eq!(loaded.certificate_der(), fake_session().certificate_der());
        assert_eq!(loaded.key_id(), fake_session().key_id());
    }

    #[test]
    fn the_cache_is_owner_only() {
        let path = temp_cache("perms");
        fake_session().save_to(&path, "user@example.com");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token file must not be world-readable");
        }
    }

    #[test]
    fn a_cache_for_another_account_is_ignored() {
        let path = temp_cache("otheraccount");
        fake_session().save_to(&path, "user@example.com");
        assert!(CloudSession::load_cached_from(&path, "someone-else@example.com").is_none());
    }

    #[test]
    fn an_expired_cache_is_ignored() {
        let path = temp_cache("expired");
        fake_session().save_to(&path, "user@example.com");
        // Rewrite the expiry into the past, leaving everything else intact.
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v["expires_at"] = serde_json::json!(now() - 1);
        fs::write(&path, v.to_string()).unwrap();
        assert!(CloudSession::load_cached_from(&path, "user@example.com").is_none());
    }

    #[test]
    fn a_cache_about_to_expire_is_ignored() {
        // A token with a minute left would expire mid-batch: refuse it rather
        // than start signing on it.
        let path = temp_cache("nearlyexpired");
        fake_session().save_to(&path, "user@example.com");
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v["expires_at"] = serde_json::json!(now() + 60);
        fs::write(&path, v.to_string()).unwrap();
        assert!(CloudSession::load_cached_from(&path, "user@example.com").is_none());
    }

    #[test]
    fn a_missing_or_corrupt_cache_is_not_fatal() {
        let path = temp_cache("corrupt");
        assert!(CloudSession::load_cached_from(&path, "user@example.com").is_none());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json at all").unwrap();
        assert!(CloudSession::load_cached_from(&path, "user@example.com").is_none());
    }

    /// The PKCS#11 key material is what osslsigncode/signtool match a cert to
    /// its key by, so a dependency bump must not move it. Pinned from the test
    /// certificate; verified byte for byte across x509-cert 0.2 -> 0.3 and
    /// der 0.7 -> 0.8, which turned the certificate fields into accessors.
    #[test]
    fn key_material_is_stable() {
        let s = fake_session();
        assert_eq!(hex::encode(s.public_key_der()), "3082020a0282020100b52b48b82dfdc0fc91f3b914bbd4defad5b198f837c2b43a917a70f37fd3542bfe54a3c32fd1fb15de905300f054850a74b57b8ea30664ec23cbd7aa25dc2d51e47b4a6a934e837acd3ded5197afab9b0be48ad29277d28ec95a35c37c71e603bdd8c0143d2d00148f4ce590d25d1f9d8383cec11b15bd2f117b3fefc4f5c13a1f2b046cc34906d221f9a78a631a5db9448f62c1235a4cc5ed0033e86507cc68cc53e7781e60eedae4b4ba6e95520a7ec944fa4743baf919f2772c55a96c0042a31f60c9b4b4276e87b8666bc71c6288af0e8c0c65573211d827be7088f0d81c3227897b37448fb0d3da50712a74c6f04cd71aeed80e43202fc28508745fecd4bca09d6070068a1c0b73816aa71af5310c77a6cb70d2b430c3a3412f52bf7d620fe63ec871eee12b562c8b22b43fc7ce20e60ed822a2494462d9f8b7c0c8800cd414032256c4792b7a8abfc1d2e82e607752e55ca61075d0aadca88147714532231c8ff0f9a41d10083ce915bc2984d2a960ea3182b1a5f6a71378c6d75fdde7384f76dbea7f988b2b0720fcf341841fa59cf4c0d812bd48b452c37ac8e875c1a1a954f3be35d95c743a356ffbd5bab31cbe04681d489db763bf59034c40b500d9ae34824f65b57eec2f72ef56474f2930167cea1a6d0baff58dee2d5f199fb05b6b44edb2dcab0cc847d15d74ee6bd211c37ba1894a989ef2c0b5d99980e1cf0203010001");
        assert_eq!(
            hex::encode(s.key_id()),
            "533cb9753a556dcb175b0698e83084f6888d5ad3"
        );
    }
}
