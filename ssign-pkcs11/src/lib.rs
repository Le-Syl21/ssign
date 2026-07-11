//! ssign-pkcs11 — a PKCS#11 module that signs with a Certum SimplySign **cloud**
//! certificate over plain HTTPS.
//!
//! It exposes the cloud key to any tool that speaks PKCS#11 — osslsigncode,
//! signtool, jsign — so they can sign **every** Authenticode format (PE, MSI,
//! CAB, catalog, APPX, PowerShell…) while the cloud access, login and signature
//! are handled here. No SimplySign Desktop, no p11-kit bridge, no smart card.
//!
//! The heavy lifting (OAuth login, card/cert fetch, remote signature) lives in
//! [`ssign_core`]; this crate is the thin PKCS#11 skin over it, built on the
//! `native-pkcs11` framework (we only supply a [`Backend`]).
//!
//! Credentials are read from the environment on first use:
//!   * `CERTUM_EMAIL` — the account e-mail (required)
//!   * `CERTUM_OTP`   — the TOTP **seed**; the 6-digit code is derived here, or
//!   * `CERTUM_TOKEN` — a current 6-digit code (used if `CERTUM_OTP` is unset)

use std::error::Error;
use std::sync::{Arc, Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use native_pkcs11::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK};
use native_pkcs11_traits::{
    Backend, Certificate, KeyAlgorithm, KeySearchOptions, PrivateKey, PublicKey, Result,
    SignatureAlgorithm,
};
use ssign_core::session::CloudSession;

/// Human-readable label for the token, certificate and key objects.
const LABEL: &str = "Certum SimplySign (ssign)";

/// DER prefix of a SHA-256 `DigestInfo` (RFC 8017), followed by the 32-byte
/// digest. osslsigncode signs via `CKM_RSA_PKCS`, which hands us this whole
/// structure; the cloud instead wants the bare digest and wraps it itself, so
/// we peel the prefix off.
const SHA256_DIGESTINFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn boxed(msg: impl Into<String>) -> Box<dyn Error> {
    msg.into().into()
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// The ssign backend: opens one Certum cloud session lazily and shares it.
struct CertumBackend {
    session: Mutex<Option<Arc<CloudSession>>>,
}

impl CertumBackend {
    fn new() -> Self {
        Self {
            session: Mutex::new(None),
        }
    }

    /// Return the shared session, logging in on first use.
    fn session(&self) -> Result<Arc<CloudSession>> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| boxed("session lock poisoned"))?;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let (email, code) = credentials()?;
        let session = CloudSession::open(&email, &code)
            .map_err(|e| boxed(format!("Certum cloud login / card fetch failed: {e:#}")))?;
        let session = Arc::new(session);
        *guard = Some(session.clone());
        Ok(session)
    }
}

impl Backend for CertumBackend {
    fn name(&self) -> String {
        "ssign".into()
    }

    fn find_all_certificates(&self) -> Result<Vec<Box<dyn Certificate>>> {
        Ok(vec![Box::new(CertumCert::new(self.session()?))])
    }

    fn find_private_key(&self, query: KeySearchOptions) -> Result<Option<Arc<dyn PrivateKey>>> {
        let session = self.session()?;
        let matches = match query {
            KeySearchOptions::Id(id) => id == session.key_id(),
            KeySearchOptions::Label(label) => label == LABEL,
        };
        Ok(matches.then(|| Arc::new(CertumKey { session }) as Arc<dyn PrivateKey>))
    }

    fn find_public_key(&self, _query: KeySearchOptions) -> Result<Option<Box<dyn PublicKey>>> {
        Ok(Some(Box::new(CertumPublic {
            session: self.session()?,
        })))
    }

    fn find_all_private_keys(&self) -> Result<Vec<Arc<dyn PrivateKey>>> {
        Ok(vec![Arc::new(CertumKey {
            session: self.session()?,
        })])
    }

    fn find_all_public_keys(&self) -> Result<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![Arc::new(CertumPublic {
            session: self.session()?,
        })])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _label: Option<&str>,
    ) -> Result<Arc<dyn PrivateKey>> {
        Err(boxed(
            "ssign is a cloud signing module; it cannot generate keys",
        ))
    }
}

// ---------------------------------------------------------------------------
// Certificate / PublicKey / PrivateKey objects
// ---------------------------------------------------------------------------

struct CertumCert {
    session: Arc<CloudSession>,
    public: CertumPublic,
}

impl CertumCert {
    fn new(session: Arc<CloudSession>) -> Self {
        Self {
            public: CertumPublic {
                session: session.clone(),
            },
            session,
        }
    }
}

impl std::fmt::Debug for CertumCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertumCert(Certum SimplySign)")
    }
}

impl Certificate for CertumCert {
    fn id(&self) -> Vec<u8> {
        self.session.key_id().to_vec()
    }
    fn label(&self) -> String {
        LABEL.into()
    }
    fn to_der(&self) -> Vec<u8> {
        self.session.certificate_der().to_vec()
    }
    fn public_key(&self) -> &dyn PublicKey {
        &self.public
    }
    fn delete(self: Box<Self>) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

struct CertumPublic {
    session: Arc<CloudSession>,
}

impl std::fmt::Debug for CertumPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertumPublic(Certum SimplySign)")
    }
}

impl PublicKey for CertumPublic {
    fn id(&self) -> Vec<u8> {
        self.session.key_id().to_vec()
    }
    fn label(&self) -> String {
        LABEL.into()
    }
    fn to_der(&self) -> Vec<u8> {
        self.session.public_key_der().to_vec()
    }
    fn verify(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<()> {
        Err(boxed("ssign does not verify signatures"))
    }
    fn delete(self: Box<Self>) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

struct CertumKey {
    session: Arc<CloudSession>,
}

impl PrivateKey for CertumKey {
    fn id(&self) -> Vec<u8> {
        self.session.key_id().to_vec()
    }
    fn label(&self) -> String {
        LABEL.into()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        let digest = match algorithm {
            // signtool-style: the bare 32-byte digest.
            SignatureAlgorithm::RsaPkcs1v15Sha256 => data.try_into().map_err(|_| {
                boxed(format!("expected a 32-byte SHA-256 digest, got {}", data.len()))
            })?,
            // osslsigncode-style (CKM_RSA_PKCS): a DER SHA-256 DigestInfo.
            SignatureAlgorithm::RsaPkcs1v15Raw => sha256_from_digestinfo(data)?,
            other => {
                return Err(boxed(format!(
                    "unsupported algorithm {other:?}; the Certum cloud cert signs SHA-256 RSA PKCS#1 v1.5 only"
                )))
            }
        };
        self.session
            .sign_sha256(&digest)
            .map_err(|e| boxed(format!("cloud signature failed: {e:#}")))
    }

    fn delete(&self) {}

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

/// Peel a SHA-256 `DigestInfo` (or accept a bare digest) down to 32 bytes.
fn sha256_from_digestinfo(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() == SHA256_DIGESTINFO_PREFIX.len() + 32
        && data[..SHA256_DIGESTINFO_PREFIX.len()] == SHA256_DIGESTINFO_PREFIX
    {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[SHA256_DIGESTINFO_PREFIX.len()..]);
        Ok(digest)
    } else if let Ok(digest) = <[u8; 32]>::try_from(data) {
        // Some callers hand a bare digest even with CKM_RSA_PKCS.
        Ok(digest)
    } else {
        Err(boxed(format!(
            "expected a SHA-256 DigestInfo (51 bytes) or a bare 32-byte digest; got {} bytes (only SHA-256 is supported)",
            data.len()
        )))
    }
}

/// Resolve `(email, six-digit code)` from the environment.
fn credentials() -> Result<(String, String)> {
    let email = std::env::var("CERTUM_EMAIL").map_err(|_| boxed("CERTUM_EMAIL is not set"))?;
    if let Ok(code) = std::env::var("CERTUM_TOKEN") {
        return Ok((email, code));
    }
    let seed = std::env::var("CERTUM_OTP")
        .map_err(|_| boxed("set CERTUM_OTP (TOTP seed) or CERTUM_TOKEN (6-digit code)"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| boxed(format!("system clock before 1970: {e}")))?
        .as_secs();
    let code = ssign_core::otp::Totp::parse(&seed)
        .map_err(|e| boxed(format!("invalid CERTUM_OTP seed: {e:#}")))?
        .code_at(now);
    Ok((email, code))
}

// ---------------------------------------------------------------------------
// PKCS#11 entry point
// ---------------------------------------------------------------------------

/// `CKR_ARGUMENTS_BAD` — native-pkcs11 only re-exports `CKR_OK`, so spell this
/// one value out rather than pull in `pkcs11-sys` for it.
const CKR_ARGUMENTS_BAD: CK_RV = 7;

static REGISTER: Once = Once::new();

/// The one exported PKCS#11 symbol. It registers our backend once, then hands
/// back native-pkcs11's function table (which routes every other call through
/// the backend).
///
/// # Safety
/// `pp_function_list` must be a valid, writable pointer as required by PKCS#11.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    REGISTER.call_once(|| {
        native_pkcs11_traits::register_backend(Box::new(CertumBackend::new()));
    });
    *pp_function_list = std::ptr::addr_of_mut!(native_pkcs11::FUNC_LIST);
    CKR_OK
}
