//! TOTP code generation for the `--otp` (seed) path.
//!
//! Certum's SimplySign uses **SHA-256** (not the SHA-1 default of most TOTP
//! libraries), 6 digits, 30 s. The input may be either a full `otpauth://` URI
//! (self-describing — the algorithm/digits/period are read from it) or a bare
//! base32 secret (Certum defaults are assumed).

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Clone, Copy)]
enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

/// Parsed TOTP parameters.
pub struct Totp {
    secret: Vec<u8>,
    algo: Algo,
    digits: u32,
    period: u64,
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI or a bare base32 secret.
    /// Certum defaults (SHA-256 / 6 / 30) are used for anything unspecified.
    pub fn parse(input: &str) -> Result<Self> {
        let mut secret_b32 = String::new();
        let mut algo = Algo::Sha256;
        let mut digits = 6u32;
        let mut period = 30u64;

        if input.trim_start().starts_with("otpauth://") {
            let query = input.split_once('?').map(|(_, q)| q).unwrap_or("");
            for (k, v) in query.split('&').filter_map(|kv| kv.split_once('=')) {
                let v = pct_decode(v);
                match k {
                    "secret" => secret_b32 = v,
                    "algorithm" => {
                        algo = match v.to_ascii_uppercase().as_str() {
                            "SHA1" => Algo::Sha1,
                            "SHA256" => Algo::Sha256,
                            "SHA512" => Algo::Sha512,
                            other => bail!("unsupported TOTP algorithm: {other}"),
                        }
                    }
                    "digits" => digits = v.parse().context("bad digits in otpauth URI")?,
                    "period" => period = v.parse().context("bad period in otpauth URI")?,
                    _ => {}
                }
            }
            if secret_b32.is_empty() {
                bail!("otpauth URI has no secret");
            }
        } else {
            secret_b32 = input.trim().to_string();
        }

        // Base32 alphabets sometimes carry padding/whitespace; normalize.
        let cleaned: String = secret_b32
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .collect();
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
            .ok_or_else(|| anyhow!("secret is not valid base32"))?;
        if secret.is_empty() {
            bail!("empty TOTP secret");
        }
        Ok(Totp {
            secret,
            algo,
            digits,
            period,
        })
    }

    /// The current code for `unix_time` (seconds since the epoch).
    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = (unix_time / self.period).to_be_bytes();
        macro_rules! mac {
            ($h:ty) => {{
                let mut m = <Hmac<$h> as Mac>::new_from_slice(&self.secret)
                    .expect("HMAC accepts any key length");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }};
        }
        let digest: Vec<u8> = match self.algo {
            Algo::Sha1 => mac!(Sha1),
            Algo::Sha256 => mac!(Sha256),
            Algo::Sha512 => mac!(Sha512),
        };
        // RFC 4226 dynamic truncation.
        let off = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((u32::from(digest[off]) & 0x7f) << 24)
            | (u32::from(digest[off + 1]) << 16)
            | (u32::from(digest[off + 2]) << 8)
            | u32::from(digest[off + 3]);
        let code = bin % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }
}

/// Minimal percent-decoding for otpauth query values (e.g. `%3D` -> `=`).
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vectors (seed "12345678901234567890" = base32 GEZD...).
    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

    #[test]
    fn rfc6238_sha1() {
        let t = Totp::parse(SEED_SHA1).unwrap();
        // RFC vectors are 8-digit; recompute with digits=8 by parsing a URI.
        let t8 = Totp {
            digits: 8,
            algo: Algo::Sha1,
            ..t
        };
        assert_eq!(t8.code_at(59), "94287082");
        assert_eq!(t8.code_at(1111111109), "07081804");
    }

    #[test]
    fn rfc6238_sha256() {
        let t = Totp::parse(SEED_SHA256).unwrap();
        let t8 = Totp { digits: 8, ..t };
        assert_eq!(t8.code_at(59), "46119246");
        assert_eq!(t8.code_at(1111111109), "68084774");
    }

    #[test]
    fn parses_otpauth_uri_algorithm() {
        // digits/period/algorithm must come from the URI, not the defaults.
        let uri = "otpauth://totp/Certum:me@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Certum&algorithm=SHA1&digits=8&period=30";
        let t = Totp::parse(uri).unwrap();
        assert!(matches!(t.algo, Algo::Sha1));
        assert_eq!(t.digits, 8);
    }
}
