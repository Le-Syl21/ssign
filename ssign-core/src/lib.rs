//! ssign — sign Windows binaries with a Certum SimplySign cloud certificate.
//!
//! The whole signing pipeline is plain HTTPS against Certum's cloud plus local
//! Authenticode/PKCS#7 assembly, so it runs on Linux, macOS and Windows alike —
//! you do NOT need Windows to sign a Windows binary.
//!
//! This is the reusable library behind both the `ssign` binary and the
//! `ssign-pkcs11` module: the binary drives the full PE pipeline itself, while
//! the PKCS#11 module reuses only the cloud half ([`auth`], [`card`], [`sign`])
//! to expose the cloud key to osslsigncode/signtool for every Authenticode
//! format.
#![allow(dead_code)] // some pipeline helpers are only used by one consumer

pub mod asn1;
pub mod auth;
pub mod authenticode;
pub mod card;
pub mod client;
pub mod msi;
pub mod otp;
pub mod session;
pub mod sign;
pub mod timestamp;
