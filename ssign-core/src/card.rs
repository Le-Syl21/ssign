//! Step 2 — materialize the cloud "card": list cards (→ serial) and fetch the
//! signing certificate (DER), each as an async SCS task with a bearer token.

use crate::client::{multipart_part, run_task, API_BASE};
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;

/// The signing card plus its certificate.
pub struct Card {
    /// Card serial (`cardno`), used in the per-card URLs.
    pub serial: String,
    /// The signing certificate exactly as the endpoint returned it (PEM) — this
    /// is what the sign request expects back; the PKCS#7 decodes it to DER.
    pub certificate_pem: Vec<u8>,
}

/// Fetch the (first) code-signing card and its certificate.
pub fn fetch(client: &Client, token: &str) -> Result<Card> {
    // 1. list cards -> serial.
    let resp = run_task(
        client,
        token,
        client
            .post(format!("{API_BASE}/card/v1/cards/tasks"))
            .bearer_auth(token)
            .header(CONTENT_TYPE, "application/json"),
    )
    .context("listing cards")?
    .1;
    let text = String::from_utf8_lossy(&resp).to_string();
    let cards: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("card list was not JSON: {text}"))?;
    let serial = cards
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c.get("cardno"))
        .and_then(|v| v.as_str())
        .with_context(|| {
            let snippet: String = text.chars().take(400).collect();
            format!("no card / cardno in the card list; response was: {snippet}")
        })?
        .to_string();

    // 2. fetch the certificate (a multipart with a `certificate` DER part).
    let resp = run_task(
        client,
        token,
        client
            .post(format!(
                "{API_BASE}/card/v1/cards/{serial}/certificates/tasks"
            ))
            .bearer_auth(token)
            .header(CONTENT_TYPE, "application/json"),
    )
    .context("fetching certificate")?
    .1;
    let certificate_pem = multipart_part(&resp, "certificate").context("extracting certificate")?;
    Ok(Card {
        serial,
        certificate_pem,
    })
}
