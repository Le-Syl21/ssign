//! Step 1 — OAuth2 authorization-code login against Certum's CAS IdP
//! (`cloudsign.webnotarius.pl`), driven entirely over HTTP.
//!
//! Flow:
//!   GET  /idp/oauth2.0/authorize            -> 302 to the login page
//!   GET  /idp/login?service=…               -> HTML with a hidden `execution`
//!   POST /idp/login?service=…               -> 302 … -> redirect_uri?code=…
//!   POST /idp/oauth2.0/accessToken          -> {"access_token": …}
//!
//! The OAuth *client* credentials below are application-level constants shipped
//! identically to every SimplySign Desktop user (a public client per RFC 8252);
//! they are not the account holder's secret.

use anyhow::{bail, Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const AUTHORIZE_URL: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize";
const LOGIN_URL: &str = "https://cloudsign.webnotarius.pl/idp/login";
const TOKEN_URL: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken";
const SCOPE: &str = "https://cloudsign.webnotarius.pl/idp/oauth2.0/profile";
const REDIRECT_URI: &str = "https://cloudsign.webnotarius.pl/redirect";
const CLIENT_ID: &str = "44rvDKKEWY53a7xBeF5w";
const CLIENT_SECRET: &str = "BRSE2u2nY3p3m77QHTt8";

/// A bearer access token (valid ~30 min).
pub struct Token(pub String);

/// Log in with the account e-mail and a 6-digit OTP; returns the bearer token.
pub fn login(email: &str, otp_code: &str) -> Result<Token> {
    // Record every redirect target so we can recover the `?code=…` no matter
    // which hop in the chain carries it.
    let seen: Arc<Mutex<Vec<reqwest::Url>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cl = seen.clone();
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        seen_cl.lock().unwrap().push(attempt.url().clone());
        if attempt.previous().len() > 20 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    });

    let client = reqwest::blocking::Client::builder()
        .cookie_store(true)
        .redirect(redirect)
        .timeout(Duration::from_secs(30))
        .user_agent("ssign")
        .build()
        .context("building HTTP client")?;

    // 1. authorize -> land on the login page.
    let resp = client
        .get(AUTHORIZE_URL)
        .query(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", SCOPE),
            ("api_key", ""),
        ])
        .send()
        .context("authorize request")?;
    let login_url = resp.url().clone();
    let html = resp.text().context("reading login page")?;

    let execution = extract_hidden(&html, "execution")
        .context("could not find the `execution` field on the login page")?;
    let service = login_url
        .query_pairs()
        .find(|(k, _)| k == "service")
        .map(|(_, v)| v.into_owned());

    // 2. submit credentials (password = the OTP).
    seen.lock().unwrap().clear();
    let mut post = client.post(LOGIN_URL);
    if let Some(s) = &service {
        post = post.query(&[("service", s.as_str())]);
    }
    let resp = post
        .form(&[
            ("username", email),
            ("password", otp_code),
            ("execution", execution.as_str()),
            ("_eventId", "submit"),
            ("geolocation", ""),
            ("submit", "LOGIN"),
            ("lt", ""),
        ])
        .send()
        .context("login POST")?;
    let final_url = resp.url().clone();

    // 3. recover the authorization code from the redirect chain (or final URL).
    let code = seen
        .lock()
        .unwrap()
        .iter()
        .chain(std::iter::once(&final_url))
        .find_map(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.into_owned())
        })
        .context("no authorization code after login — wrong e-mail or OTP?")?;

    // 4. exchange the code for a bearer token (params go in the query string,
    //    body is empty — matching the desktop client).
    let resp = client
        .post(TOKEN_URL)
        .query(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("scope", SCOPE),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .context("accessToken request")?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .with_context(|| format!("accessToken response was not JSON (status {status})"))?;

    match body.get("access_token").and_then(|v| v.as_str()) {
        Some(tok) => Ok(Token(tok.to_string())),
        None => bail!("token exchange failed (status {status}): {body}"),
    }
}

/// Pull the value of a hidden `<input name="…" value="…">` out of the HTML.
fn extract_hidden(html: &str, name: &str) -> Option<String> {
    // Tolerate attribute order: match an <input> tag that mentions the name and
    // capture its value, whichever attribute comes first.
    let by_name_then_value = regex::Regex::new(&format!(
        r#"(?is)<input[^>]*\bname=["']{}["'][^>]*\bvalue=["']([^"']*)["']"#,
        regex::escape(name)
    ))
    .unwrap();
    let by_value_then_name = regex::Regex::new(&format!(
        r#"(?is)<input[^>]*\bvalue=["']([^"']*)["'][^>]*\bname=["']{}["']"#,
        regex::escape(name)
    ))
    .unwrap();
    by_name_then_value
        .captures(html)
        .or_else(|| by_value_then_name.captures(html))
        .map(|c| c[1].to_string())
}
