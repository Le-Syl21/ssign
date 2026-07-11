# The Certum SimplySign cloud-signing protocol

This is the reverse-engineered reference for the HTTPS protocol that `ssign`
speaks to Certum's SimplySign cloud signing service. It documents the *validated*
end-to-end flow (captured against SimplySign Desktop 2.9.14 via a redacting
MITM, then re-implemented from scratch), the version pitfall that blocks older
clients, and — in the appendices — the dead ends the static analysis first
suggested, so nobody has to walk them again.

> Reverse-engineered from the author's own licensed SimplySign Desktop install,
> for interoperability. No user secret is recorded here — only app-level
> constants and protocol structure. Not affiliated with or endorsed by Certum /
> Asseco; "Certum" and "SimplySign" are their trademarks.

**Host:** `cloudsign.webnotarius.pl` (all calls).
**Timestamp authority:** `http://time.certum.pl/` (RFC 3161, standard, unrelated
to auth). The endpoint is currently HTTP-only; `ssign` requires an explicit
`--allow-insecure-timestamp` acknowledgement before using it.

The whole flow is plain HTTPS — there is **no cryptographic activation wall**
(see [Appendix A](#appendix-a--superseded-hypotheses)). Session control is the
OAuth bearer token, nothing more. That is what makes a GUI-less, container-less,
PKCS#11-less signer possible.

---

## The flow, end to end

Each step below maps to the module in `src/` that implements it.

### 1 · Login — OAuth 2.0 authorization-code via the CAS IdP  (`auth.rs`)

Login is **not** ROPC (resource-owner password) as the binary strings first
suggested — it is a full CAS authorization-code dance. The credentials are the
account **e-mail** and a **6-digit TOTP OTP** (`otp.rs` derives it from the
seed); there is no stored account password.

1. `GET /idp/oauth2.0/authorize?response_type=code&client_id=<id>&redirect_uri=…&scope=…/idp/oauth2.0/profile`
   → `302`, sets a cookie, redirects to `/idp/login?service=…`
2. `GET /idp/login?service=…` → `200`, an HTML form carrying a hidden CAS
   `execution` token (~4700 chars) and `lt`.
3. `POST /idp/login?service=…` (form-urlencoded):
   `username` = e-mail, `password` = **6-digit OTP**, `execution` = the token
   from step 2, `_eventId=submit`, `submit=LOGIN`, `lt`, `geolocation=` (empty)
   → `302`, sets the TGT cookie.
4. `GET /idp/oauth2.0/callbackAuthorize?…&ticket=…` → `302`
5. `GET /idp/oauth2.0/authorize` (again) → `302` → `redirect_uri?code=<code>`
6. `POST /idp/oauth2.0/accessToken?client_id=<id>&client_secret=<secret>&scope=…&code=<code>&redirect_uri=…&grant_type=authorization_code`
   → `200` `{"access_token":…,"token_type":"bearer","expires_in":1800,"refresh_token":…}`

**Two distinct OAuth clients.** This web-login `client_id`/`client_secret` are
**20-char** strings (the ones `ssign` uses, embedded in `auth.rs`). They are
*not* the 64-hex API client found in SimplySign Desktop's plist — that pair
belongs to the PKCS#11/redirector path, which `ssign` does not use.

Every call from here on carries `Authorization: Bearer <access_token>`.

### 2 · Materialize the card  (`card.rs`)

After login, fetch the card and its certificate. Each is an **async task**
(`POST …/tasks` → `303` → `GET` the result):

- `POST /card/v1/cards/tasks`
  → card list: `{profile,label,cardno,pinrequired:false,maxkeysno,validthru}`
- `POST /card/v1/cards/{serial}/keys/tasks` → keys (multipart)
- `POST /card/v1/cards/{serial}/certificates/tasks` → certificates (multipart;
  the signing certificate as DER)

`pinrequired` is **`false`** — the card needs no PIN; the bearer token is the
sole control. The exposed key is RSA-4096; the private key stays in the cloud HSM.

### 3 · Compute the Authenticode digest  (`authenticode.rs`, `msi.rs`, `asn1.rs`)

Locally, hash the PE (or MSI) the Authenticode way → a **SHA-256** digest.
No network, no cloud involvement.

### 4 · Sign — SCS1_ATOM async protocol  (`sign.rs`)

Three calls, all `Authorization: Bearer`:

1. `POST /card/v1/cards/{serial}/certificates/signature` → `202`
   `multipart/form-data`, two parts:
   - **`req`** (`application/json;charset=UTF-8`):
     `{"digests":["<SHA-256 hex, 64 chars>"],"digesttype":"SHA256"}`
   - **`certificate`** (`application/octet-stream`, filename `blob`): the signing
     cert (DER)
   → resp `{"state":…,"atom:link":<poll URL>,"message":…,"ping-after":<ms>}`
2. `GET /scs1/card/v1/cards/{serial}/certificates/signature/task/{taskId}` → `303`
   → `{"state":…,"atom:link":<result URL>,"message":…}` — poll until ready
3. `GET /scs1/card/v1/cards/{serial}/certificates/signature/{resultId}` → `200`
   → `[{"<digest-hex-64>":"<signature 1024-hex = 512 bytes = RSA-4096>"}]`

### 5 · Assemble & embed  (`sign.rs`, `timestamp.rs`, `certs/`)

Wrap [RSA signature + certificate chain + RFC 3161 timestamp from
`http://time.certum.pl/`] into a PKCS#7 blob and embed it in the file. Standard
Authenticode assembly.

---

## Version gotcha — why older clients loop forever

This was the root cause of the early failures, and it was **not** the proxy.

- **SimplySign 2.9.10** (Dec 2017 client): `POST /card/v1/cards/tasks` returns
  **`415`** in a tight loop → the card never inserts → the login page loops.
- **SimplySign 2.9.14** (Mar 2025 binary, *same* PKCS#11 module 1.0.20): speaks
  the current API — clean login, no `/card/tasks` 415 loop.

`ssign` targets the 2.9.14-era protocol directly, so this only matters if you
compare against a captured older-client trace.

---

## Appendix A — superseded hypotheses

The initial **static** analysis of the SimplySign Desktop binary suggested a
more elaborate scheme that the live capture **disproved**. Recorded here so the
strings in the binary don't send anyone back down these paths:

- **SAD (Signature Activation Data).** The binary contains templates for a
  SHA-512-bound, RSA-encrypted `sadEncryptedData` object over
  `{pin, nonce, encryptkeyid, usertoken, cardno, …}`, plus a
  `scs-sad/v1/infrastructureKey` endpoint to fetch the encrypting RSA key.
  **None of this is exercised** for a cloud code-signing cert: the request has
  no `sadEncryptedData`, no `encryptKeyId`, no `pin`, no `nonce`. The SAD path
  belongs to **PIN-protected** cards; ours reports `pinrequired: false`.
- **ROPC login.** `O2::GrantFlow` lists `GrantFlowResourceOwnerPasswordCredentials`
  and the only literal token template in the binary is the `refresh_token` one,
  which made ROPC (`grant_type=password`) look likely. The real login is the
  CAS **authorization-code** flow in §1.
- **The 64-hex API client** (`client_id`/`client_secret` in the plist,
  `OAuth2ProtectClientCredentials=Yes`) is for the redirector/PKCS#11 layer, not
  the web login. `ssign` uses the 20-char web client instead.

## Appendix B — why the PKCS#11 module can't sign on its own

`SimplySignPKCS_64-MS-1.0.20.so` is a **thin shim** with no network code. It
talks to the **CloudConnector / "redirector"** inside SimplySign Desktop over a
named pipe (`cccPipeName`) + shared memory (`shmHandle`) — commands like
`pkislGetUserData`, `pkislGetCertificateList`. The Desktop app holds the OAuth
session and makes the HTTPS calls. So PKCS#11 is useless without the
authenticated Desktop running. `ssign` skips this entire layer and talks HTTPS
to the signing service directly.

## Appendix C — how this was captured

The protocol above was recorded with a **redacting MITM**: mitmproxy over SOCKS5
(the app ignores `http_proxy`, so it was routed via `proxychains-ng`), with the
mitmproxy CA dropped into SimplySign's private `CACerts/` store to defeat
pinning. A mitmproxy addon logged request/response **structure only** — URLs,
param keys, JSON field names and types — and **masked every value** behind a
fail-closed allowlist, so no token, OTP, PIN or signature was ever written to
disk. The redacted trace is what made the capture safe to keep and to reason
about; the exact byte values in this document are lengths (`<43>` = 43 chars),
not secrets.

A real `hello.exe` was signed end-to-end through this flow on 2026-07-10 with
the live certificate (CN = Sylvain GARGASSON, issuer Certum Code Signing 2021
CA), timestamped and verified OK — which is what validated everything above
before `ssign` was written.
