//! ssign — Authenticode-sign Windows binaries with a Certum SimplySign cloud cert.
//!
//! The whole signing pipeline is plain HTTPS against Certum's cloud plus local
//! Authenticode/PKCS#7 assembly, so it runs on Linux, macOS and Windows alike —
//! you do NOT need Windows to sign a Windows binary.
#![allow(dead_code)] // pipeline modules are stubs until each step lands

mod asn1;
mod auth;
mod authenticode;
mod card;
mod client;
mod msi;
mod otp;
mod sign;
mod timestamp;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Authenticode-sign Windows binaries (exe/dll/msi/sys) with a Certum SimplySign
/// cloud certificate — cross-platform, no GUI, no vendor stack.
#[derive(Parser, Debug)]
#[command(name = "ssign", version, about, long_about = None)]
#[command(after_long_help = USAGE_NOTES)]
struct Cli {
    /// Files to sign (Authenticode: exe/dll/msi/sys). Signed in place unless -o.
    #[arg(value_name = "FILES", required = true)]
    files: Vec<PathBuf>,

    /// Certum account e-mail.
    #[arg(short = 'e', long, env = "CERTUM_EMAIL", value_name = "EMAIL")]
    email: String,

    /// TOTP **seed** (base32). ssign derives the 6-digit code itself — use this
    /// for CI / full automation. Mutually exclusive with --token.
    #[arg(short = 'O', long, env = "CERTUM_OTP", value_name = "SEED")]
    otp: Option<String>,

    /// A **current** 6-digit code from your authenticator app — use this for a
    /// one-off manual signing on your own machine. Mutually exclusive with --otp.
    #[arg(short = 'T', long, env = "CERTUM_TOKEN", value_name = "CODE")]
    token: Option<String>,

    /// Write signed files here instead of overwriting them in place.
    #[arg(short = 'o', long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// RFC3161 timestamp authority.
    #[arg(long, value_name = "URL", default_value = "http://time.certum.pl/")]
    timestamp_url: String,

    /// Permit an HTTP timestamp authority after explicitly acknowledging its
    /// transport risk. Prefer HTTPS whenever the authority supports it.
    #[arg(long)]
    allow_insecure_timestamp: bool,

    /// Signature description embedded in the file.
    #[arg(short = 'n', long, value_name = "TEXT")]
    name: Option<String>,

    /// Signature info URL embedded in the file.
    #[arg(short = 'u', long, value_name = "URL")]
    url: Option<String>,

    /// When signing in place, keep the original next to it as `<file>.orig`.
    #[arg(long)]
    backup: bool,

    #[arg(short, long)]
    verbose: bool,
}

/// One-time code resolved from either --otp (seed) or --token (literal code).
enum Otp {
    /// A base32 TOTP seed; the 6-digit code is derived at run time.
    Seed(String),
    /// A literal 6-digit code, valid only for its ~30 s window.
    Code(String),
}

const USAGE_NOTES: &str = "\
AUTHENTICATION (exactly one of --otp / --token):
  --otp   <SEED>   your TOTP seed; ssign computes the 6-digit code. Best for CI:
                   set it once as the CERTUM_OTP secret and every run is hands-off.
  --token <CODE>   a code you read from your authenticator right now. Best for a
                   manual, local sign when you'd rather not store the seed.

Every flag also reads an environment variable (CERTUM_EMAIL / CERTUM_OTP /
CERTUM_TOKEN). Prefer the env vars for secrets — a value passed on the command
line is visible in your shell history and in the process list.

TIMESTAMPING
  Certum's public TSA currently serves RFC3161 over HTTP. Passing
  --allow-insecure-timestamp explicitly acknowledges that transport risk. Use
  an HTTPS TSA with --timestamp-url whenever one is available.

EXAMPLES
  # manual, on your own machine (paste the current code):
  ssign --allow-insecure-timestamp -e you@example.com -T 123456 app.exe

  # CI / automation (seed once, then unattended):
  export CERTUM_EMAIL=you@example.com CERTUM_OTP=BASE32SEED
  ssign --allow-insecure-timestamp app.exe installer.msi driver.sys
";

fn main() -> Result<()> {
    let cli = Cli::parse();

    let otp = match (&cli.otp, &cli.token) {
        (Some(_), Some(_)) => bail!("pass only one of --otp (seed) or --token (code)"),
        (None, None) => bail!("authentication required: pass --otp <seed> or --token <code> (or set CERTUM_OTP / CERTUM_TOKEN)"),
        (Some(seed), None) => Otp::Seed(seed.clone()),
        (None, Some(code)) => Otp::Code(code.clone()),
    };

    run(&cli, otp).context("signing failed")
}

/// Resolve the current 6-digit code from either the seed or a literal token.
fn resolve_code(otp: &Otp) -> Result<String> {
    match otp {
        Otp::Code(code) => Ok(code.clone()),
        Otp::Seed(seed) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock before 1970")?
                .as_secs();
            Ok(otp::Totp::parse(seed)
                .context("invalid TOTP seed / otpauth URI in --otp / CERTUM_OTP")?
                .code_at(now))
        }
    }
}

fn run(cli: &Cli, otp: Otp) -> Result<()> {
    let code = resolve_code(&otp)?;
    timestamp::validate_url(&cli.timestamp_url, cli.allow_insecure_timestamp)?;
    if cli.timestamp_url.starts_with("http://") {
        eprintln!(
            "warning: timestamping over HTTP was explicitly allowed; a network attacker can disrupt the timestamp"
        );
    }

    // 1. authenticate (once for the whole batch).
    if cli.verbose {
        eprintln!("· logging in as {}…", cli.email);
    }
    let token = auth::login(&cli.email, &code).context("login")?.0;

    // 2. materialize the card + certificate (once).
    let http = client::client()?;
    let card = card::fetch(&http, &token).context("fetching card/certificate")?;
    if cli.verbose {
        eprintln!("· card {} ready, certificate fetched", card.serial);
    }

    // 3. sign each file, reusing the same session.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_secs();
    let signing_time = authenticode::utc_time(now);

    for file in &cli.files {
        if cli.verbose {
            eprintln!("· signing {}…", file.display());
        }
        let pe = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
        let prep =
            authenticode::prepare(&pe, cli.name.as_deref(), cli.url.as_deref(), &signing_time)
                .with_context(|| format!("preparing {}", file.display()))?;
        let signature = sign::request(&http, &token, &card, &prep.to_be_signed)
            .with_context(|| format!("remote signing {}", file.display()))?;
        let cert_der = authenticode::pem_to_der(&card.certificate_pem)?;
        let ts = if cli.timestamp_url.is_empty() {
            None
        } else {
            Some(
                timestamp::fetch(&cli.timestamp_url, &signature, cli.allow_insecure_timestamp)
                    .with_context(|| format!("timestamping {}", file.display()))?,
            )
        };
        let signed = authenticode::finalize(prep, &signature, &cert_der, ts.as_deref())
            .with_context(|| format!("assembling signature for {}", file.display()))?;

        let out = output_path(file, cli.output_dir.as_deref())?;
        write_signed_file(file, &out, &pe, &signed, cli.backup)?;
        println!("signed {}", out.display());
    }
    Ok(())
}

/// Write a signed output safely: an in-place backup is never overwritten, and
/// the completed output is swapped in only after its bytes have reached disk.
fn write_signed_file(
    input: &std::path::Path,
    out: &std::path::Path,
    original: &[u8],
    signed: &[u8],
    backup: bool,
) -> Result<()> {
    if backup && out == input {
        let mut backup_path = OsString::from(input.as_os_str());
        backup_path.push(".orig");
        write_new_file_atomically(&PathBuf::from(backup_path), original)
            .context("writing backup (refusing to overwrite an existing .orig file)")?;
    }
    write_file_atomically(out, signed).with_context(|| format!("writing {}", out.display()))
}

fn temp_file_path(path: &std::path::Path, attempt: u8) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path.file_name().context("output has no file name")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_nanos();
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".ssign-{}-{nonce}-{attempt}.tmp",
        std::process::id()
    ));
    Ok(parent.join(temp_name))
}

fn write_temp_file(path: &std::path::Path, bytes: &[u8]) -> Result<PathBuf> {
    for attempt in 0..10 {
        let temp = temp_file_path(path, attempt)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    let _ = std::fs::remove_file(&temp);
                    return Err(err).context("writing temporary output");
                }
                return Ok(temp);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).context("creating temporary output"),
        }
    }
    bail!("could not allocate a temporary output file")
}

fn write_new_file_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let temp = write_temp_file(path, bytes)?;
    // A same-directory hard link publishes the complete temp file atomically
    // and fails if a previous backup exists; it never replaces user data.
    let result = std::fs::hard_link(&temp, path).context("publishing new file");
    let _ = std::fs::remove_file(&temp);
    result
}

fn write_file_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let permissions = std::fs::metadata(path).ok().map(|m| m.permissions());
    let temp = write_temp_file(path, bytes)?;
    if let Some(permissions) = permissions {
        std::fs::set_permissions(&temp, permissions).context("preserving output permissions")?;
    }
    let result = replace_file_atomically(&temp, path);
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_file_atomically(temp: &std::path::Path, path: &std::path::Path) -> Result<()> {
    std::fs::rename(temp, path).context("replacing output atomically")
}

#[cfg(windows)]
fn replace_file_atomically(temp: &std::path::Path, path: &std::path::Path) -> Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let source: Vec<u16> = temp.as_os_str().encode_wide().chain(once(0)).collect();
    let target: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("replacing output atomically");
    }
    Ok(())
}

/// Where a signed file is written: into `output_dir` (same file name) if given,
/// otherwise in place.
fn output_path(file: &std::path::Path, output_dir: Option<&std::path::Path>) -> Result<PathBuf> {
    match output_dir {
        None => Ok(file.to_path_buf()),
        Some(dir) => {
            std::fs::create_dir_all(dir).context("creating output dir")?;
            let name = file.file_name().context("input has no file name")?;
            Ok(dir.join(name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_place_backup_is_preserved_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "ssign-main-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("app.exe");
        std::fs::write(&input, b"original").unwrap();

        write_signed_file(&input, &input, b"original", b"signed", true).unwrap();
        assert_eq!(std::fs::read(&input).unwrap(), b"signed");
        assert_eq!(
            std::fs::read(dir.join("app.exe.orig")).unwrap(),
            b"original"
        );
        assert!(write_signed_file(&input, &input, b"signed", b"new", true).is_err());

        std::fs::remove_dir_all(dir).unwrap();
    }
}
