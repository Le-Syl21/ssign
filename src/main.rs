//! ssign — Authenticode-sign Windows binaries with a Certum SimplySign cloud cert.
//!
//! This is the command-line front end; the signing pipeline itself lives in the
//! `ssign` library crate ([`auth`], [`card`], [`sign`], [`authenticode`], …) so
//! it can be shared with the `ssign-pkcs11` module.

use ssign_core::{auth, authenticode, card, client, otp, sign, timestamp};

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
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

EXAMPLES
  # manual, on your own machine (paste the current code):
  ssign -e you@example.com -T 123456 app.exe

  # CI / automation (seed once, then unattended):
  export CERTUM_EMAIL=you@example.com CERTUM_OTP=BASE32SEED
  ssign app.exe installer.msi driver.sys
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
                timestamp::fetch(&cli.timestamp_url, &signature)
                    .with_context(|| format!("timestamping {}", file.display()))?,
            )
        };
        let signed = authenticode::finalize(prep, &signature, &cert_der, ts.as_deref())
            .with_context(|| format!("assembling signature for {}", file.display()))?;

        let out = output_path(file, cli.output_dir.as_deref())?;
        write_signed_file(file, &out, &pe, &signed, cli.backup)
            .with_context(|| format!("writing {}", out.display()))?;
        println!("signed {}", out.display());
    }
    Ok(())
}

fn write_signed_file(
    input: &Path,
    out: &Path,
    original: &[u8],
    signed: &[u8],
    backup: bool,
) -> Result<()> {
    let signed_temp = write_synced_temp(out, "signed", signed)?;
    let result = (|| -> Result<()> {
        match fs::metadata(out) {
            Ok(metadata) => fs::set_permissions(&signed_temp, metadata.permissions())
                .with_context(|| format!("preserving permissions for {}", out.display()))?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("reading metadata for {}", out.display()))
            }
        }

        if backup && input == out {
            publish_backup(input, out, original)?;
        }

        atomic_replace(&signed_temp, out)
            .with_context(|| format!("atomically replacing {}", out.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&signed_temp);
    }
    result
}

fn publish_backup(input: &Path, out: &Path, original: &[u8]) -> Result<()> {
    let backup_path = backup_path(input)?;
    let backup_temp = write_synced_temp(out, "backup", original)?;
    let result = fs::hard_link(&backup_temp, &backup_path)
        .with_context(|| format!("creating backup {}", backup_path.display()));
    let _ = fs::remove_file(&backup_temp);
    result
}

fn backup_path(input: &Path) -> Result<PathBuf> {
    let mut backup_name = input
        .file_name()
        .context("input has no file name")?
        .to_os_string();
    backup_name.push(".orig");
    Ok(input.with_file_name(backup_name))
}

fn write_synced_temp(out: &Path, purpose: &str, contents: &[u8]) -> Result<PathBuf> {
    let (mut temp, temp_path) = create_temp_file(out, purpose)?;
    let write_result = (|| -> io::Result<()> {
        temp.write_all(contents)?;
        temp.sync_all()
    })();
    drop(temp);

    if let Err(err) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(err).with_context(|| format!("writing temporary file {}", temp_path.display()));
    }

    Ok(temp_path)
}

fn create_temp_file(out: &Path, purpose: &str) -> Result<(File, PathBuf)> {
    const MAX_ATTEMPTS: u32 = 32;

    let directory = out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = out.file_name().context("output has no file name")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_nanos();

    for attempt in 0..MAX_ATTEMPTS {
        let mut temp_name = file_name.to_os_string();
        temp_name.push(format!(
            ".{purpose}.{}.{}.{}.tmp",
            std::process::id(),
            nonce,
            attempt
        ));
        let temp_path = directory.join(temp_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((file, temp_path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("creating temporary file {}", temp_path.display()))
            }
        }
    }

    bail!(
        "could not create a unique temporary file for {}",
        out.display()
    )
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, out: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let temp_wide: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let out_wide: Vec<u16> = out.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe {
        MoveFileExW(
            temp_wide.as_ptr(),
            out_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(temp: &Path, out: &Path) -> io::Result<()> {
    fs::rename(temp, out)
}

/// Where a signed file is written: into `output_dir` (same file name) if given,
/// otherwise in place.
fn output_path(file: &Path, output_dir: Option<&Path>) -> Result<PathBuf> {
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

    fn unique_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ssign-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn in_place_backup_is_preserved_and_never_overwritten() {
        let dir = unique_test_dir("backup");
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
