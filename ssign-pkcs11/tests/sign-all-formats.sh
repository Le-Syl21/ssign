#!/usr/bin/env bash
#
# Sign one file of every Authenticode format ssign covers — through the
# ssign-pkcs11 module driven by osslsigncode — and verify each. A live,
# end-to-end smoke test of the whole cloud → PKCS#11 → osslsigncode chain.
#
# The first file logs in to Certum (one OTP); the module caches the session,
# so the remaining files reuse it without another code.
#
# Requirements:
#   - osslsigncode + the OpenSSL PKCS#11 engine (Debian/Ubuntu:
#       apt-get install osslsigncode libengine-pkcs11-openssl)
#   - a built module: cargo build -p ssign-pkcs11 --release
#   - Certum credentials in the environment:
#       CERTUM_EMAIL, and CERTUM_OTP (TOTP seed) or CERTUM_TOKEN (6-digit code)
#
# Usage:
#   CERTUM_EMAIL=you@example.com CERTUM_OTP=SEED \
#     ssign-pkcs11/tests/sign-all-formats.sh
#
# Add more formats by dropping a fixture into the FIXTURES list below — CAB,
# CAT and APPX work too once you provide a sample file (osslsigncode signs
# them; we just don't generate them here).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIX="$ROOT/ssign-core/tests/fixtures"
INTER_DER="$ROOT/ssign-core/src/certs/ccsca2021.der"

# --- locate the built module (release preferred) ---------------------------
MODULE="${SSIGN_PKCS11_MODULE:-}"
if [[ -z "$MODULE" ]]; then
  for cand in "$ROOT"/target/{release,debug}/libssign_pkcs11.{so,dylib}; do
    [[ -f "$cand" ]] && MODULE="$cand" && break
  done
fi
[[ -f "$MODULE" ]] || {
  echo "error: module not found — build it with 'cargo build -p ssign-pkcs11 --release'" >&2
  exit 2
}

: "${CERTUM_EMAIL:?set CERTUM_EMAIL}"
[[ -n "${CERTUM_OTP:-}${CERTUM_TOKEN:-}" ]] || {
  echo "error: set CERTUM_OTP (TOTP seed) or CERTUM_TOKEN (6-digit code)" >&2
  exit 2
}

# --- workspace on disk (not tmpfs) -----------------------------------------
mkdir -p "$ROOT/target"
WORK="$(mktemp -d "$ROOT/target/sign-all.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The Certum intermediate (embedded in ssign-core) as PEM, so the signed
# chain is complete for verification. osslsigncode adds it via -ac.
INTER="$WORK/intermediate.pem"
openssl x509 -inform DER -in "$INTER_DER" -out "$INTER" 2>/dev/null

# --- build the fixture set -------------------------------------------------
# The ones we ship (PE, MSI) plus a couple we generate (a PE DLL is just a
# copy; a PowerShell script is plain text).
cp "$FIX/hello.exe" "$WORK/app.exe"
cp "$FIX/hello.exe" "$WORK/library.dll"
cp "$FIX/test.msi"  "$WORK/installer.msi"
printf 'Write-Host "signed by ssign"\n' > "$WORK/script.ps1"

FIXTURES=(app.exe library.dll installer.msi script.ps1)

# PKCS#11 object URIs — a single cert/key in the token, selected by type.
CERT_URI="pkcs11:object=Certum%20SimplySign%20%28ssign%29;type=cert"
KEY_URI="pkcs11:object=Certum%20SimplySign%20%28ssign%29;type=private"

pass=0
fail=0
printf '\n  %-16s %s\n' "FILE" "RESULT"
printf '  %s\n' "---------------- ----------------------"
for f in "${FIXTURES[@]}"; do
  out="$WORK/signed-$f"
  if osslsigncode sign -pkcs11module "$MODULE" \
        -pkcs11cert "$CERT_URI" -key "$KEY_URI" \
        -ac "$INTER" -h sha256 -t http://time.certum.pl/ \
        -in "$WORK/$f" -out "$out" >/dev/null 2>&1 \
     && osslsigncode verify "$out" >/dev/null 2>&1; then
    printf '  %-16s ✓ signed + verified\n' "$f"
    pass=$((pass + 1))
  else
    printf '  %-16s ✗ FAILED\n' "$f"
    fail=$((fail + 1))
  fi
done
printf '  %s\n' "---------------- ----------------------"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
