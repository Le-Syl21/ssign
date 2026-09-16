#!/usr/bin/env bash
#
# Live checks run against the Certum cloud before a release is signed: every
# way a user drives ssign must produce a valid signature, or nothing ships.
#
#   1. PKCS#11 mechanisms (pkcs11-tool): CKM_SHA256_RSA_PKCS, fed the message in
#      several parts (C_SignUpdate/C_SignFinal), and CKM_RSA_PKCS, fed a SHA-256
#      DigestInfo, give the same signature, and it verifies with the public key.
#      Includes a 32-byte and a 51-byte message, which are still messages.
#   2. jsign through Java's SunPKCS11 (issue #11): PE + MSI, verified.
#   3. osslsigncode through the module: every format (sign-all-formats.sh).
#   4. The ssign CLI on a PE file, verified.
#
# The first sign logs in (CERTUM_OTP or CERTUM_TOKEN); the session cache makes
# every later step, in every process, reuse that login.
#
# Requirements: pkcs11-tool (opensc), osslsigncode + libengine-pkcs11-openssl,
# openssl, java 11+, and the jsign jar (JSIGN_JAR).
#
# Usage:
#   CERTUM_EMAIL=you@example.com CERTUM_OTP=SEED JSIGN_JAR=jsign.jar \
#     tests/pre-sign.sh target/release/ssign target/release/libssign_pkcs11.so

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/ssign-core/tests/fixtures"
INTER_DER="$ROOT/ssign-core/src/certs/ccsca2021.der"

SSIGN="$(realpath "${1:?usage: pre-sign.sh <ssign binary> <PKCS#11 module>}")"
MODULE="$(realpath "${2:?usage: pre-sign.sh <ssign binary> <PKCS#11 module>}")"
: "${CERTUM_EMAIL:?set CERTUM_EMAIL}"
[[ -n "${CERTUM_OTP:-}${CERTUM_TOKEN:-}" ]] || {
  echo "error: set CERTUM_OTP (TOTP seed) or CERTUM_TOKEN (6-digit code)" >&2
  exit 2
}
: "${JSIGN_JAR:?set JSIGN_JAR to the jsign jar}"

TSA=http://time.certum.pl/
LABEL="Certum SimplySign (ssign)"

mkdir -p "$ROOT/target"
WORK="$(mktemp -d "$ROOT/target/pre-sign.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

failures=0
ok() { printf '  ✓ %s\n' "$1"; }
ko() { printf '  ✗ %s\n' "$1"; failures=$((failures + 1)); }

# Check the facts osslsigncode reports, not just its exit code: a digest
# mismatch or a missing timestamp still prints a lot of reassuring lines.
verify() {
  local out
  out=$(osslsigncode verify -in "$1" 2>&1) || true
  if grep -q "MISMATCH" <<<"$out"; then
    echo "$out"; echo "  $1: Authenticode digest mismatch"; return 1
  fi
  if grep -q "Timestamp is not available" <<<"$out"; then
    echo "$out"; echo "  $1: no timestamp"; return 1
  fi
  if ! grep -q "Signature verification: ok" <<<"$out"; then
    echo "$out"; return 1
  fi
}

p11() { pkcs11-tool --module "$MODULE" "$@"; }

# --- 1. PKCS#11 mechanisms -------------------------------------------------
echo "== PKCS#11 mechanisms (pkcs11-tool)"

# The certificate from the module itself, and the Certum intermediate.
if p11 --read-object --type cert --label "$LABEL" -o "$WORK/leaf.der" >/dev/null 2>&1; then
  openssl x509 -inform DER -in "$WORK/leaf.der" -out "$WORK/leaf.pem"
  openssl x509 -in "$WORK/leaf.pem" -pubkey -noout >"$WORK/pub.pem"
  ok "certificate read from the module"
else
  ko "cannot read the certificate from the module"
  p11 --read-object --type cert --label "$LABEL" -o "$WORK/leaf.der"
  exit 1
fi
openssl x509 -inform DER -in "$INTER_DER" -out "$WORK/inter.pem"

# 1 MiB so pkcs11-tool streams it through several C_SignUpdate calls.
head -c 1048576 /dev/urandom >"$WORK/msg-large"
head -c 32 /dev/urandom >"$WORK/msg-32"
# 51 bytes shaped exactly like a SHA-256 DigestInfo.
{ printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
  head -c 32 /dev/urandom; } >"$WORK/msg-51"

for m in msg-large msg-32 msg-51; do
  msg="$WORK/$m"
  if ! p11 --sign --mechanism SHA256-RSA-PKCS --label "$LABEL" \
        -i "$msg" -o "$msg.sha256-rsa" >/dev/null 2>&1; then
    ko "$m: CKM_SHA256_RSA_PKCS sign failed"
    p11 --sign --mechanism SHA256-RSA-PKCS --label "$LABEL" -i "$msg" -o "$msg.sha256-rsa"
    continue
  fi
  if openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$msg.sha256-rsa" "$msg" >/dev/null; then
    ok "$m: CKM_SHA256_RSA_PKCS signature verifies"
  else
    ko "$m: CKM_SHA256_RSA_PKCS signature does not verify"
  fi
  { printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    openssl dgst -sha256 -binary "$msg"; } >"$msg.digestinfo"
  if p11 --sign --mechanism RSA-PKCS --label "$LABEL" \
        -i "$msg.digestinfo" -o "$msg.rsa" >/dev/null 2>&1 \
     && cmp -s "$msg.sha256-rsa" "$msg.rsa"; then
    ok "$m: CKM_RSA_PKCS over its DigestInfo gives the same signature"
  else
    ko "$m: CKM_RSA_PKCS over its DigestInfo differs or failed"
  fi
done

# --- 2. jsign (Java SunPKCS11) ---------------------------------------------
echo "== jsign $(basename "$JSIGN_JAR") through SunPKCS11"
printf 'name = ssign\nlibrary = %s\n' "$MODULE" >"$WORK/pkcs11.cfg"
# The module only holds the leaf; jsign gets the full chain from a .p7b.
openssl crl2pkcs7 -nocrl -certfile "$WORK/leaf.pem" -certfile "$WORK/inter.pem" \
  -outform DER -out "$WORK/chain.p7b"
cp "$FIX/hello.exe" "$WORK/jsign.exe"
cp "$FIX/test.msi" "$WORK/jsign.msi"
for f in jsign.exe jsign.msi; do
  if java -jar "$JSIGN_JAR" --storetype PKCS11 --keystore "$WORK/pkcs11.cfg" \
        --storepass "" --alias "$LABEL" --certfile "$WORK/chain.p7b" \
        --alg SHA-256 --tsaurl "$TSA" "$WORK/$f" >"$WORK/$f.log" 2>&1 \
     && verify "$WORK/$f"; then
    ok "$f signed by jsign and verified"
  else
    ko "$f: jsign failed"
    cat "$WORK/$f.log"
  fi
done

# --- 3. osslsigncode, every format -----------------------------------------
echo "== osslsigncode through the module"
if SSIGN_PKCS11_MODULE="$MODULE" "$ROOT/ssign-pkcs11/tests/sign-all-formats.sh"; then
  ok "every format signed and verified"
else
  ko "sign-all-formats.sh failed"
fi

# --- 4. ssign CLI ------------------------------------------------------------
echo "== ssign CLI"
cp "$FIX/hello.exe" "$WORK/cli.exe"
if "$SSIGN" -n "ssign pre-sign check" "$WORK/cli.exe" >"$WORK/cli.log" 2>&1 \
   && verify "$WORK/cli.exe"; then
  ok "cli.exe signed by ssign and verified"
else
  ko "ssign CLI failed"
  cat "$WORK/cli.log"
fi

echo
if [[ $failures -eq 0 ]]; then
  echo "pre-sign checks: all passed"
else
  echo "pre-sign checks: $failures failed"
  exit 1
fi
