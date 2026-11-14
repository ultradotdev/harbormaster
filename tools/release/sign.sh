#!/bin/sh
# Builds the release binary and signs it with a Developer ID, so that macOS
# treats every build as the same program. Permissions granted to it (local
# network access, Keychain approvals) then carry over from one update to
# the next, which they do not for the throwaway signature a plain build has.
#
# The identity is taken from HARBORMASTER_SIGN_IDENTITY, or else the first
# "Developer ID Application" certificate in the Keychain is used.
set -eu
cd "$(dirname "$0")/../.."

identity="${HARBORMASTER_SIGN_IDENTITY:-}"
if [ -z "$identity" ]; then
  identity="$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -n 1)"
fi
if [ -z "$identity" ]; then
  echo "No Developer ID Application certificate found. Set HARBORMASTER_SIGN_IDENTITY." >&2
  exit 1
fi

. tools/release/flags.sh
cargo build --release
binary=target/release/harbormaster
# The hardened runtime is what notarization requires later; the secure
# timestamp keeps the signature valid after the certificate expires.
codesign --force --options runtime --timestamp --identifier dev.ultra.harbormaster --sign "$identity" "$binary"
codesign --verify --strict --verbose=2 "$binary"
codesign -dv "$binary" 2>&1 | grep -E "^(Identifier|TeamIdentifier|Timestamp|Authority=Developer ID Application)" || true
echo "Signed $binary"
