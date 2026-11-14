#!/usr/bin/env bash
# Signs macOS agent binaries with the certificate in MACOS_CODESIGN_P12 (#352).
#
# Usage (macOS only, run by the release workflow's sign job):
#   MACOS_CODESIGN_P12=<base64 .p12> MACOS_CODESIGN_P12_PASSWORD=<password> \
#     scripts/macos-codesign.sh dist/sentinelgo-darwin-amd64 dist/sentinelgo-darwin-arm64
#
# The .p12 holds one code-signing identity: a certificate (with the
# codeSigning extended key usage), its private key and, ideally, the CA
# certificates above it, so the signature embeds the chain. Today that is a
# certificate from our internal CA, whose root MDM installs on managed Macs;
# a Developer ID Application identity drops in the same way later.
#
# The identifier never changes: profiles that grant the agent permissions
# (Full Disk Access, notifications) pin it with the certificate.
#
# The certificate is imported into a throwaway keychain that is deleted on
# exit, so nothing outlives the job.
set -euo pipefail

IDENTIFIER="com.sentinelgo.agent"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macos-codesign: needs macOS (codesign)" >&2
    exit 1
fi
if [[ $# -eq 0 ]]; then
    echo "usage: $0 <binary>..." >&2
    exit 2
fi
: "${MACOS_CODESIGN_P12:?MACOS_CODESIGN_P12 is not set}"
: "${MACOS_CODESIGN_P12_PASSWORD:?MACOS_CODESIGN_P12_PASSWORD is not set}"

work="$(mktemp -d)"
keychain="$work/signing.keychain-db"
keychain_password="$(openssl rand -hex 24)"
cleanup() {
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

printf '%s' "$MACOS_CODESIGN_P12" | base64 --decode > "$work/identity.p12"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$work/identity.p12" -k "$keychain" -P "$MACOS_CODESIGN_P12_PASSWORD" \
    -T /usr/bin/codesign -f pkcs12 >/dev/null
rm -f "$work/identity.p12"
# Let codesign use the key without a GUI prompt.
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
# codesign finds identities and their chains through the search list.
existing="$(security list-keychains -d user | tr -d '"' | xargs)"
# shellcheck disable=SC2086 # the existing keychains are separate arguments
security list-keychains -d user -s "$keychain" $existing

# Without -v, find-identity also lists identities whose root isn't trusted on
# this runner, which an internal CA's isn't. The keychain holds one identity.
identity="$(security find-identity "$keychain" | awk '/^ *[0-9]+\) [0-9A-F]{40} /{print $2; exit}')"
if [[ -z "$identity" ]]; then
    echo "macos-codesign: no signing identity in MACOS_CODESIGN_P12" >&2
    exit 1
fi
echo "Signing with identity $identity"

for bin in "$@"; do
    # The hardened runtime is what notarization will need with a Developer
    # ID certificate. The agent only loads system frameworks, which it
    # allows. No timestamp: Apple's timestamp server is for Apple-issued
    # certificates.
    codesign --force --sign "$identity" --keychain "$keychain" \
        --identifier "$IDENTIFIER" --options runtime --timestamp=none "$bin"
    codesign --verify --strict --verbose=2 "$bin"
    codesign -dv --verbose=2 "$bin" 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier|CodeDirectory)='
    codesign -d -r- "$bin" 2>&1 | grep '^designated'
done
