#!/usr/bin/env bash
# Builds the generic macOS distribution package (#352):
# sentinelgo-darwin-universal.pkg, which MDM installs on every Mac with
# InstallEnterpriseApplication (Compliance-OS#555).
#
# Usage (macOS only, run by the release workflow's pkg job):
#   [MACOS_INSTALLER_P12=<base64 .p12> MACOS_INSTALLER_P12_PASSWORD=<password>] \
#   [APPLE_NOTARY_KEY_P8=... APPLE_NOTARY_KEY_ID=... APPLE_NOTARY_ISSUER_ID=...] \
#     scripts/macos-pkg.sh v4.1.0 dist/sentinelgo-darwin-amd64 dist/sentinelgo-darwin-arm64 \
#       dist/sentinelgo-darwin-universal.pkg
#
# The package:
#   - holds one universal binary at /opt/sentinelgo/sentinelgo, made with
#     lipo from the two binaries the sign job already code-signed (each slice
#     keeps its signature);
#   - has no config.json: the agent enrolls on first start from the MDM
#     managed preferences com.sentinelgo.agent (#360, Compliance-OS#543);
#   - stops a running agent before the files are replaced (preinstall), and
#     installs and starts the launchd job with `sentinelgo -install`
#     (postinstall), the same code path as installation-doc/install.sh, so the
#     plist arguments live in one place (cmd/sentinelgo/service/launchd.go).
#
# Signing: MDM only installs packages signed with a Developer ID Installer
# certificate. With MACOS_INSTALLER_P12 the package is signed with productsign
# and, when the notary key is set, notarized and stapled. Without it the
# package is built unsigned, with a warning, and the script prints
# signed=false so the release leaves it out of sentinelgo-installers.json.
#
# Prints signed=true|false, and writes it to $GITHUB_OUTPUT when that is set.
set -euo pipefail

IDENTIFIER="com.sentinelgo.agent" # the package receipt; Compliance-OS pkg.ts and installer-metadata.ts use the same
MIN_MACOS="11.0"                  # Go 1.23+ binaries need macOS 11

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macos-pkg: needs macOS (lipo, pkgbuild, productbuild)" >&2
    exit 1
fi
if [[ $# -ne 4 ]]; then
    echo "usage: $0 <tag> <darwin-amd64> <darwin-arm64> <out.pkg>" >&2
    exit 2
fi
tag="$1" amd64="$2" arm64="$3" out="$4"
if [[ ! "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    echo "macos-pkg: $tag is not a vMAJOR.MINOR.PATCH tag" >&2
    exit 2
fi
version="${BASH_REMATCH[1]}"

emit_signed() {
    echo "signed=$1"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "signed=$1" >> "$GITHUB_OUTPUT"
    fi
}

work="$(mktemp -d)"
keychain="$work/installer.keychain-db"
cleanup() {
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# ── Payload: the universal binary ────────────────────────────────────────────
root="$work/root"
mkdir -p "$root/opt/sentinelgo"
lipo -create -output "$root/opt/sentinelgo/sentinelgo" "$amd64" "$arm64"
chmod 755 "$root/opt/sentinelgo" "$root/opt/sentinelgo/sentinelgo"
lipo -info "$root/opt/sentinelgo/sentinelgo"
# A code-signed slice must still verify after lipo; unsigned builds have no
# signature to check (the agent signs them ad-hoc at install).
if codesign -dv "$root/opt/sentinelgo/sentinelgo" >/dev/null 2>&1; then
    codesign --verify --strict --all-architectures --verbose=2 "$root/opt/sentinelgo/sentinelgo"
fi

# ── Scripts ──────────────────────────────────────────────────────────────────
scripts="$work/scripts"
mkdir -p "$scripts"
cat > "$scripts/preinstall" <<'EOF'
#!/bin/sh
# Stop a running agent so its binary can be replaced. Not an error when none.
launchctl bootout system/com.sentinelgo.agent >/dev/null 2>&1 || true
exit 0
EOF
cat > "$scripts/postinstall" <<'EOF'
#!/bin/sh
set -e
chown root:wheel /opt/sentinelgo /opt/sentinelgo/sentinelgo
chmod 755 /opt/sentinelgo /opt/sentinelgo/sentinelgo
# Writes /Library/LaunchDaemons/com.sentinelgo.agent.plist, bootstraps and
# starts it, and keeps a Developer ID signature (signs ad-hoc otherwise).
/opt/sentinelgo/sentinelgo -install
EOF
chmod 755 "$scripts/preinstall" "$scripts/postinstall"

# ── Component and product packages ───────────────────────────────────────────
pkgbuild --root "$root" --scripts "$scripts" --identifier "$IDENTIFIER" \
    --version "$version" --install-location / --ownership recommended \
    "$work/sentinelgo.pkg"

cat > "$work/Distribution" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>SentinelGo Agent $version</title>
    <options customize="never" require-scripts="true" hostArchitectures="x86_64,arm64"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="$MIN_MACOS"/>
        </allowed-os-versions>
    </volume-check>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="$IDENTIFIER"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$IDENTIFIER" visible="false">
        <pkg-ref id="$IDENTIFIER"/>
    </choice>
    <pkg-ref id="$IDENTIFIER" version="$version" onConclusion="none">sentinelgo.pkg</pkg-ref>
</installer-gui-script>
EOF
productbuild --distribution "$work/Distribution" --package-path "$work" "$work/unsigned.pkg"

# ── Sign, notarize, staple ───────────────────────────────────────────────────
if [[ -z "${MACOS_INSTALLER_P12:-}" ]]; then
    cp "$work/unsigned.pkg" "$out"
    echo "::warning::MACOS_INSTALLER_P12 is not set: $out is unsigned. MDM can't install it, so it is left out of sentinelgo-installers.json."
    pkgutil --check-signature "$out" || true
    emit_signed false
    exit 0
fi
: "${MACOS_INSTALLER_P12_PASSWORD:?MACOS_INSTALLER_P12_PASSWORD is not set}"

keychain_password="$(openssl rand -hex 24)"
printf '%s' "$MACOS_INSTALLER_P12" | base64 --decode > "$work/identity.p12"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$work/identity.p12" -k "$keychain" -P "$MACOS_INSTALLER_P12_PASSWORD" \
    -T /usr/bin/productsign -f pkcs12 >/dev/null
rm -f "$work/identity.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
existing="$(security list-keychains -d user | tr -d '"' | xargs)"
# shellcheck disable=SC2086 # the existing keychains are separate arguments
security list-keychains -d user -s "$keychain" $existing

# productsign takes the certificate's common name. The keychain holds one.
identity="$(security find-certificate -a -c "Developer ID Installer: " -Z "$keychain" 2>/dev/null |
    awk -F'"' '/"labl"<blob>=/{print $4; exit}')"
if [[ -z "$identity" ]]; then
    echo "macos-pkg: no \"Developer ID Installer\" certificate in MACOS_INSTALLER_P12" >&2
    exit 1
fi
echo "Signing the package with $identity"
productsign --sign "$identity" --keychain "$keychain" --timestamp "$work/unsigned.pkg" "$out"
pkgutil --check-signature "$out"

if [[ -z "${APPLE_NOTARY_KEY_P8:-}" ]]; then
    echo "::warning::APPLE_NOTARY_KEY_P8 is not set: $out is signed but not notarized."
    emit_signed true
    exit 0
fi
: "${APPLE_NOTARY_KEY_ID:?APPLE_NOTARY_KEY_ID is not set}"
: "${APPLE_NOTARY_ISSUER_ID:?APPLE_NOTARY_ISSUER_ID is not set}"
umask 077
key="$work/AuthKey_${APPLE_NOTARY_KEY_ID}.p8"
printf '%s\n' "$APPLE_NOTARY_KEY_P8" > "$key"
auth=(--key "$key" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID")

result="$work/result.json"
# As in macos-notarize.sh: the status in the output tells a rejection from
# Apple being unreachable.
xcrun notarytool submit "$out" "${auth[@]}" --wait --timeout 30m --output-format json > "$result" || true
status="$(plutil -extract status raw -o - "$result" 2>/dev/null || true)"
id="$(plutil -extract id raw -o - "$result" 2>/dev/null || true)"
echo "Notarization submission ${id:-?}: ${status:-no result}"
case "$status" in
    Accepted)
        # Stapling changes the package's bytes, so it happens before the
        # release signs and checksums it.
        xcrun stapler staple "$out"
        xcrun stapler validate "$out"
        ;;
    Invalid | Rejected)
        echo "macos-pkg: Apple rejected the package. Log:" >&2
        xcrun notarytool log "$id" "${auth[@]}" >&2 || true
        exit 1
        ;;
    *)
        cat "$result" >&2 || true
        echo "::warning::Notarization of the package didn't finish (${status:-no response from Apple}, submission ${id:-none}). It is signed but not notarized or stapled."
        ;;
esac
emit_signed true
