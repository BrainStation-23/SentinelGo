#!/usr/bin/env bash
# Notarizes Developer ID-signed macOS agent binaries with Apple (#352, #491).
#
# Usage (macOS only, run by the release workflow's sign job after
# scripts/macos-codesign.sh):
#   APPLE_NOTARY_KEY_P8=<contents of AuthKey_XXXXXXXXXX.p8> \
#   APPLE_NOTARY_KEY_ID=<key ID> APPLE_NOTARY_ISSUER_ID=<issuer UUID> \
#     scripts/macos-notarize.sh dist/sentinelgo-darwin-amd64 dist/sentinelgo-darwin-arm64
#
# The key is an App Store Connect API team key with Developer access.
#
# Bare binaries can't be stapled, so the ticket stays with Apple: Gatekeeper
# looks it up online by the binary's code hash. Notarizing doesn't change the
# files, so the Ed25519 signatures and checksums made afterwards still match.
#
# Exit status:
#   0  notarized, or skipped (no key, or not a Developer ID signature), or
#      Apple couldn't be reached in time. The last two print a warning: the
#      release goes out signed, and the same binaries can be notarized later
#      with this script, since the ticket is tied to the code hash.
#   1  Apple rejected the binaries (the log is printed), or bad usage.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macos-notarize: needs macOS (xcrun notarytool)" >&2
    exit 1
fi
if [[ $# -eq 0 ]]; then
    echo "usage: $0 <binary>..." >&2
    exit 1
fi

if [[ -z "${APPLE_NOTARY_KEY_P8:-}" ]]; then
    echo "::warning::APPLE_NOTARY_KEY_P8 is not set: the macOS binaries are not notarized."
    exit 0
fi
: "${APPLE_NOTARY_KEY_ID:?APPLE_NOTARY_KEY_ID is not set}"
: "${APPLE_NOTARY_ISSUER_ID:?APPLE_NOTARY_ISSUER_ID is not set}"

# Apple notarizes only Developer ID signatures with a secure timestamp and the
# hardened runtime. With an internal CA's certificate there's nothing to do.
for bin in "$@"; do
    info="$(codesign -dv --verbose=2 "$bin" 2>&1 || true)"
    if ! grep -q '^Authority=Developer ID Application: ' <<<"$info"; then
        echo "::notice::$bin isn't signed with Developer ID: skipping notarization."
        exit 0
    fi
    if ! grep -q '^Timestamp=' <<<"$info"; then
        echo "macos-notarize: $bin has no secure timestamp; sign it with scripts/macos-codesign.sh" >&2
        exit 1
    fi
    if ! grep -q 'flags=.*(runtime)' <<<"$info"; then
        echo "macos-notarize: $bin isn't signed with the hardened runtime" >&2
        exit 1
    fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
key="$work/AuthKey_${APPLE_NOTARY_KEY_ID}.p8"
printf '%s\n' "$APPLE_NOTARY_KEY_P8" > "$key"
auth=(--key "$key" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID")

# One submission for all binaries. ditto keeps the signatures intact.
mkdir "$work/bin"
cp "$@" "$work/bin/"
ditto -c -k --keepParent "$work/bin" "$work/sentinelgo-darwin.zip"

result="$work/result.json"
# notarytool exits non-zero both when Apple rejects the binaries and when it
# can't reach Apple, so the status in its output decides which it was.
xcrun notarytool submit "$work/sentinelgo-darwin.zip" "${auth[@]}" \
    --wait --timeout 30m --output-format json > "$result" || true
status="$(plutil -extract status raw -o - "$result" 2>/dev/null || true)"
id="$(plutil -extract id raw -o - "$result" 2>/dev/null || true)"
echo "Notarization submission ${id:-?}: ${status:-no result}"

case "$status" in
    Accepted)
        for bin in "$@"; do
            echo "Notarized: $bin"
        done
        ;;
    Invalid | Rejected)
        echo "macos-notarize: Apple rejected the binaries. Log:" >&2
        xcrun notarytool log "$id" "${auth[@]}" >&2 || true
        exit 1
        ;;
    *)
        cat "$result" >&2 || true
        echo "::warning::Notarization didn't finish (${status:-no response from Apple}, submission ${id:-none}). The binaries are signed but not notarized yet; check with: xcrun notarytool info ${id:-<id>}"
        ;;
esac
