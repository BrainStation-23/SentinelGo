#!/bin/bash

# Regenerate the embedded DLP secrets ruleset from a pinned betterleaks tag.
#
#   scripts/update-dlp-rules.sh            # regenerate from the pinned tag
#   scripts/update-dlp-rules.sh v1.10.0    # bump the pin and regenerate
#
# Writes internal/dlp/detect/secrets/rules.json and tools/dlprules/catalog.json
# (the detector catalog seed for the backend), then prints which rules were
# added or removed so the PR can list them. A catalog change needs a matching
# seed migration in the backend.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIN_FILE="$ROOT/tools/dlprules/BETTERLEAKS_TAG"
RULES="$ROOT/internal/dlp/detect/secrets/rules.json"
CATALOG="$ROOT/tools/dlprules/catalog.json"
REPO="https://github.com/betterleaks/betterleaks"

TAG="${1:-$(tr -d '[:space:]' < "$PIN_FILE")}"
COMMIT="$(git ls-remote "$REPO" "refs/tags/$TAG^{}" "refs/tags/$TAG" | head -n1 | cut -f1)"
if [ -z "$COMMIT" ]; then
    echo "tag $TAG not found in $REPO" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL "https://raw.githubusercontent.com/betterleaks/betterleaks/$COMMIT/config/betterleaks.toml" -o "$WORK/betterleaks.toml"
curl -fsSL "https://raw.githubusercontent.com/betterleaks/betterleaks/$COMMIT/LICENSE" -o "$ROOT/internal/dlp/detect/secrets/LICENSE.betterleaks"

ids() { [ -f "$1" ] && grep -o '"id": "[^"]*"' "$1" | cut -d'"' -f4 | sort || true; }
ids "$CATALOG" > "$WORK/before.txt"

(cd "$ROOT/tools/dlprules" && go run . -in "$WORK/betterleaks.toml" -tag "$TAG" -commit "$COMMIT" -out "$RULES" -catalog "$CATALOG")
echo "$TAG" > "$PIN_FILE"

ids "$CATALOG" > "$WORK/after.txt"
echo ""
echo "betterleaks $TAG ($COMMIT)"
echo "Added detectors:"
comm -13 "$WORK/before.txt" "$WORK/after.txt" | sed 's/^/  + /'
echo "Removed detectors (a backend policy rule may still use these):"
comm -23 "$WORK/before.txt" "$WORK/after.txt" | sed 's/^/  - /'
