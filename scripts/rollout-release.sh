#!/bin/bash

# Rolls a published GitHub Release out to agents: mirrors it into the
# SentinelOps backend's agent-releases Storage bucket, marks it as the latest
# version, and checks that get_latest_agent_release now returns it. This is
# what Settings -> Agents -> "Mirror & mark vX as latest" does in the console.
# Agents only ever update to that version, never straight from GitHub (#306).
#
# Usage: scripts/rollout-release.sh vX.Y.Z
#
# Environment:
#   SENTINELOPS_SUPABASE_URL       backend Supabase URL (https://<ref>.supabase.co)
#   SENTINELOPS_SUPABASE_ANON_KEY  backend anon key
#   SENTINELOPS_RELEASE_EMAIL      user allowed to manage agent releases (admin)
#   SENTINELOPS_RELEASE_PASSWORD   that user's password
#   PUBLISHED_AT                   optional, the release's publish time (RFC 3339)
#
# With none of the SENTINELOPS_* variables set it only warns, so a fork or an
# unconfigured repository still releases. Any other failure exits non-zero.

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "usage: $0 vX.Y.Z" >&2
    exit 2
fi

summary() {
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "$1" >> "$GITHUB_STEP_SUMMARY"
    fi
}

vars=(SENTINELOPS_SUPABASE_URL SENTINELOPS_SUPABASE_ANON_KEY SENTINELOPS_RELEASE_EMAIL SENTINELOPS_RELEASE_PASSWORD)
missing=()
for v in "${vars[@]}"; do
    [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -eq "${#vars[@]}" ]; then
    msg="$VERSION was not rolled out to agents: the SENTINELOPS_* secrets are not set. Agents stay on the current version until an admin clicks \"Mirror & mark $VERSION as latest\" in SentinelOps, Settings -> Agents."
    echo "::warning::$msg"
    summary "⚠️ $msg"
    exit 0
fi
if [ "${#missing[@]}" -gt 0 ]; then
    echo "::error::Missing ${missing[*]}" >&2
    exit 1
fi

URL="${SENTINELOPS_SUPABASE_URL%/}"
ANON="$SENTINELOPS_SUPABASE_ANON_KEY"

# Leading "v" ignored, as the backend compares versions.
norm() { echo "${1#[vV]}"; }

echo "Signing in to SentinelOps as the release user"
token=$(jq -n --arg e "$SENTINELOPS_RELEASE_EMAIL" --arg p "$SENTINELOPS_RELEASE_PASSWORD" '{email: $e, password: $p}' |
    curl -sS --fail-with-body --max-time 30 \
        -H "apikey: $ANON" -H "Content-Type: application/json" \
        --data-binary @- "$URL/auth/v1/token?grant_type=password" |
    jq -r '.access_token // empty')
if [ -z "$token" ]; then
    echo "::error::Sign-in returned no access token" >&2
    exit 1
fi
echo "::add-mask::$token"

# The mirror copies GitHub's *latest* release and refuses (409) when that isn't
# $VERSION. Right after publishing, GitHub can briefly still report the
# previous release as latest, so a 409 is retried.
mirror_out=$(mktemp)
trap 'rm -f "$mirror_out"' EXIT
echo "Mirroring $VERSION into the agent-releases bucket"
for attempt in 1 2 3 4 5; do
    status=$(curl -sS --max-time 600 -o "$mirror_out" -w '%{http_code}' -X POST \
        -H "apikey: $ANON" -H "Authorization: Bearer $token" \
        "$URL/functions/v1/agent-installer-assets?action=mirror&version=$VERSION")
    if [ "$status" = "200" ]; then
        break
    fi
    echo "Mirror attempt $attempt returned HTTP $status: $(jq -r '.error // .' "$mirror_out" 2>/dev/null || cat "$mirror_out")"
    if [ "$status" != "409" ] || [ "$attempt" -eq 5 ]; then
        echo "::error::Mirroring $VERSION failed (HTTP $status)" >&2
        exit 1
    fi
    sleep 30
done
mirrored=$(jq -r '.version' "$mirror_out")
if [ "$(norm "$mirrored")" != "$(norm "$VERSION")" ]; then
    echo "::error::Mirrored $mirrored instead of $VERSION" >&2
    exit 1
fi
echo "Mirrored $(jq -r '.assetCount' "$mirror_out") assets"

echo "Marking $VERSION as the latest agent version"
jq -n --arg v "$VERSION" --arg t "${PUBLISHED_AT:-}" \
    '{p_version: $v, p_published_at: (if $t == "" then null else $t end), p_source: "github_release"}' |
    curl -sS --fail-with-body --max-time 30 -o /dev/null \
        -H "apikey: $ANON" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        --data-binary @- "$URL/rest/v1/rpc/sync_latest_agent_version"

# Ask exactly what an agent asks, for every platform it ships on.
echo "Checking what agents are offered"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    offered=$(jq -n --arg p "${target%/*}" --arg a "${target#*/}" '{p_platform: $p, p_arch: $a}' |
        curl -sS --fail-with-body --max-time 30 \
            -H "apikey: $ANON" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
            --data-binary @- "$URL/rest/v1/rpc/get_latest_agent_release" |
        jq -r '.[0].version // empty')
    if [ "$(norm "$offered")" != "$(norm "$VERSION")" ]; then
        echo "::error::Agents on $target are offered '${offered:-nothing}', not $VERSION" >&2
        exit 1
    fi
    echo "  $target: $offered"
done

summary "✅ $VERSION rolled out: agents update to it at their next check (within about an hour)."
echo "Done: agents update to $VERSION at their next check"
