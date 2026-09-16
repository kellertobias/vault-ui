#!/usr/bin/env bash
# Run the integration tests against a throwaway local Vaultwarden.
#
#   scripts/test-integration.sh                 start a fresh server, test, remove it
#   KEEP_VAULTWARDEN=1 scripts/test-integration.sh
#                                               leave the server running afterwards
#   VAULTWARDEN_URL=https://127.0.0.1:8443 VAULTWARDEN_CA_CERT=.build/vaultwarden-test-tls/ca.pem \
#       scripts/test-integration.sh             use a server that is already running
#
# The suite includes checks against the official Bitwarden CLI and the web vault
# (Tests/Interop). Their npm dependencies are installed here when missing; the
# web vault runs in the locally installed Chrome, falling back to Playwright's
# Chromium if Chrome is absent (`npx playwright install chromium` in Tests/Interop).
#
# Extra arguments are passed to `swift test`, e.g. a narrower filter:
#   scripts/test-integration.sh --filter testMemberReadsSharedLegacyItemWithoutItemKey
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$ROOT_DIR/scripts/vaultwarden-test-server.sh"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

INTEROP_DIR="$ROOT_DIR/Tests/Interop"
if [[ ! -d "$INTEROP_DIR/node_modules" ]]; then
    if command -v npm >/dev/null 2>&1; then
        echo "Installing official-client test tooling (Tests/Interop)"
        (cd "$INTEROP_DIR" && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --no-audit --no-fund)
    else
        echo "warning: npm not found; official-client interop tests will be skipped" >&2
    fi
fi

if [[ -z "${VAULTWARDEN_URL:-}" ]]; then
    export VAULTWARDEN_URL="https://127.0.0.1:${VAULTWARDEN_PORT:-8443}"
    export VAULTWARDEN_CA_CERT="$ROOT_DIR/.build/vaultwarden-test-tls/ca.pem"
    "$SERVER" up
    if [[ "${KEEP_VAULTWARDEN:-0}" != "1" ]]; then
        trap '"$SERVER" down' EXIT
    fi
else
    echo "Using existing Vaultwarden at $VAULTWARDEN_URL"
fi

filter=(--filter VaultIntegrationTests)
if [[ " $* " == *" --filter "* ]]; then
    filter=()
fi

cd "$ROOT_DIR"
export WEBVAULT_ARTIFACTS="${WEBVAULT_ARTIFACTS:-$ROOT_DIR/.build/webvault-artifacts}"
mkdir -p "$WEBVAULT_ARTIFACTS"
log="$(mktemp -t vault-ui-integration)"
set +e
swift test ${filter[@]+"${filter[@]}"} "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e

# A run where nothing executed, or everything skipped, means the tests never
# reached the server (wrong filter, VAULTWARDEN_URL lost) — that must not pass.
if ! awk '/Executed [0-9]+ tests?/ {
        total = 0; skipped = 0
        for (i = 1; i <= NF; i++) {
            if ($i == "Executed") total = $(i + 1)
            if ($i == "with" && $(i + 2) ~ /^tests?$/ && $(i + 3) == "skipped") skipped = $(i + 1)
        }
        if (total > 0 && total > skipped) ran = 1
    } END { exit !ran }' "$log"; then
    echo "error: no integration test actually ran against the server (all skipped or none matched)" >&2
    status=1
fi
rm -f "$log"
exit "$status"
