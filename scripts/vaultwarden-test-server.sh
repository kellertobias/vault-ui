#!/usr/bin/env bash
# Throwaway Vaultwarden instance for the integration tests.
#
#   scripts/vaultwarden-test-server.sh up      start (fresh, empty) and wait until healthy
#   scripts/vaultwarden-test-server.sh down    stop and remove it
#   scripts/vaultwarden-test-server.sh status  print whether it is running
#
# The server keeps its data on a tmpfs, so every `up` starts from an empty
# database, and it binds to 127.0.0.1 only. Signups are open and mail is off,
# which makes Vaultwarden accept organization invites for existing users
# immediately — the tests rely on that.
#
# It serves HTTPS: the app and the official Bitwarden clients all refuse plain
# HTTP. Each `up` mints a throwaway CA and a server certificate for 127.0.0.1
# into $TLS_DIR; clients trust that CA explicitly (VAULTWARDEN_CA_CERT), so
# nothing is ever added to the system keychain.
#
# Works with docker or podman. Override with VAULTWARDEN_CONTAINER_RUNTIME.
set -euo pipefail

IMAGE="${VAULTWARDEN_IMAGE:-docker.io/vaultwarden/server:1.37.3}"
NAME="${VAULTWARDEN_CONTAINER_NAME:-vault-ui-test-vaultwarden}"
PORT="${VAULTWARDEN_PORT:-8443}"
URL="https://127.0.0.1:${PORT}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_DIR="${VAULTWARDEN_TLS_DIR:-$ROOT_DIR/.build/vaultwarden-test-tls}"
CA_CERT="$TLS_DIR/ca.pem"

# TLS_DIR is deleted on every up/down; refuse anything that isn't clearly ours.
case "$TLS_DIR" in
    */vaultwarden-test-tls) ;;
    *)
        echo "error: VAULTWARDEN_TLS_DIR must end in /vaultwarden-test-tls (got: $TLS_DIR)" >&2
        exit 2
        ;;
esac

runtime() {
    if [[ -n "${VAULTWARDEN_CONTAINER_RUNTIME:-}" ]]; then
        echo "$VAULTWARDEN_CONTAINER_RUNTIME"
    elif command -v docker >/dev/null 2>&1; then
        echo docker
    elif command -v podman >/dev/null 2>&1; then
        echo podman
    else
        echo "error: neither docker nor podman is installed" >&2
        exit 1
    fi
}

# A fresh CA and server certificate. Short-lived, and within Apple's TLS rules
# (SAN, serverAuth EKU, SHA-256, RSA-2048, < 825 days) so URLSession accepts it.
make_certificates() {
    rm -rf "$TLS_DIR"
    mkdir -p "$TLS_DIR"
    (
        cd "$TLS_DIR"
        openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
            -keyout ca.key -out ca.pem -subj "/CN=Vault UI Test CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
        openssl req -newkey rsa:2048 -sha256 -nodes \
            -keyout key.pem -out server.csr -subj "/CN=127.0.0.1" 2>/dev/null
        printf '%s\n' \
            "basicConstraints=CA:FALSE" \
            "keyUsage=critical,digitalSignature,keyEncipherment" \
            "extendedKeyUsage=serverAuth" \
            "subjectAltName=IP:127.0.0.1,DNS:localhost" > server.ext
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -days 7 -sha256 -extfile server.ext -out cert.pem 2>/dev/null
        openssl verify -CAfile ca.pem cert.pem >/dev/null
        # The CA key is only needed to sign; don't leave it around.
        rm -f ca.key ca.srl server.csr server.ext
        # The container user must be able to read the key.
        chmod 644 cert.pem key.pem ca.pem
    )
}

up() {
    local rt
    rt="$(runtime)"
    make_certificates

    # Always start clean: a leftover container would carry old accounts.
    "$rt" rm -f "$NAME" >/dev/null 2>&1 || true

    "$rt" run -d \
        --name "$NAME" \
        -p "127.0.0.1:${PORT}:80" \
        --tmpfs /data \
        -v "$TLS_DIR:/ssl:ro" \
        -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' \
        -e SIGNUPS_ALLOWED=true \
        -e SIGNUPS_VERIFY=false \
        -e INVITATIONS_ALLOWED=true \
        -e DISABLE_ICON_DOWNLOAD=true \
        -e ICON_SERVICE=internal \
        -e LOGIN_RATELIMIT_MAX_BURST=1000 \
        -e LOGIN_RATELIMIT_SECONDS=1 \
        -e DOMAIN="$URL" \
        "$IMAGE" >/dev/null

    echo -n "Waiting for Vaultwarden at $URL "
    for _ in $(seq 1 60); do
        if curl -fsS --cacert "$CA_CERT" "$URL/alive" >/dev/null 2>&1; then
            echo " ready"
            echo "VAULTWARDEN_URL=$URL"
            echo "VAULTWARDEN_CA_CERT=$CA_CERT"
            return 0
        fi
        echo -n "."
        sleep 1
    done

    echo " timed out" >&2
    "$rt" logs "$NAME" >&2 || true
    exit 1
}

down() {
    "$(runtime)" rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$TLS_DIR"
    echo "Vaultwarden test server removed"
}

status() {
    if curl -fsS --cacert "$CA_CERT" "$URL/alive" >/dev/null 2>&1; then
        echo "running at $URL (CA: $CA_CERT)"
    else
        echo "not running"
        return 1
    fi
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *)
        echo "usage: $0 up|down|status" >&2
        exit 2
        ;;
esac
