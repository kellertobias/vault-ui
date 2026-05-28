#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-registry.tokenet.de/tobisk/loginflow-tester:latest}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER_TOOL="${CONTAINER_TOOL:-}"
PLATFORM="${PLATFORM:-linux/amd64}"

if [ -z "$CONTAINER_TOOL" ]; then
  if command -v podman >/dev/null 2>&1; then
    CONTAINER_TOOL="podman"
  else
    CONTAINER_TOOL="docker"
  fi
fi

"$CONTAINER_TOOL" build --platform "$PLATFORM" -t "$IMAGE" "$ROOT"
"$CONTAINER_TOOL" push "$IMAGE"

echo "Pushed $IMAGE for $PLATFORM with $CONTAINER_TOOL"
