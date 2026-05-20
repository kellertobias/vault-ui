#!/bin/bash
set -e

if [ ! -d "Vault UI.app" ]; then
    echo "⚠️ App bundle not found. Building..."
    ./build.sh
fi

echo "🚀 Launching Vault UI..."
open "Vault UI.app"
