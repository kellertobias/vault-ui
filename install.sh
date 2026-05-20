#!/bin/bash
set -e

echo "Building application..."
./build.sh

APP_NAME="Vault UI.app"
DEST_DIR="/Applications"

echo "📦 Installing $APP_NAME to $DEST_DIR..."

if [ -d "$DEST_DIR/$APP_NAME" ]; then
    echo "Removing old version..."
    rm -rf "$DEST_DIR/$APP_NAME"
fi

cp -R "$APP_NAME" "$DEST_DIR/"

echo "✅ Installed successfully!"
echo "You can now launch 'Vault UI' from Launchpad or your Applications folder."
