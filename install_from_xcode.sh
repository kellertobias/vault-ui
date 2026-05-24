#!/bin/bash
set -e

echo "🔍 Locating latest Vault UI build from Xcode DerivedData..."

# Find the most recently modified Vault UI.app in Xcode's DerivedData
APP_PATH=$(find ~/Library/Developer/Xcode/DerivedData -maxdepth 7 -type d -name "Vault UI.app" -not -path "*/Index.noindex/*" -print0 2>/dev/null | xargs -0 stat -f "%m %N" | sort -rn | head -1 | cut -d' ' -f2-)

if [ -z "$APP_PATH" ]; then
    echo "❌ Could not find Vault UI.app in Xcode DerivedData."
    echo "Please build the project in Xcode first."
    exit 1
fi

echo "✅ Found latest build at: $APP_PATH"

APP_NAME="Vault UI.app"
DEST_DIR="/Applications"

echo "📦 Installing $APP_NAME to $DEST_DIR..."

# Close existing app if it's running
killall "Vault UI" 2>/dev/null || true

# Remove old version
rm -rf "$DEST_DIR/$APP_NAME"

# Copy the newly built app using ditto (preserves code signature and symlinks)
ditto "$APP_PATH" "$DEST_DIR/$APP_NAME"

# Force LaunchServices to register the new bundle
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$DEST_DIR/$APP_NAME"

echo "✅ Installed successfully!"
echo "🚀 Launching Vault UI..."
open "$DEST_DIR/$APP_NAME"
