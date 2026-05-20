#!/bin/bash
set -e

echo "🔨 Building Vault UI..."

# Ensure we use the right developer dir
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

# 1. Build the release binary
swift build -c release

# 2. Setup App Bundle Structure
APP_NAME="Vault UI.app"
APP_CONTENTS="$APP_NAME/Contents"
MACOS_DIR="$APP_CONTENTS/MacOS"
RESOURCES_DIR="$APP_CONTENTS/Resources"

echo "📦 Packaging $APP_NAME..."
rm -rf "$APP_NAME"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

# 3. Copy executable
cp .build/release/VaultUIApp "$MACOS_DIR/VaultUI"

# 4. Generate App Icon
ICON_PNG="/Users/keller/.gemini/antigravity/brain/20aa6c39-7712-433b-80af-a030c0944a6d/vault_app_icon_1779155706779.png"
ICON_DIR="AppIcon.iconset"

if [ -f "$ICON_PNG" ]; then
    echo "🎨 Generating AppIcon.icns..."
    mkdir -p "$ICON_DIR"
    
    # Generate different sizes required for macOS icons
    sips -s format png -z 16 16     "$ICON_PNG" --out "$ICON_DIR/icon_16x16.png" > /dev/null
    sips -s format png -z 32 32     "$ICON_PNG" --out "$ICON_DIR/icon_16x16@2x.png" > /dev/null
    sips -s format png -z 32 32     "$ICON_PNG" --out "$ICON_DIR/icon_32x32.png" > /dev/null
    sips -s format png -z 64 64     "$ICON_PNG" --out "$ICON_DIR/icon_32x32@2x.png" > /dev/null
    sips -s format png -z 128 128   "$ICON_PNG" --out "$ICON_DIR/icon_128x128.png" > /dev/null
    sips -s format png -z 256 256   "$ICON_PNG" --out "$ICON_DIR/icon_128x128@2x.png" > /dev/null
    sips -s format png -z 256 256   "$ICON_PNG" --out "$ICON_DIR/icon_256x256.png" > /dev/null
    sips -s format png -z 512 512   "$ICON_PNG" --out "$ICON_DIR/icon_256x256@2x.png" > /dev/null
    sips -s format png -z 512 512   "$ICON_PNG" --out "$ICON_DIR/icon_512x512.png" > /dev/null
    sips -s format png -z 1024 1024 "$ICON_PNG" --out "$ICON_DIR/icon_512x512@2x.png" > /dev/null
    
    # Convert iconset to icns
    iconutil -c icns "$ICON_DIR" -o "$RESOURCES_DIR/AppIcon.icns"
    rm -rf "$ICON_DIR"
else
    echo "⚠️ App icon source not found. Skipping icon generation."
fi

# 5. Create Info.plist
echo "📝 Creating Info.plist..."
cat > "$APP_CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>VaultUI</string>
    <key>CFBundleIdentifier</key>
    <string>com.vaultui.mac</string>
    <key>CFBundleName</key>
    <string>Vault UI</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>15.0</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <!-- Keep app in dock even when windows are closed -->
    <key>NSSupportsAutomaticTermination</key>
    <false/>
    <key>NSSupportsSuddenTermination</key>
    <false/>
</dict>
</plist>
EOF

echo "✅ Build complete! App bundle created at $APP_NAME"
