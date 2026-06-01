#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICON_SOURCE="$ROOT_DIR/AppIcon.png"
ASSET_DIR="$ROOT_DIR/Sources/VaultUIApp/Assets.xcassets"
APP_ICONSET_DIR="$ASSET_DIR/AppIcon.appiconset"
EXTENSION_ICONSET_DIR="$ASSET_DIR/ExtensionIcon.appiconset"
SAFARI_ICON_DIR="$ROOT_DIR/Sources/VaultSafariExtension/Resources/icons"

if [ ! -f "$ICON_SOURCE" ]; then
  echo "error: Source icon not found: $ICON_SOURCE" >&2
  exit 1
fi

write_appicon_contents() {
  local iconset_dir="$1"
  mkdir -p "$iconset_dir"
  cat > "$iconset_dir/Contents.json" << 'JSON_EOF'
{
  "images": [
    {"filename": "icon_16x16@1x.png","idiom": "mac","scale": "1x","size": "16x16"},
    {"filename": "icon_16x16@2x.png","idiom": "mac","scale": "2x","size": "16x16"},
    {"filename": "icon_32x32@1x.png","idiom": "mac","scale": "1x","size": "32x32"},
    {"filename": "icon_32x32@2x.png","idiom": "mac","scale": "2x","size": "32x32"},
    {"filename": "icon_128x128@1x.png","idiom": "mac","scale": "1x","size": "128x128"},
    {"filename": "icon_128x128@2x.png","idiom": "mac","scale": "2x","size": "128x128"},
    {"filename": "icon_256x256@1x.png","idiom": "mac","scale": "1x","size": "256x256"},
    {"filename": "icon_256x256@2x.png","idiom": "mac","scale": "2x","size": "256x256"},
    {"filename": "icon_512x512@1x.png","idiom": "mac","scale": "1x","size": "512x512"},
    {"filename": "icon_512x512@2x.png","idiom": "mac","scale": "2x","size": "512x512"}
  ],
  "info": {"author": "xcode","version": 1}
}
JSON_EOF
}

generate_appiconset() {
  local iconset_dir="$1"
  write_appicon_contents "$iconset_dir"

  sips -z 16 16 "$ICON_SOURCE" --out "$iconset_dir/icon_16x16@1x.png" >/dev/null
  sips -z 32 32 "$ICON_SOURCE" --out "$iconset_dir/icon_16x16@2x.png" >/dev/null
  sips -z 32 32 "$ICON_SOURCE" --out "$iconset_dir/icon_32x32@1x.png" >/dev/null
  sips -z 64 64 "$ICON_SOURCE" --out "$iconset_dir/icon_32x32@2x.png" >/dev/null
  sips -z 128 128 "$ICON_SOURCE" --out "$iconset_dir/icon_128x128@1x.png" >/dev/null
  sips -z 256 256 "$ICON_SOURCE" --out "$iconset_dir/icon_128x128@2x.png" >/dev/null
  sips -z 256 256 "$ICON_SOURCE" --out "$iconset_dir/icon_256x256@1x.png" >/dev/null
  sips -z 512 512 "$ICON_SOURCE" --out "$iconset_dir/icon_256x256@2x.png" >/dev/null
  sips -z 512 512 "$ICON_SOURCE" --out "$iconset_dir/icon_512x512@1x.png" >/dev/null
  sips -z 1024 1024 "$ICON_SOURCE" --out "$iconset_dir/icon_512x512@2x.png" >/dev/null
}

generate_safari_icons() {
  mkdir -p "$SAFARI_ICON_DIR"

  sips -z 16 16 "$ICON_SOURCE" --out "$SAFARI_ICON_DIR/16.png" >/dev/null
  sips -z 32 32 "$ICON_SOURCE" --out "$SAFARI_ICON_DIR/32.png" >/dev/null
  sips -z 128 128 "$ICON_SOURCE" --out "$SAFARI_ICON_DIR/128.png" >/dev/null
  sips -z 16 16 "$ICON_SOURCE" --out "$SAFARI_ICON_DIR/toolbar_16.png" >/dev/null
  sips -z 32 32 "$ICON_SOURCE" --out "$SAFARI_ICON_DIR/toolbar_32.png" >/dev/null
}

generate_appiconset "$APP_ICONSET_DIR"
generate_appiconset "$EXTENSION_ICONSET_DIR"
generate_safari_icons

echo "Updated all icons from $ICON_SOURCE:"
echo "  - $APP_ICONSET_DIR"
echo "  - $EXTENSION_ICONSET_DIR"
echo "  - $SAFARI_ICON_DIR"
