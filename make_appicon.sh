#!/bin/bash
set -e
mkdir -p Sources/VaultUIApp/Assets.xcassets/ExtensionIcon.appiconset
cd Sources/VaultUIApp/Assets.xcassets/ExtensionIcon.appiconset

cat << 'JSON_EOF' > Contents.json
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

sips -z 16 16 ../../../../ExtensionIcon.png --out icon_16x16@1x.png
sips -z 32 32 ../../../../ExtensionIcon.png --out icon_16x16@2x.png
sips -z 32 32 ../../../../ExtensionIcon.png --out icon_32x32@1x.png
sips -z 64 64 ../../../../ExtensionIcon.png --out icon_32x32@2x.png
sips -z 128 128 ../../../../ExtensionIcon.png --out icon_128x128@1x.png
sips -z 256 256 ../../../../ExtensionIcon.png --out icon_128x128@2x.png
sips -z 256 256 ../../../../ExtensionIcon.png --out icon_256x256@1x.png
sips -z 512 512 ../../../../ExtensionIcon.png --out icon_256x256@2x.png
sips -z 512 512 ../../../../ExtensionIcon.png --out icon_512x512@1x.png
sips -z 1024 1024 ../../../../ExtensionIcon.png --out icon_512x512@2x.png
