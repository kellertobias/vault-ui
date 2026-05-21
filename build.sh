#!/bin/bash
set -e

# ─── Vault UI Build Script ──────────────────────────────────────────────
# Builds the Vault UI app with AutoFill extension using Xcode signing.
#
# Prerequisites:
#   1. Xcode installed (with command line tools)
#   2. Apple ID signed into Xcode (Settings → Accounts → Add)
#   3. xcodegen installed: brew install xcodegen
#
# Usage:
#   ./build.sh                    # Debug build
#   ./build.sh release            # Release build
#   ./build.sh --team TEAMID      # Specify development team
# ─────────────────────────────────────────────────────────────────────────

CONFIGURATION="Debug"
TEAM_ID=""
OPEN_APP=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        release|Release)
            CONFIGURATION="Release"
            shift
            ;;
        --team)
            TEAM_ID="$2"
            shift 2
            ;;
        --open)
            OPEN_APP=true
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: ./build.sh [release] [--team TEAMID] [--open]"
            exit 1
            ;;
    esac
done

# Ensure developer dir
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

# ── Step 1: Generate Xcode project ──────────────────────────────────────
if ! command -v xcodegen &>/dev/null; then
    echo "❌ xcodegen not found. Install it with: brew install xcodegen"
    exit 1
fi

echo "⚙️  Generating Xcode project..."
xcodegen generate --quiet 2>/dev/null || xcodegen generate

# ── Step 2: Auto-detect development team if not provided ────────────────
if [ -z "$TEAM_ID" ]; then
    # Try to detect from existing signing identities
    TEAM_ID=$(security find-identity -v -p codesigning 2>/dev/null \
        | grep "Apple Development" \
        | head -1 \
        | sed -E 's/.*\(([A-Z0-9]+)\).*/\1/' 2>/dev/null || true)

    if [ -z "$TEAM_ID" ]; then
        echo ""
        echo "⚠️  No development signing identity found."
        echo ""
        echo "To set up signing:"
        echo "  1. Open Xcode"
        echo "  2. Go to Settings → Accounts"
        echo "  3. Click '+' and sign in with your Apple ID"
        echo "  4. Close Xcode and re-run this script"
        echo ""
        echo "Or specify your team ID manually:"
        echo "  ./build.sh --team YOUR_TEAM_ID"
        echo ""
        echo "Attempting build without team (may fail for AutoFill)..."
        echo ""
    fi
fi

# ── Step 3: Build with xcodebuild ───────────────────────────────────────
echo "🔨 Building Vault UI ($CONFIGURATION)..."

XCODEBUILD_ARGS=(
    -project VaultUI.xcodeproj
    -scheme VaultUI
    -configuration "$CONFIGURATION"
    -derivedDataPath .build/xcode
    CODE_SIGN_STYLE=Automatic
    -allowProvisioningUpdates
)

if [ -n "$TEAM_ID" ]; then
    XCODEBUILD_ARGS+=(DEVELOPMENT_TEAM="$TEAM_ID")
    echo "   Team: $TEAM_ID"
fi

xcodebuild "${XCODEBUILD_ARGS[@]}" build 2>&1 | \
    grep -E '(error:|warning:|BUILD|Signing|✗|✓|Linking|Compiling)' | \
    grep -v "warning: variable" | \
    grep -v "warning: '.*' was deprecated" || true

# Check if build succeeded
BUILD_DIR=".build/xcode/Build/Products/$CONFIGURATION"
APP_PATH="$BUILD_DIR/Vault UI.app"

if [ ! -d "$APP_PATH" ]; then
    echo ""
    echo "❌ Build failed. Run with full output:"
    echo "   xcodebuild -project VaultUI.xcodeproj -scheme VaultUI build"
    exit 1
fi

# ── Step 4: Copy app to project root ────────────────────────────────────
echo "📦 Copying app bundle..."
rm -rf "Vault UI.app"
cp -R "$APP_PATH" "Vault UI.app"

# ── Step 5: Verify extension ────────────────────────────────────────────
if [ -d "Vault UI.app/Contents/PlugIns/VaultAutoFillExtension.appex" ]; then
    echo "✅ AutoFill extension embedded"
else
    echo "⚠️  AutoFill extension NOT found in app bundle"
fi

# Verify signing
echo ""
echo "📋 Code signing info:"
codesign -dvvv "Vault UI.app" 2>&1 | grep -E '(TeamIdentifier|Identifier|Authority)' || true

if [ -d "Vault UI.app/Contents/PlugIns/VaultAutoFillExtension.appex" ]; then
    echo ""
    echo "📋 Extension signing info:"
    codesign -dvvv "Vault UI.app/Contents/PlugIns/VaultAutoFillExtension.appex" 2>&1 \
        | grep -E '(TeamIdentifier|Identifier|Authority)' || true
fi

echo ""
echo "✅ Build complete! App at: Vault UI.app"

if [ "$OPEN_APP" = true ]; then
    echo "🚀 Launching Vault UI..."
    open "Vault UI.app"
fi
