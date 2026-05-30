#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$ROOT_DIR/VaultUI.xcodeproj"
SCHEME="VaultUI"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-$ROOT_DIR/.build/xcode}"
ARCHIVE_PATH="${ARCHIVE_PATH:-$ROOT_DIR/.build/archive/VaultUI.xcarchive}"
APP_NAME="Vault UI.app"
INSTALL_DIR="${INSTALL_DIR:-/Applications}"
DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export DEVELOPER_DIR

usage() {
  cat <<USAGE
Usage: ./build.sh [debug|run|release|archive|install] [--team TEAM_ID]

Modes:
  debug     Build the Debug app, like Xcode's Cmd+B. Default.
  run       Build Debug and launch it, like Xcode's Cmd+R.
  release   Build the Release app without archiving.
  archive   Create a signed Release .xcarchive.
  install   Archive, extract Vault UI.app, and replace $INSTALL_DIR/$APP_NAME.

Options:
  --team TEAM_ID    Override VAULTUI_DEVELOPMENT_TEAM for this build.

Environment:
  DEVELOPER_DIR       Xcode path. Defaults to /Applications/Xcode.app/Contents/Developer.
  DERIVED_DATA_PATH   Build output path. Defaults to .build/xcode.
  ARCHIVE_PATH        Archive output path. Defaults to .build/archive/VaultUI.xcarchive.
  INSTALL_DIR         Install destination. Defaults to /Applications.
USAGE
}

mode="debug"
development_team=()
team_override=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    debug|run|release|archive|install)
      mode="$1"
      shift
      ;;
    --team)
      if [[ $# -lt 2 ]]; then
        echo "error: --team requires a Team ID" >&2
        exit 64
      fi
      team_override="$2"
      development_team=("DEVELOPMENT_TEAM=$team_override")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ ! -d "$DEVELOPER_DIR" ]]; then
  echo "error: Xcode was not found at $DEVELOPER_DIR" >&2
  echo "Set DEVELOPER_DIR to your Xcode.app developer directory." >&2
  exit 69
fi

if [[ ! -d "$PROJECT" ]]; then
  if ! command -v xcodegen >/dev/null 2>&1; then
    echo "error: $PROJECT was not found, and xcodegen is not installed." >&2
    echo "Install xcodegen or generate VaultUI.xcodeproj before building." >&2
    exit 69
  fi

  echo "Generating VaultUI.xcodeproj..."
  xcodegen generate --spec "$ROOT_DIR/project.yml"
fi

xcconfig_value() {
  local key="$1"

  awk -F= -v key="$key" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      value = $2
      sub(/\/\/.*/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "$ROOT_DIR/Config/Signing.xcconfig"
}

require_real_signing_settings() {
  local configured_team
  local bundle_id
  local effective_team

  configured_team="$(xcconfig_value VAULTUI_DEVELOPMENT_TEAM)"
  bundle_id="$(xcconfig_value VAULTUI_BUNDLE_ID)"
  effective_team="${team_override:-$configured_team}"

  if [[ -z "$effective_team" ]]; then
    cat >&2 <<ERROR
error: no Apple Developer Team ID is configured.

Set VAULTUI_DEVELOPMENT_TEAM in Config/Signing.xcconfig, or pass:
  ./build.sh $mode --team YOUR_TEAM_ID
ERROR
    exit 78
  fi

  if [[ "$bundle_id" == com.example* ]]; then
    cat >&2 <<ERROR
error: Config/Signing.xcconfig still uses placeholder bundle ID '$bundle_id'.

Set VAULTUI_BUNDLE_ID to a bundle identifier registered to your Apple
Developer account, then regenerate the Xcode project if you use XcodeGen.
ERROR
    exit 78
  fi
}

require_real_signing_settings

common_xcodebuild_args=(
  -project "$PROJECT"
  -scheme "$SCHEME"
  -allowProvisioningUpdates
  CODE_SIGN_STYLE=Automatic
  "${development_team[@]}"
)

build_app() {
  local configuration="$1"

  xcodebuild \
    "${common_xcodebuild_args[@]}" \
    -configuration "$configuration" \
    -destination "platform=macOS" \
    -derivedDataPath "$DERIVED_DATA_PATH" \
    build
}

debug_app_path() {
  printf '%s\n' "$DERIVED_DATA_PATH/Build/Products/Debug/$APP_NAME"
}

archive_app_path() {
  printf '%s\n' "$ARCHIVE_PATH/Products/Applications/$APP_NAME"
}

open_app() {
  local app_path="$1"

  if [[ ! -d "$app_path" ]]; then
    echo "error: app bundle not found at $app_path" >&2
    exit 66
  fi

  open "$app_path"
}

archive_app() {
  rm -rf "$ARCHIVE_PATH"
  mkdir -p "$(dirname "$ARCHIVE_PATH")"

  xcodebuild \
    "${common_xcodebuild_args[@]}" \
    -configuration Release \
    -destination "generic/platform=macOS" \
    -archivePath "$ARCHIVE_PATH" \
    archive
}

install_archived_app() {
  local source_app
  local destination_app

  source_app="$(archive_app_path)"
  destination_app="$INSTALL_DIR/$APP_NAME"

  if [[ ! -d "$source_app" ]]; then
    echo "error: archive did not contain $APP_NAME at $source_app" >&2
    exit 66
  fi

  echo "Verifying code signature..."
  codesign --verify --deep --strict --verbose=2 "$source_app"

  echo "Installing $APP_NAME to $INSTALL_DIR..."
  killall "Vault UI" 2>/dev/null || true
  rm -rf "$destination_app"
  ditto "$source_app" "$destination_app"

  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f "$destination_app"

  echo "Installed $destination_app"
}

case "$mode" in
  debug)
    build_app Debug
    ;;
  run)
    build_app Debug
    open_app "$(debug_app_path)"
    ;;
  release)
    build_app Release
    ;;
  archive)
    archive_app
    echo "Archive written to $ARCHIVE_PATH"
    ;;
  install)
    archive_app
    install_archived_app
    open_app "$INSTALL_DIR/$APP_NAME"
    ;;
esac
