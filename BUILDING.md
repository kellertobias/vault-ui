# Building Vault UI

## Prerequisites

| Tool | Install | Purpose |
|------|---------|---------|
| **Xcode** | Mac App Store | Build & sign the app |
| **xcodegen** | `brew install xcodegen` | Generate `.xcodeproj` from `project.yml` |
| **Swift 6.0+** | Included with Xcode | Compiler |
| **Apple Developer Account** | developer.apple.com | **Paid account ($99/year) required** for the AutoFill extension |

> [!IMPORTANT]
> The **AutoFill Credential Provider** system capability requires a paid Apple Developer Account. 
> Free Apple IDs (Personal Teams) are not permitted by Apple to use this restricted entitlement.

---

## Developer Portal Configuration

Before building in Xcode, you must configure the App IDs in the Apple Developer Portal:

1. **Log in** to [developer.apple.com](https://developer.apple.com).
2. Go to **Certificates, Identifiers & Profiles** → **Identifiers**.
3. Register the **Main App ID**:
   - Click the **+** (plus) icon.
   - Select **App IDs**, choose type **App**.
   - Description: `Vault UI Main App`
   - Explicit Bundle ID: the value of `VAULTUI_BUNDLE_ID` in `Config/Signing.xcconfig`
   - Click **Continue** and then **Register**.
4. Register the **AutoFill Extension App ID**:
   - Click the **+** (plus) icon again.
   - Select **App IDs**, choose type **App**.
   - Description: `Vault UI AutoFill Extension`
   - Explicit Bundle ID: the value of `VAULTUI_AUTOFILL_BUNDLE_ID` in `Config/Signing.xcconfig`
   - In the **Capabilities** list below, check the box for **AutoFill Credential Provider**.
   - Click **Continue** and then **Register**.

Xcode can now automatically manage the signing and generate the required provisioning profiles.

---

## First-Time Setup

### 1. Sign into Xcode with your Apple ID

1. Open **Xcode**
2. Go to **Xcode → Settings → Accounts** (⌘,)
3. Click the **+** button → **Apple ID**
4. Sign in with your Apple ID
5. Your paid **Apple Developer Program Team** will appear in the list

### 2. Install xcodegen

```bash
brew install xcodegen
```

### 3. Configure signing and generate the Xcode project

Edit `Config/Signing.xcconfig`:

```xcconfig
VAULTUI_DEVELOPMENT_TEAM = YOUR_TEAM_ID
VAULTUI_BUNDLE_ID = com.yourname.vaultui
VAULTUI_AUTOFILL_BUNDLE_ID = $(VAULTUI_BUNDLE_ID).AutoFillExtension
VAULTUI_SAFARI_BUNDLE_ID = $(VAULTUI_BUNDLE_ID).SafariExtension
VAULTUI_APP_GROUP = group.$(VAULTUI_BUNDLE_ID)
VAULTUI_KEYCHAIN_GROUP = $(VAULTUI_BUNDLE_ID).shared
```

```bash
xcodegen generate
```

This reads `project.yml`, applies `Config/Signing.xcconfig`, and creates `VaultUI.xcodeproj`.

### 4. Select your development team

**Option A — In Xcode (recommended for first time):**

1. Open `VaultUI.xcodeproj` in Xcode
2. Select the **VaultUI** target → **Signing & Capabilities**
3. Check **"Automatically manage signing"**
4. Select your **Developer Team** (the one with the paid account, not the Personal Team) from the Team dropdown
5. Repeat for the **VaultAutoFillExtension** target
6. Xcode will fetch provisioning profiles and set up code signing

**Option B — From command line:**

If you know your Team ID (visible in Xcode → Settings → Accounts → select team → Team ID):

```bash
./build.sh --team YOUR_TEAM_ID
```

---

## Building

### Cmd+R-style Build and Launch

```bash
./build.sh run
```

This uses `xcodebuild` with the shared `VaultUI` scheme, automatic signing, and
the Team ID from `Config/Signing.xcconfig`. You can override the team for one
build with:

```bash
./build.sh run --team YOUR_TEAM_ID
```

### Archive and Install to Applications

Create a signed Release archive, extract `Vault UI.app`, verify its signature,
replace `/Applications/Vault UI.app`, register it with LaunchServices, and launch
it:

```bash
./build.sh install
```

For only the archive:

```bash
./build.sh archive
```

The archive is written to `.build/archive/VaultUI.xcarchive` by default.

### Other Build Modes

```bash
./build.sh debug    # Debug build only
./build.sh release  # Release build only, no archive
```

### Full xcodebuild (if you need more control)

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodebuild \
  -project VaultUI.xcodeproj \
  -scheme VaultUI \
  -configuration Release \
  -derivedDataPath .build/xcode \
  CODE_SIGN_STYLE=Automatic \
  DEVELOPMENT_TEAM=YOUR_TEAM_ID \
  -allowProvisioningUpdates \
  build
```

---

## Enabling AutoFill

After building and running the app:

1. Open **System Settings**
2. Go to **General → Login Items & Extensions**
3. Find **Credential Provider Extensions** (or go to **Passwords → AutoFill**)
4. Toggle **Vault UI** ON
5. Visit any login page in Safari — Vault UI should appear in the AutoFill dropdown

> [!TIP]
> If Vault UI doesn't appear in the list, try:
> - Quit and relaunch the app
> - Sign out and back into Xcode, then rebuild
> - Restart your Mac (extension registration sometimes requires it)

---

## Building the CLI Tool (without Xcode)

The CLI tool and all library targets can still be built with plain SPM:

```bash
swift build -c release
# CLI binary at: .build/release/vaultui
```

---

## Project Structure

```
project.yml                     ← XcodeGen spec (generates .xcodeproj)
VaultUI.entitlements            ← Main app sandbox + keychain entitlements
VaultAutoFillExtension.entitlements ← Extension sandbox + credential provider
Package.swift                   ← SPM package (libraries, CLI, tests)
Sources/
  VaultUIApp/                   ← App entry point (@main)
  VaultAppUI/                   ← SwiftUI views (imported via SPM)
  VaultAutoFillExtension/       ← AutoFill Credential Provider extension
  VaultCrypto/                  ← Encryption (AES-CBC, PBKDF2, Argon2)
  VaultModels/                  ← Data models (Cipher, Folder, etc.)
  VaultAPI/                     ← Bitwarden/Vaultwarden API client
  VaultSync/                    ← SwiftData sync engine
  VaultSSH/                     ← SSH agent
  VaultServices/                ← Business logic, session management
  VaultCLI/                     ← CLI tool
```

---

## Troubleshooting

### "No signing identity found"

Run `security find-identity -v -p codesigning` — if it shows no identities,
you need to sign into Xcode with your Apple ID first.

### "Missing package product"

Run `xcodegen generate` to regenerate the project, then clean:
```bash
xcodebuild -project VaultUI.xcodeproj -scheme VaultUI clean
```

### Extension not registering

The extension needs a proper provisioning profile. Verify signing:
```bash
codesign -dvvv "Vault UI.app/Contents/PlugIns/VaultAutoFillExtension.appex" 2>&1 | grep TeamIdentifier
```
If `TeamIdentifier` shows `not set`, the signing failed. Rebuild with your team ID.

### "Hardened Runtime is Not Enabled"

Verify the app and the embedded CLI both show the hardened runtime flag:
```bash
codesign -dvvv "Vault UI.app" 2>&1 | grep Runtime
codesign -dvvv "Vault UI.app/Contents/MacOS/vaultui" 2>&1 | grep Runtime
```

The Xcode targets enable hardened runtime in `project.yml`. The embedded `vaultui`
CLI is built by SwiftPM, then copied into the app bundle, so the Xcode build phase
also signs that binary with `--options runtime` before distribution.
