# Configuring Your Apple Developer Account

Vault UI no longer requires source-code edits to move between Apple Developer accounts. Build-time identifiers live in one file:

```text
Config/Signing.xcconfig
```

Update these values for your account:

| Setting | Purpose |
|---------|---------|
| `VAULTUI_DEVELOPMENT_TEAM` | Your 10-character Apple Developer Team ID. Leave empty if you prefer selecting the team in Xcode. |
| `VAULTUI_BUNDLE_ID` | Main app bundle identifier registered to your account. |
| `VAULTUI_AUTOFILL_BUNDLE_ID` | AutoFill extension bundle identifier. |
| `VAULTUI_SAFARI_BUNDLE_ID` | Safari Web Extension bundle identifier. |
| `VAULTUI_APP_GROUP` | Shared App Group identifier enabled for all app targets. |
| `VAULTUI_KEYCHAIN_GROUP` | Shared Keychain group suffix enabled for all app targets. |

The Xcode project, entitlements, Info.plists, keychain access group, app-group container paths, and Safari extension identifier are derived from these settings.

After editing `Config/Signing.xcconfig`, run:

```bash
xcodegen generate
```

Then open `VaultUI.xcodeproj`, verify Signing & Capabilities for each target, and build.

## Apple Developer Portal Checklist

- Register the main app bundle ID from `VAULTUI_BUNDLE_ID`.
- Register the AutoFill extension bundle ID from `VAULTUI_AUTOFILL_BUNDLE_ID`.
- Register the Safari extension bundle ID from `VAULTUI_SAFARI_BUNDLE_ID`.
- Enable AutoFill Credential Provider for the AutoFill extension.
- Enable App Groups for all targets and add `VAULTUI_APP_GROUP`.
- Enable Keychain Sharing for all targets and add `VAULTUI_KEYCHAIN_GROUP`.

Users changing these identifiers will need to log in again because Keychain and App Group storage are intentionally namespaced by bundle/account identity.
