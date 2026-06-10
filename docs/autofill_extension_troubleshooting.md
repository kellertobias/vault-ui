# macOS AutoFill Credential Provider Extension Integration

This document outlines the troubleshooting steps, issues, and solutions encountered while integrating the macOS AutoFill Credential Provider extension (`VaultAutoFillExtension`) into the **Vault UI** application.

---

## Summary of Key Issues & Solutions

### 1. Extension Not Showing in System Settings (Missing `NSExtension` Metadata)
* **Problem**: The extension was completely ignored by macOS and did not show up in the *System Settings > Passwords > AutoFill Options* list.
* **Cause**: The extension's `Info.plist` was missing the `NSExtension` dictionary entirely. Without this metadata, macOS cannot identify the plugin type or know which view controller to load.
* **Solution**: Added the following to `Sources/VaultAutoFillExtension/Info.plist`:
  ```xml
  <key>NSExtension</key>
  <dict>
      <key>NSExtensionPointIdentifier</key>
      <string>com.apple.authentication-services-credential-provider-ui</string>
      <key>NSExtensionPrincipalClass</key>
      <string>VaultCredentialProviderViewController</string>
  </dict>
  ```

### 2. Safari Crashing / Freezing / Blank Overlays (Lack of UI)
* **Problem**: Once the extension appeared in System Settings, selecting it in Safari caused Safari to crash, freeze, or display a blank gray overlay.
* **Cause**:
  1. The credential provider's main view controller (`VaultCredentialProviderViewController`) did not define or host any visible user interface.
  2. It was missing a call to `prepareInterfaceForExtensionConfiguration()` or failed to respond to the extension context, leaving Safari waiting indefinitely for a response or a UI presentation.
* **Solution**:
  - Rewrote `CredentialProviderViewController.swift` to inherit from `ASCredentialProviderViewController` and implement a proper SwiftUI-based credential selection UI (`CredentialListView`).
  - Implemented `prepareInterface(forExtensionConfiguration:)` to immediately call `completeExtensionConfigurationRequest()` if no setup UI is needed.
  - Implemented `prepareInterface(forConnection:)` to load the list of credentials matching the host request, showing a searchable UI where the user can pick a credential.

### 3. Signing, Team IDs, and Hardened Runtime
* **Problem**: Build or keychain access issues when building the targets.
* **Cause**:
  - The App Sandbox and Keychain sharing require a valid Development Team and matching bundle identifier prefix across all components.
  - Hardened Runtime was not enabled for the targets, which is mandatory for extensions on macOS.
* **Solution**:
  - Configured `ENABLE_HARDENED_RUNTIME: true` on both the app and extension targets in `project.yml`.
  - Standardized bundle, App Group, and Keychain identifiers through `Config/Signing.xcconfig`.
  - Runtime references in Swift are derived from Info.plist build settings.
  - Set `VAULTUI_DEVELOPMENT_TEAM` in `Config/Signing.xcconfig` to keep signing persistent across `xcodegen generate` runs.

### 4. Missing Host App Entitlements
* **Problem**: The extension was not recognized by Safari even when registered.
* **Cause**: macOS requires the host app *itself* to contain the `com.apple.developer.authentication-services.autofill-credential-provider` entitlement, not just the extension.
* **Solution**: Added the entitlement to both `VaultUI.entitlements` and `VaultAutoFillExtension.entitlements`.

### 5. App Registration Path Requirement
* **Problem**: Building and running the app from Xcode's `DerivedData` directory did not reliably register the extension with macOS `pluginkit`.
* **Solution**: The compiled `.app` bundle must be copied to a standard directory (e.g. `/Applications/`) and launched. macOS automatically indexes applications in `/Applications/` and registers their bundled extensions.

### 6. Registering for Passkeys and Verification Codes (TOTP)
* **Problem**: Registering the extension to show up in the verification code autofill menu and support passkeys.
* **Cause**: macOS autofill architecture categorizes requests into separate extension capabilities. Unless the extension declares support for `ProvidesPasskeys` and `ProvidesOneTimeCodes`, the system won't query it for TOTP fields or passkeys.
* **Solution**:
  - **Capabilities plist Configuration**: Added capabilities to `Info.plist`'s `NSExtensionAttributes` > `ASCredentialProviderExtensionCapabilities`:
    - `ProvidesPasswords`: `true`
    - `ProvidesPasskeys`: `true`
    - `ProvidesOneTimeCodes`: `true`
  - **TOTP Extraction & Generation**: Modified the shared store to export decrypted TOTP secrets to the shared keychain, and implemented TOTP generation using `TOTPService`.
  - **AutoFillRequestMode Routing**: Added request modes to handle `.oneTimeCodes` and `.passkeyRegistration` in the view controller, completing requests using `completeOneTimeCodeRequest` and stubbing out passkey requests gracefully.
  - **Strict OSLog Interpolation Error**: Fixed a compiler error in Swift 6 where logging the request mode enum required conforming `AutoFillRequestMode` to `CustomStringConvertible`.

### 7. URI Match Types Are Not Honored

**By design.** Bitwarden items support per-URI match type settings (`domain`, `host`, `startsWith`, `exact`, `regularExpression`, `never`). The AutoFill extension does **not** respect these settings. When `SharedCredentialStore` exports credentials to the shared keychain it flattens each `LoginUri` to a plain string, discarding the `match` field entirely. The extension then applies domain matching unconditionally for all URIs.

Practical consequences:
- Items marked **"never autofill"** (`UriMatchType.never`) are still offered in the credential picker.
- Items using `exact`, `host`, or `regularExpression` match types receive the same domain-based matching as the default.

This is intentional — implementing per-URI match semantics in the credential provider extension would require re-decrypting the vault inside the extension process, which is architecturally undesirable. If a "never autofill" behavior is needed, delete the URI from the item or move the item to a non-login type.

---

## Helpful Diagnostics & CLI Commands

### Verify Extension Registration
Check if the system registers your extension and whether it is marked active (`+`):
```bash
pluginkit -m -i <your-autofill-extension-bundle-id>
```

### Inspect System Logs
To watch the extension lifecycle or debug crashes/entitlement violations in real time:
```bash
log show --predicate 'sender CONTAINS[cd] "VaultAutoFill" OR message CONTAINS[cd] "VaultAutoFill"' --last 5m
```
