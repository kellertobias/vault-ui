# Transferring to a New Apple Developer Account

When moving this project to a different Apple Developer account, the following values must be updated. The **Team ID** is the 10-character alphanumeric identifier assigned by Apple (e.g. `F55HNXZ7TD`). You can find the new one in [Apple Developer → Membership](https://developer.apple.com/account#MembershipDetailsCard).

---

## 1. Team ID in Build Configuration

The `DEVELOPMENT_TEAM` build setting must be updated in two places:

| File | Line(s) | Current Value |
|------|---------|---------------|
| `project.yml` | Target **VaultUI** → `settings` | `DEVELOPMENT_TEAM: F55HNXZ7TD` |
| `project.yml` | Target **VaultAutoFillExtension** → `settings` | `DEVELOPMENT_TEAM: F55HNXZ7TD` |

---

## 2. Bundle Identifiers (if changing)

Bundle identifiers are independent of the team ID, but if the new developer account already uses a different naming convention, update:

| File | Value |
|------|-------|
| `project.yml` → `options.bundleIdPrefix` | `de.tobisk.apps.vaultui` |
| `project.yml` → VaultUI target → `PRODUCT_BUNDLE_IDENTIFIER` | `de.tobisk.apps.vaultui` |
| `project.yml` → AutoFill target → `PRODUCT_BUNDLE_IDENTIFIER` | `de.tobisk.apps.vaultui.AutoFillExtension` |

> [!IMPORTANT]
> If you change the bundle ID, you must also update **every** file listed in sections 3–5 below, since they reference the bundle ID in Keychain service names, access groups, and container identifiers.

---

## 3. Hardcoded Team-Prefixed Keychain Access Group

The Keychain access group in `SharedCredentialStore` includes the **full team-prefixed** identifier. macOS does **not** auto-prepend the team ID at runtime.

| File | Constant | Current Value |
|------|----------|---------------|
| `Sources/VaultServices/SharedCredentialStore.swift` | `keychainAccessGroup` | `"F55HNXZ7TD.de.tobisk.apps.vaultui.shared"` |

Change `F55HNXZ7TD` to the new Team ID. The suffix must match the `keychain-access-groups` entitlement entries.

---

## 4. Entitlements

The entitlements use `$(AppIdentifierPrefix)` which Xcode resolves automatically from the signing identity at build time. **These do not need manual changes** for a team transfer — only if the bundle ID changes.

| File | Keys |
|------|------|
| `VaultUI.entitlements` | `keychain-access-groups` → `$(AppIdentifierPrefix)de.tobisk.apps.vaultui`, `$(AppIdentifierPrefix)de.tobisk.apps.vaultui.shared` |
| `VaultAutoFillExtension.entitlements` | `keychain-access-groups` → `$(AppIdentifierPrefix)de.tobisk.apps.vaultui.shared` |

> [!NOTE]
> `$(AppIdentifierPrefix)` is expanded to `<TeamID>.` automatically. No changes needed here unless the bundle ID changes.

---

## 5. Keychain Service Names (bundle-ID-derived)

These are string constants used as Keychain `kSecAttrService` values. They don't contain the Team ID, but they reference the bundle ID. Update them if you change the bundle identifier.

| File | Constant | Current Value |
|------|----------|---------------|
| `Sources/VaultServices/SharedCredentialStore.swift` | `indexServiceName` | `"de.tobisk.apps.vaultui.credentials"` |
| `Sources/VaultServices/SharedCredentialStore.swift` | `passwordServiceName` | `"de.tobisk.apps.vaultui.password"` |
| `Sources/VaultServices/SharedCredentialStore.swift` | `totpServiceName` | `"de.tobisk.apps.vaultui.totp"` |
| `Sources/VaultSync/VaultDataStore.swift` | `groupContainer` | `"group.de.tobisk.apps.vaultui"` |

---

## 6. Other Identifiers (no Team ID, but bundle-ID-derived)

These use a `com.vaultui` namespace that is independent of the bundle ID and Team ID. They do **not** need to change on a team transfer, but are listed here for completeness.

| File | Value | Purpose |
|------|-------|---------|
| `Sources/VaultAPI/TokenStorage.swift` | `"com.vaultui.tokens"` | Keychain service for auth tokens |
| `Sources/VaultServices/BiometricKeyStorage.swift` | `"com.vaultui.biometric"` | Keychain service for biometric vault keys |
| `Sources/VaultSSH/SSHAgentServer.swift` | `"com.vaultui.ssh-agent"` | LaunchAgent label & plist name |
| Various files | `Logger(subsystem: "com.vaultui", ...)` | os_log subsystem for Console.app filtering |

---

## Quick Checklist

For a **team-only transfer** (same bundle ID, different Apple Developer account):

- [ ] Update `DEVELOPMENT_TEAM` in `project.yml` (2 places)
- [ ] Update the team prefix in `SharedCredentialStore.keychainAccessGroup`
- [ ] Re-generate the Xcode project: `xcodegen generate`
- [ ] Clean build folder in Xcode (Shift+Cmd+K)
- [ ] Delete old Keychain items (users will need to re-login after the transfer)

For a **full rebrand** (new bundle ID + new team):

- [ ] All of the above
- [ ] Update `bundleIdPrefix` and `PRODUCT_BUNDLE_IDENTIFIER` in `project.yml`
- [ ] Update all Keychain service names in `SharedCredentialStore.swift`
- [ ] Update `groupContainer` in `VaultDataStore.swift`
- [ ] Update entitlements if the bundle ID suffix changed
