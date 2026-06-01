# Vault UI TODO List & Technical Implementation Plans

This document outlines the detailed technical design and implementation steps for the remaining features.

---

## 1. AutoFill Integration & Verification
**Goal**: Test and verify the native macOS AutoFill Credential Provider extension end-to-end using the paid Apple Developer account.

### Technical Plan
1. **Dynamic Keychain Sharing Team ID Resolution**:
   - Implement dynamic Team ID discovery in `SharedCredentialStore` by querying a dummy Keychain item. This avoids hardcoding the Team ID prefix in the source code and works seamlessly with whatever developer account/team is selected in Xcode.
   - The resolved Keychain access group will be constructed at runtime as `$(TeamID).de.tobisk.opensource.vaultui.shared`.
2. **Xcode Target Signing**:
   - Open `VaultUI.xcodeproj` in Xcode.
   - Select both the `VaultUI` and `VaultAutoFillExtension` targets.
   - Under **Signing & Capabilities**, select the paid Developer Team.
3. **Register Extension**:
   - Build and run the app from Xcode or using `./build release --open`.
   - Open **System Settings → Passwords → AutoFill** (or **General → Login Items & Extensions → Credential Provider Extensions**).
   - Enable **Vault UI** as a credential provider.
4. **Verification**:
   - Navigate to a login page in Safari (e.g. `github.com`).
   - Click the credential fields and verify the AutoFill dropdown suggests the matching username/password from the shared Keychain.

---

## 2. Touch ID Unlock
**Goal**: Integrate Touch ID biometric unlock into the main app so users can unlock their vault without entering the master password.

### Technical Plan
1. **Keychain Persistence**:
   - Use `BiometricKeyStorage` to store the derived vault key and organization private key in the Keychain, secured with `.biometryCurrentSet` access control.
   - In `SessionManager`, when the user successfully logs in with their password:
     - If `useTouchID` is enabled, call `biometricKeyStorage.storeKeys(...)` to save the keys.
2. **Settings Reactivity**:
   - Add a listener in `SessionManager` for settings changes (`UserDefaults.didChangeNotification`).
   - If `useTouchID` is toggled ON, and the vault is currently unlocked, immediately store the keys.
   - If `useTouchID` is toggled OFF, delete the stored keys from the Keychain.
3. **Unlock Flow**:
   - In `UnlockView.swift`, when the app launches or returns to the foreground, if `useTouchID` is enabled and biometric keys are present, prompt the user for Touch ID using `LAContext`.
   - Evaluate `.deviceOwnerAuthenticationWithBiometrics`. Upon success, pass the authenticated context to `BiometricKeyStorage.retrieveKeys(for:context:)` to fetch the vault key and transition the state to `.unlocked`.

---

## 3. SSH Key Syncing & SSH Agent
**Goal**: Sync SSH keys from the Vaultwarden vault and expose them to macOS SSH clients via the SSH Agent protocol.

### Technical Plan
1. **Native Vaultwarden SSH Key Support**:
   - Use the native `sshKey` cipher type (type `5`) exposed by Vaultwarden.
   - The sync engine already fetches and persists these keys as `PersistedCipher` records using SwiftData.
2. **SSH Agent Server Lifecycle**:
   - Integrate the `SSHAgentServer` and `SSHAgentHandler` lifecycle directly into `SessionManager`.
   - When the user toggles "Enable SSH Agent" in the settings, start the Unix socket server on `~/.vaultui/agent.sock`.
   - When toggled OFF, stop the socket server and delete the socket file.
   - Add an observer for `UserDefaults` settings changes in `SessionManager` to handle this reactively.
3. **Identity Updates**:
   - **On Unlock / Successful Sync**: Fetch all ciphers of type `sshKey` from the SwiftData database. Decrypt the public key fields, parse them to extract the base64-encoded public key blob, and call `sshAgentHandler.setIdentities(...)`.
   - **On Lock**: Call `sshAgentHandler.clearIdentities()` to wipe all key metadata from memory.
4. **Cryptographic Signing Callback**:
   - Initialize `SSHAgentHandler` with a private key provider closure.
   - When an SSH client requests a signature, the handler will run the closure.
   - The closure will look up the cipher in the offline database, decrypt the private key PEM using the active `vaultKey`, and return the raw key data for signing (using `Curve25519.Signing.PrivateKey` for Ed25519 keys, and `SecKey` for RSA keys).
   - This ensures private keys are only decrypted in memory on-demand and are never stored in the agent's long-term memory.

---

## 4. CLI Environment Secret Hydrator (with Touch ID)
**Goal**: Provide a secure CLI command `vaultui populate-env <template>` that replaces placeholders in environment templates using Touch ID.

### Technical Plan
1. **Subcommand Registration**:
   - Add a subcommand `populate-env` to `VaultCLI.swift`.
   - Arguments: `templatePath` (e.g. `example.env`) and optional `--output` / `-o`.
2. **Account Meta File**:
   - When the GUI app updates its active account, write a lightweight configuration file to `~/.vaultui/config.json` containing the active account ID, email, and server URL.
   - The CLI will read this file to determine which account's vault to query.
3. **Touch ID Auth in CLI**:
   - Use `LAContext` to trigger the system Touch ID prompt in the terminal:
     ```swift
     let context = LAContext()
     let success = try await context.evaluatePolicy(
         .deviceOwnerAuthenticationWithBiometrics,
         localizedReason: "Decrypt environment secrets"
     )
     ```
   - Fetch the vault key using `BiometricKeyStorage.retrieveKeys(for:context:)` passing the authenticated context.
4. **Database Access**:
   - Configure the SwiftData container in `VaultDataStore` to store the database file `VaultUI.sqlite` inside the shared App Group directory.
   - The CLI will load the same database directly from this directory, granting offline access to synced ciphers.
5. **Placeholder Matching & Extraction**:
   - Read the template env file and find all placeholders matching the format `<path/to/secret/name>`.
   - Find matching ciphers in the database:
     - Check if any cipher has a custom field with the name `secret_name`, `path`, or `env_path` whose value is exactly `path/to/secret/name`.
     - Fallback: Check if the cipher name itself matches `path/to/secret/name`.
   - Extract the decrypted secret value from the matching cipher:
     - Use `password` for login ciphers.
     - Use the value of a custom field named `value` or `secret`.
     - Use the `notes` field as a fallback.
   - Replace the placeholders and write the output (defaulting to `.env` in the template's directory).
