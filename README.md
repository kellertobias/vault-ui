# Vault UI

A native macOS Bitwarden/Vaultwarden client built with Swift 6, SwiftUI, and CryptoKit.

No Electron. No compromises.

> [!WARNING]
> This project was substantially AI-coded and has not received an independent security audit. It handles passwords, passkeys, TOTP seeds, and SSH keys; use it at your own risk.

## Features

| Feature | Status |
|---------|--------|
| **Vault Management** — Logins, secure notes, cards, identities, SSH keys | ✅ Complete |
| **End-to-end Encryption** — AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) | ✅ Complete |
| **KDF Support** — PBKDF2-SHA256 and Argon2id | ✅ Complete |
| **Biometric Unlock** — Touch ID with Keychain-backed key storage | ✅ Complete |
| **Offline Sync** — SwiftData-backed local vault with conflict resolution | ✅ Complete |
| **SSH Agent** — Unix socket agent for Ed25519 and RSA keys | ✅ Complete |
| **TOTP Codes** — RFC 6238 code generation (SHA-1, SHA-256, SHA-512) | ✅ Complete |
| **Password Generator** — CSPRNG-backed passwords and passphrases | ✅ Complete |
| **CLI Tool** — `vaultui get`, `vaultui list`, `vaultui agent`, `vaultui secret` | ✅ Complete |
| **AutoFill Credential Provider** — macOS credential provider service logic | ✅ Logic only |
| **Safari Extension** — Native message handler for web extension | ⚠️ Partial |
| **FIDO2/Passkey** — WebAuthn credential matching | ✅ Logic only |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    VaultUIApp                       │
│                  (App entry point)                  │
├─────────────────────────────────────────────────────┤
│                    VaultAppUI                       │
│  LoginView · UnlockView · MainVaultView · Settings  │
├──────────────────────┬──────────────────────────────┤
│    VaultServices     │         VaultCLI             │
│  SessionManager      │   CLI tool (vaultui)         │
│  BiometricKeyStorage │                              │
│  PasswordGenerator   │                              │
│  TOTPService         │                              │
│  ClipboardService    │                              │
│  SafariExtension     │                              │
│  CredentialProvider   │                              │
│  ImportService       │                              │
├──────────┬───────────┼──────────┬───────────────────┤
│ VaultSync│ VaultSSH  │ VaultAPI │   VaultModels     │
│ SwiftData│ SSH Agent │ REST API │   Cipher, Login,  │
│ SyncEng. │ Ed25519   │ Auth     │   Card, Identity  │
│          │ RSA       │ Tokens   │   SSHKey, Send    │
├──────────┴───────────┴──────────┴───────────────────┤
│                   VaultCrypto                       │
│  AES-CBC · HMAC-SHA256 · PBKDF2 · Argon2id · HKDF  │
│  RSA-OAEP · EncString · SymmetricCryptoKey          │
└─────────────────────────────────────────────────────┘
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| **VaultCrypto** | All cryptographic primitives: key derivation, AES-CBC encryption, HMAC authentication, RSA-OAEP, EncString format parsing |
| **VaultModels** | Codable data models matching the Bitwarden API schema: Cipher, LoginData, CardData, IdentityData, SSHKeyData, SendItem, etc. |
| **VaultAPI** | REST API client for Bitwarden/Vaultwarden servers: authentication, token management, CRUD operations, Keychain-based token storage |
| **VaultSync** | Offline-first sync engine using SwiftData: local persistence, conflict resolution, offline queue with pending operations |
| **VaultSSH** | SSH agent implementation: Unix domain socket server (SwiftNIO), SSH agent protocol handler, Ed25519 and RSA signing |
| **VaultServices** | Business logic orchestration: session management, biometric unlock, password generation, TOTP, clipboard, Safari extension handler, credential provider, import |
| **VaultAppUI** | SwiftUI views: login, unlock, vault browser, cipher detail/edit, password generator, settings, import |
| **VaultCLI** | Command-line interface: `vaultui get`, `vaultui list`, `vaultui agent start/status/install` |
| **VaultUIApp** | macOS application entry point |

## Building

### Prerequisites

- macOS 15+ (Sequoia)
- Xcode 16+ (for SwiftData macro support)
- Swift 6.0+

### Build with Xcode

```bash
open Package.swift
# Build: ⌘B
# Run:   ⌘R
```

> **Note:** SwiftData `@Model` macros require Xcode for proper compilation. SPM CLI (`swift build`) will show SwiftData macro errors for the VaultSync and VaultServices modules — this is a known SPM limitation. Individual modules without SwiftData (VaultCrypto, VaultSSH, VaultAPI, VaultModels) compile cleanly with `swift build`.

### Build individual modules (SPM CLI)

```bash
swift build --target VaultCrypto    # Cryptographic primitives
swift build --target VaultSSH       # SSH agent
swift build --target VaultAPI       # API client
swift build --target VaultModels    # Data models
```

### Build the CLI tool

```bash
swift build --target VaultCLI
.build/debug/vaultui --help
```

## Usage

### GUI Application

1. Launch Vault UI
2. Enter your Vaultwarden/Bitwarden server URL (HTTPS required), email, and master password
3. The vault syncs automatically after login
4. Lock/unlock with Touch ID (automatically enabled after first login)

### CLI

```bash
# Get a password
vaultui get github.com --field password --server https://vault.example.com --email user@example.com

# List all vault items
vaultui list --server https://vault.example.com --email user@example.com

# Generate a password
vaultui generate --length 24 --symbols

# SSH agent
vaultui agent start                     # Start the agent
vaultui agent status                    # Check status
vaultui agent install                   # Install as LaunchAgent
export SSH_AUTH_SOCK="$HOME/Library/Group Containers/group.de.tobisk.apps.vaultui/.vaultui/agent.sock"

# Secret access (requires running Vault UI app)
vaultui secret get my-app.database           # Full secret as JSON
vaultui secret get my-app.database/password   # Just the password
eval "$(vaultui secret extend my.env)" && ./my-app  # Resolve .env file
```

See [CLI Secrets Documentation](docs/cli-secrets.md) for full details on the `secret` commands.

### SSH Agent

The SSH agent serves keys from your vault's SSH Key items over a Unix domain socket:

```bash
# Start the agent
vaultui agent start

# Or install as a LaunchAgent (starts on login)
vaultui agent install

# Configure your shell
echo 'export SSH_AUTH_SOCK="$HOME/Library/Group Containers/group.de.tobisk.apps.vaultui/.vaultui/agent.sock"' >> ~/.zshrc
source ~/.zshrc

# Test
ssh-add -l    # List keys from vault
ssh git@github.com  # Use vault keys for SSH
```

**Supported key types:** Ed25519 (via Curve25519) and RSA (via Security framework).

**Socket permissions:** `0600` (owner-only access).

## Security

### Cryptographic Design

| Component | Implementation |
|-----------|---------------|
| **Key Derivation** | PBKDF2-HMAC-SHA256 (≥100,000 iterations enforced) or Argon2id |
| **Vault Encryption** | AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC) |
| **MAC Verification** | Constant-time comparison (`XOR + OR` accumulator) |
| **Key Stretching** | HKDF-Expand with `"enc"` and `"mac"` info strings → 512-bit stretched key |
| **Organization Keys** | RSA-2048-OAEP-SHA1 via Apple Security framework |
| **Random Generation** | `SecRandomCopyBytes` (CSPRNG) for all IVs, keys, and password generation |
| **Password Generator** | `SecRandomCopyBytes` with rejection sampling (no modulo bias) |

### Key Material Handling

| Mechanism | Detail |
|-----------|--------|
| **Token Storage** | macOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **Biometric Keys** | Keychain with `kSecAccessControlBiometryCurrentSet` — invalidated on enrollment change |
| **Memory Zeroing** | `SymmetricCryptoKey.zeroize()` called on vault lock; `Data.resetBytes` for private keys |
| **Local Persistence** | SwiftData stores encrypted EncString blobs only — plaintext never touches disk |
| **Type 0 (Legacy)** | Rejected — unauthenticated AES-CBC is refused with `unsupportedEncryptionType` |
| **PBKDF2 Floor** | Server-requested iterations below 100,000 are rejected to prevent downgrade attacks |

### Authentication Flow

```
1. Prelogin  → Server returns KDF config (type, iterations, memory, parallelism)
2. Derive    → Master key from password + email salt via PBKDF2/Argon2id
3. Stretch   → HKDF-Expand to 512-bit stretched key (enc + mac)
4. Hash      → PBKDF2(masterKey, password, 1 iteration) → auth hash
5. Login     → POST auth hash to server → receive access token + encrypted vault key
6. Decrypt   → Decrypt vault key using stretched master key
7. Store     → Save vault key in Keychain with biometric protection
8. Sync      → Full vault sync, decrypt items in memory only
```

### Biometric Unlock Flow

```
1. User locks vault → keys zeroed from memory, references released
2. User taps "Unlock with Touch ID"
3. LAContext evaluates biometric policy
4. Pre-authenticated context passed to Keychain retrieval (single prompt)
5. Vault key + private key restored from biometric-protected Keychain item
6. API tokens loaded from standard Keychain storage
7. API client and sync engine reconstructed
8. Background sync initiated
```

## Safari Extension

### Current Status

The Safari extension native message handler (`SafariExtensionService`) is **implemented as business logic** but requires additional Xcode setup to function as a full browser extension:

**✅ Implemented (native handler):**
- `getCredentials` — Find matching credentials for a URL (domain matching, host, exact, regex, startsWith)
- `fillCredential` — Decrypt and return password for a specific cipher
- `generatePassword` — Generate a CSPRNG-backed password
- `getVaultStatus` — Report lock/unlock state
- `copyTotp` — Generate and return TOTP code for a cipher
- `lockVault` — Report lock acknowledgment

**⚠️ Stub/incomplete:**
- `saveCredential` — Logs the request but does not persist (needs cipher creation flow)
- `lockVault` — Returns success but does not actually trigger `SessionManager.lock()` (needs callback wiring)

**❌ Not yet created:**
- Safari Web Extension target (Xcode project configuration)
- `manifest.json` (browser extension manifest)
- `background.js` (background script for native messaging)
- `content.js` (content script for page interaction and form detection)
- `popup.html/js` (extension popup UI)
- App Group configuration for IPC between main app and extension

### To complete the Safari extension:

1. **In Xcode:** File → New → Target → Safari Web Extension
2. **Configure:** Add the extension to the same App Group as the main app
3. **Wire up:** The `SafariExtensionService.handleMessage()` function handles all message routing — call it from your extension's native message handler
4. **Content script:** Implement form detection, credential injection, and save prompts
5. **Add `lockVault` callback:** Wire the lock message to actually call `SessionManager.lock()`

### AutoFill Credential Provider

The `CredentialProviderService` provides the matching logic for macOS AutoFill:

```swift
// Find credentials matching a URL
let matches = CredentialProviderService.findCredentials(
    for: "https://github.com",
    ciphers: ciphers,
    key: vaultKey
)

// Find passkeys for a relying party
let passkeys = CredentialProviderService.findPasskeyCredentials(
    for: "github.com",
    ciphers: ciphers,
    key: vaultKey
)
```

To enable as a system credential provider, create an AutoFill Credential Provider Extension target in Xcode with the `com.apple.developer.authentication-services.autofill-credential-provider` entitlement.

## Project Layout

```
bitwarden-gui/
├── Package.swift                    # SPM manifest
├── Sources/
│   ├── VaultCrypto/                 # Cryptographic primitives
│   │   ├── AESCBCEngine.swift       #   AES-256-CBC + HMAC-SHA256
│   │   ├── AsymmetricCrypto.swift   #   RSA-2048-OAEP
│   │   ├── CipherEncryption.swift   #   High-level encrypt/decrypt API
│   │   ├── CryptoConstants.swift    #   Protocol constants
│   │   ├── CryptoError.swift        #   Error types
│   │   ├── EncString.swift          #   Bitwarden wire format parser
│   │   ├── KeyDerivation.swift      #   PBKDF2 + Argon2id
│   │   ├── MasterKey.swift          #   HKDF key stretching
│   │   ├── MasterPasswordHash.swift #   Auth hash computation
│   │   └── SymmetricCryptoKey.swift  #   512-bit key pair with zeroize()
│   ├── VaultModels/                 # API-compatible data models
│   │   ├── Cipher.swift             #   Core vault item
│   │   ├── Login.swift              #   Login data + FIDO2 credentials
│   │   ├── Account.swift            #   Server account + auth tokens
│   │   └── ...                      #   Card, Identity, SSHKey, Send, etc.
│   ├── VaultAPI/                    # REST API client
│   │   ├── VaultAPI.swift           #   APIClient (URLSession-based)
│   │   ├── AuthService.swift        #   Login, prelogin, token refresh
│   │   ├── TokenStorage.swift       #   Keychain-backed token persistence
│   │   └── APIError.swift           #   API error types
│   ├── VaultSync/                   # Offline sync engine
│   │   ├── SyncEngine.swift         #   Full sync + merge + conflict resolution
│   │   ├── PersistedModels.swift    #   SwiftData @Model definitions
│   │   └── VaultDataStore.swift     #   ModelContainer factory
│   ├── VaultSSH/                    # SSH agent
│   │   ├── SSHAgentServer.swift     #   Unix socket server (SwiftNIO)
│   │   ├── SSHAgentHandler.swift    #   Agent protocol handler
│   │   └── SSHAgentProtocol.swift   #   SSH wire format utilities
│   ├── VaultServices/               # Business logic
│   │   ├── VaultServices.swift      #   SessionManager (auth orchestration)
│   │   ├── BiometricKeyStorage.swift#   Touch ID key storage
│   │   ├── PasswordGenerator.swift  #   CSPRNG password/passphrase gen
│   │   ├── TOTPService.swift        #   RFC 6238 TOTP
│   │   ├── ClipboardService.swift   #   Auto-clearing clipboard
│   │   ├── SafariExtensionService.swift  # Safari extension handler
│   │   ├── CredentialProviderService.swift # AutoFill matching
│   │   └── ImportService.swift      #   SSH key + 1Password/CSV import
│   ├── VaultAppUI/                  # SwiftUI views
│   │   ├── VaultApp.swift           #   App root + content router
│   │   ├── LoginView.swift          #   Server login (HTTPS enforced)
│   │   ├── UnlockView.swift         #   Touch ID + password fallback
│   │   ├── MainVaultView.swift      #   Vault browser
│   │   ├── CipherDetailView.swift   #   Item detail
│   │   ├── CipherEditView.swift     #   Item editor
│   │   ├── PasswordGeneratorView.swift # Generator UI
│   │   ├── SettingsView.swift       #   Preferences
│   │   └── ...
│   ├── VaultCLI/                    # CLI tool
│   │   └── VaultCLI.swift           #   ArgumentParser commands
│   └── VaultUIApp/                  # App entry point
│       └── VaultUIApplication.swift
└── Tests/
    ├── VaultCryptoTests/
    ├── VaultModelsTests/
    └── VaultAPITests/
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [swift-crypto](https://github.com/apple/swift-crypto) | 3.0+ | HMAC-SHA256 for PBKDF2 implementation |
| [swift-nio](https://github.com/apple/swift-nio) | 2.65+ | Unix domain socket server for SSH agent |
| [swift-argument-parser](https://github.com/apple/swift-argument-parser) | 1.3+ | CLI argument parsing |
| [Argon2Swift](https://github.com/tmthecoder/Argon2Swift) | main | Argon2id key derivation |

## License

Vault UI is released under the MIT License. See [LICENSE](LICENSE).

Third-party dependencies are distributed under their own licenses. See [THIRD_PARTY_LICENSES.md](Sources/VaultAppUI/Resources/THIRD_PARTY_LICENSES.md).
