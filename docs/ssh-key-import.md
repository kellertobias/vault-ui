# SSH Key Import

This document describes how SSH key import works in Vault UI — both via the **"Import from File"** button in the New SSH Key editor and via the **Import Data** wizard.

## Overview

Users can store SSH keys in their vault as first-class cipher items. Keys can be:

1. **Generated** in-app (Ed25519 only)
2. **Imported from file** (any OpenSSH key type)

Imported keys are encrypted with a per-item key and synced to the Vaultwarden server, just like any other vault item.

## Import Flow (CipherEditView)

When the user clicks **"Import from File…"** in the SSH Key editor:

```
User clicks button
  → NSOpenPanel opens (defaults to ~/.ssh, shows hidden files)
  → User selects one or more files
  → For each file:
      1. Read file contents as UTF-8
      2. Detect file type (public key vs private key)
      3. Populate the corresponding text field
      4. Auto-extract public key from private key if needed
  → User clicks Save
  → Fields are encrypted and synced to server
```

### File Type Detection

Files are classified by content inspection:

| Condition | Classification |
|---|---|
| Extension is `.pub`, or content starts with `ssh-` or `ecdsa-` | **Public key** |
| Content contains `PRIVATE KEY` | **Private key** (OpenSSH PEM) |
| Extension is `.pub` (fallback) | **Public key** |
| Otherwise | **Private key** (assumed) |

### Public Key Auto-Extraction

When only a private key file is selected, the public key field is populated automatically:

1. **Try the sibling `.pub` file** — e.g., if `id_ed25519` is selected, try reading `id_ed25519.pub`. This may fail in a sandboxed app because only user-selected files get sandbox file access.
2. **Extract from the private key PEM** — OpenSSH private key files embed the public key. The parser extracts it directly from the binary format (see below).

## OpenSSH Private Key Format

The `ImportService.extractPublicKeyFromOpenSSHPrivateKey()` function parses the [OpenSSH private key format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key) to extract the embedded public key.

### Binary Structure

```
"openssh-key-v1\0"       ← magic bytes (null-terminated)
string   ciphername      ← "none" for unencrypted, "aes256-ctr" etc.
string   kdfname         ← "none" for unencrypted, "bcrypt" etc.
string   kdfoptions      ← empty for unencrypted
uint32   number-of-keys  ← usually 1
string   public-key-blob ← ← THIS is what we extract
string   private-section ← encrypted if passphrase-protected
```

All `string` fields are length-prefixed: a big-endian `uint32` length followed by that many bytes.

The **public key blob** is itself in SSH wire format:

```
string   key-type        ← e.g., "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"
string   key-data        ← type-specific key material
```

### Parsing Steps

1. Base64-decode the PEM body (strip `-----BEGIN/END OPENSSH PRIVATE KEY-----` lines)
2. Verify the `openssh-key-v1\0` magic
3. Skip `ciphername`, `kdfname`, `kdfoptions` (read and discard)
4. Read `number-of-keys`
5. Read the `public-key-blob`
6. Parse the key type from the blob
7. Return as `"{key-type} {base64(blob)}"` — standard OpenSSH public key format

### Safety

All integer reads use safe byte-by-byte construction rather than `UnsafeRawBufferPointer.load()` to avoid crashes from Data slice buffer alignment issues:

```swift
let value = UInt32(data[offset])   << 24
          | UInt32(data[offset+1]) << 16
          | UInt32(data[offset+2]) << 8
          | UInt32(data[offset+3])
```

Every read is bounds-checked and returns `nil` on malformed input — the function never crashes, it simply returns `nil` if the key can't be parsed.

## Encryption & Save

When the user saves an SSH key (whether generated or imported), the save flow is:

```
1. Generate a new 512-bit item key (SymmetricCryptoKey)
2. Encrypt item key with the vault key → cipher.key
3. Encrypt each field with the item key:
   - cipher.name
   - cipher.sshKey.privateKey
   - cipher.sshKey.publicKey
   - cipher.sshKey.keyFingerprint (SHA-256 of public key blob)
4. Save locally via SyncEngine.saveCipherLocally()
5. Push to server via SyncEngine.fullSync()
```

The **fingerprint** is computed as `SHA256:{base64}` from the raw public key blob bytes — the same format used by `ssh-keygen -l`.

## Entitlements

The app requires the `com.apple.security.files.user-selected.read-only` entitlement in `VaultUI.entitlements` for `NSOpenPanel` to function in the sandboxed app. Without this, the file picker silently fails to grant access to selected files.

## Key Files

| File | Purpose |
|---|---|
| `Sources/VaultAppUI/CipherEditView.swift` | UI for SSH key creation/editing, file import button handler |
| `Sources/VaultServices/ImportService.swift` | Key format parsing, public key extraction, encryption helpers |
| `Sources/VaultModels/SSHKey.swift` | `SSHKeyData` model (privateKey, publicKey, keyFingerprint) |
| `VaultUI.entitlements` | Sandbox entitlements including file access |
