# SSH Key Import

This document describes how SSH key import works in Vault UI — both via the **"Import from File"** button in the New SSH Key editor and via the **Import Data** wizard.

## Overview

Users can store SSH keys in their vault as first-class cipher items. Keys can be:

1. **Generated** in-app (Ed25519 only)
2. **Imported from file** (OpenSSH, RSA PKCS#1, and other key types)

Imported keys are encrypted with a per-item key and synced to the Vaultwarden server, just like any other vault item.

## Format Compatibility

Vaultwarden requires private keys in **OpenSSH format** (`-----BEGIN OPENSSH PRIVATE KEY-----`). Legacy formats are auto-converted on import:

| Input Format | Header | Handling |
|---|---|---|
| OpenSSH | `BEGIN OPENSSH PRIVATE KEY` | ✅ Passed through as-is |
| PKCS#1 RSA | `BEGIN RSA PRIVATE KEY` | ✅ Auto-converted to OpenSSH |
| PKCS#1 RSA (encrypted) | `BEGIN RSA PRIVATE KEY` + `Proc-Type: ENCRYPTED` | ⚠️ Stored as-is (cannot convert) |
| ECDSA | `BEGIN EC PRIVATE KEY` | ⚠️ Stored as-is (not yet supported) |
| PKCS#8 | `BEGIN PRIVATE KEY` | ⚠️ Stored as-is (not yet supported) |

## Import Flow (CipherEditView)

When the user clicks **"Import from File…"** in the SSH Key editor:

```
User clicks button
  → NSOpenPanel opens (defaults to ~/.ssh, shows hidden files)
  → User selects one or more files
  → For each file:
      1. Read file contents as UTF-8
      2. Detect file type (public key vs private key)
      3. Process private key via ImportService.processImportedSSHKey():
         a. Auto-convert PKCS#1 RSA → OpenSSH format
         b. Extract public key from private key
      4. Populate the corresponding text fields
  → User clicks Save
  → Fields are encrypted and synced to server
```

### File Type Detection

Files are classified by content inspection:

| Condition | Classification |
|---|---|
| Extension is `.pub`, or content starts with `ssh-` or `ecdsa-` | **Public key** |
| Content contains `PRIVATE KEY` | **Private key** (PEM) |
| Extension is `.pub` (fallback) | **Public key** |
| Otherwise | **Private key** (assumed) |

### Public Key Auto-Extraction

When only a private key file is selected, the public key field is populated automatically:

1. **Try the sibling `.pub` file** — e.g., if `id_rsa` is selected, try reading `id_rsa.pub`. This may fail in a sandboxed app because only user-selected files get sandbox file access.
2. **Extract from the private key** — Both OpenSSH and PKCS#1 formats contain the public key material. The parser extracts it and formats as a standard SSH public key line.

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

## PKCS#1 RSA Key Conversion

Legacy RSA keys (`-----BEGIN RSA PRIVATE KEY-----`) use a different format based on ASN.1 DER encoding. The `ImportService.convertPKCS1ToOpenSSH()` function converts them to OpenSSH format.

### PKCS#1 DER Structure

```
SEQUENCE {
  INTEGER  version       ← 0
  INTEGER  n             ← modulus
  INTEGER  e             ← public exponent
  INTEGER  d             ← private exponent
  INTEGER  p             ← prime1
  INTEGER  q             ← prime2
  INTEGER  dp            ← d mod (p-1)
  INTEGER  dq            ← d mod (q-1)
  INTEGER  iqmp          ← q^(-1) mod p
}
```

### Conversion Steps

1. Strip PEM armor, decode base64 → DER bytes
2. Parse ASN.1 DER SEQUENCE containing 9 INTEGERs
3. Extract RSA components: n, e, d, p, q, dp, dq, iqmp
4. Re-encode as OpenSSH format:
   - Build public key blob: `string "ssh-rsa" || mpint e || mpint n`
   - Build private section: `check || check || "ssh-rsa" || n || e || d || iqmp || p || q || comment || padding`
   - Wrap in openssh-key-v1 container with `ciphername=none`
5. Base64-encode and wrap in PEM armor

> **Note:** ASN.1 DER integers use the same two's complement encoding as SSH mpints (leading 0x00 when the high bit is set), so the raw integer bytes can be used directly without re-encoding.

### Limitations

- **Encrypted keys** (`Proc-Type: 4,ENCRYPTED`) cannot be converted — the DER body is encrypted and would need the passphrase to decode.
- **PKCS#8 and EC keys** are not yet supported for conversion.

## Safety

All integer reads use safe byte-by-byte construction rather than `UnsafeRawBufferPointer.load()` to avoid crashes from Data slice buffer alignment issues:

```swift
let value = UInt32(data[offset])   << 24
          | UInt32(data[offset+1]) << 16
          | UInt32(data[offset+2]) << 8
          | UInt32(data[offset+3])
```

Every read is bounds-checked and returns `nil` on malformed input — the functions never crash, they simply return `nil` if the key can't be parsed.

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
| `Sources/VaultServices/ImportService.swift` | Key format parsing, PKCS#1 conversion, public key extraction, encryption |
| `Sources/VaultModels/SSHKey.swift` | `SSHKeyData` model (privateKey, publicKey, keyFingerprint) |
| `VaultUI.entitlements` | Sandbox entitlements including file access |
