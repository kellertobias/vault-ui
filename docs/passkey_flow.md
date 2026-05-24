# Vault UI Passkey (WebAuthn) Flow

This document explains the architecture and implementation details of Passkey (WebAuthn) support in the Vault UI macOS AutoFill Extension, as well as an overview of recent bugs that were resolved to ensure compatibility with strict Relying Parties (RPs) and macOS's `AuthenticationServices` framework.

## 1. Overview of the Passkey Flow

Passkeys are essentially discoverable WebAuthn credentials based on public-key cryptography (typically ECDSA over the P-256 curve). Vault UI acts as a third-party authenticator via the macOS Credential Provider Extension.

### Registration (Credential Creation)
When a user registers a passkey on a website:
1. The RP sends an `ASPasskeyCredentialRequest` to create a passkey.
2. Vault UI intercepts this request and generates a new secure Enclave-backed or software-backed P-256 keypair.
3. The public key is bundled with an `authenticatorData` payload and an Attestation Object.
4. Vault UI securely stores the base64-encoded `privateKey`, `credentialId`, `userHandle`, and `rpId` in the local SyncEngine (which is synced to the Bitwarden server).
5. The extension completes the request, handing the public key back to the website.

### Assertion (Login)
When a user logs in with a passkey:
1. The RP sends an assertion request containing a `clientDataHash`.
2. macOS triggers Vault UI's AutoFill extension.
3. The user selects the appropriate passkey for the domain.
4. Vault UI decrypts the stored `privateKey` and dynamically constructs the `authenticatorData` (which includes the RP ID hash, FIDO2 flags, and a signature counter).
5. Vault UI signs the concatenation of `authenticatorData` and `clientDataHash` using the decrypted private key.
6. The resulting `ASPasskeyAssertionCredential` is returned to the system, authenticating the user.

---

## 2. Recent Bugs and Resolutions

Several subtle issues previously caused passkey assertions to fail with an ambiguous "NotAllowedError" in Safari/macOS. These were root-caused and fixed as follows:

### Bug 1: Missing Sync/Backup Flags in Authenticator Data
**The Problem:** 
During passkey registration, Vault UI properly informed the Relying Party that the credential was a multi-device passkey by setting the WebAuthn flags to include `BE` (Backup Eligible) and `BS` (Backup State) (`0x5D`). However, during **assertion (login)**, the extension was hardcoded to only return `0x05` (User Present and User Verified). Because strict relying parties (and Safari's internal validations) expect the backup state of a credential to remain consistent, the sudden disappearance of the `BE` and `BS` flags caused the login attempt to be rejected.

**The Fix:**
Updated `WebAuthnGenerator.generateAssertion` to properly include the `BE` and `BS` flags during assertion generation, changing the assertion flags byte to `0x1D`.

### Bug 2: Missing Request Parameters during `prepareCredentialList`
**The Problem:**
macOS triggers `prepareCredentialList(for:requestParameters:)` to populate the QuickType autofill bar. If the user ignored the QuickType bar and instead clicked into our custom SwiftUI picker, the system expected us to handle the assertion manually. However, our extension was failing to store the `requestParameters` from that initial call. When the user eventually tapped a passkey in our UI, the extension assumed it was a standard password request because `currentPasskeyAssertionRequest` was `nil`. It then attempted to fetch a password that didn't exist, failing silently or throwing errors.

**The Fix:**
The extension now explicitly captures the `ASPasskeyCredentialRequestParameters` during `prepareCredentialList`. In the `provideSelectedCredential(_:)` callback, if an explicit request object is missing, the extension falls back to extracting the `relyingPartyIdentifier` and `clientDataHash` directly from those captured parameters and completes the `completeAssertionRequest(using:)` pipeline correctly.

### Bug 3: Typecasting `ASCredentialIdentity`
**The Problem:**
The macOS `AuthenticationServices` framework passes identities as `any ASCredentialIdentity`. The base protocol lacks passkey-specific properties.
**The Fix:**
Added explicit typecasting to `ASPasskeyCredentialIdentity` to successfully extract the `relyingPartyIdentifier` needed to compute the correct RP ID SHA-256 hash during the signature phase.

---

By resolving these issues, the Vault UI extension now correctly respects the WebAuthn specifications for multi-device syncable credentials and seamlessly intercepts assertion payloads regardless of how the user triggers the AutoFill UI.
