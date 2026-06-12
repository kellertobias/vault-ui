# Missing feature: Legacy account login

**Status:** Resolved — legacy accounts can log in; a warning is shown instead of
a hard lockout.

> **Implemented (2026-06-12):**
> 1. **KDF floor → warning path:** `KeyDerivation.deriveKey` /
>    `MasterKey.derive` accept an explicit `allowWeakKDF` opt-in (default
>    remains reject). `VaultServices.login` derives anyway for sub-100k PBKDF2
>    configs and sets `SessionManager.weakKDFWarning`; `MainVaultView` shows an
>    alert telling the user to raise their KDF iterations.
> 2. **Type-0 account-key fallback:** `CipherEncryption.decryptUserKey` decrypts
>    type-2 protected keys with the stretched master key as before, and falls
>    back to the legacy type-0 form (AES-CBC, no MAC, raw unstretched master
>    key) — scoped to the protected account key only; vault items still reject
>    type 0 (`testVaultItemsStillRejectType0`).
>
> Covered by `UserKeyDecryptionTests` in `Tests/VaultCryptoTests/`. Real-vault
> legacy fixtures (from an actual pre-2023 account) would still be a nice
> addition. The original findings are kept below for reference.

## Problem

Two deliberate hardening choices reject configurations that older Bitwarden /
Vaultwarden accounts legitimately use, and that the official clients still
support. The result is a complete login failure rather than a downgrade warning.

### 1. Hard 100,000-iteration PBKDF2 minimum

`Sources/VaultCrypto/KeyDerivation.swift` throws before deriving if the server's
prelogin iteration count is below 100,000 (`CryptoConstants.swift`). Accounts
created before the 2023 default bump have 5,000–100,000 iterations. Official
clients warn but still derive the key, then let the user raise the count. Here
the user can't even log in to fix it.

### 2. Type-0 EncString decryption is rejected

`Sources/VaultCrypto/CipherEncryption.swift` rejects EncString type 0
(`AesCbc256_B64`, AES-CBC without HMAC). This is a sound default for vault items
(padding-oracle resistance), **but** legacy accounts store their account
encryption key as a **type-0 EncString encrypted with the unstretched master
key**. Official clients try stretched/type-2 first and fall back to
unstretched/type-0. Without that fallback, those accounts can't unlock.
Type 1 (AES-128-CBC+HMAC) is also rejected (rarer, same class).

## Impact

- Anyone with a pre-2023 account is locked out with no in-app remedy.

## Suggested direction

- Replace the hard PBKDF2 floor with a **warning** path: derive anyway below
  100k, surface a "weak KDF — increase iterations" prompt, and offer to bump the
  iteration count after unlock.
- Add the legacy account-key unlock fallback: attempt type-2 with the stretched
  master key, then fall back to type-0 with the unstretched master key — scoped
  to the protected account key only, not arbitrary vault items.
- Add fixtures from a real legacy vault to lock the behavior in with tests.
