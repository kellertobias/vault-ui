# Missing feature: Legacy account login

**Status:** Pre-2023 (low-iteration PBKDF2) accounts still cannot log in, but now
fail with a **clear, actionable warning** instead of a cryptic crypto error.
**Severity:** Medium (hard lockout for affected users).

> **Mitigation in place:** `VaultServices.login` checks the KDF config returned by
> prelogin and, when PBKDF2 iterations are below
> `CryptoConstants.minimumPBKDF2Iterations`, throws a user-facing message telling
> the user to raise their KDF iterations in another client and try again. This
> does **not** let legacy accounts in — the full fix below (KDF floor → warning,
> type-0 unlock fallback) is still outstanding.

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
