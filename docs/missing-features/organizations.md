# Missing feature: Organization / collection support

**Status:** Not implemented. Org items are now **hard-blocked as read-only** so they
can no longer be corrupted; full support is still outstanding.
**Severity:** High (was silent data corruption for other org members).

> **Mitigation in place:** Items with `organizationId != nil` are read-only. The
> detail view shows an "Organizations are not supported" notice and disables
> Edit/Delete, and `CipherEditView.save()` refuses to save org items — so the
> personal-key re-encryption corruption described below can no longer happen.
> The decryption/sync gaps remain; org items still display blank fields.

## Problem

The app presents itself as a Bitwarden/Vaultwarden client, but organization
(shared collection) vaults are effectively unsupported, and the partial wiring
that does exist will corrupt org items rather than fail safely.

### 1. The RSA layer is dead and wrong

`Sources/VaultCrypto/AsymmetricCrypto.swift` is the only path that could unwrap
an organization key (each org key is an RSA-encrypted symmetric key that the
user decrypts with their account private key). As shipped:

- It has **zero call sites** and **zero tests** — nothing in `VaultServices` or
  `VaultSync` ever uses it to decrypt an org key.
- `importPublicKey` / `importPrivateKey` use `SecKeyCreateWithData` with
  `kSecAttrKeyTypeRSA`, which expects **PKCS#1** DER. Bitwarden delivers the
  account public key as **SPKI** and the decrypted private key as **PKCS#8**.
  Without ASN.1 header conversion these imports fail on first contact with real
  server data.

The app decrypts and stores the account `privateKeyData` (see
`VaultServices.swift`) "for org operations" but never actually uses it.

### 2. Org ciphers decrypt to blank

`SyncEngine.mergeServerResponse` ignores `response.collections` and
`profile.organizations`. Org ciphers are encrypted with the org key, not the
user's vault key, so with no org-key decryption path their fields decrypt to
nil — they appear blank in the UI.

### 3. Saving an org item corrupts it for everyone

`getItemKey` (in `VaultServices.swift`) falls back to the **personal vault key**
for org items. `CipherEditView.save()` therefore re-encrypts an edited org
cipher with a key **no other org member has**. The item is now unreadable to the
rest of the organization — silent, shared-data corruption.

## Impact

- Users in organizations see blank items and cannot use shared logins.
- Editing/saving a shared item destroys it for every other member.

## Suggested direction

1. Decide whether organizations are in scope at all. If **not**, hard-block org
   items: detect `cipher.organizationId != nil` and make them read-only with a
   clear "Organizations are not supported" notice; never re-encrypt them with
   the personal key.
2. If **yes**:
   - Fix `AsymmetricCrypto` key import/export to SPKI/PKCS#8 (convert ASN.1
     headers, or use a vetted ASN.1 helper). Add RFC/known-answer tests.
   - Decrypt each org key from `profile.organizations[].key` using the account
     RSA private key on unlock; cache org keys in memory.
   - Merge `collections`/`organizations` in `SyncEngine`.
   - Route `getItemKey` to the correct org key for org ciphers (item key →
     org key, not personal vault key).
   - Add interop tests against a real Vaultwarden org vault.
