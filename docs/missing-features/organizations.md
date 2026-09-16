# Organization / collection support

**Status:** Shared items are readable and editable. Creating items directly in an
organization, moving items into one, and a collections UI are still missing.

## What works

Organization ciphers decrypt and behave like personal items — in the app window,
in AutoFill, in the CLI, and through the SSH/secret agents.

- `AsymmetricCrypto` imports real server keys. Bitwarden ships the account public
  key as **SPKI** and the decrypted private key as **PKCS#8**, while Security's
  `SecKeyCreateWithData` only accepts **PKCS#1**; `ASN1DER`
  (`Sources/VaultCrypto/ASN1DER.swift`) strips and re-applies those wrappers and
  reads the real modulus size instead of assuming 2048 bits.
- `SyncEngine` merges `profile.organizations` and `collections`, persisting them
  as `PersistedOrganization` / `PersistedCollection`. A full sync is
  authoritative: a membership the server stops reporting is deleted locally, so a
  revoked organization's key stops being unwrappable on the device.
- `OrganizationKeyStore` unwraps each org key with the account private key on
  unlock and after every successful sync, producing a `VaultKeyRing` (personal
  vault key + org keys). The keys live in memory only and are dropped on lock.
- Every decrypt/encrypt path resolves its base key from the cipher's
  `organizationId` through that ring. A missing org key yields `nil`/throws — it
  never falls back to the personal vault key, which is what used to corrupt
  shared items on save.
- The AutoFill/CLI export decrypts org items with their org key and re-seals the
  secrets under the personal vault key, so the extensions and agents keep working
  with only the personal key exported.

## Permissions

`SessionManager.canEdit(_:)` allows a save only when the org key is available and
at least one collection the item belongs to is not `readOnly`. The detail view
reflects three states: shared and writable, shared and read-only, and
"organization key unavailable" (fields cannot be shown). `CipherEditView.save()`
re-checks both conditions as a safety net.

Editing an existing shared item reuses the cipher's own item key (or, for older
ciphers without one, the org key directly), so other members can still read it.

## Still missing

- **Creating an item directly in an organization**, and **moving a personal item
  into one**. New items are always personal: `generateItemKey()` wraps the item
  key under the personal vault key, and there is no collection picker.
- **A collections UI.** Collections are synced and used for permissions, but the
  sidebar has no collection filter and `PersistedCollection.encryptedName` is
  never decrypted for display.
- **Merging across organizations** is blocked in `MultiSelectMergeView`: the
  merge splices ciphertext between items, which is only valid within one key
  scope.
- **Interop tests against a real Vaultwarden organization.** The RSA layer has
  known-answer tests against OpenSSL-generated key material in all four
  encodings, and the merge/routing rules are unit-tested, but nothing has been
  run against a live org vault.
