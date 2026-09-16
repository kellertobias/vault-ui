# Organization / collection support

**Status:** Shared items are readable, editable, and can be created. A collections
sidebar and un-sharing are still missing.

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

## Creating and sharing

- **New shared items.** `CipherEditView` shows an Ownership picker (My Vault, or
  any organization with a collection this account can write to) when creating an
  item. `OrganizationSharing.makeItemKey` wraps the new item key under the chosen
  owner's key, so a shared item is readable by the organization from the moment
  it is created. The item goes to `POST /ciphers/create`.
- **Moving a personal item in.** The detail view's Share action opens a sheet
  that picks an organization and collections, then re-keys the item and sends it
  to `PUT /ciphers/{id}/share`. Online only, and the local copy is replaced only
  after the server accepts it, so a failed share leaves the personal item intact.
- **Re-keying.** An item with its own item key keeps it and only has the wrapper
  swapped (vault key → org key), so its fields and attachments are untouched. A
  pre-2023 item without one gets a fresh item key and every field is moved onto
  it by `CipherKeyRewrap`.
- **Attachments.** Their keys are re-wrapped and sent as `attachments2`, the only
  field the server actually re-keys from — it ignores the `attachments` array. An
  attachment with no key of its own predates per-attachment keys, is tied to the
  personal vault key, and cannot be shared without a re-upload, so the share is
  refused with an explanation.
- **Empty collection lists are refused client-side.** The server accepts a share
  with no collections and the item then belongs to the organization but sits in
  no collection, invisible to everyone — so both the service and the UI require
  at least one.

## Permissions

`SessionManager.canEdit(_:)` allows a save only when the org key is available and
at least one collection the item belongs to is not `readOnly`. The detail view
reflects three states: shared and writable, shared and read-only, and
"organization key unavailable" (fields cannot be shown). `CipherEditView.save()`
re-checks both conditions as a safety net.

Editing an existing shared item reuses the cipher's own item key (or, for older
ciphers without one, the org key directly), so other members can still read it.

## Still missing

- **Un-sharing.** There is no way to move an item back out of an organization;
  Bitwarden itself has no such endpoint.
- **Changing an existing shared item's collections**, and sharing several items
  at once (`PUT /ciphers/share` takes a bulk request).
- **A collections sidebar.** Collection names are decrypted for the ownership
  pickers, but there is no collection filter in the item list.
- **Merging across organizations** is blocked in `MultiSelectMergeView`: the
  merge splices ciphertext between items, which is only valid within one key
  scope.
- **Interop tests against a real Vaultwarden organization.** The RSA layer has
  known-answer tests against OpenSSL-generated key material in all four
  encodings, and the merge/routing rules are unit-tested, but nothing has been
  run against a live org vault.
