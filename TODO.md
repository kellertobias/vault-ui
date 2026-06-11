# Vault UI — TODO

Status snapshot as of 2026-06-12. The four original feature plans (AutoFill
extension, Touch ID unlock, SSH agent, CLI secret hydrator) are all implemented;
see "Done" at the bottom. Detailed write-ups for the larger open items live in
`docs/missing-features/`.

---

## Open

### 1. Ship v1.3.5 (uncommitted work in the tree)
The working tree contains an unreleased security fix and feature work:
- **Passkey cross-rpId assertion fix** (`VaultAutoFillExtension/CredentialProviderViewController.swift`):
  removed the `allPasskeys.first` fallback that could let a passkey registered
  for domain A sign an assertion for domain B; added an rpId guard in
  `completeAssertion`.
- **Passkey picker scoping**: `prepareCredentialList(for:requestParameters:)`
  now folds `relyingPartyIdentifier` into the match filter (the system often
  passes empty service identifiers for passkey assertions, which previously made
  every vault entry a "match") and lists passkey-capable entries first.
- **System credential identities**: `systemCredentialIdentitySyncEnabled` now
  defaults to on and has a Settings toggle ("Suggest credentials in system
  AutoFill"), so passwords/TOTP/passkeys appear inline in QuickType and the
  passkey sheet instead of only behind the picker. Disabling unregisters all
  identities.
- Version bumps to 1.3.5, `project.yml` `configFiles` relocation.

**To do:** commit, tag, build via xcodebuild (Safari extension needs the
SYMROOT override), release.

### 2. End-to-end AutoFill / passkey verification
Manual verification pass with the paid developer account (System Settings →
Passwords → AutoFill → enable Vault UI), covering:
- password fill, TOTP fill
- passkey assertion via inline OS suggestion (new identity registration path)
- passkey assertion via "show more sign-in options" (rpId-scoped picker)
- passkey registration
- confirm a wrong-rpId selection is rejected (new guard) rather than asserting

### 3. Organization / collection support — `docs/missing-features/organizations.md`
Org items are hard-blocked read-only (no more shared-data corruption), but they
still decrypt to blank. Full support needs: SPKI/PKCS#8 fixes in
`AsymmetricCrypto`, org-key decryption on unlock, `collections`/`organizations`
merge in `SyncEngine`, and `getItemKey` routing to the org key.

### 4. Official bitwarden.com compatibility — `docs/missing-features/bitwarden-com-compatibility.md`
Client is Vaultwarden-only today (login screen warns on bitwarden.com hosts).
Outstanding: `Auth-Email` header on the password grant, Azure raw-PUT attachment
upload (`fileUploadType == 1`), two-phase `sends/file/v2`, and a
`GET /api/config` capability probe.

### 5. Legacy (pre-2023) account login — `docs/missing-features/legacy-account-login.md`
Low-iteration PBKDF2 accounts now fail with a clear message instead of a crypto
error, but still cannot log in. Outstanding: derive-with-warning below the 100k
floor, and the type-0/unstretched-master-key fallback for the protected account
key.

### 6. Vault export
No export feature (encrypted or plaintext JSON/CSV). Users cannot get their
data out without another client.

### 7. Broken/dead API methods — `docs/missing-features/other-gaps.md`
Both currently unused, both broken as written; fix or delete:
- `SyncAPI.incrementalSync` percent-encodes the `?` in its path → guaranteed 404.
- `CipherAPI.moveToFolder` posts to nonexistent `ciphers/{id}/move` (real
  endpoint is bulk `POST /ciphers/move`).

### 8. Decide: reprompt semantics in the AutoFill extension
The main app gates `reprompt == .password` items behind a master-password /
Touch ID reprompt. The AutoFill extension doesn't check `reprompt` — every fill
already requires Touch ID, which may be acceptable. Decide and either document
that stance or add an explicit gate.

### 9. Nice-to-have: plaintext passkey rpId metadata
A passkey whose cipher has missing/mismatched URIs won't appear in the
rpId-scoped "matches" list (rpIds are only decryptable after unlock). If that
bites in practice, mirror rpIds into `SharedCredentialEntry` — same sensitivity
class as the already-plaintext `uris`.

### 10. Known issue: 6 failing crypto tests
`swift test --filter VaultCryptoTests`: 30 tests, 6 long-standing failures
(pre-existing; also noted in build docs). Triage whether they encode real bugs
or stale fixtures.

---

## Done

- **AutoFill Credential Provider** — passwords, TOTP, passkeys (registration +
  assertion), biometric-gated secrets, encrypted at rest. Docs:
  `docs/passkey_flow.md`, `docs/autofill_extension_troubleshooting.md`.
- **Touch ID unlock** — `BiometricKeyStorage` + `UnlockView` auto-trigger.
- **SSH key sync & SSH agent** — `VaultSSH` server/handler, launch agent,
  on-demand key decryption, re-auth policies. Docs: `docs/ssh-key-import.md`.
- **CLI secret hydrator** — shipped as `vaultui get` / `vaultui env` (planned as
  `populate-env`), plus `agent`, `generate`, `status`. Docs: `docs/cli-secrets.md`.
- **Fixed since the missing-features review:** trash restore UI, real account
  switching (`session.switchAccount`), "New Send" sidebar button, lock on screen
  lock/screensaver, master-password reprompt in the main app, password history
  on edits, removed the hardcoded hostname ranking hack, corrected CLI docs.
