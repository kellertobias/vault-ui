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

### 3. Organization / collection follow-ups — `docs/missing-features/organizations.md`
Shared items now decrypt and save correctly (org-key unwrapping, `collections`/
`organizations` merge, key-ring routing, read-only/hidden-password permissions).
Shared items can also be created and moved into an organization. Remaining:
un-sharing (no server endpoint), editing an existing item's collections, bulk
sharing, a collections sidebar, and interop testing against a real Vaultwarden
org vault — none of the org endpoints have been exercised against a live server.

### 4. Verify bitwarden.com compatibility against a real account
The three core gaps (`Auth-Email` header, Azure raw-PUT uploads, two-phase
`sends/file/v2` with legacy fallback) are implemented but untested against a
live bitwarden.com account: login, attachment upload, file Send. Also re-test
file Sends against Vaultwarden (v2 path is now the default there too).
Optional follow-up: a `GET /api/config` capability probe.

### 5. Legacy-login fixtures from a real pre-2023 vault
The KDF warning path and type-0 account-key fallback are implemented and
unit-tested with synthetic fixtures; capturing fixtures from a real legacy
account would lock in interop.

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
- **bitwarden.com core compatibility (2026-06-12):** `Auth-Email` on the
  password grant, Azure SAS attachment uploads, two-phase `sends/file/v2` with
  legacy Vaultwarden fallback. Org vaults still unsupported (item 3).
- **Legacy account login (2026-06-12):** sub-100k PBKDF2 accounts derive with a
  user-facing weak-KDF warning (`SessionManager.weakKDFWarning`), and type-0
  protected account keys decrypt via `CipherEncryption.decryptUserKey` —
  scoped so vault items still reject type 0.
- **Crypto test suite green** — the 6 long-standing failures were stale
  fixtures using 5,000 PBKDF2 iterations, written before the deliberate 100k
  floor in `KeyDerivation.deriveKey`; fixtures now use
  `CryptoConstants.minimumPBKDF2Iterations`, and a regression test locks in the
  floor itself.
