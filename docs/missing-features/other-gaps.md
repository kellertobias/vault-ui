# Missing features & smaller gaps

A grab-bag of smaller missing behaviors and latent bugs found during review.
None are individually large, but several are correctness or security relevant.

## Security / correctness

### Master-password re-prompt is never enforced
`Cipher.reprompt` is decoded (`Sources/VaultModels/Cipher.swift`) but no view or
service checks it before revealing, copying, or autofilling a password. Items the
user flagged "re-prompt master password" behave exactly like normal items.
**Fix:** gate reveal/copy/autofill of `reprompt == 1` items behind a
master-password (or biometric) re-prompt.

### Vault doesn't lock on screen lock
`Sources/VaultAppUI/VaultApp.swift` only observes
`NSWorkspace.screensDidSleepNotification` (display sleep). It ignores
`com.apple.screenIsLocked` and `com.apple.screensaver.didstart`, so Ctrl-Cmd-Q
or a hot-corner lock leaves the vault unlocked while the displays stay on.
**Fix:** also observe the screen-lock / screensaver-start notifications and lock.

## API dead code / wrong endpoints

### `incrementalSync` is malformed
`Sources/VaultAPI/SyncAPI.swift` builds the path
`"sync?excludeDomains=true&since=…"` and passes it to `appendingPathComponent`,
which percent-encodes the `?` into `%3F` → guaranteed 404. It has no callers
(every sync is a full sync), but it's broken as written and the doc comment
claims a fallback that doesn't exist.
**Fix:** build the query with `URLComponents`, or delete the method until
incremental sync is actually implemented.

### `moveToFolder` targets a nonexistent endpoint
`Sources/VaultAPI/CipherAPI.swift` posts to `ciphers/{id}/move`, which doesn't
exist in the Bitwarden/Vaultwarden API (the real endpoint is bulk
`POST /ciphers/move` with `{ids, folderId}`). Currently unused (folder moves go
through `update`), so it would 404 the moment anyone calls it.
**Fix:** implement the bulk move endpoint or remove the method.

## Data fidelity

### No password history on edits
`CipherEditView.save()` never appends the previous password to
`passwordHistory` when the password changes, so other Bitwarden clients show no
history for edits made here.
**Fix:** on password change, prepend the old password + timestamp to
`login.passwordHistory` before saving.

### No vault export
There is no "export vault" feature (encrypted or plaintext JSON/CSV). Users
can't get their data out without another client.

## Cleanup

### Hardcoded personal-hostname ranking hack
`Sources/VaultServices/SharedCredentialStore.swift` contains
`if serviceId.identifier.contains("nas.tokenet.de") { identity.rank = 10 }` — a
leftover "experiment" that ships a personal hostname and ranks it above
everything else for that substring. **Fix:** remove it (or replace with a real,
user-driven ranking signal).

### CLI docs describe commands that don't exist
`docs/cli-secrets.md` documents `vaultui secret get` / `vaultui secret extend`,
but the CLI implements top-level `vaultui get` and `vaultui env`
(`Sources/VaultCLI/VaultCLI.swift`, `SecretCommand.swift`). Every example in the
doc fails as written. **Fix:** update the docs to the real command names.
