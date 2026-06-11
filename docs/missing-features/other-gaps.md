# Missing features & smaller gaps

A grab-bag of smaller missing behaviors and latent bugs found during review.
Several of the original findings have since been fixed; they are kept below as
a record. Still open: the two broken API methods and vault export.

## Security / correctness

### ~~Master-password re-prompt is never enforced~~ — fixed (main app)
`CipherDetailView` now gates items flagged `reprompt == .password` behind a
master-password / Touch ID reprompt (`repromptSatisfied`, with the prompt UI in
`Sources/VaultAppUI/CipherDetailView.swift` and verification helpers in
`Sources/VaultServices/VaultServices.swift`).
**Still open (decision):** the AutoFill extension does not check `reprompt`;
every fill already requires Touch ID, which may be an acceptable equivalent —
decide and document, or add an explicit gate.

### ~~Vault doesn't lock on screen lock~~ — fixed
`Sources/VaultAppUI/VaultApp.swift` now observes `com.apple.screenIsLocked` and
`com.apple.screensaver.didstart` (distributed notifications) in addition to
display sleep, controlled by the "Lock on screen saver" setting.

## API dead code / wrong endpoints — still open

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

### ~~No password history on edits~~ — fixed
`CipherEditView.save()` now prepends the previous password (with timestamp) to
`login.passwordHistory`, capped at 5 entries.

### No vault export — still open
There is no "export vault" feature (encrypted or plaintext JSON/CSV). Users
can't get their data out without another client.

## Cleanup

### ~~Hardcoded personal-hostname ranking hack~~ — fixed
The `nas.tokenet.de` rank override was removed from
`Sources/VaultServices/SharedCredentialStore.swift`.

### ~~CLI docs describe commands that don't exist~~ — fixed
`docs/cli-secrets.md` now documents the real `vaultui get` / `vaultui env`
commands.
