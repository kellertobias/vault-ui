# Missing feature: UI controls that don't do what they say

**Status:** Several controls are wired to nothing or to the wrong action.
**Severity:** Medium (misleading; users believe an action happened when it didn't).

## Problem

### 1. "Switch Account" doesn't switch accounts

Both "Switch Account" entry points just lock the vault:

- `Sources/VaultAppUI/UnlockView.swift` — calls `session.lock(requirePassword: true)`.
- `Sources/VaultAppUI/SidebarView.swift` — same.

There is no mechanism anywhere to change which `PersistedAccount.isActive` is
set, or to select among `session.accounts`. The only way to reach another
account is a destructive logout. Multi-account is effectively absent despite the
UI implying it exists.

### 2. "New Send" sidebar button is a no-op

`Sources/VaultAppUI/SidebarView.swift` has `// TODO: Implement New Send` with an
empty action. (Send creation does exist via the Send list's own create flow, so
only this entry point is dead.)

### 3. Trash promises restore, but nothing restores

`PendingOperation.restore` is fully wired in `SyncEngine` (and the REST call
works), but **no UI ever invokes it** — there are zero call sites for
`operation: .restore`. Meanwhile the trash alerts in `CipherDetailView.swift`
and `CipherListView.swift` tell the user "You can restore it later."

## Impact

- Users expect account switching, Send creation from the sidebar, and trash
  restore — none of which happen.

## Suggested direction

- **Account switching:** add a real switcher that updates `isActive`, swaps the
  active `SyncEngine`/keys, and re-exports AutoFill credentials. Until then,
  relabel the buttons to "Lock Vault" so they're honest.
- **New Send:** wire the sidebar button to the existing Send create flow, or
  remove it.
- **Restore:** add a "Restore" action in the trash UI that calls
  `saveCipherLocally(_, operation: .restore)` (now safe for never-synced items
  too). The backend path already exists.
