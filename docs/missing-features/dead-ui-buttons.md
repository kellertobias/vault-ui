# Missing feature: UI controls that don't do what they say

**Status:** Resolved — all three controls are now wired to real actions.
**Severity:** — (was Medium).

All items below have since been fixed; this file is kept as a record of the
original findings.

## Original findings (all fixed)

### 1. ~~"Switch Account" doesn't switch accounts~~ — fixed

Real account switching now exists: `SessionManager.switchAccount(to:)`
(`Sources/VaultServices/VaultServices.swift`) updates the active account, and
both entry points use it (`Sources/VaultAppUI/SidebarView.swift`,
`Sources/VaultAppUI/UnlockView.swift`).

### 2. ~~"New Send" sidebar button is a no-op~~ — fixed

The sidebar button now invokes the Send create flow via `onCreateSend`
(`Sources/VaultAppUI/SidebarView.swift`).

### 3. ~~Trash promises restore, but nothing restores~~ — fixed

The trash UI invokes `saveCipherLocally(_, operation: .restore)`
(`Sources/VaultAppUI/CipherDetailView.swift`); shipped in commit `ea7d802`
("feat: trash restore").
