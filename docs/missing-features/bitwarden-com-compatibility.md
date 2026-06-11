# Missing feature: Official bitwarden.com compatibility

**Status:** Partial — the client is **Vaultwarden-only** today.
**Severity:** Medium (works against Vaultwarden; breaks against Bitwarden cloud).

> **Mitigation in place:** Vault UI is now marked Vaultwarden-only. The login
> screen shows a warning when the server URL is an official Bitwarden host
> (`bitwarden.com` / `bitwarden.eu`), via `OfficialBitwardenServer`
> (`Sources/VaultModels/OfficialBitwardenServer.swift`). The underlying
> compatibility gaps below are still unaddressed.

## Problem

Several API behaviors are implemented the way Vaultwarden tolerates them, but the
official bitwarden.com / self-hosted Bitwarden server is stricter. Against those
servers the following break.

### 1. Missing `Auth-Email` header on the password grant

`Sources/VaultAPI/AuthService.swift` issues `grant_type=password` without the
`Auth-Email` header (base64url of the username). Bitwarden's identity server
requires it and rejects logins without it. Vaultwarden ignores it, which is why
this has gone unnoticed.

### 2. Azure blob attachment upload uses the wrong request

`Sources/VaultAPI/AttachmentAPI.swift` always builds a `multipart/form-data`
body. For `fileUploadType == 1` (Azure SAS upload, used by Bitwarden cloud and
S3-backed setups) the correct request is a `PUT` of the **raw encrypted bytes**
with the `x-ms-blob-type: BlockBlob` header. Only the direct-upload path
(type 0, Vaultwarden) works today; attachments to Bitwarden cloud are rejected
or stored corrupted.

### 3. Legacy single-step Send file upload

`Sources/VaultAPI/SendAPI.swift` uses the legacy single-step `sends/file`
endpoint. Bitwarden cloud removed it in favor of the two-phase `sends/file/v2`
flow (request URL → upload to blob). Vaultwarden still accepts the legacy call.

## Impact

- Login fails against bitwarden.com / official self-hosted Bitwarden.
- File attachments and file Sends fail or corrupt on Bitwarden cloud.

## Suggested direction

- Add the `Auth-Email` header to the password grant.
- Branch attachment upload on `fileUploadType`: direct multipart (Vaultwarden)
  vs. raw `PUT` + `x-ms-blob-type: BlockBlob` (Azure).
- Implement the two-phase `sends/file/v2` upload, falling back to the legacy
  endpoint when the server doesn't advertise v2.
- Add a `GET /api/config` probe to detect server type/capabilities and pick the
  right code paths automatically.
