# Missing feature: Official bitwarden.com compatibility

**Status:** Largely resolved — the three core gaps below are implemented.
Bitwarden-cloud support is **experimental** (organization vaults remain
unsupported, see `organizations.md`); the login screen still shows a notice via
`OfficialBitwardenServer`.

> **Implemented (2026-06-12):**
> 1. `Auth-Email` header (base64url of the username) is sent on every password
>    grant (`Sources/VaultAPI/AuthService.swift`). Vaultwarden ignores it.
> 2. Attachment uploads branch on `fileUploadType`: Azure SAS uploads
>    (`fileUploadType == 1`) are a raw `PUT` with `x-ms-blob-type: BlockBlob`
>    (`Sources/VaultAPI/AzureBlobUpload.swift`,
>    `Sources/VaultAPI/AttachmentAPI.swift`); direct uploads (Vaultwarden) are
>    unchanged.
> 3. File Sends use the two-phase `sends/file/v2` flow with Azure/direct upload
>    branches, falling back to the legacy single-step `sends/file` multipart on
>    404/405 from pre-v2 Vaultwarden (`Sources/VaultAPI/SendAPI.swift`). A
>    failed upload deletes the half-created Send.
>
> Not implemented: the optional `GET /api/config` capability probe (the
> 404-fallback covers the v2 detection need). The original findings are kept
> below for reference.

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
