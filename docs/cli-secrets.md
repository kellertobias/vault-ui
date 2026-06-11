# CLI Secret Access

Use vault secrets in development workflows without leaving the terminal. The `vaultui` secret commands let you look up secrets by a stable, human-readable slug — no UUIDs or name-based searching.

## Overview

The Vault UI app exposes a local Unix domain socket in its app-group container (`~/Library/Group Containers/<your-app-group>/.vaultui/secret.sock`) that the `vaultui` CLI connects to for secret lookups. This is the same architecture used by the SSH agent.

**Two commands:**
- `vaultui get <slug>` — retrieve a single secret
- `vaultui env <env-file>` — resolve vault references in a `.env` file

## Setup

### Prerequisites
1. **Vault UI app** must be running (the secret agent starts automatically with the app)
2. **Touch ID** must be enrolled (used for biometric unlock when the vault is locked)
3. **`vaultui` CLI** must be in your PATH

### Installing the CLI

After building the project, copy the CLI binary to your PATH:

```bash
# From the project root
swift build -c release
cp .build/release/vaultui /usr/local/bin/vaultui
```

Verify installation:
```bash
vaultui --version
```

## Adding a Slug to a Secret

1. Open **Vault UI**
2. Edit any vault item (login, secure note, card, identity, or SSH key)
3. In the **Details** section, find the **CLI Slug** field
4. Enter a slug value, for example: `my-app.database`
5. Save the item

### Slug Format

Slugs must contain only:
- Letters: `a-z`, `A-Z`
- Digits: `0-9`
- Hyphens: `-`
- Underscores: `_`
- Dots: `.`

No spaces or special characters. Examples: `my-app.database`, `prod_api-key`, `staging.redis`

> **Tip:** Use a consistent naming convention like `project.service` (e.g. `myapp.postgres`, `myapp.redis`, `myapp.stripe`).

## `vaultui get`

Retrieve a secret by its slug.

### Full Secret (JSON)

```bash
vaultui get my-app.database
```

Output:
```json
{
  "name": "My App Database",
  "type": "Login",
  "username": "admin",
  "password": "s3cret-p4ssword",
  "uris": ["https://db.example.com"],
  "notes": "Production database credentials",
  "fields": {
    "port": "5432",
    "database": "myapp_prod"
  }
}
```

### Specific Field

```bash
vaultui get my-app.database/password
# Output: s3cret-p4ssword

vaultui get my-app.database/username
# Output: admin
```

### Supported Fields

| Field | Description |
|-------|-------------|
| `username` | Login username |
| `password` | Login password |
| `totp` | Current TOTP code (generated live) |
| `notes` | Item notes |
| `uri` / `url` | First URI |
| `<custom>` | Any custom field by name |

### Usage in Scripts

```bash
# Use in a variable
DB_PASS=$(vaultui get my-app.database/password)

# Pipe to another command
vaultui get my-app.ssh-key/password | pbcopy

# Use with jq for JSON parsing
vaultui get my-app.database | jq -r '.username'
```

## `vaultui env`

Parse a `.env` file and output shell `export` commands with vault secrets resolved.

### `.env` File Format

```env
# Regular environment variables (passed through as-is)
APP_ENV="development"
LOG_LEVEL="debug"

# Full secret as JSON
DB_CONFIG="vaultui://my-app.database"

# Specific field from a secret
DB_PASSWORD="vaultui://my-app.database/password"
DB_USERNAME="vaultui://my-app.database/username"

# API key from another secret
STRIPE_KEY="vaultui://my-app.stripe/password"
```

Lines starting with `#` are comments and are skipped. Empty lines are skipped.

The `vaultui://` prefix marks a value for vault resolution:
- `vaultui://<slug>` → resolves to the full secret JSON
- `vaultui://<slug>/<field>` → resolves to just that field's value

### Usage

```bash
# Load secrets and run your app
eval "$(vaultui env my.env)" && ./my-app

# Or in a Makefile
.PHONY: run
run:
	eval "$$(vaultui env .env.development)" && go run .

# Or source them for the whole shell session
eval "$(vaultui env my.env)"
echo $DB_PASSWORD
```

### Output Format

The command outputs valid shell `export` statements:

```bash
export APP_ENV='development'
export LOG_LEVEL='debug'
export DB_CONFIG='{"name":"My App Database","type":"Login","username":"admin",...}'
export DB_PASSWORD='s3cret-p4ssword'
export DB_USERNAME='admin'
export STRIPE_KEY='sk_live_...'
```

Values are single-quoted for shell safety. Embedded single quotes are properly escaped.

## Authentication

### When the vault is unlocked
Secrets are returned immediately — no prompts.

### When the vault is locked
Touch ID is triggered automatically (same as the SSH agent). You'll see the standard macOS biometric prompt:

> "Vault UI wants to use Touch ID — Unlock Secret"

After authenticating, the vault key is used for this request only and then securely erased from memory.

### Caching

Results are cached **in memory** to avoid repeated Touch ID prompts during development:

- **Default timeout:** 15 minutes (same as SSH agent, configurable in app settings)
- **Sliding window:** Each reuse of a cached result extends the timeout
- **Query-scoped:**
  - `get` commands cache individual slug lookups
  - `extend` commands cache the full set of resolved secrets
- **Cleared on vault lock:** All cached results are wiped when the vault is locked

This means:
1. First `vaultui get my-app/password` → Touch ID prompt
2. Second call within 15 min → instant (cache hit, timer extended)
3. After 15 min of no use → Touch ID prompt again

## Security

- **No disk writes:** Secrets are never written to disk by the CLI
- **Socket permissions:** `secret.sock` is `0600` (owner-only access)
- **Memory only:** Cache lives in the app process memory, cleared on lock
- **Process isolation:** `eval` injects secrets as environment variables in the calling shell only
- **Biometric protection:** Vault key is protected by Touch ID via the macOS Keychain
- **Key zeroing:** Temporary vault keys are securely erased after each request

## Troubleshooting

### "Vault UI is not running"
Start the Vault UI app. The secret agent socket starts automatically.

### "No secret found with slug 'xyz'"
Check that the vault item has a `vaultui-slug` custom field set to exactly `xyz`. The slug is case-sensitive.

### Touch ID not appearing
- Ensure Touch ID is enrolled in System Settings
- Ensure you've logged in with your master password at least once (this stores the biometric key)
- Check that the Vault UI app is running in the background

### Timeout / connection issues
The CLI waits up to 30 seconds for a response (to allow time for the Touch ID prompt). If you're getting timeouts, check that the Vault UI app is responsive.
