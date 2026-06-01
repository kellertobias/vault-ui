# Login Flow Tester

Small Dockerized test app for password, TOTP, passkey, and autofill flows.

## Local Development

```sh
npm install
DATABASE_PATH=./data/loginflow.db PORT=8080 RP_ID=localhost PUBLIC_ORIGIN=http://localhost:8080 npm start
```

Open `http://localhost:8080`.

## Routes

- `/` links to the login/register variants and stored-user inspector.
- `/login` uses email login and omits explicit autocomplete hints.
- `/login-username` uses username login and omits explicit autocomplete hints.
- `/login-autocomplete` uses email login with `email`, `current-password`, and `one-time-code` hints.
- `/login-username-autocomplete` uses username login with `username`, `current-password`, and `one-time-code` hints.
- `/login-passkey` starts a passkey-only discoverable credential login.
- `/register` omits explicit autocomplete hints.
- `/register-autocomplete` uses `name`, `username`, `email`, and `new-password` hints.
- `/register-passkey` directly shows a `Register with Passkey` button and creates a passkey-only account.

## Debug Storage Warning

This app intentionally stores passwords in clear text. It is a debug harness for inspecting encoding and autofill behavior. Do not use real passwords.

## Container Image

```sh
../scripts/deploy_local.sh
```

The script uses `podman` when available, otherwise `docker`. By default this builds a `linux/amd64` NAS image and pushes:

```text
registry.tokenet.de/tobisk/loginflow-tester:latest
```

Override with:

```sh
IMAGE=registry.tokenet.de/tobisk/loginflow-tester:test ../scripts/deploy_local.sh
```

Override the platform with `PLATFORM=linux/arm64` if needed.

## NAS Runtime

Expected production environment:

```text
DATABASE_PATH=/data/loginflow.db
PUBLIC_ORIGIN=https://loginflow.nas.tokenet.de
RP_ID=loginflow.nas.tokenet.de
NODE_ENV=production
```

Passkeys require HTTPS and the configured origin/RP ID to match the served hostname.
