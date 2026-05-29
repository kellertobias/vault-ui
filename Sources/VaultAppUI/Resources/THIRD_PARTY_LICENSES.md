# Third Party Licenses

Vault UI depends on the following third-party open source packages. This file is provided for attribution and notice preservation when distributing the application or source code.

## Swift Package Dependencies

| Package | Resolved Version | License | Notes |
|---------|------------------|---------|-------|
| swift-crypto | 3.15.1 | Apache-2.0 | Includes a NOTICE file for the SwiftCrypto project and references to Wycheproof and SwiftNIO-derived files. |
| swift-nio | 2.99.0 | Apache-2.0 | Includes a NOTICE file for the SwiftNIO project and third-party components including Netty-inspired code, llhttp, uSHET, FreeBSD SHA1 code, and Swift Base64-derived code. |
| swift-argument-parser | 1.7.1 | Apache-2.0 | Apple Swift argument parsing library. |
| Argon2Swift | 53543623fefe68461b7eeea03d7f96677c2fd76d | MIT | Swift wrapper for Argon2. |
| phc-winner-argon2 | f57e61e19229e23c4445b85494dbf7c07de721cb | CC0-1.0 or Apache-2.0 | Argon2 reference C implementation used by Argon2Swift. |
| swift-asn1 | 1.7.0 | Apache-2.0 | Transitive dependency with NOTICE text. |
| swift-atomics | 1.3.0 | Apache-2.0 | Transitive dependency. |
| swift-collections | 1.5.1 | Apache-2.0 | Transitive dependency. |
| swift-system | 1.6.4 | Apache-2.0 | Transitive dependency. |

## Loginflow Tester npm Dependencies

The `loginflow-tester` development utility uses npm packages under permissive licenses:

| License | Packages |
|---------|----------|
| MIT | @hexagon/base64, @levischuck/tiny-cbor, @noble/hashes, @peculiar/* packages, @simplewebauthn/server, better-sqlite3, express, otpauth, qrcode, and most transitive dependencies. |
| Apache-2.0 | detect-libc, reflect-metadata, tunnel-agent. |
| BSD-3-Clause | asn1js, ieee754, qs. |
| ISC | chownr, cliui, get-caller-file, inherits, ini, once, require-main-filename, semver, set-blocking, setprototypeof, which-module, wrappy, y18n, yargs-parser. |
| 0BSD | tslib and tslib as bundled below tsyringe. |
| Dual license | rc is BSD-2-Clause or MIT or Apache-2.0; expand-template is MIT or WTFPL. |

## License Text Locations

Full third-party license texts are available from the corresponding upstream packages and are also present after dependency resolution in SwiftPM checkouts and npm `node_modules` directories. When distributing binaries, preserve the Apache-2.0 NOTICE text for SwiftCrypto, SwiftNIO, and SwiftASN1, and preserve copyright/license text for MIT, BSD, ISC, 0BSD, and Apache-2.0 dependencies.

## Project License

Vault UI's own source code is licensed separately. See the repository `LICENSE` file.
