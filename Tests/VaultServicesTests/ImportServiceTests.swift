// Tests for ImportService — SSH key formatting/fingerprinting (pure, KATs) and
// the import parsers (Bitwarden JSON, macOS Passwords CSV) via encrypt→decrypt
// round-trips. ImportService is ~1000 lines of data-integrity-critical parsing
// that previously had no coverage.

import XCTest
import VaultModels
import VaultCrypto
@testable import VaultServices

final class ImportServiceTests: XCTestCase {

    // MARK: - SSH wire format & fingerprint (pure, deterministic)

    func testFormatEd25519PublicKeyBlobStructure() throws {
        let raw = Data(repeating: 0x01, count: 32)
        let blob = ImportService.formatEd25519PublicKeyBlob(raw)

        // [00 00 00 0b] "ssh-ed25519" [00 00 00 20] <32 raw bytes>
        XCTAssertEqual(blob.count, 4 + 11 + 4 + 32)
        XCTAssertEqual(Array(blob.prefix(4)), [0, 0, 0, 0x0b])
        XCTAssertEqual(String(data: blob.subdata(in: 4..<15), encoding: .utf8), "ssh-ed25519")
        XCTAssertEqual(Array(blob.subdata(in: 15..<19)), [0, 0, 0, 0x20])
        XCTAssertEqual(Data(blob.suffix(32)), raw)
        XCTAssertEqual(
            blob.base64EncodedString(),
            "AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        )
    }

    func testComputeSSHFingerprintKnownAnswer() {
        // Public key line built from a 32-byte all-0x01 ed25519 key (see blob above).
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB user@host"
        XCTAssertEqual(
            ImportService.computeSSHFingerprint(line),
            "SHA256:RXm/ruZ0eTzRXKwi1AQEDynB0VgHQ2ac9KPSFdf/YnA"
        )
    }

    func testComputeSSHFingerprintRejectsGarbage() {
        XCTAssertNil(ImportService.computeSSHFingerprint("not-a-key"))
        XCTAssertNil(ImportService.computeSSHFingerprint("ssh-ed25519 @@@not-base64@@@"))
    }

    // MARK: - SSH key generation & import (round-trip)

    func testGenerateSSHKeyRoundTrip() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let (cipher, publicKeyString) = try ImportService.generateSSHKey(
            name: "my-key", comment: "me@host", encryptionKey: vaultKey
        )

        XCTAssertEqual(cipher.type, .sshKey)
        XCTAssertTrue(publicKeyString.hasPrefix("ssh-ed25519 "))

        let itemKey = try VaultCryptoFacade.itemKey(for: cipher, vaultKey: vaultKey)
        let sshKey = try XCTUnwrap(cipher.sshKey)

        // Private key is a real OpenSSH PEM
        let privPem = try CipherEncryption.decryptString(try XCTUnwrap(sshKey.privateKey), key: itemKey)
        XCTAssertTrue(privPem.contains("BEGIN OPENSSH PRIVATE KEY"))

        // The public key recovered from the private key matches the generated one
        let extracted = try XCTUnwrap(ImportService.extractPublicKeyFromOpenSSHPrivateKey(privPem))
        let fpFromPublic = ImportService.computeSSHFingerprint(publicKeyString)
        XCTAssertNotNil(fpFromPublic)
        XCTAssertEqual(fpFromPublic, ImportService.computeSSHFingerprint(extracted))

        // The stored fingerprint matches what we'd compute
        let storedFp = try CipherEncryption.decryptString(try XCTUnwrap(sshKey.keyFingerprint), key: itemKey)
        XCTAssertEqual(storedFp, fpFromPublic)
    }

    func testImportSSHKeyRoundTrip() throws {
        let vaultKey = try SymmetricCryptoKey.generate()

        // Produce a genuine OpenSSH private key to import.
        let (generated, _) = try ImportService.generateSSHKey(name: "g", comment: "c", encryptionKey: vaultKey)
        let genItemKey = try VaultCryptoFacade.itemKey(for: generated, vaultKey: vaultKey)
        let privPem = try CipherEncryption.decryptString(try XCTUnwrap(generated.sshKey?.privateKey), key: genItemKey)

        let imported = try ImportService.importSSHKey(
            privateKeyData: Data(privPem.utf8),
            publicKeyData: nil,
            name: "imported",
            encryptionKey: vaultKey
        )

        XCTAssertEqual(imported.type, .sshKey)
        let itemKey = try VaultCryptoFacade.itemKey(for: imported, vaultKey: vaultKey)

        let decryptedPriv = try CipherEncryption.decryptString(try XCTUnwrap(imported.sshKey?.privateKey), key: itemKey)
        XCTAssertTrue(decryptedPriv.contains("BEGIN OPENSSH PRIVATE KEY"))

        // Public key is derived even though none was supplied
        let pub = try CipherEncryption.decryptString(try XCTUnwrap(imported.sshKey?.publicKey), key: itemKey)
        XCTAssertTrue(pub.hasPrefix("ssh-ed25519 "))

        XCTAssertEqual(try CipherEncryption.decryptString(try XCTUnwrap(imported.name), key: itemKey), "imported")
    }

    func testImportSSHKeyRejectsNonUTF8() {
        let vaultKey = try! SymmetricCryptoKey.generate()
        let garbage = Data([0xff, 0xfe, 0xfd])
        XCTAssertThrowsError(
            try ImportService.importSSHKey(privateKeyData: garbage, publicKeyData: nil, name: "x", encryptionKey: vaultKey)
        )
    }

    // MARK: - Bitwarden JSON import (round-trip)

    func testImportBitwardenJSONDecryptsFieldsAndFolders() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let json = Data("""
        {
          "encrypted": false,
          "folders": [{ "id": "f1", "name": "Work" }],
          "items": [{
            "id": "i1", "type": 1, "name": "Example", "notes": "a note",
            "login": {
              "username": "alice", "password": "s3cr3t",
              "uris": [{ "uri": "https://example.com" }]
            }
          }]
        }
        """.utf8)

        let result = try ImportService.importBitwardenJSON(data: json, encryptionKey: vaultKey)

        XCTAssertEqual(result.ciphers.count, 1)
        XCTAssertEqual(result.folders.count, 1)

        let cipher = result.ciphers[0]
        func dec(_ s: EncString?) throws -> String { try CipherEncryption.decryptString(try XCTUnwrap(s), key: vaultKey) }
        XCTAssertEqual(try dec(cipher.name), "Example")
        XCTAssertEqual(try dec(cipher.notes), "a note")
        XCTAssertEqual(try dec(cipher.login?.username), "alice")
        XCTAssertEqual(try dec(cipher.login?.password), "s3cr3t")
        XCTAssertEqual(try dec(cipher.login?.uris?.first?.uri), "https://example.com")
        XCTAssertEqual(try dec(result.folders[0].name), "Work")
    }

    func testImportBitwardenJSONRejectsEncryptedExport() {
        let vaultKey = try! SymmetricCryptoKey.generate()
        let json = Data(#"{ "encrypted": true, "items": [] }"#.utf8)
        XCTAssertThrowsError(try ImportService.importBitwardenJSON(data: json, encryptionKey: vaultKey))
    }

    // MARK: - macOS Passwords CSV import (round-trip + quoting)

    func testImportMacOSPasswordsCSVMapsColumnsAndPreservesQuotedCommas() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let csv = Data("""
        Title,URL,Username,Password,Notes,OTPAuth
        Example,https://example.com,alice,s3cr3t,"a, quoted note",
        """.utf8)

        let result = try ImportService.importMacOSPasswordsCSV(data: csv, encryptionKey: vaultKey)
        XCTAssertEqual(result.ciphers.count, 1)

        let cipher = result.ciphers[0]
        func dec(_ s: EncString?) throws -> String { try CipherEncryption.decryptString(try XCTUnwrap(s), key: vaultKey) }
        XCTAssertEqual(try dec(cipher.name), "Example")
        XCTAssertEqual(try dec(cipher.login?.username), "alice")
        XCTAssertEqual(try dec(cipher.login?.password), "s3cr3t")
        XCTAssertEqual(try dec(cipher.login?.uris?.first?.uri), "https://example.com")
        // The comma inside the quoted field must survive CSV parsing intact.
        XCTAssertEqual(try dec(cipher.notes), "a, quoted note")
    }

    func testImportMacOSPasswordsCSVRejectsEmpty() {
        let vaultKey = try! SymmetricCryptoKey.generate()
        XCTAssertThrowsError(
            try ImportService.importMacOSPasswordsCSV(data: Data("Title,Username\n".utf8), encryptionKey: vaultKey)
        )
    }
}
