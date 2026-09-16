// Tests for URI checksums — without a valid one, official Bitwarden clients hide
// the URI of any item that has its own item key.

import XCTest
import Foundation
import VaultCrypto
@testable import VaultModels

final class LoginUriEncryptionTests: XCTestCase {

    /// Known answer: base64(SHA-256("https://example.com")).
    func testChecksumMatchesOfficialFormat() {
        XCTAssertEqual(
            LoginUri.checksum(for: "https://example.com"),
            "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk="
        )
    }

    func testEncryptedURICarriesChecksumUnderSameKey() throws {
        let key = try SymmetricCryptoKey.generate()
        let uri = try LoginUri.encrypted("https://example.com/login", match: .host, key: key)

        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(uri.uri), key: key), "https://example.com/login")
        XCTAssertEqual(uri.match, .host)
        let checksum = try CipherEncryption.decryptString(EncString(serialized: XCTUnwrap(uri.uriChecksum)), key: key)
        XCTAssertEqual(checksum, LoginUri.checksum(for: "https://example.com/login"))
    }

    func testAddingChecksumLeavesExistingChecksumAlone() throws {
        let key = try SymmetricCryptoKey.generate()
        let original = try LoginUri.encrypted("https://example.com", key: key)

        XCTAssertEqual(original.addingChecksumIfMissing(key: key), original)
    }

    func testAddingChecksumIsNoOpWithWrongKey() throws {
        let key = try SymmetricCryptoKey.generate()
        let other = try SymmetricCryptoKey.generate()
        let bare = LoginUri(uri: try CipherEncryption.encrypt(string: "https://example.com", key: key))

        XCTAssertNil(bare.addingChecksumIfMissing(key: other).uriChecksum)
    }
}
