// Tests for VaultCryptoFacade — the pure, key-parameterized vault-item crypto
// extracted from SessionManager.

import XCTest
import VaultModels
import VaultCrypto
@testable import VaultServices

final class VaultCryptoFacadeTests: XCTestCase {

    func testEncryptDecryptRoundTripWithVaultKey() throws {
        let key = try SymmetricCryptoKey.generate()
        let enc = try VaultCryptoFacade.encrypt("hunter2", vaultKey: key)
        let dec = VaultCryptoFacade.decrypt(enc, itemKey: nil, vaultKey: key)
        XCTAssertEqual(dec, "hunter2")
    }

    func testDecryptViaItemKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let (itemKey, encryptedItemKey) = try VaultCryptoFacade.generateItemKey(vaultKey: vaultKey)
        let secret = try VaultCryptoFacade.encrypt("per-item-secret", using: itemKey)

        let dec = VaultCryptoFacade.decrypt(secret, itemKey: encryptedItemKey, vaultKey: vaultKey)
        XCTAssertEqual(dec, "per-item-secret")
    }

    func testDecryptNilReturnsNil() throws {
        let key = try SymmetricCryptoKey.generate()
        XCTAssertNil(VaultCryptoFacade.decrypt(nil, itemKey: nil, vaultKey: key))
    }

    func testItemKeyFallsBackToVaultKeyWhenCipherKeyMissing() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let cipher = Cipher(type: .login) // no per-item key
        let resolved = try VaultCryptoFacade.itemKey(for: cipher, vaultKey: vaultKey)
        XCTAssertEqual(resolved.keyData, vaultKey.keyData)
    }

    func testItemKeyUsesCipherKeyWhenPresent() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let (itemKey, encryptedItemKey) = try VaultCryptoFacade.generateItemKey(vaultKey: vaultKey)
        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey

        let resolved = try VaultCryptoFacade.itemKey(for: cipher, vaultKey: vaultKey)
        XCTAssertEqual(resolved.keyData, itemKey.keyData)
    }
}

// MARK: - Organization key routing

final class VaultCryptoFacadeOrganizationTests: XCTestCase {

    private func orgCipher(_ organizationId: String?, key: EncString? = nil) -> Cipher {
        var cipher = Cipher(type: .login)
        cipher.id = UUID().uuidString
        cipher.organizationId = organizationId
        cipher.key = key
        return cipher
    }

    /// A shared item with no item key of its own: fields are wrapped directly
    /// under the org key.
    func testDecryptsOrganizationItemWithOrganizationKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])

        let secret = try VaultCryptoFacade.encrypt("shared-password", using: orgKey)

        XCTAssertEqual(
            VaultCryptoFacade.decrypt(secret, itemKey: nil, organizationId: "org-1", keyRing: ring),
            "shared-password"
        )
    }

    /// A shared item whose item key is itself wrapped under the org key.
    func testDecryptsOrganizationItemViaOrgWrappedItemKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])

        let (itemKey, encryptedItemKey) = try VaultCryptoFacade.generateItemKey(vaultKey: orgKey)
        let secret = try VaultCryptoFacade.encrypt("shared-secret", using: itemKey)

        XCTAssertEqual(
            VaultCryptoFacade.decrypt(secret, itemKey: encryptedItemKey, organizationId: "org-1", keyRing: ring),
            "shared-secret"
        )

        let resolved = try VaultCryptoFacade.itemKey(
            for: orgCipher("org-1", key: encryptedItemKey),
            keyRing: ring
        )
        XCTAssertEqual(resolved.keyData, itemKey.keyData)
    }

    /// The personal key must never stand in for a missing org key — that is the
    /// path that used to corrupt shared items on save.
    func testMissingOrganizationKeyDoesNotFallBackToVaultKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey)

        let secret = try VaultCryptoFacade.encrypt("shared-password", using: vaultKey)

        XCTAssertNil(
            VaultCryptoFacade.decrypt(secret, itemKey: nil, organizationId: "org-1", keyRing: ring)
        )
        XCTAssertThrowsError(try VaultCryptoFacade.itemKey(for: orgCipher("org-1"), keyRing: ring))
    }

    func testPersonalItemStillUsesVaultKeyThroughKeyRing() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])

        let secret = try VaultCryptoFacade.encrypt("personal", using: vaultKey)

        XCTAssertEqual(
            VaultCryptoFacade.decrypt(secret, itemKey: nil, organizationId: nil, keyRing: ring),
            "personal"
        )
        XCTAssertEqual(
            try VaultCryptoFacade.itemKey(for: orgCipher(nil), keyRing: ring).keyData,
            vaultKey.keyData
        )
    }
}
