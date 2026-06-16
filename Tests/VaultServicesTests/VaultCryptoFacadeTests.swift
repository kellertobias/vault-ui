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
