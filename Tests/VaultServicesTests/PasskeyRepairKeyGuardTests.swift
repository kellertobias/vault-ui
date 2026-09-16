// Tests for the key guard on the passkey compatibility repair.
//
// The repair only holds the personal vault key. It used to fall back to that key
// for shared items and write defaults no other member could read, then upload
// the item.

import XCTest
import Foundation
import SwiftData
import VaultAPI
import VaultCrypto
import VaultModels
import VaultSync
@testable import VaultServices

final class PasskeyRepairKeyGuardTests: XCTestCase {

    @MainActor
    func testPasskeyRepairLeavesSharedItemsAlone() async throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let itemKey = try SymmetricCryptoKey.generate()
        let engine = try makeEngine()

        var cipher = Cipher(type: .login)
        cipher.id = "shared-passkey"
        cipher.organizationId = "org-1"
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: orgKey)
        cipher.name = try CipherEncryption.encrypt(string: "Shared passkey", key: itemKey)
        var credential = Fido2Credential()
        credential.credentialId = try CipherEncryption.encrypt(
            string: "b9e5f1f0-5a3b-4d7c-9a51-6a0f2c1d7e42", key: itemKey
        )
        // `keyType`, `counter`, `discoverable`… are missing — exactly what the repair fills in.
        var login = LoginData()
        login.fido2Credentials = [credential]
        cipher.login = login
        try engine.replaceCipherFromServer(cipher)

        _ = await PendingPasskeyManager.repairPasskeyCompatibility(syncEngine: engine, vaultKey: vaultKey)

        let stored = try XCTUnwrap(engine.fetchCiphers().first)
        XCTAssertNil(stored.pendingOperation, "A shared item must not be queued for upload")
        XCTAssertEqual(try stored.toCipher(), cipher)
    }

    @MainActor
    private func makeEngine() throws -> SyncEngine {
        let container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            PersistedOrganization.self, PersistedCollection.self,
            configurations: ModelConfiguration(isStoredInMemoryOnly: true)
        )
        let account = Account(
            email: "passkey@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        return SyncEngine(apiClient: APIClient(account: account), modelContainer: container, accountId: account.id)
    }
}
