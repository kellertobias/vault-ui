// Tests for SyncEngine's local persistence operations against an in-memory
// SwiftData store. These cover the offline-first write path and, in particular,
// the `neverSynced` guard that keeps a client-generated item from being turned
// into a PUT/DELETE the server would 404 on — a real data-loss avoidance rule.

import XCTest
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI
@testable import VaultSync

@MainActor
final class SyncEngineLocalOpsTests: XCTestCase {

    private func makeEngine() throws -> SyncEngine {
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        let container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            configurations: config
        )
        let account = Account(
            email: "u@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        return SyncEngine(apiClient: APIClient(account: account), modelContainer: container, accountId: account.id)
    }

    private func makeLoginCipher(id: String, name: String) throws -> Cipher {
        let key = try SymmetricCryptoKey.generate()
        var cipher = Cipher(type: .login)
        cipher.id = id
        cipher.name = try CipherEncryption.encrypt(string: name, key: key)
        return cipher
    }

    func testCreateThenFetch() throws {
        let engine = try makeEngine()
        try engine.saveCipherLocally(try makeLoginCipher(id: "c1", name: "Example"), operation: .create)

        let all = try engine.fetchCiphers()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first?.id, "c1")
        XCTAssertEqual(all.first?.syncStatus, .pendingCreate)
        XCTAssertEqual(all.first?.pendingOperation, .create)
    }

    func testNeverSyncedUpdateStaysCreate() throws {
        // A locally-created item (client-generated id) must NOT be downgraded to a
        // pendingUpload update — issuing a PUT against an id the server never saw
        // would 404 and wedge the item.
        let engine = try makeEngine()
        let cipher = try makeLoginCipher(id: "c1", name: "Example")
        try engine.saveCipherLocally(cipher, operation: .create)
        try engine.saveCipherLocally(cipher, operation: .update)

        let item = try XCTUnwrap(try engine.fetchCiphers().first)
        XCTAssertEqual(item.syncStatus, .pendingCreate)
        XCTAssertEqual(item.pendingOperation, .create)
    }

    func testNeverSyncedDeleteRemovesLocally() throws {
        // Deleting a never-synced item just removes it locally — no pending delete.
        let engine = try makeEngine()
        let cipher = try makeLoginCipher(id: "c1", name: "Example")
        try engine.saveCipherLocally(cipher, operation: .create)
        try engine.saveCipherLocally(cipher, operation: .delete)

        XCTAssertTrue(try engine.fetchCiphers(includeDeleted: true).isEmpty)
    }

    func testSyncedItemUpdateQueuesUpload() throws {
        // A server-backed (synced) item DOES queue a pendingUpload update.
        let engine = try makeEngine()
        let cipher = try makeLoginCipher(id: "c1", name: "Example")
        try engine.replaceCipherFromServer(cipher)   // inserts as .synced
        XCTAssertEqual(try engine.fetchCiphers().first?.syncStatus, .synced)

        try engine.saveCipherLocally(cipher, operation: .update)
        let item = try XCTUnwrap(try engine.fetchCiphers().first)
        XCTAssertEqual(item.syncStatus, .pendingUpload)
        XCTAssertEqual(item.pendingOperation, .update)
    }

    func testSoftDeleteThenRestoreOnSyncedItem() throws {
        let engine = try makeEngine()
        let cipher = try makeLoginCipher(id: "c1", name: "Example")
        try engine.replaceCipherFromServer(cipher)

        try engine.saveCipherLocally(cipher, operation: .softDelete)
        XCTAssertTrue(try engine.fetchCiphers().isEmpty, "soft-deleted item is excluded by default")
        let deleted = try XCTUnwrap(try engine.fetchCiphers(includeDeleted: true).first)
        XCTAssertNotNil(deleted.deletedDate)
        XCTAssertEqual(deleted.syncStatus, .pendingUpload)
        XCTAssertEqual(deleted.pendingOperation, .softDelete)

        try engine.saveCipherLocally(cipher, operation: .restore)
        let restored = try XCTUnwrap(try engine.fetchCiphers().first)
        XCTAssertNil(restored.deletedDate)
        XCTAssertEqual(restored.pendingOperation, .restore)
    }

    func testFetchIsScopedToAccount() throws {
        let engine = try makeEngine()
        try engine.saveCipherLocally(try makeLoginCipher(id: "c1", name: "Mine"), operation: .create)
        // Same store, different account id — should see nothing.
        let otherAccount = Account(
            email: "other@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        let otherEngine = SyncEngine(
            apiClient: APIClient(account: otherAccount),
            modelContainer: engine.modelContainer,
            accountId: otherAccount.id
        )
        XCTAssertTrue(try otherEngine.fetchCiphers().isEmpty)
        XCTAssertEqual(try engine.fetchCiphers().count, 1)
    }
}
