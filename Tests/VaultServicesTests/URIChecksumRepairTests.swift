// Tests for the URI checksum repair pass.
//
// The pass rewrites existing vault items in the background, so the cases that
// matter most are the ones it must leave alone: items without a usable key,
// shared items it may not write, and items with edits still pending.

import XCTest
import Foundation
import SwiftData
import VaultAPI
import VaultCrypto
import VaultModels
import VaultSync
@testable import VaultServices

final class URIChecksumRepairTests: XCTestCase {

    private var vaultKey: SymmetricCryptoKey!
    private var orgKey: SymmetricCryptoKey!
    private var keyRing: VaultKeyRing!

    override func setUpWithError() throws {
        vaultKey = try SymmetricCryptoKey.generate()
        orgKey = try SymmetricCryptoKey.generate()
        keyRing = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])
    }

    // MARK: - repaired(_:keyRing:)

    func testAddsChecksumToKeyedPersonalItem() throws {
        let (cipher, itemKey) = try keyedLogin(uris: ["https://a.example", "https://b.example"])

        let repaired = try XCTUnwrap(URIChecksumRepair.repaired(cipher, keyRing: keyRing))

        let uris = try XCTUnwrap(repaired.login?.uris)
        XCTAssertEqual(try checksums(of: uris, key: itemKey), [
            LoginUri.checksum(for: "https://a.example"),
            LoginUri.checksum(for: "https://b.example"),
        ])
        XCTAssertEqual(
            uris.map { $0.uri?.serialized() },
            cipher.login?.uris?.map { $0.uri?.serialized() },
            "The URIs themselves must not be re-encrypted"
        )
    }

    func testAddsChecksumToSharedItemUsingOrganizationKey() throws {
        let (cipher, itemKey) = try keyedLogin(uris: ["https://shared.example"], organizationId: "org-1")

        let repaired = try XCTUnwrap(URIChecksumRepair.repaired(cipher, keyRing: keyRing))

        XCTAssertEqual(
            try checksums(of: XCTUnwrap(repaired.login?.uris), key: itemKey),
            [LoginUri.checksum(for: "https://shared.example")]
        )
    }

    /// Official clients don't check items without an item key; nothing to do.
    func testLeavesItemWithoutItemKeyAlone() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "legacy"
        var login = LoginData()
        login.uris = [LoginUri(uri: try CipherEncryption.encrypt(string: "https://legacy.example", key: vaultKey))]
        cipher.login = login

        XCTAssertNil(URIChecksumRepair.repaired(cipher, keyRing: keyRing))
    }

    func testLeavesItemWithAllChecksumsAlone() throws {
        let itemKey = try SymmetricCryptoKey.generate()
        var cipher = Cipher(type: .login)
        cipher.id = "done"
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: vaultKey)
        var login = LoginData()
        login.uris = [try LoginUri.encrypted("https://done.example", key: itemKey)]
        cipher.login = login

        XCTAssertNil(URIChecksumRepair.repaired(cipher, keyRing: keyRing))
    }

    func testLeavesSharedItemWithoutAvailableOrganizationKeyAlone() throws {
        let (cipher, _) = try keyedLogin(uris: ["https://x.example"], organizationId: "org-unknown")

        XCTAssertNil(URIChecksumRepair.repaired(cipher, keyRing: keyRing))
    }

    /// An item key that doesn't open must not lead to a checksum under some other key.
    func testLeavesItemWithUnreadableItemKeyAlone() throws {
        var (cipher, _) = try keyedLogin(uris: ["https://x.example"])
        let foreignKey = try SymmetricCryptoKey.generate()
        cipher.key = try CipherEncryption.encrypt(data: SymmetricCryptoKey.generate().keyData, key: foreignKey)

        XCTAssertNil(URIChecksumRepair.repaired(cipher, keyRing: keyRing))
    }

    /// Only missing checksums are added; an existing one — even a wrong one — is kept.
    func testKeepsExistingChecksumsAndFillsOnlyMissingOnes() throws {
        let itemKey = try SymmetricCryptoKey.generate()
        let wrongChecksum = try CipherEncryption.encrypt(string: "not-the-checksum", key: itemKey).serialized()
        var cipher = Cipher(type: .login)
        cipher.id = "mixed"
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: vaultKey)
        var login = LoginData()
        login.uris = [
            LoginUri(uri: try CipherEncryption.encrypt(string: "https://kept.example", key: itemKey), uriChecksum: wrongChecksum),
            LoginUri(uri: nil, match: .never),
            LoginUri(uri: try CipherEncryption.encrypt(string: "https://filled.example", key: itemKey)),
        ]
        cipher.login = login

        let repaired = try XCTUnwrap(URIChecksumRepair.repaired(cipher, keyRing: keyRing))
        let uris = try XCTUnwrap(repaired.login?.uris)

        XCTAssertEqual(uris[0].uriChecksum, wrongChecksum)
        XCTAssertEqual(uris[1], LoginUri(uri: nil, match: .never))
        XCTAssertEqual(
            try CipherEncryption.decryptString(EncString(serialized: XCTUnwrap(uris[2].uriChecksum)), key: itemKey),
            LoginUri.checksum(for: "https://filled.example")
        )
    }

    // MARK: - repairLocally

    @MainActor
    func testRepairLocallyQueuesOnlyEligibleItems() throws {
        let engine = try makeEngine()

        let (personal, _) = try keyedLogin(id: "personal", uris: ["https://p.example"])
        let (readOnly, _) = try keyedLogin(id: "read-only", uris: ["https://r.example"], organizationId: "org-1")
        let (pending, _) = try keyedLogin(id: "pending", uris: ["https://e.example"])
        try engine.replaceCipherFromServer(personal)
        try engine.replaceCipherFromServer(readOnly)
        try engine.replaceCipherFromServer(pending)
        // A local edit that hasn't been uploaded yet must not be raced.
        try engine.saveCipherLocally(pending, operation: .update)

        let repairedIds = try URIChecksumRepair.repairLocally(
            syncEngine: engine,
            keyRing: keyRing,
            canEdit: { $0.id != "read-only" }
        )

        XCTAssertEqual(repairedIds, ["personal"])
        let stored = try Dictionary(uniqueKeysWithValues: engine.fetchCiphers().map { ($0.id, $0) })
        XCTAssertEqual(stored["personal"]?.pendingOperation, .update)
        XCTAssertNotNil(try stored["personal"]?.toCipher().login?.uris?.first?.uriChecksum)
        XCTAssertNil(stored["read-only"]?.pendingOperation)
        XCTAssertNil(try stored["read-only"]?.toCipher().login?.uris?.first?.uriChecksum)
        XCTAssertNil(try stored["pending"]?.toCipher().login?.uris?.first?.uriChecksum)
    }

    @MainActor
    func testRepairLocallyIsIdempotent() throws {
        let engine = try makeEngine()
        let (cipher, _) = try keyedLogin(id: "once", uris: ["https://once.example"])
        try engine.replaceCipherFromServer(cipher)

        XCTAssertEqual(try URIChecksumRepair.repairLocally(syncEngine: engine, keyRing: keyRing, canEdit: { _ in true }), ["once"])

        // Simulate the upload having succeeded.
        try engine.replaceCipherFromServer(try XCTUnwrap(engine.fetchCiphers().first).toCipher())
        XCTAssertEqual(try URIChecksumRepair.repairLocally(syncEngine: engine, keyRing: keyRing, canEdit: { _ in true }), [])
    }

    // MARK: - Helpers

    @MainActor
    private func makeEngine() throws -> SyncEngine {
        let container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            PersistedOrganization.self, PersistedCollection.self,
            configurations: ModelConfiguration(isStoredInMemoryOnly: true)
        )
        let account = Account(
            email: "repair@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        return SyncEngine(apiClient: APIClient(account: account), modelContainer: container, accountId: account.id)
    }

    /// A login with an item key and URIs in the pre-checksum layout.
    private func keyedLogin(
        id: String = "cipher",
        uris: [String],
        organizationId: String? = nil
    ) throws -> (Cipher, SymmetricCryptoKey) {
        let itemKey = try SymmetricCryptoKey.generate()
        let baseKey = organizationId == "org-1" ? orgKey! : (organizationId == nil ? vaultKey! : try SymmetricCryptoKey.generate())

        var cipher = Cipher(type: .login)
        cipher.id = id
        cipher.organizationId = organizationId
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: baseKey)
        cipher.name = try CipherEncryption.encrypt(string: id, key: itemKey)
        var login = LoginData()
        login.uris = try uris.map { LoginUri(uri: try CipherEncryption.encrypt(string: $0, key: itemKey)) }
        cipher.login = login
        return (cipher, itemKey)
    }

    private func checksums(of uris: [LoginUri], key: SymmetricCryptoKey) throws -> [String] {
        try uris.map { uri in
            try CipherEncryption.decryptString(EncString(serialized: XCTUnwrap(uri.uriChecksum)), key: key)
        }
    }
}
