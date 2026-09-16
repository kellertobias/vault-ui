// Tests for merging organizations and collections out of a full sync response.
// A full sync is authoritative, so the important cases are not just "new rows
// appear" but "revoked membership disappears" — a stale org row would keep an
// organization's key unwrappable locally after the server took access away.

import XCTest
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI
@testable import VaultSync

final class SyncEngineOrganizationMergeTests: XCTestCase {

    private let accountId = "account-1"
    private var container: ModelContainer!

    /// The background merge path, wired to an in-memory store and no server.
    private func makeMerger() throws -> BackgroundSyncActor {
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            PersistedOrganization.self, PersistedCollection.self,
            configurations: config
        )
        let account = Account(
            id: accountId,
            email: "u@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        return BackgroundSyncActor(
            modelContainer: container,
            apiClient: APIClient(account: account),
            accountId: accountId,
            encoder: JSONEncoder()
        )
    }

    /// A sync response carrying just the organization/collection halves.
    private func response(
        organizations: [Organization]? = nil,
        collections: [VaultModels.Collection]? = nil
    ) -> SyncResponse {
        var response = SyncResponse()
        if let organizations {
            var profile = Profile()
            profile.organizations = organizations
            response.profile = profile
        }
        response.collections = collections
        return response
    }

    /// An RSA-sealed org key, serialized the way the server sends it.
    private func sealedKey(byte: UInt8) -> EncString {
        EncString(
            type: .rsa2048_OAEPSHA1_B64,
            iv: nil,
            ciphertext: Data(repeating: byte, count: 256),
            mac: nil
        )
    }

    private func organization(id: String, name: String, keyByte: UInt8 = 0x01) -> Organization {
        var organization = Organization(id: id, name: name)
        organization.key = sealedKey(byte: keyByte)
        organization.status = OrganizationUserStatus.confirmed.rawValue
        organization.enabled = true
        return organization
    }

    private func collection(id: String, organizationId: String, readOnly: Bool = false) -> VaultModels.Collection {
        var collection = VaultModels.Collection(id: id, organizationId: organizationId)
        collection.name = try? EncString(serialized: "2.aXY=|Y3Q=|bWFj")
        collection.readOnly = readOnly
        collection.hidePasswords = false
        return collection
    }

    private func storedOrganizations() throws -> [PersistedOrganization] {
        let accountId = accountId
        let context = ModelContext(container)
        return try context.fetch(
            FetchDescriptor<PersistedOrganization>(
                predicate: #Predicate { $0.accountId == accountId },
                sortBy: [SortDescriptor(\.id)]
            )
        )
    }

    private func storedCollections() throws -> [PersistedCollection] {
        let accountId = accountId
        let context = ModelContext(container)
        return try context.fetch(
            FetchDescriptor<PersistedCollection>(
                predicate: #Predicate { $0.accountId == accountId },
                sortBy: [SortDescriptor(\.id)]
            )
        )
    }

    func testInsertsOrganizationsAndCollections() async throws {
        let merger = try makeMerger()

        _ = try await merger.merge(response(
            organizations: [organization(id: "org-1", name: "Acme")],
            collections: [collection(id: "col-1", organizationId: "org-1")]
        ))

        let organizations = try storedOrganizations()
        XCTAssertEqual(organizations.count, 1)
        XCTAssertEqual(organizations.first?.name, "Acme")
        XCTAssertEqual(organizations.first?.encryptedKey, sealedKey(byte: 0x01).serialized())

        let collections = try storedCollections()
        XCTAssertEqual(collections.count, 1)
        XCTAssertEqual(collections.first?.organizationId, "org-1")
        XCTAssertFalse(collections.first?.readOnly ?? true)
    }

    func testUpdatesExistingOrganizationInPlace() async throws {
        let merger = try makeMerger()

        _ = try await merger.merge(response(organizations: [organization(id: "org-1", name: "Acme")]))

        var renamed = organization(id: "org-1", name: "Acme Corp", keyByte: 0x02)
        renamed.enabled = false
        _ = try await merger.merge(response(organizations: [renamed]))

        let organizations = try storedOrganizations()
        XCTAssertEqual(organizations.count, 1, "The org must be updated, not duplicated")
        XCTAssertEqual(organizations.first?.name, "Acme Corp")
        XCTAssertEqual(organizations.first?.encryptedKey, sealedKey(byte: 0x02).serialized(),
                       "A re-sealed org key must replace the stored one")
        XCTAssertEqual(organizations.first?.enabled, false)
    }

    /// Losing access server-side must drop the local row — otherwise the org key
    /// stays unwrappable on this device after the membership is revoked.
    func testRevokedMembershipIsRemovedLocally() async throws {
        let merger = try makeMerger()

        _ = try await merger.merge(response(organizations: [
            organization(id: "org-1", name: "Acme"),
            organization(id: "org-2", name: "Other"),
        ]))
        XCTAssertEqual(try storedOrganizations().count, 2)

        _ = try await merger.merge(response(organizations: [organization(id: "org-1", name: "Acme")]))

        XCTAssertEqual(try storedOrganizations().map(\.id), ["org-1"])
    }

    func testRemovedCollectionIsDeletedAndPermissionsUpdate() async throws {
        let merger = try makeMerger()

        _ = try await merger.merge(response(collections: [
            collection(id: "col-1", organizationId: "org-1"),
            collection(id: "col-2", organizationId: "org-1"),
        ]))

        _ = try await merger.merge(response(collections: [
            collection(id: "col-1", organizationId: "org-1", readOnly: true),
        ]))

        let collections = try storedCollections()
        XCTAssertEqual(collections.map(\.id), ["col-1"])
        XCTAssertTrue(collections.first?.readOnly ?? false, "A downgrade to read-only must be picked up")
    }

    func testCollectionWithoutOrganizationIsIgnored() async throws {
        let merger = try makeMerger()

        var orphan = VaultModels.Collection(id: "col-orphan")
        orphan.organizationId = nil
        _ = try await merger.merge(response(collections: [orphan]))

        XCTAssertTrue(try storedCollections().isEmpty)
    }
}
