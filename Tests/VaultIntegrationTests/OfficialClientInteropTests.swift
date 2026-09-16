// MARK: - VaultIntegrationTests/OfficialClientInteropTests.swift
// Cross-client checks: the app against the official Bitwarden CLI and web vault.

import XCTest
import Foundation
import VaultCrypto
import VaultModels
@testable import VaultAPI
@testable import VaultServices

final class OfficialClientInteropTests: VaultwardenIntegrationTestCase {

    // MARK: - App writes, official CLI reads

    func testCLIReadsItemTheAppCreatedInOrganization() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let itemId = try await createSharedLogin(
            by: owner, in: org, name: "App → CLI", username: "app-user", password: "app-pass"
        )

        let cli = try await loginCLI(as: member)
        let item = try await cli.item(id: itemId)
        XCTAssertEqual(item.organizationId, org.id)
        XCTAssertEqual(item.collectionIds, [org.defaultCollectionId])
        XCTAssertEqual(item.name, "App → CLI")
        XCTAssertEqual(item.login?.username, "app-user")
        XCTAssertEqual(item.login?.password, "app-pass")
    }

    /// An ordinary login saved by the app — item key plus URI, as the editor
    /// writes it. Official clients hide a URI whose checksum is missing or wrong,
    /// which would also break autofill matching in the browser extension.
    func testCLISeesURIOfLoginTheAppCreated() async throws {
        let user = try await TestUser.register(on: serverURL, label: "uri")
        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(
            forOrganization: nil,
            keyRing: VaultKeyRing(vaultKey: user.vaultKey)
        )

        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey
        cipher.name = try CipherEncryption.encrypt(string: "With websites", key: itemKey)
        var login = LoginData()
        login.uris = [
            try LoginUri.encrypted("https://app.example/login", key: itemKey),
            try LoginUri.encrypted("https://second.example", match: .host, key: itemKey),
        ]
        cipher.login = login
        let created = try await CipherAPI(client: user.client).create(cipher)

        let item = try await loginCLI(as: user).item(id: try XCTUnwrap(created.id))
        XCTAssertEqual(item.login?.uris?.map(\.uri), ["https://app.example/login", "https://second.example"])
    }

    /// Items saved before the app wrote URI checksums: the official client shows
    /// no websites until the repair pass runs, then shows them all.
    func testRepairPassMakesOldURIsVisibleToCLI() async throws {
        let user = try await TestUser.register(on: serverURL, label: "repair")
        let itemId = try await createLoginWithoutChecksums(
            by: user, organizationId: nil, uris: ["https://old.example", "https://older.example"]
        )

        let cli = try await loginCLI(as: user)
        let before = try await cli.item(id: itemId)
        XCTAssertEqual(before.login?.uris?.count, 0, "Precondition: the official client hides unchecksummed URIs")

        let engine = try await MainActor.run { try user.makeSyncEngine() }
        try await engine.fullSync()
        let repaired = await URIChecksumRepair.run(
            syncEngine: engine,
            keyRing: try await user.syncedKeyRing(),
            canEdit: { _ in true }
        )
        XCTAssertEqual(repaired, 1)

        let after = try await cli.item(id: itemId)
        XCTAssertEqual(after.login?.uris?.map(\.uri), ["https://old.example", "https://older.example"])
        XCTAssertEqual(after.name, "Needs repair", "The rest of the item must be untouched")

        let second = await URIChecksumRepair.run(
            syncEngine: engine,
            keyRing: try await user.syncedKeyRing(),
            canEdit: { _ in true }
        )
        XCTAssertEqual(second, 0, "A second run has nothing left to do")
    }

    /// The owner's repair of a shared item must be readable by other members'
    /// official clients — the checksum goes under the org-wrapped item key.
    func testRepairPassOnSharedItemIsVisibleToMembersCLI() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let itemId = try await createLoginWithoutChecksums(
            by: owner, organizationId: org.id, collectionId: org.defaultCollectionId,
            uris: ["https://shared-old.example"]
        )

        let engine = try await MainActor.run { try owner.makeSyncEngine() }
        try await engine.fullSync()
        let repaired = await URIChecksumRepair.run(
            syncEngine: engine,
            keyRing: try await owner.syncedKeyRing(),
            canEdit: { _ in true }
        )
        XCTAssertEqual(repaired, 1)

        let item = try await loginCLI(as: member).item(id: itemId)
        XCTAssertEqual(item.login?.uris?.map(\.uri), ["https://shared-old.example"])
    }

    /// The app re-encrypts every field of a pre-2023 item when sharing it; the
    /// official client must read every one of them.
    func testCLIReadsLegacyItemTheAppShared() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        var legacy = Cipher(type: .login)
        legacy.name = try CipherEncryption.encrypt(string: "Legacy shared by app", key: owner.vaultKey)
        legacy.notes = try CipherEncryption.encrypt(string: "legacy notes", key: owner.vaultKey)
        var login = LoginData()
        login.username = try CipherEncryption.encrypt(string: "legacy-user", key: owner.vaultKey)
        login.password = try CipherEncryption.encrypt(string: "legacy-pass", key: owner.vaultKey)
        login.totp = try CipherEncryption.encrypt(string: "JBSWY3DPEHPK3PXP", key: owner.vaultKey)
        login.uris = [LoginUri(uri: try CipherEncryption.encrypt(string: "https://legacy.example", key: owner.vaultKey))]
        legacy.login = login
        legacy.fields = [CustomField(
            name: try CipherEncryption.encrypt(string: "PIN", key: owner.vaultKey),
            value: try CipherEncryption.encrypt(string: "2468", key: owner.vaultKey),
            type: .hidden
        )]
        let created = try await CipherAPI(client: owner.client).create(legacy)
        let itemId = try XCTUnwrap(created.id)
        try await shareWithApp(itemId, from: owner, into: org)

        let item = try await loginCLI(as: member).item(id: itemId)
        XCTAssertEqual(item.organizationId, org.id)
        XCTAssertEqual(item.name, "Legacy shared by app")
        XCTAssertEqual(item.notes, "legacy notes")
        XCTAssertEqual(item.login?.username, "legacy-user")
        XCTAssertEqual(item.login?.password, "legacy-pass")
        XCTAssertEqual(item.login?.totp, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(item.login?.uris?.first?.uri, "https://legacy.example")
        XCTAssertEqual(item.fields?.first?.name, "PIN")
        XCTAssertEqual(item.fields?.first?.value, "2468")
    }

    func testCLIReadsKeyedItemTheAppShared() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(
            forOrganization: nil,
            keyRing: VaultKeyRing(vaultKey: owner.vaultKey)
        )
        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey
        cipher.name = try CipherEncryption.encrypt(string: "Keyed shared by app", key: itemKey)
        var login = LoginData()
        login.password = try CipherEncryption.encrypt(string: "keyed-pass", key: itemKey)
        cipher.login = login
        let created = try await CipherAPI(client: owner.client).create(cipher)
        let itemId = try XCTUnwrap(created.id)
        try await shareWithApp(itemId, from: owner, into: org)

        let item = try await loginCLI(as: member).item(id: itemId)
        XCTAssertEqual(item.name, "Keyed shared by app")
        XCTAssertEqual(item.login?.password, "keyed-pass")
    }

    // MARK: - Official CLI writes, app reads

    /// A personal item written by the official client — whatever key scheme the
    /// current CLI uses — must open in the app.
    func testAppReadsPersonalItemTheCLICreated() async throws {
        let user = try await TestUser.register(on: serverURL, label: "cli-personal")
        let cli = try await loginCLI(as: user)

        let created = try await cli.createItem(loginItem(
            name: "CLI personal", username: "cli-user", password: "cli-pass",
            notes: "from the official client", fieldValue: "1357"
        ))

        let cipher = try await findCipher(created.id, for: user)
        let ring = try await user.syncedKeyRing()
        XCTAssertNil(cipher.organizationId)
        XCTAssertEqual(try read(cipher.name, of: cipher, ring: ring), "CLI personal")
        XCTAssertEqual(try read(cipher.notes, of: cipher, ring: ring), "from the official client")
        XCTAssertEqual(try read(cipher.login?.username, of: cipher, ring: ring), "cli-user")
        XCTAssertEqual(try read(cipher.login?.password, of: cipher, ring: ring), "cli-pass")
        XCTAssertEqual(try read(cipher.fields?.first?.value, of: cipher, ring: ring), "1357")
    }

    func testAppReadsItemTheCLICreatedInOrganization() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let cli = try await loginCLI(as: owner)

        var item = loginItem(name: "CLI → App", username: "cli-org-user", password: "cli-org-pass")
        item["organizationId"] = org.id
        item["collectionIds"] = [org.defaultCollectionId]
        let created = try await cli.createItem(item)
        XCTAssertEqual(created.organizationId, org.id)

        let cipher = try await findCipher(created.id, for: member)
        let ring = try await member.syncedKeyRing()
        XCTAssertEqual(try read(cipher.name, of: cipher, ring: ring), "CLI → App")
        XCTAssertEqual(try read(cipher.login?.username, of: cipher, ring: ring), "cli-org-user")
        XCTAssertEqual(try read(cipher.login?.password, of: cipher, ring: ring), "cli-org-pass")
    }

    /// The official client's own "move to organization" — the reference
    /// implementation of what the app's Share action does.
    func testAppReadsItemTheCLIMovedIntoOrganization() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let cli = try await loginCLI(as: owner)

        let personal = try await cli.createItem(loginItem(name: "Moved by CLI", username: "moved", password: "moved-pass"))
        // `bw move` sometimes echoes the item's pre-move local state, so judge the
        // move by what the server returns to the member, not by that output.
        _ = try await cli.moveItem(id: personal.id, toOrganization: org.id, collectionIds: [org.defaultCollectionId])

        let cipher = try await findCipher(personal.id, for: member)
        XCTAssertEqual(cipher.organizationId, org.id)
        XCTAssertEqual(cipher.collectionIds, [org.defaultCollectionId])
        let ring = try await member.syncedKeyRing()
        XCTAssertEqual(try read(cipher.name, of: cipher, ring: ring), "Moved by CLI")
        XCTAssertEqual(try read(cipher.login?.password, of: cipher, ring: ring), "moved-pass")
    }

    // MARK: - Edits across clients

    /// The member edits in the app; the owner reads the change with the CLI.
    func testCLISeesEditTheAppMadeToSharedItem() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let itemId = try await createSharedLogin(by: owner, in: org, name: "Rotate me", username: "u", password: "before")

        var cipher = try await findCipher(itemId, for: member)
        let itemKey = try VaultCryptoFacade.itemKey(for: cipher, keyRing: try await member.syncedKeyRing())
        cipher.login?.password = try CipherEncryption.encrypt(string: "after-app-edit", key: itemKey)
        _ = try await CipherAPI(client: member.client).update(cipher)

        let item = try await loginCLI(as: owner).item(id: itemId)
        XCTAssertEqual(item.login?.password, "after-app-edit")
        XCTAssertEqual(item.name, "Rotate me", "Untouched fields must still decrypt")
    }

    /// The owner edits with the CLI; the member reads the change in the app.
    func testAppSeesEditTheCLIMadeToSharedItem() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let itemId = try await createSharedLogin(by: owner, in: org, name: "Edited by CLI", username: "u", password: "before")

        let cli = try await loginCLI(as: owner)
        var raw = try await cli.rawItem(id: itemId)
        var login = try XCTUnwrap(raw["login"] as? [String: Any])
        login["password"] = "after-cli-edit"
        raw["login"] = login
        _ = try await cli.editItem(id: itemId, raw)

        let cipher = try await findCipher(itemId, for: member)
        let ring = try await member.syncedKeyRing()
        XCTAssertEqual(try read(cipher.login?.password, of: cipher, ring: ring), "after-cli-edit")
        XCTAssertEqual(try read(cipher.name, of: cipher, ring: ring), "Edited by CLI")
    }

    // MARK: - Web vault

    /// The member opens the web vault and reads an item the app created in the
    /// organization — the official web client decrypting app-written data.
    func testWebVaultShowsItemTheAppCreatedInOrganization() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        _ = try await createSharedLogin(
            by: owner, in: org, name: "App → Web", username: "web-user", password: "web-pass"
        )

        let item = try await WebVault.readItem(named: "App → Web", as: member, serverURL: serverURL)
        XCTAssertEqual(item.name, "App → Web")
        XCTAssertEqual(item.username, "web-user")
        XCTAssertEqual(item.password, "web-pass")
    }

    func testWebVaultShowsLegacyItemTheAppShared() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        var legacy = Cipher(type: .login)
        legacy.name = try CipherEncryption.encrypt(string: "Legacy → Web", key: owner.vaultKey)
        var login = LoginData()
        login.username = try CipherEncryption.encrypt(string: "legacy-web-user", key: owner.vaultKey)
        login.password = try CipherEncryption.encrypt(string: "legacy-web-pass", key: owner.vaultKey)
        legacy.login = login
        let created = try await CipherAPI(client: owner.client).create(legacy)
        try await shareWithApp(try XCTUnwrap(created.id), from: owner, into: org)

        let item = try await WebVault.readItem(named: "Legacy → Web", as: member, serverURL: serverURL)
        XCTAssertEqual(item.username, "legacy-web-user")
        XCTAssertEqual(item.password, "legacy-web-pass")
    }

    // MARK: - Helpers

    /// A login with an item key and URIs but no checksums — how this app saved
    /// logins before it wrote them.
    private func createLoginWithoutChecksums(
        by user: TestUser,
        organizationId: String?,
        collectionId: String? = nil,
        uris: [String]
    ) async throws -> String {
        let ring = try await user.syncedKeyRing()
        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(forOrganization: organizationId, keyRing: ring)

        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey
        cipher.organizationId = organizationId
        cipher.collectionIds = collectionId.map { [$0] }
        cipher.name = try CipherEncryption.encrypt(string: "Needs repair", key: itemKey)
        var login = LoginData()
        login.uris = try uris.map { LoginUri(uri: try CipherEncryption.encrypt(string: $0, key: itemKey)) }
        cipher.login = login

        let created = try await CipherAPI(client: user.client).create(cipher)
        return try XCTUnwrap(created.id)
    }

    /// A CLI session for `user`, logged out and cleaned up when the test ends.
    private func loginCLI(as user: TestUser) async throws -> BitwardenCLI {
        let cli = try await BitwardenCLI.login(as: user, serverURL: serverURL)
        addTeardownBlock { await cli.logout() }
        return cli
    }

    /// A login item in the JSON shape `bw create item` takes.
    private func loginItem(
        name: String,
        username: String,
        password: String,
        notes: String? = nil,
        fieldValue: String? = nil
    ) -> [String: Any] {
        var item: [String: Any] = [
            "type": 1,
            "name": name,
            "notes": notes ?? NSNull(),
            "favorite": false,
            "reprompt": 0,
            "login": [
                "username": username,
                "password": password,
                "uris": [] as [Any],
            ],
        ]
        if let fieldValue {
            item["fields"] = [["name": "PIN", "value": fieldValue, "type": 1]]
        }
        return item
    }

    private func findCipher(_ id: String, for user: TestUser) async throws -> Cipher {
        let ciphers = try await user.sync().ciphers ?? []
        return try XCTUnwrap(ciphers.first { $0.id == id }, "\(user.email) should see cipher \(id)")
    }

    private func read(_ encString: EncString?, of cipher: Cipher, ring: VaultKeyRing) throws -> String {
        try XCTUnwrap(
            VaultCryptoFacade.decrypt(encString, itemKey: cipher.key, organizationId: cipher.organizationId, keyRing: ring),
            "Field did not decrypt with this user's keys"
        )
    }

    /// Share an item the way the app's Share action does.
    private func shareWithApp(_ itemId: String, from owner: TestUser, into org: TestOrganization) async throws {
        let current = try await findCipher(itemId, for: owner)
        let prepared = try OrganizationSharing.prepareForSharing(
            current,
            organizationId: org.id,
            collectionIds: [org.defaultCollectionId],
            keyRing: try await owner.syncedKeyRing()
        )
        _ = try await CipherAPI(client: owner.client).share(prepared, collectionIds: [org.defaultCollectionId])
    }

    private func makeOrganizationWithMember() async throws -> (TestUser, TestUser, TestOrganization) {
        let owner = try await TestUser.register(on: serverURL, label: "owner")
        let member = try await TestUser.register(on: serverURL, label: "member")
        let org = try await TestOrganization.create(by: owner)
        try await org.addMember(member, access: [.init(collectionId: org.defaultCollectionId)])
        return (owner, member, org)
    }

    /// A login created the way the app's editor creates a shared item.
    private func createSharedLogin(
        by owner: TestUser,
        in org: TestOrganization,
        name: String,
        username: String,
        password: String
    ) async throws -> String {
        let ring = try await owner.syncedKeyRing()
        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(forOrganization: org.id, keyRing: ring)

        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey
        cipher.organizationId = org.id
        cipher.collectionIds = [org.defaultCollectionId]
        cipher.name = try CipherEncryption.encrypt(string: name, key: itemKey)
        var login = LoginData()
        login.username = try CipherEncryption.encrypt(string: username, key: itemKey)
        login.password = try CipherEncryption.encrypt(string: password, key: itemKey)
        cipher.login = login

        let created = try await CipherAPI(client: owner.client).create(cipher)
        return try XCTUnwrap(created.id)
    }
}
