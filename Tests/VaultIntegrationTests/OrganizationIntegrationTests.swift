// MARK: - VaultIntegrationTests/OrganizationIntegrationTests.swift
// End-to-end organization tests against a live Vaultwarden.
//
// Two real accounts per test: an owner who creates and shares items, and a member
// who must be able to read them with nothing but their own keys. Every assertion
// about readability is made from the member's side, because that is where a
// wrongly-keyed item fails — the owner can often still read their own mistakes.

import XCTest
import Foundation
import VaultCrypto
import VaultModels
@testable import VaultAPI
@testable import VaultServices

final class OrganizationIntegrationTests: VaultwardenIntegrationTestCase {

    // MARK: - Baseline

    /// Registration and login through the app's own key handling: if this fails,
    /// nothing else in the suite is meaningful.
    func testRegisteredUserLogsInAndReadsOwnItem() async throws {
        let user = try await TestUser.register(on: serverURL, label: "solo")

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(
            forOrganization: nil,
            keyRing: VaultKeyRing(vaultKey: user.vaultKey)
        )
        let created = try await CipherAPI(client: user.client).create(
            try makeLogin(name: "Personal", password: "p4ss", itemKey: itemKey, encryptedItemKey: encryptedItemKey)
        )

        let synced = try await findCipher(try XCTUnwrap(created.id), for: user)
        XCTAssertNil(synced.organizationId)
        XCTAssertEqual(try read(synced.login?.password, of: synced, ring: VaultKeyRing(vaultKey: user.vaultKey)), "p4ss")
    }

    // MARK: - Organization keys

    /// The core of org support: a confirmed member unwraps the same org key the
    /// owner created, using the account private key the server returned at login.
    func testConfirmedMemberUnwrapsTheOrganizationKey() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        let memberRing = try await member.syncedKeyRing()
        XCTAssertEqual(memberRing.organizationKeys[org.id]?.keyData, org.key.keyData)

        let ownerRing = try await owner.syncedKeyRing()
        XCTAssertEqual(ownerRing.organizationKeys[org.id]?.keyData, org.key.keyData)
    }

    /// Before confirmation there is no key to unwrap; the resolver must skip the
    /// membership quietly rather than report a failure.
    func testAcceptedButUnconfirmedMemberHasNoKeyAndNoFailure() async throws {
        let owner = try await TestUser.register(on: serverURL, label: "owner")
        let member = try await TestUser.register(on: serverURL, label: "pending")
        let org = try await TestOrganization.create(by: owner)
        try await org.inviteWithoutConfirming(member)

        let resolved = member.keyRing(from: try await member.sync())
        XCTAssertNil(resolved.ring.organizationKeys[org.id])
        XCTAssertEqual(resolved.failures, [])
    }

    // MARK: - Creating shared items

    func testMemberReadsItemCreatedDirectlyInOrganization() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let ownerRing = try await owner.syncedKeyRing()

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(
            forOrganization: org.id,
            keyRing: ownerRing
        )
        var cipher = try makeLogin(name: "Shared DB", password: "s3cret", itemKey: itemKey, encryptedItemKey: encryptedItemKey)
        cipher.organizationId = org.id
        cipher.collectionIds = [org.defaultCollectionId]
        let created = try await CipherAPI(client: owner.client).create(cipher)

        let seen = try await findCipher(try XCTUnwrap(created.id), for: member)
        XCTAssertEqual(seen.organizationId, org.id)
        XCTAssertEqual(seen.collectionIds, [org.defaultCollectionId])

        let memberRing = try await member.syncedKeyRing()
        XCTAssertEqual(try read(seen.name, of: seen, ring: memberRing), "Shared DB")
        XCTAssertEqual(try read(seen.login?.password, of: seen, ring: memberRing), "s3cret")
    }

    func testMemberDoesNotSeeItemsInCollectionsTheyLack() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let privateCollection = try await org.addCollection(named: "Owners only")
        let ownerRing = try await owner.syncedKeyRing()

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(forOrganization: org.id, keyRing: ownerRing)
        var cipher = try makeLogin(name: "Hidden", password: "x", itemKey: itemKey, encryptedItemKey: encryptedItemKey)
        cipher.organizationId = org.id
        cipher.collectionIds = [privateCollection]
        let created = try await CipherAPI(client: owner.client).create(cipher)

        let memberCiphers = try await member.sync().ciphers ?? []
        XCTAssertFalse(memberCiphers.contains { $0.id == created.id })
    }

    // MARK: - Moving personal items into an organization

    /// A modern item keeps its item key; only the wrapper moves to the org key.
    func testMemberReadsSharedItemThatHadItsOwnItemKey() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(
            forOrganization: nil,
            keyRing: VaultKeyRing(vaultKey: owner.vaultKey)
        )
        let personal = try await CipherAPI(client: owner.client).create(
            try makeLogin(name: "Was personal", password: "keyed", itemKey: itemKey, encryptedItemKey: encryptedItemKey)
        )
        let personalId = try XCTUnwrap(personal.id)

        let beforeShare = try await member.sync().ciphers ?? []
        XCTAssertFalse(beforeShare.contains { $0.id == personalId }, "A personal item must not be visible yet")

        try await share(personalId, from: owner, into: org)

        let seen = try await findCipher(personalId, for: member)
        let memberRing = try await member.syncedKeyRing()
        XCTAssertEqual(seen.organizationId, org.id)
        XCTAssertEqual(try read(seen.name, of: seen, ring: memberRing), "Was personal")
        XCTAssertEqual(try read(seen.login?.password, of: seen, ring: memberRing), "keyed")
    }

    /// A pre-2023 item has no item key, so sharing re-encrypts every field. The
    /// server stores whatever it is sent, so only the member's read proves it.
    func testMemberReadsSharedLegacyItemWithoutItemKey() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        var legacy = Cipher(type: .login)
        legacy.name = try CipherEncryption.encrypt(string: "Legacy", key: owner.vaultKey)
        legacy.notes = try CipherEncryption.encrypt(string: "old notes", key: owner.vaultKey)
        var login = LoginData()
        login.username = try CipherEncryption.encrypt(string: "ada", key: owner.vaultKey)
        login.password = try CipherEncryption.encrypt(string: "legacy-pass", key: owner.vaultKey)
        login.uris = [LoginUri(uri: try CipherEncryption.encrypt(string: "https://legacy.example", key: owner.vaultKey))]
        legacy.login = login
        legacy.fields = [CustomField(
            name: try CipherEncryption.encrypt(string: "PIN", key: owner.vaultKey),
            value: try CipherEncryption.encrypt(string: "4321", key: owner.vaultKey),
            type: .hidden
        )]
        let created = try await CipherAPI(client: owner.client).create(legacy)
        let legacyId = try XCTUnwrap(created.id)
        XCTAssertNil(created.key, "Precondition: the server must store the item without an item key")

        try await share(legacyId, from: owner, into: org)

        let seen = try await findCipher(legacyId, for: member)
        let ring = try await member.syncedKeyRing()
        XCTAssertNotNil(seen.key, "Sharing must give a keyless item an org-wrapped item key")
        XCTAssertEqual(try read(seen.name, of: seen, ring: ring), "Legacy")
        XCTAssertEqual(try read(seen.notes, of: seen, ring: ring), "old notes")
        XCTAssertEqual(try read(seen.login?.username, of: seen, ring: ring), "ada")
        XCTAssertEqual(try read(seen.login?.password, of: seen, ring: ring), "legacy-pass")
        XCTAssertEqual(try read(seen.login?.uris?.first?.uri, of: seen, ring: ring), "https://legacy.example")
        XCTAssertEqual(try read(seen.fields?.first?.value, of: seen, ring: ring), "4321")
    }

    /// Sharing a keyless item re-wraps its attachment keys. The server only applies
    /// those from `attachments2`; if that is missing, the member cannot open the file.
    func testMemberOpensAttachmentOfSharedLegacyItem() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()

        var legacy = Cipher(type: .secureNote)
        legacy.name = try CipherEncryption.encrypt(string: "With file", key: owner.vaultKey)
        legacy.secureNote = SecureNoteData(type: .generic)
        let created = try await CipherAPI(client: owner.client).create(legacy)
        let cipherId = try XCTUnwrap(created.id)

        let fileContents = Data("attachment payload \(UUID())".utf8)
        try await uploadAttachment(fileContents, named: "report.txt", to: cipherId, sealedWith: owner.vaultKey, by: owner)

        try await share(cipherId, from: owner, into: org)

        let seen = try await findCipher(cipherId, for: member)
        let ring = try await member.syncedKeyRing()
        let attachment = try XCTUnwrap(seen.attachments?.first)
        XCTAssertEqual(try read(attachment.fileName, of: seen, ring: ring), "report.txt")

        let downloaded = try await downloadAttachment(attachment, of: seen, ring: ring, as: member)
        XCTAssertEqual(downloaded, fileContents)
    }

    /// Server-side refusal is not the safety net here: Vaultwarden accepts a share
    /// with no collections, which strands the item. The client must refuse first.
    func testSharingWithoutCollectionsIsRefusedBeforeReachingTheServer() async throws {
        let (owner, _, org) = try await makeOrganizationWithMember()
        let created = try await CipherAPI(client: owner.client).create(
            try makeLogin(name: "Stay personal", password: "x", itemKey: nil, encryptedItemKey: nil, sealedWith: owner.vaultKey)
        )
        let cipher = try await findCipher(try XCTUnwrap(created.id), for: owner)
        let ring = try await owner.syncedKeyRing()

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(cipher, organizationId: org.id, collectionIds: [], keyRing: ring)
        )

        let unchanged = try await findCipher(try XCTUnwrap(created.id), for: owner)
        XCTAssertNil(unchanged.organizationId)
    }

    // MARK: - Permissions and edits

    func testReadOnlyCollectionIsReportedToMember() async throws {
        let owner = try await TestUser.register(on: serverURL, label: "owner")
        let member = try await TestUser.register(on: serverURL, label: "reader")
        let org = try await TestOrganization.create(by: owner)
        try await org.addMember(member, access: [.init(collectionId: org.defaultCollectionId, readOnly: true)])

        let collections = try await member.sync().collections ?? []
        let collection = try XCTUnwrap(collections.first { $0.id == org.defaultCollectionId })
        XCTAssertEqual(collection.readOnly, true)
        XCTAssertEqual(collection.organizationId, org.id)
    }

    /// A member with write access edits a shared item with the key ring's item
    /// key; the owner must still be able to read the result. This is the path that
    /// used to re-encrypt shared items with the personal key.
    func testMemberEditIsReadableByOwner() async throws {
        let (owner, member, org) = try await makeOrganizationWithMember()
        let ownerRing = try await owner.syncedKeyRing()

        let (itemKey, encryptedItemKey) = try OrganizationSharing.makeItemKey(forOrganization: org.id, keyRing: ownerRing)
        var cipher = try makeLogin(name: "Rotating", password: "v1", itemKey: itemKey, encryptedItemKey: encryptedItemKey)
        cipher.organizationId = org.id
        cipher.collectionIds = [org.defaultCollectionId]
        let created = try await CipherAPI(client: owner.client).create(cipher)
        let cipherId = try XCTUnwrap(created.id)

        var memberCopy = try await findCipher(cipherId, for: member)
        let memberRing = try await member.syncedKeyRing()
        let memberItemKey = try VaultCryptoFacade.itemKey(for: memberCopy, keyRing: memberRing)
        memberCopy.login?.password = try CipherEncryption.encrypt(string: "v2", key: memberItemKey)
        _ = try await CipherAPI(client: member.client).update(memberCopy)

        let ownerCopy = try await findCipher(cipherId, for: owner)
        let ownerRingAfter = try await owner.syncedKeyRing()
        XCTAssertEqual(try read(ownerCopy.login?.password, of: ownerCopy, ring: ownerRingAfter), "v2")
    }

    // MARK: - Helpers

    private func makeOrganizationWithMember() async throws -> (TestUser, TestUser, TestOrganization) {
        let owner = try await TestUser.register(on: serverURL, label: "owner")
        let member = try await TestUser.register(on: serverURL, label: "member")
        let org = try await TestOrganization.create(by: owner)
        try await org.addMember(member, access: [.init(collectionId: org.defaultCollectionId)])
        return (owner, member, org)
    }

    /// A login cipher. With an item key, fields are sealed with it; without one,
    /// with `sealedWith` directly (the pre-2023 layout).
    private func makeLogin(
        name: String,
        password: String,
        itemKey: SymmetricCryptoKey?,
        encryptedItemKey: EncString?,
        sealedWith baseKey: SymmetricCryptoKey? = nil
    ) throws -> Cipher {
        let fieldKey = try XCTUnwrap(itemKey ?? baseKey)
        var cipher = Cipher(type: .login)
        cipher.key = encryptedItemKey
        cipher.name = try CipherEncryption.encrypt(string: name, key: fieldKey)
        var login = LoginData()
        login.password = try CipherEncryption.encrypt(string: password, key: fieldKey)
        cipher.login = login
        return cipher
    }

    private func findCipher(_ id: String, for user: TestUser) async throws -> Cipher {
        let ciphers = try await user.sync().ciphers ?? []
        return try XCTUnwrap(ciphers.first { $0.id == id }, "\(user.email) should see cipher \(id)")
    }

    /// Decrypt one field exactly as the app would for this user.
    private func read(_ encString: EncString?, of cipher: Cipher, ring: VaultKeyRing) throws -> String {
        try XCTUnwrap(
            VaultCryptoFacade.decrypt(encString, itemKey: cipher.key, organizationId: cipher.organizationId, keyRing: ring),
            "Field did not decrypt with this user's keys"
        )
    }

    /// Share the owner's current copy of an item, as the app's Share action does.
    private func share(_ cipherId: String, from owner: TestUser, into org: TestOrganization) async throws {
        let current = try await findCipher(cipherId, for: owner)
        let prepared = try OrganizationSharing.prepareForSharing(
            current,
            organizationId: org.id,
            collectionIds: [org.defaultCollectionId],
            keyRing: try await owner.syncedKeyRing()
        )
        _ = try await CipherAPI(client: owner.client).share(prepared, collectionIds: [org.defaultCollectionId])
    }

    /// Upload a file in the app's attachment format, its key sealed under `baseKey`
    /// (the cipher's key for a keyless item).
    private func uploadAttachment(
        _ contents: Data,
        named fileName: String,
        to cipherId: String,
        sealedWith baseKey: SymmetricCryptoKey,
        by user: TestUser
    ) async throws {
        let attachmentKey = try SymmetricCryptoKey.generate()
        let encryptedName = try CipherEncryption.encrypt(string: fileName, key: baseKey).serialized()
        let payload = Data(try CipherEncryption.encrypt(data: contents, key: attachmentKey).serialized().utf8)

        let api = AttachmentAPI(client: user.client)
        let slot = try await api.requestUpload(
            cipherId: cipherId,
            fileName: encryptedName,
            fileSize: payload.count,
            key: try CipherEncryption.encrypt(data: attachmentKey.keyData, key: baseKey).serialized()
        )
        try await api.uploadFile(
            cipherId: cipherId,
            attachmentId: slot.attachmentId,
            data: payload,
            fileName: encryptedName,
            uploadURL: URL(string: slot.uploadURL),
            fileUploadType: slot.fileUploadType
        )
    }

    private func downloadAttachment(
        _ attachment: Attachment,
        of cipher: Cipher,
        ring: VaultKeyRing,
        as user: TestUser
    ) async throws -> Data {
        let itemKey = try VaultCryptoFacade.itemKey(for: cipher, keyRing: ring)
        let attachmentKey = try SymmetricCryptoKey(
            keyData: try CipherEncryption.decryptData(XCTUnwrap(attachment.key), key: itemKey)
        )
        let url = try XCTUnwrap(attachment.url.flatMap(URL.init(string:)))
        let payload = try await AttachmentAPI(client: user.client).download(url: url)
        let encrypted = try EncString(serialized: XCTUnwrap(String(data: payload, encoding: .utf8)))
        return try CipherEncryption.decryptData(encrypted, key: attachmentKey)
    }
}
