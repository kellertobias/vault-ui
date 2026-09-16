// Tests for creating shared items and moving personal items into an organization.
//
// The property that matters throughout: after sharing, everything the item is
// made of must be reachable from the *organization* key alone. If any part still
// needs the personal vault key, other members get an unreadable entry.

import XCTest
import Foundation
import VaultModels
import VaultCrypto
@testable import VaultServices

final class OrganizationSharingTests: XCTestCase {

    private var vaultKey: SymmetricCryptoKey!
    private var orgKey: SymmetricCryptoKey!
    private var keyRing: VaultKeyRing!

    override func setUpWithError() throws {
        vaultKey = try SymmetricCryptoKey.generate()
        orgKey = try SymmetricCryptoKey.generate()
        keyRing = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])
    }

    // MARK: - New shared items

    func testNewPersonalItemKeyIsWrappedUnderVaultKey() throws {
        let made = try OrganizationSharing.makeItemKey(forOrganization: nil, keyRing: keyRing)

        let unwrapped = try CipherEncryption.decryptData(made.encryptedItemKey, key: vaultKey)
        XCTAssertEqual(unwrapped, made.itemKey.keyData)
    }

    func testNewSharedItemKeyIsWrappedUnderOrganizationKey() throws {
        let made = try OrganizationSharing.makeItemKey(forOrganization: "org-1", keyRing: keyRing)

        let unwrapped = try CipherEncryption.decryptData(made.encryptedItemKey, key: orgKey)
        XCTAssertEqual(unwrapped, made.itemKey.keyData)

        XCTAssertThrowsError(
            try CipherEncryption.decryptData(made.encryptedItemKey, key: vaultKey),
            "An org item key must not be readable with the personal vault key"
        )
    }

    func testNewSharedItemKeyRequiresAKnownOrganization() throws {
        XCTAssertThrowsError(
            try OrganizationSharing.makeItemKey(forOrganization: "org-unknown", keyRing: keyRing)
        )
    }

    // MARK: - Moving a personal item into an organization

    /// A modern item keeps its item key; only the wrapper changes. The ciphertext
    /// of every field must be byte-identical, since nothing was re-encrypted.
    func testItemWithItemKeyIsRewrappedWithoutTouchingFields() throws {
        let (itemKey, encryptedItemKey) = try VaultCryptoFacade.generateItemKey(vaultKey: vaultKey)
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.key = encryptedItemKey
        cipher.name = try CipherEncryption.encrypt(string: "Shared login", key: itemKey)
        var login = LoginData()
        login.password = try CipherEncryption.encrypt(string: "hunter2", key: itemKey)
        cipher.login = login

        let shared = try OrganizationSharing.prepareForSharing(
            cipher,
            organizationId: "org-1",
            collectionIds: ["col-1"],
            keyRing: keyRing
        )

        XCTAssertEqual(shared.name?.serialized(), cipher.name?.serialized())
        XCTAssertEqual(shared.login?.password?.serialized(), cipher.login?.password?.serialized())
        XCTAssertEqual(shared.organizationId, "org-1")
        XCTAssertEqual(shared.collectionIds, ["col-1"])

        // An org member holding only the org key can reach the fields.
        let unwrappedItemKey = try SymmetricCryptoKey(
            keyData: try CipherEncryption.decryptData(XCTUnwrap(shared.key), key: orgKey)
        )
        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(shared.name), key: unwrappedItemKey), "Shared login")
        XCTAssertEqual(unwrappedItemKey.keyData, itemKey.keyData, "The item key itself must not change")
    }

    /// A pre-2023 item has no item key, so every field has to move onto a new one.
    func testKeylessItemGetsNewItemKeyAndReencryptedFields() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.name = try CipherEncryption.encrypt(string: "Legacy login", key: vaultKey)
        var login = LoginData()
        login.username = try CipherEncryption.encrypt(string: "ada", key: vaultKey)
        login.password = try CipherEncryption.encrypt(string: "hunter2", key: vaultKey)
        login.uris = [LoginUri(uri: try CipherEncryption.encrypt(string: "https://example.com", key: vaultKey))]
        cipher.login = login
        cipher.fields = [CustomField(
            name: try CipherEncryption.encrypt(string: "PIN", key: vaultKey),
            value: try CipherEncryption.encrypt(string: "1234", key: vaultKey)
        )]

        let shared = try OrganizationSharing.prepareForSharing(
            cipher,
            organizationId: "org-1",
            collectionIds: ["col-1"],
            keyRing: keyRing
        )

        let itemKey = try SymmetricCryptoKey(
            keyData: try CipherEncryption.decryptData(XCTUnwrap(shared.key), key: orgKey)
        )
        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(shared.name), key: itemKey), "Legacy login")
        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(shared.login?.username), key: itemKey), "ada")
        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(shared.login?.password), key: itemKey), "hunter2")
        XCTAssertEqual(
            try CipherEncryption.decryptString(XCTUnwrap(shared.login?.uris?.first?.uri), key: itemKey),
            "https://example.com"
        )
        XCTAssertEqual(try CipherEncryption.decryptString(XCTUnwrap(shared.fields?.first?.value), key: itemKey), "1234")
    }

    /// The completeness guard: walk the shared item's JSON and assert that nothing
    /// in it can still be opened with the personal vault key. This fails if a new
    /// encrypted field is added to the model without being added to the rewrap.
    func testNothingInASharedItemStillNeedsThePersonalVaultKey() throws {
        let cipher = try fullyPopulatedKeylessCipher()

        let shared = try OrganizationSharing.prepareForSharing(
            cipher,
            organizationId: "org-1",
            collectionIds: ["col-1"],
            keyRing: keyRing
        )

        let data = try JSONEncoder().encode(shared)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data))

        var checked = 0
        for value in Self.allStrings(in: json) {
            guard let encString = try? EncString(serialized: value) else { continue }
            checked += 1
            XCTAssertThrowsError(
                try CipherEncryption.decryptData(encString, key: vaultKey),
                "\(value.prefix(12))… still decrypts with the personal vault key"
            )
        }
        XCTAssertGreaterThan(checked, 20, "Expected the populated fixture to contain many encrypted fields")
    }

    // MARK: - Attachments

    func testAttachmentKeyIsRewrappedOntoTheNewItemKey() throws {
        let attachmentKey = try SymmetricCryptoKey.generate()
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.name = try CipherEncryption.encrypt(string: "With file", key: vaultKey)
        cipher.attachments = [Attachment(
            id: "att-1",
            fileName: try CipherEncryption.encrypt(string: "secret.pdf", key: vaultKey),
            key: try CipherEncryption.encrypt(data: attachmentKey.keyData, key: vaultKey)
        )]

        let shared = try OrganizationSharing.prepareForSharing(
            cipher,
            organizationId: "org-1",
            collectionIds: ["col-1"],
            keyRing: keyRing
        )

        let itemKey = try SymmetricCryptoKey(
            keyData: try CipherEncryption.decryptData(XCTUnwrap(shared.key), key: orgKey)
        )
        let movedKey = try CipherEncryption.decryptData(XCTUnwrap(shared.attachments?.first?.key), key: itemKey)
        XCTAssertEqual(movedKey, attachmentKey.keyData, "The file's own key must survive unchanged")
        XCTAssertEqual(
            try CipherEncryption.decryptString(XCTUnwrap(shared.attachments?.first?.fileName), key: itemKey),
            "secret.pdf"
        )
    }

    /// A legacy attachment with no key of its own is tied to the personal vault
    /// key; re-keying the cipher cannot fix that, so the share must be refused.
    func testAttachmentWithoutKeyIsRefused() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.name = try CipherEncryption.encrypt(string: "With legacy file", key: vaultKey)
        cipher.attachments = [Attachment(
            id: "att-1",
            fileName: try CipherEncryption.encrypt(string: "old.pdf", key: vaultKey),
            key: nil
        )]

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(
                cipher,
                organizationId: "org-1",
                collectionIds: ["col-1"],
                keyRing: keyRing
            )
        )
    }

    // MARK: - Guards

    func testRefusesAlreadySharedItem() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.organizationId = "org-1"

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(
                cipher, organizationId: "org-1", collectionIds: ["col-1"], keyRing: keyRing
            )
        )
    }

    func testRefusesEmptyCollectionList() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(
                cipher, organizationId: "org-1", collectionIds: [], keyRing: keyRing
            )
        )
    }

    func testRefusesUnknownOrganization() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(
                cipher, organizationId: "org-unknown", collectionIds: ["col-1"], keyRing: keyRing
            )
        )
    }

    func testRefusesItemThatWasNeverSaved() throws {
        let cipher = Cipher(type: .login)

        XCTAssertThrowsError(
            try OrganizationSharing.prepareForSharing(
                cipher, organizationId: "org-1", collectionIds: ["col-1"], keyRing: keyRing
            )
        )
    }

    // MARK: - Helpers

    /// A cipher with every encrypted field the model has, all under the vault key.
    private func fullyPopulatedKeylessCipher() throws -> Cipher {
        func enc(_ value: String) throws -> EncString {
            try CipherEncryption.encrypt(string: value, key: vaultKey)
        }

        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.name = try enc("Everything")
        cipher.notes = try enc("notes")

        var login = LoginData()
        login.username = try enc("ada")
        login.password = try enc("hunter2")
        login.totp = try enc("JBSWY3DPEHPK3PXP")
        login.uris = [LoginUri(uri: try enc("https://example.com"))]
        var credential = Fido2Credential()
        credential.credentialId = try enc("cred-id")
        credential.keyType = try enc("public-key")
        credential.keyAlgorithm = try enc("ECDSA")
        credential.keyCurve = try enc("P-256")
        credential.keyValue = try enc("key-value")
        credential.rpId = try enc("example.com")
        credential.rpName = try enc("Example")
        credential.userHandle = try enc("user-handle")
        credential.userName = try enc("ada")
        credential.userDisplayName = try enc("Ada L")
        credential.discoverable = try enc("true")
        credential.counter = try enc("0")
        login.fido2Credentials = [credential]
        cipher.login = login

        cipher.card = CardData(
            cardholderName: try enc("Ada"),
            brand: try enc("Visa"),
            number: try enc("4111111111111111"),
            expMonth: try enc("12"),
            expYear: try enc("2030"),
            code: try enc("123")
        )

        var identity = IdentityData()
        identity.title = try enc("Dr")
        identity.firstName = try enc("Ada")
        identity.middleName = try enc("M")
        identity.lastName = try enc("Lovelace")
        identity.address1 = try enc("1 Road")
        identity.address2 = try enc("Apt 2")
        identity.address3 = try enc("Block C")
        identity.city = try enc("London")
        identity.state = try enc("London")
        identity.postalCode = try enc("E1")
        identity.country = try enc("UK")
        identity.company = try enc("Analytical")
        identity.email = try enc("ada@example.com")
        identity.phone = try enc("555")
        identity.ssn = try enc("000")
        identity.username = try enc("ada")
        identity.passportNumber = try enc("P1")
        identity.licenseNumber = try enc("L1")
        cipher.identity = identity

        cipher.sshKey = SSHKeyData(
            privateKey: try enc("PRIVATE"),
            publicKey: try enc("PUBLIC"),
            keyFingerprint: try enc("SHA256:abc")
        )

        cipher.fields = [CustomField(name: try enc("PIN"), value: try enc("1234"))]
        cipher.passwordHistory = [PasswordHistoryEntry(password: try enc("old"), lastUsedDate: Date())]
        cipher.attachments = [Attachment(
            id: "att-1",
            fileName: try enc("secret.pdf"),
            key: try CipherEncryption.encrypt(data: try SymmetricCryptoKey.generate().keyData, key: vaultKey)
        )]
        return cipher
    }

    /// Every string value anywhere in a decoded JSON tree.
    private static func allStrings(in json: Any) -> [String] {
        switch json {
        case let string as String:
            return [string]
        case let array as [Any]:
            return array.flatMap { allStrings(in: $0) }
        case let object as [String: Any]:
            return object.values.flatMap { allStrings(in: $0) }
        default:
            return []
        }
    }
}
