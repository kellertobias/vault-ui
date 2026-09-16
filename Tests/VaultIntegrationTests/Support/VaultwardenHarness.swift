// MARK: - VaultIntegrationTests/Support/VaultwardenHarness.swift
// Drives a real Vaultwarden: registering users, logging in, and setting up
// organizations — everything the app itself does not need to do but a test does.
//
// All key material is produced by the app's own crypto (`MasterKey`,
// `CipherEncryption`, `AsymmetricCrypto`), so a test passing here means the app's
// formats are what the server stores and what other clients will read.

import XCTest
import Foundation
import Security
import VaultCrypto
import VaultModels
@testable import VaultAPI

// MARK: - Environment

enum IntegrationEnvironment {

    /// The server under test, or a skip when none is configured.
    ///
    /// Integration tests only run when `VAULTWARDEN_URL` is set — normally by
    /// `scripts/test-integration.sh` — so a plain `swift test` stays offline. The
    /// server's certificate comes from a throwaway CA (`VAULTWARDEN_CA_CERT`),
    /// which is handed to the client instead of the system keychain.
    static func requireServer() throws -> URL {
        let environment = ProcessInfo.processInfo.environment
        guard let raw = environment["VAULTWARDEN_URL"], let url = URL(string: raw) else {
            throw XCTSkip("Set VAULTWARDEN_URL (see scripts/test-integration.sh) to run integration tests")
        }
        if let caPath = environment["VAULTWARDEN_CA_CERT"] {
            TestTrustAnchors.certificates = [try loadCertificate(atPath: caPath)]
        }
        return url
    }

    static var caCertificatePath: String? {
        ProcessInfo.processInfo.environment["VAULTWARDEN_CA_CERT"]
    }

    /// A PEM certificate from disk.
    static func loadCertificate(atPath path: String) throws -> SecCertificate {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        let base64 = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        let der = try XCTUnwrap(Data(base64Encoded: base64), "\(path) is not a PEM certificate")
        return try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData), "\(path) is not a certificate")
    }

    /// A unique address per call, so tests never collide on a shared server.
    static func uniqueEmail(_ label: String) -> String {
        "\(label)-\(UUID().uuidString.prefix(8).lowercased())@vault-ui.test"
    }
}

/// Base class that skips without a server and drops the test CA afterwards.
class VaultwardenIntegrationTestCase: XCTestCase {
    var serverURL: URL!

    override func setUpWithError() throws {
        serverURL = try IntegrationEnvironment.requireServer()
    }

    override func tearDown() {
        TestTrustAnchors.certificates = []
        super.tearDown()
    }
}

// MARK: - Users

/// A registered, logged-in Vaultwarden user and its decrypted keys.
struct TestUser: Sendable {
    let email: String
    let userId: String
    let client: APIClient
    let vaultKey: SymmetricCryptoKey
    /// Account RSA private key, PKCS#8 — decrypted from what the server returned.
    let privateKey: Data
    /// Account RSA public key, SPKI.
    let publicKey: Data

    static let password = "correct horse battery staple"
    static let kdf = KDFConfig(type: .pbkdf2, iterations: 600_000)

    /// Register a fresh account, then log in through the app's real login path.
    static func register(on serverURL: URL, label: String) async throws -> TestUser {
        let email = IntegrationEnvironment.uniqueEmail(label)
        let account = Account(email: email, serverURL: serverURL, kdfConfig: kdf)
        let client = APIClient(account: account)

        // Keys exactly as an official client creates them: a user key sealed with
        // the stretched master key, and an RSA pair whose private half is sealed
        // with the user key.
        let masterKey = try MasterKey.derive(password: password, email: email, kdfConfig: kdf)
        let userKey = try SymmetricCryptoKey.generate()
        let keyPair = try AsymmetricCrypto.generateRSAKeyPair()

        let registration = RegisterRequest(
            email: email,
            name: label,
            masterPasswordHash: try MasterPasswordHash.compute(masterKey: masterKey, password: password),
            masterPasswordHint: nil,
            key: try CipherEncryption.encrypt(data: userKey.keyData, key: masterKey.stretch()).serialized(),
            kdf: kdf.type.rawValue,
            kdfIterations: Int(kdf.iterations),
            keys: .init(
                publicKey: keyPair.publicKey.base64EncodedString(),
                encryptedPrivateKey: try CipherEncryption.encrypt(data: keyPair.privateKey, key: userKey).serialized()
            )
        )
        let _: EmptyResponse = try await client.post(
            path: "accounts/register",
            body: registration,
            baseURL: account.identityURL,
            authenticated: false
        )

        return try await login(email: email, serverURL: serverURL)
    }

    /// Log in and decrypt the account keys the same way `SessionManager` does.
    static func login(email: String, serverURL: URL) async throws -> TestUser {
        let account = Account(email: email, serverURL: serverURL, kdfConfig: kdf)
        let client = APIClient(account: account)
        let masterKey = try MasterKey.derive(password: password, email: email, kdfConfig: kdf)

        let result = try await AuthService(client: client).login(.init(
            email: email,
            masterPasswordHash: try MasterPasswordHash.compute(masterKey: masterKey, password: password)
        ))

        let protectedKey = try EncString(serialized: XCTUnwrap(result.tokens.encryptedKey))
        let vaultKey = try CipherEncryption.decryptUserKey(protectedKey, masterKey: masterKey)

        let encryptedPrivateKey = try EncString(serialized: XCTUnwrap(result.tokens.encryptedPrivateKey))
        let privateKey = try CipherEncryption.decryptData(encryptedPrivateKey, key: vaultKey)

        let profile: ProfileResponse = try await client.get(path: "accounts/profile")
        let publicKeyResponse: PublicKeyResponse = try await client.get(path: "users/\(profile.id)/public-key")

        return TestUser(
            email: email,
            userId: profile.id,
            client: client,
            vaultKey: vaultKey,
            privateKey: privateKey,
            publicKey: try XCTUnwrap(Data(base64Encoded: publicKeyResponse.publicKey))
        )
    }

    func sync() async throws -> SyncResponse {
        try await SyncAPI(client: client).fullSync()
    }

    /// The key ring this user's session would build from a sync — the same
    /// resolver the app runs on unlock.
    func keyRing(from sync: SyncResponse) -> (ring: VaultKeyRing, failures: [String]) {
        let result = OrganizationKeyResolver.resolve(
            organizations: sync.profile?.organizations ?? [],
            privateKeyData: privateKey
        )
        return (
            VaultKeyRing(vaultKey: vaultKey, organizationKeys: result.keys),
            result.failures.map { "\($0.organizationId): \($0.error.localizedDescription)" }
        )
    }

    func syncedKeyRing() async throws -> VaultKeyRing {
        let resolved = keyRing(from: try await sync())
        XCTAssertEqual(resolved.failures, [], "Every organization key should unwrap")
        return resolved.ring
    }
}

// MARK: - Organizations

/// An organization created by a test user, with its plaintext key.
struct TestOrganization: Sendable {
    let id: String
    let key: SymmetricCryptoKey
    let owner: TestUser
    /// The collection Vaultwarden creates along with the organization.
    let defaultCollectionId: String

    struct CollectionAccess: Sendable {
        let collectionId: String
        var readOnly = false
        var hidePasswords = false
    }

    /// Create an organization owned by `owner`, sealing its key to the owner the
    /// way an official client does.
    static func create(by owner: TestUser, name: String = "Test Org") async throws -> TestOrganization {
        let orgKey = try SymmetricCryptoKey.generate()
        let orgKeyPair = try AsymmetricCrypto.generateRSAKeyPair()

        let request = CreateOrganizationRequest(
            name: name,
            billingEmail: owner.email,
            collectionName: try CipherEncryption.encrypt(string: "Default", key: orgKey).serialized(),
            key: try sealed(orgKey, to: owner.publicKey),
            keys: .init(
                publicKey: orgKeyPair.publicKey.base64EncodedString(),
                encryptedPrivateKey: try CipherEncryption.encrypt(data: orgKeyPair.privateKey, key: orgKey).serialized()
            ),
            planType: 0
        )
        let created: IdResponse = try await owner.client.post(path: "organizations", body: request)

        let collections: ListResponse<IdResponse> = try await owner.client.get(
            path: "organizations/\(created.id)/collections"
        )
        let defaultCollection = try XCTUnwrap(collections.data.first, "Vaultwarden should create a default collection")

        return TestOrganization(
            id: created.id,
            key: orgKey,
            owner: owner,
            defaultCollectionId: defaultCollection.id
        )
    }

    /// Add another collection; returns its ID.
    func addCollection(named name: String) async throws -> String {
        let created: IdResponse = try await owner.client.post(
            path: "organizations/\(id)/collections",
            body: CreateCollectionRequest(
                name: try CipherEncryption.encrypt(string: name, key: key).serialized(),
                groups: [],
                users: []
            )
        )
        return created.id
    }

    /// Invite `member` and confirm them, granting the given collections.
    ///
    /// Confirming seals the org key to the member's public key — the step that
    /// makes the key appear in the member's sync profile.
    func addMember(_ member: TestUser, access: [CollectionAccess]) async throws {
        let membershipId = try await invite(member, access: access)

        let memberPublicKey: PublicKeyResponse = try await owner.client.get(path: "users/\(member.userId)/public-key")
        try await owner.client.postNoResponse(
            path: "organizations/\(id)/users/\(membershipId)/confirm",
            body: ConfirmRequest(
                key: try Self.sealed(key, to: XCTUnwrap(Data(base64Encoded: memberPublicKey.publicKey)))
            )
        )
    }

    /// Invite `member` but stop before confirming, leaving a membership with no key.
    func inviteWithoutConfirming(_ member: TestUser) async throws {
        _ = try await invite(member, access: [.init(collectionId: defaultCollectionId)])
    }

    /// Invite `member`; returns the membership ID.
    ///
    /// With mail disabled, Vaultwarden accepts an invite for an existing user
    /// immediately, so no invite link has to be followed.
    private func invite(_ member: TestUser, access: [CollectionAccess]) async throws -> String {
        try await owner.client.postNoResponse(
            path: "organizations/\(id)/users/invite",
            body: InviteRequest(
                emails: [member.email],
                type: 2, // User
                collections: access.map {
                    .init(id: $0.collectionId, readOnly: $0.readOnly, hidePasswords: $0.hidePasswords, manage: false)
                },
                groups: [],
                permissions: [:]
            )
        )

        let members: ListResponse<MemberResponse> = try await owner.client.get(path: "organizations/\(id)/users")
        let membership = try XCTUnwrap(
            members.data.first { $0.userId == member.userId },
            "Invited member should be listed"
        )
        return membership.id
    }

    /// An org key sealed to one user's RSA public key, as a type-4 EncString.
    static func sealed(_ key: SymmetricCryptoKey, to publicKey: Data) throws -> String {
        let ciphertext = try AsymmetricCrypto.encrypt(data: key.keyData, publicKeyData: publicKey)
        return EncString(type: .rsa2048_OAEPSHA1_B64, iv: nil, ciphertext: ciphertext, mac: nil).serialized()
    }
}

// MARK: - Wire types (test-only endpoints)

private struct RegisterRequest: Encodable {
    struct Keys: Encodable {
        let publicKey: String
        let encryptedPrivateKey: String
    }

    let email: String
    let name: String
    let masterPasswordHash: String
    let masterPasswordHint: String?
    let key: String
    let kdf: Int
    let kdfIterations: Int
    let keys: Keys
}

private struct CreateOrganizationRequest: Encodable {
    struct Keys: Encodable {
        let publicKey: String
        let encryptedPrivateKey: String
    }

    let name: String
    let billingEmail: String
    let collectionName: String
    let key: String
    let keys: Keys
    let planType: Int
}

private struct CreateCollectionRequest: Encodable {
    let name: String
    let groups: [String]
    let users: [String]
}

private struct InviteRequest: Encodable {
    struct Collection: Encodable {
        let id: String
        let readOnly: Bool
        let hidePasswords: Bool
        let manage: Bool
    }

    let emails: [String]
    let type: Int
    let collections: [Collection]
    let groups: [String]
    let permissions: [String: Bool]
}

private struct ConfirmRequest: Encodable {
    let key: String
}

/// Decodes any body, including an empty JSON object.
struct EmptyResponse: Decodable, Sendable {}

private struct IdResponse: Decodable, Sendable {
    let id: String
}

private struct ListResponse<Item: Decodable & Sendable>: Decodable, Sendable {
    let data: [Item]
}

private struct MemberResponse: Decodable, Sendable {
    let id: String
    let userId: String?
}

private struct ProfileResponse: Decodable, Sendable {
    let id: String
}

private struct PublicKeyResponse: Decodable, Sendable {
    let publicKey: String
}
