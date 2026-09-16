// Tests for organization key routing: which key an item decrypts with, and which
// memberships yield a usable key at all. Getting this wrong either shows shared
// items as blank or re-encrypts them with a key no other member holds.

import XCTest
import Foundation
import VaultCrypto
@testable import VaultModels

final class VaultKeyRingTests: XCTestCase {

    private func makeCipher(organizationId: String?) -> Cipher {
        var cipher = Cipher(type: .login)
        cipher.id = UUID().uuidString
        cipher.organizationId = organizationId
        return cipher
    }

    func testPersonalItemUsesVaultKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])

        XCTAssertEqual(ring.baseKey(for: makeCipher(organizationId: nil))?.keyData, vaultKey.keyData)
    }

    func testOrganizationItemUsesOrganizationKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let orgKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: ["org-1": orgKey])

        XCTAssertEqual(ring.baseKey(for: makeCipher(organizationId: "org-1"))?.keyData, orgKey.keyData)
    }

    /// The critical negative case: an unknown org must NOT fall back to the
    /// personal vault key.
    func testUnknownOrganizationHasNoKey() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey, organizationKeys: [:])

        XCTAssertNil(ring.baseKey(for: makeCipher(organizationId: "org-unknown")))
        XCTAssertFalse(ring.canDecrypt(organizationId: "org-unknown"))
        XCTAssertTrue(ring.canDecrypt(organizationId: nil))
    }

    func testEmptyOrganizationIdIsTreatedAsPersonal() throws {
        let vaultKey = try SymmetricCryptoKey.generate()
        let ring = VaultKeyRing(vaultKey: vaultKey)

        XCTAssertEqual(ring.baseKey(forOrganization: "")?.keyData, vaultKey.keyData)
    }
}

final class OrganizationKeyResolverTests: XCTestCase {

    /// An RSA key pair plus an org whose symmetric key is sealed to it, mirroring
    /// what the sync profile carries.
    private func makeSealedOrganization(
        id: String,
        status: Int? = OrganizationUserStatus.confirmed.rawValue,
        enabled: Bool = true,
        publicKey: Data
    ) throws -> (organization: Organization, key: SymmetricCryptoKey) {
        let orgKey = try SymmetricCryptoKey.generate()
        let sealed = try AsymmetricCrypto.encrypt(data: orgKey.keyData, publicKeyData: publicKey)

        var organization = Organization(id: id, name: "Org \(id)")
        organization.key = EncString(type: .rsa2048_OAEPSHA1_B64, iv: nil, ciphertext: sealed, mac: nil)
        organization.status = status
        organization.enabled = enabled
        return (organization, orgKey)
    }

    func testResolvesConfirmedMembershipKey() throws {
        let pair = try AsymmetricCrypto.generateRSAKeyPair()
        let sealed = try makeSealedOrganization(id: "org-1", publicKey: pair.publicKey)

        let result = OrganizationKeyResolver.resolve(
            organizations: [sealed.organization],
            privateKeyData: pair.privateKey
        )

        XCTAssertTrue(result.isComplete)
        XCTAssertEqual(result.keys["org-1"]?.keyData, sealed.key.keyData)
    }

    func testSkipsInvitedAndDisabledMembershipsWithoutFailing() throws {
        let pair = try AsymmetricCrypto.generateRSAKeyPair()
        var invited = Organization(id: "org-invited", name: "Invited")
        invited.status = OrganizationUserStatus.invited.rawValue
        var disabled = try makeSealedOrganization(id: "org-disabled", enabled: false, publicKey: pair.publicKey).organization
        disabled.enabled = false

        let result = OrganizationKeyResolver.resolve(
            organizations: [invited, disabled],
            privateKeyData: pair.privateKey
        )

        XCTAssertTrue(result.keys.isEmpty)
        XCTAssertTrue(result.isComplete, "A membership with no key yet is not a failure")
    }

    func testReportsFailureForConfirmedMembershipWithUnreadableKey() throws {
        let pair = try AsymmetricCrypto.generateRSAKeyPair()
        let otherPair = try AsymmetricCrypto.generateRSAKeyPair()
        // Sealed to somebody else's public key — this account cannot open it.
        let sealed = try makeSealedOrganization(id: "org-1", publicKey: otherPair.publicKey)

        let result = OrganizationKeyResolver.resolve(
            organizations: [sealed.organization],
            privateKeyData: pair.privateKey
        )

        XCTAssertTrue(result.keys.isEmpty)
        XCTAssertEqual(result.failures.count, 1)
        XCTAssertEqual(result.failures.first?.organizationId, "org-1")
    }

    func testNoPrivateKeyFailsEveryOrganization() throws {
        let pair = try AsymmetricCrypto.generateRSAKeyPair()
        let sealed = try makeSealedOrganization(id: "org-1", publicKey: pair.publicKey)

        let result = OrganizationKeyResolver.resolve(
            organizations: [sealed.organization],
            privateKeyData: nil
        )

        XCTAssertTrue(result.keys.isEmpty)
        XCTAssertEqual(result.failures.count, 1)
    }
}
