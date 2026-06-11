import XCTest
@testable import VaultModels

final class AccountLabelResolverTests: XCTestCase {

    private func source(
        id: String,
        shortName: String? = nil,
        alias: String? = nil,
        host: String? = nil,
        email: String
    ) -> AccountLabelSource {
        AccountLabelSource(accountId: id, shortName: shortName, alias: alias, serverHost: host, email: email)
    }

    // MARK: - Chain order

    func testShortNameWinsOverEverything() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", shortName: "Work", alias: "Company", host: "vault.example.com", email: "me@example.com"),
            source(id: "b", host: "vault.other.com", email: "me@other.com"),
        ])
        XCTAssertEqual(labels["a"], "Work")
        XCTAssertEqual(labels["b"], "other.com")
    }

    func testAliasUsedWhenNoShortName() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", alias: "Private", host: "vault.example.com", email: "me@example.com"),
        ])
        XCTAssertEqual(labels["a"], "Private")
    }

    func testRegistrableDomainBeforeHostname() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", host: "vault.example.com", email: "me@example.com"),
        ])
        XCTAssertEqual(labels["a"], "example.com")
    }

    func testBlankShortNameSkipped() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", shortName: "  ", host: "vault.example.com", email: "me@example.com"),
        ])
        XCTAssertEqual(labels["a"], "example.com")
    }

    // MARK: - Uniqueness

    func testSameServerTwoUsersFallsThroughToEmail() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", host: "vault.example.com", email: "alice@example.com"),
            source(id: "b", host: "vault.example.com", email: "bob@example.com"),
        ])
        // Domain and hostname collide between the two; email is the first unique candidate.
        XCTAssertEqual(labels["a"], "alice@example.com")
        XCTAssertEqual(labels["b"], "bob@example.com")
    }

    func testDuplicateShortNamesAreNotUsed() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", shortName: "Vault", host: "vault.one.com", email: "me@one.com"),
            source(id: "b", shortName: "Vault", host: "vault.two.com", email: "me@two.com"),
        ])
        XCTAssertEqual(labels["a"], "one.com")
        XCTAssertEqual(labels["b"], "two.com")
    }

    func testShortNameClaimBlocksLaterCandidateWithSameValue() {
        // "a" claims "example.com" as short name; "b" must not also resolve to it.
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", shortName: "example.com", host: "vault.other.com", email: "me@other.com"),
            source(id: "b", host: "vault.example.com", email: "me@example.com"),
        ])
        XCTAssertEqual(labels["a"], "example.com")
        XCTAssertEqual(labels["b"], "vault.example.com")
    }

    func testSameEmailTwoServersUsesDomains() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", host: "vault.one.com", email: "me@same.com"),
            source(id: "b", host: "vault.two.com", email: "me@same.com"),
        ])
        XCTAssertEqual(labels["a"], "one.com")
        XCTAssertEqual(labels["b"], "two.com")
    }

    func testTotalCollisionFallsBackToEmailHostPair() {
        // Same email, same host: every chain candidate collides.
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", host: "vault.example.com", email: "me@example.com"),
            source(id: "b", host: "vault.example.com", email: "me@example.com"),
        ])
        XCTAssertEqual(Set(labels.values).count, 2, "labels must still be unique: \(labels)")
        XCTAssertTrue(labels.values.allSatisfy { $0.contains("me@example.com") })
    }

    func testSingleAccountUsesDomain() {
        let labels = AccountLabelResolver.resolveLabels(for: [
            source(id: "a", host: "bitwarden.mycorp.de", email: "me@mycorp.de"),
        ])
        XCTAssertEqual(labels["a"], "mycorp.de")
    }

    // MARK: - Registrable domain

    func testRegistrableDomainPlain() {
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "vault.example.com"), "example.com")
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "example.com"), "example.com")
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "a.b.example.com"), "example.com")
    }

    func testRegistrableDomainCommonSLD() {
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "vault.example.co.uk"), "example.co.uk")
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "vault.example.com.au"), "example.com.au")
    }

    func testRegistrableDomainIPAddressUntouched() {
        XCTAssertEqual(AccountLabelResolver.registrableDomain(of: "192.168.1.10"), "192.168.1.10")
    }

    // MARK: - Palette index assignment

    func testNextIndexPicksLowestUnused() {
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: []), 0)
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: [0]), 1)
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: [0, 2]), 1)
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: [1, 0, 3]), 2)
    }

    func testNextIndexWhenExhaustedPicksLeastUsed() {
        let all = Array(0..<AccountAvatarPalette.count)
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: all), 0)
        XCTAssertEqual(AccountAvatarPalette.nextIndex(usedIndices: all + [0]), 1)
    }
}
