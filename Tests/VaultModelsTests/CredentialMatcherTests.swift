import XCTest
@testable import VaultModels

final class CredentialMatcherTests: XCTestCase {

    // MARK: - Domain rule

    func testExactHostMatches() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "https://example.com"))
        XCTAssertEqual(
            CredentialMatcher.matchQuality(storedURI: "https://example.com", siteIdentifier: "https://example.com"),
            .exactMatch
        )
    }

    func testSubdomainOfStoredDomainMatches() {
        // auth.example.com (site) matches a credential stored for example.com
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "https://auth.example.com"))
        XCTAssertEqual(
            CredentialMatcher.matchQuality(storedURI: "example.com", siteIdentifier: "auth.example.com"),
            .domainMatch
        )
    }

    func testSiteIsNotSubdomainOfStoredSubdomain() {
        // Credential stored for blog.example.com must NOT match auth.example.com
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://blog.example.com", siteIdentifier: "https://auth.example.com"))
    }

    // MARK: - Phishing / look-alike origins (the Vuln 1 class)

    func testLookalikeSuffixDomainDoesNotMatch() {
        // The classic prefix/suffix-confusion attack.
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://paypal.com", siteIdentifier: "https://paypal.com.evil.com/login"))
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "paypal.com", siteIdentifier: "xpaypal.com"))
    }

    func testUserinfoSpoofDoesNotMatch() {
        // host is evil.com, not paypal.com
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://paypal.com", siteIdentifier: "https://paypal.com@evil.com/"))
    }

    func testUnrelatedDomainDoesNotMatch() {
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "https://example.org"))
    }

    // MARK: - Protocol rule

    func testHttpsSecretRejectsHttpSite() {
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "http://example.com"))
    }

    func testHttpSecretAllowsHttpsSite() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "http://example.com", siteIdentifier: "https://example.com"))
    }

    func testSchemelessSecretAllowsAnyProtocol() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "example.com", siteIdentifier: "http://example.com"))
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "example.com", siteIdentifier: "https://example.com"))
    }

    func testSchemelessSiteIdentifierNotDowngradeChecked() {
        // A domain-type identifier carries no scheme; an https secret should still match.
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "example.com"))
    }

    // MARK: - Path rule

    func testNoSecretPathAllowsAnyPath() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: "https://example.com/anything/here"))
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com/", siteIdentifier: "https://example.com/anything"))
    }

    func testSecretPathRequiresSubPath() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com/app", siteIdentifier: "https://example.com/app"))
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://example.com/app", siteIdentifier: "https://example.com/app/home"))
    }

    func testSecretPathRejectsNonBoundaryPrefix() {
        // "/app" must not match "/application"
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://example.com/app", siteIdentifier: "https://example.com/application"))
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://example.com/app", siteIdentifier: "https://example.com/other"))
    }

    // MARK: - Wildcards

    func testWildcardMatchesSubdomains() {
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://*.example.com", siteIdentifier: "https://auth.example.com"))
        XCTAssertTrue(CredentialMatcher.matches(storedURI: "https://*.example.com", siteIdentifier: "https://example.com"))
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://*.example.com", siteIdentifier: "https://example.org"))
    }

    // MARK: - Best match across multiple URIs

    func testBestMatchQualityPicksStrongest() {
        let uris = ["https://other.com", "https://example.com", "https://sub.example.com"]
        XCTAssertEqual(
            CredentialMatcher.bestMatchQuality(storedURIs: uris, siteIdentifier: "https://example.com"),
            .exactMatch
        )
    }

    func testEmptyAndGarbageInputs() {
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "", siteIdentifier: "https://example.com"))
        XCTAssertFalse(CredentialMatcher.matches(storedURI: "https://example.com", siteIdentifier: ""))
    }
}
