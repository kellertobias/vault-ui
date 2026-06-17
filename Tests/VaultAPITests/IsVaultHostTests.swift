// Tests for APIClient.isVaultHost — the guard that prevents the bearer token
// from being attached to server-supplied external URLs (e.g. S3/Azure blob
// storage for attachments). A regression here leaks the access token to an
// arbitrary host, so it's worth pinning explicitly.

import XCTest
@testable import VaultAPI
@testable import VaultModels
import VaultCrypto

final class IsVaultHostTests: XCTestCase {

    private func makeClient(server: String) -> APIClient {
        let account = Account(
            email: "user@example.com",
            serverURL: URL(string: server)!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )
        return APIClient(account: account)
    }

    func testMatchesConfiguredHostOverHTTPS() {
        let client = makeClient(server: "https://vault.example.com")
        XCTAssertTrue(client.isVaultHost(URL(string: "https://vault.example.com/api/ciphers/1/attachment/x")!))
    }

    func testHostMatchIsCaseInsensitive() {
        let client = makeClient(server: "https://vault.example.com")
        XCTAssertTrue(client.isVaultHost(URL(string: "https://VAULT.Example.COM/api")!))
    }

    func testRejectsExternalBlobHost() {
        let client = makeClient(server: "https://vault.example.com")
        // Server-supplied attachment URL pointing at external storage — token must NOT go here.
        XCTAssertFalse(client.isVaultHost(URL(string: "https://my-bucket.s3.amazonaws.com/abc")!))
        XCTAssertFalse(client.isVaultHost(URL(string: "https://blob.core.windows.net/abc")!))
    }

    func testRejectsLookAlikeSuffixHost() {
        let client = makeClient(server: "https://vault.example.com")
        XCTAssertFalse(client.isVaultHost(URL(string: "https://vault.example.com.evil.com/x")!))
        XCTAssertFalse(client.isVaultHost(URL(string: "https://evilvault.example.com/x")!))
    }

    func testRejectsNonHTTPSEvenForCorrectHost() {
        let client = makeClient(server: "https://vault.example.com")
        XCTAssertFalse(client.isVaultHost(URL(string: "http://vault.example.com/api")!))
    }
}
