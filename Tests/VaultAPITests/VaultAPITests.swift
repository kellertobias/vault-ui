import XCTest
@testable import VaultAPI
@testable import VaultModels
import VaultCrypto

final class VaultAPITests: XCTestCase {

    func testAPIClientCreation() throws {
        let account = Account(
            email: "test@example.com",
            serverURL: URL(string: "https://vault.example.com")!,
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 600_000)
        )

        // Verify account URLs are constructed correctly
        XCTAssertEqual(
            account.apiURL.absoluteString,
            "https://vault.example.com/api"
        )
        XCTAssertEqual(
            account.identityURL.absoluteString,
            "https://vault.example.com/identity"
        )
    }

    func testAuthTokensCodable() throws {
        let tokens = AuthTokens(
            accessToken: "test-token",
            refreshToken: "refresh-token",
            expiresIn: 3600,
            encryptedKey: "2.xxx|yyy|zzz",
            encryptedPrivateKey: "2.aaa|bbb|ccc"
        )

        let encoded = try JSONEncoder().encode(tokens)
        let decoded = try JSONDecoder().decode(AuthTokens.self, from: encoded)

        XCTAssertEqual(decoded.accessToken, "test-token")
        XCTAssertEqual(decoded.refreshToken, "refresh-token")
        XCTAssertEqual(decoded.expiresIn, 3600)
        XCTAssertEqual(decoded.encryptedKey, "2.xxx|yyy|zzz")
    }

    func testAccountEquatable() {
        let url = URL(string: "https://vault.example.com")!
        let a1 = Account(id: "1", email: "a@b.com", serverURL: url)
        let a2 = Account(id: "1", email: "a@b.com", serverURL: url)
        let a3 = Account(id: "2", email: "c@d.com", serverURL: url)

        XCTAssertEqual(a1, a2)
        XCTAssertNotEqual(a1, a3)
    }
}
