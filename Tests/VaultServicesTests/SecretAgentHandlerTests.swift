// Characterization tests for SecretAgentHandler.
//
// These pin the current observable behavior of the CLI secret agent — env-file
// rendering (`extend`) and slug lookup (`get`) — so the upcoming decomposition
// of VaultServices can be verified to preserve behavior. They also guard the
// shell-injection hardening (key validation + single-quote escaping).

import XCTest
import VaultModels
import VaultCrypto
@testable import VaultServices

final class SecretAgentHandlerTests: XCTestCase {

    // MARK: - Helpers

    private func makeHandler(
        ciphers: [(cipher: Cipher, key: SymmetricCryptoKey)] = []
    ) -> SecretAgentHandler {
        SecretAgentHandler(cipherProvider: { _ in ciphers })
    }

    private func send(_ request: SecretRequest, to handler: SecretAgentHandler) async throws -> SecretResponse {
        let data = try JSONEncoder().encode(request)
        let responseData = await handler.processRequest(data)
        return try JSONDecoder().decode(SecretResponse.self, from: responseData)
    }

    private func extend(_ env: String, _ handler: SecretAgentHandler) async throws -> SecretResponse {
        try await send(SecretRequest(type: "extend", envContent: env), to: handler)
    }

    /// Build a login cipher carrying a `vaultui-slug` field, encrypted under a fresh key.
    private func makeSluggedLogin(
        slug: String,
        username: String,
        password: String
    ) throws -> (cipher: Cipher, key: SymmetricCryptoKey) {
        let key = try SymmetricCryptoKey.generate()
        func enc(_ s: String) throws -> EncString { try CipherEncryption.encrypt(string: s, key: key) }

        var cipher = Cipher(type: .login)
        cipher.login = LoginData(username: try enc(username), password: try enc(password))
        cipher.fields = [CustomField(name: try enc(VaultUISlug.fieldName), value: try enc(slug))]
        return (cipher, key)
    }

    // MARK: - extend: rendering & escaping

    func testPlaintextValueIsSingleQuoted() async throws {
        let resp = try await extend("FOO=bar", makeHandler())
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export FOO='bar'")
    }

    func testEmbeddedSingleQuoteIsEscaped() async throws {
        let resp = try await extend("FOO=a'b", makeHandler())
        XCTAssertTrue(resp.ok)
        // POSIX single-quote escaping: a'b -> 'a'\''b'
        XCTAssertEqual(resp.value, "export FOO='a'\\''b'")
    }

    func testShellMetacharactersInValueAreLiteral() async throws {
        let resp = try await extend("FOO=a b$c`d", makeHandler())
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export FOO='a b$c`d'")
    }

    func testExportPrefixIsTolerated() async throws {
        let resp = try await extend("export FOO=bar", makeHandler())
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export FOO='bar'")
    }

    func testQuotedValuesAreUnwrapped() async throws {
        let resp = try await extend("FOO=\"bar baz\"", makeHandler())
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export FOO='bar baz'")
    }

    func testCommentsAndBlankLinesSkipped() async throws {
        let resp = try await extend("# a comment\n\nFOO=bar", makeHandler())
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export FOO='bar'")
    }

    func testInjectionKeyIsRejected() async throws {
        let resp = try await extend("x; rm -rf ~ =evil", makeHandler())
        XCTAssertFalse(resp.ok)
        XCTAssertNotNil(resp.error)
    }

    func testHyphenatedKeyIsRejected() async throws {
        let resp = try await extend("NOT-VALID=x", makeHandler())
        XCTAssertFalse(resp.ok)
        XCTAssertNotNil(resp.error)
    }

    // MARK: - get: slug lookup & field extraction

    func testGetPasswordBySlug() async throws {
        let handler = makeHandler(ciphers: [try makeSluggedLogin(slug: "my-app", username: "alice", password: "s3cr3t")])
        let resp = try await send(SecretRequest(type: "get", slug: "my-app", field: "password"), to: handler)
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "s3cr3t")
    }

    func testGetUnknownSlugFails() async throws {
        let handler = makeHandler(ciphers: [try makeSluggedLogin(slug: "my-app", username: "alice", password: "s3cr3t")])
        let resp = try await send(SecretRequest(type: "get", slug: "no-such", field: "password"), to: handler)
        XCTAssertFalse(resp.ok)
    }

    // MARK: - extend: vaultui:// resolution

    func testExtendResolvesVaultuiReference() async throws {
        let handler = makeHandler(ciphers: [try makeSluggedLogin(slug: "my-app", username: "alice", password: "s3cr3t")])
        let resp = try await extend("DB_PASS=vaultui://my-app/password", handler)
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export DB_PASS='s3cr3t'")
    }

    func testExtendMixesPlaintextAndReference() async throws {
        let handler = makeHandler(ciphers: [try makeSluggedLogin(slug: "my-app", username: "alice", password: "s3cr3t")])
        let resp = try await extend("HOST=localhost\nDB_PASS=vaultui://my-app/password", handler)
        XCTAssertTrue(resp.ok)
        XCTAssertEqual(resp.value, "export HOST='localhost'\nexport DB_PASS='s3cr3t'")
    }
}
