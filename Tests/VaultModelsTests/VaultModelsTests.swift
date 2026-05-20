import XCTest
@testable import VaultModels
import VaultCrypto

final class VaultModelsTests: XCTestCase {

    func testCipherTypeDisplayNames() {
        XCTAssertEqual(CipherType.login.displayName, "Login")
        XCTAssertEqual(CipherType.secureNote.displayName, "Secure Note")
        XCTAssertEqual(CipherType.card.displayName, "Card")
        XCTAssertEqual(CipherType.identity.displayName, "Identity")
        XCTAssertEqual(CipherType.sshKey.displayName, "SSH Key")
    }

    func testCipherTypeRawValues() {
        XCTAssertEqual(CipherType.login.rawValue, 1)
        XCTAssertEqual(CipherType.secureNote.rawValue, 2)
        XCTAssertEqual(CipherType.card.rawValue, 3)
        XCTAssertEqual(CipherType.identity.rawValue, 4)
        XCTAssertEqual(CipherType.sshKey.rawValue, 5)
    }

    func testCipherCreation() {
        let cipher = Cipher(type: .login, favorite: true)
        XCTAssertEqual(cipher.type, .login)
        XCTAssertTrue(cipher.favorite)
        XCTAssertEqual(cipher.reprompt, .none)
        XCTAssertFalse(cipher.isDeleted)
    }

    func testFolderCodable() throws {
        let folder = Folder(id: "test-id", revisionDate: Date(timeIntervalSince1970: 1000))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(folder)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(Folder.self, from: data)
        XCTAssertEqual(decoded.id, "test-id")
    }

    func testSendItemCreation() {
        let send = SendItem(type: .text)
        XCTAssertEqual(send.type, .text)
        XCTAssertNil(send.maxAccessCount)
        XCTAssertNil(send.expirationDate)
    }

    func testAnyCodableValue() throws {
        let values: [AnyCodableValue] = [.string("hello"), .int(42), .bool(true), .null]
        let data = try JSONEncoder().encode(values)
        let decoded = try JSONDecoder().decode([AnyCodableValue].self, from: data)

        XCTAssertEqual(decoded[0], .string("hello"))
        XCTAssertEqual(decoded[1], .int(42))
        XCTAssertEqual(decoded[2], .bool(true))
        XCTAssertEqual(decoded[3], .null)
    }

    func testSyncResponseDecodable() throws {
        // Test that a minimal sync response can be decoded
        let json = """
        {
            "profile": {
                "id": "user-123",
                "email": "user@test.com"
            },
            "ciphers": [],
            "folders": [],
            "sends": []
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(SyncResponse.self, from: json)
        XCTAssertEqual(response.profile?.id, "user-123")
        XCTAssertEqual(response.profile?.email, "user@test.com")
        XCTAssertEqual(response.ciphers?.count, 0)
        XCTAssertEqual(response.folders?.count, 0)
    }
}
