// Wire-format tests for the two organization endpoints.
//
// These are the only endpoints where the cipher stays nested instead of being
// flattened, and the server re-keys attachments exclusively from `attachments2` —
// it ignores the `attachments` array. Getting either wrong fails silently in a
// way that leaves other members with an unreadable item, so the shape is pinned
// here.

import XCTest
import Foundation
import VaultModels
import VaultCrypto
@testable import VaultAPI

final class CipherShareRequestTests: XCTestCase {

    private func encodedBody(_ request: CipherCollectionRequest) throws -> [String: Any] {
        let data = try JSONEncoder().encode(request)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func sampleEncString(_ byte: UInt8) -> EncString {
        EncString(
            type: .aesCBC256_HMACSHA256_B64,
            iv: Data(repeating: byte, count: 16),
            ciphertext: Data(repeating: byte, count: 16),
            mac: Data(repeating: byte, count: 32)
        )
    }

    func testCipherStaysNestedAlongsideCollectionIds() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.organizationId = "org-1"
        cipher.name = sampleEncString(0x01)

        let body = try encodedBody(CipherCollectionRequest(cipher: cipher, collectionIds: ["col-1", "col-2"]))

        XCTAssertEqual(body["collectionIds"] as? [String], ["col-1", "col-2"])
        let nested = try XCTUnwrap(body["cipher"] as? [String: Any])
        XCTAssertEqual(nested["organizationId"] as? String, "org-1")
        XCTAssertEqual(nested["name"] as? String, cipher.name?.serialized())
    }

    func testAttachmentKeysAreSentAsAttachments2() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.organizationId = "org-1"
        cipher.name = sampleEncString(0x01)
        cipher.attachments = [Attachment(
            id: "att-1",
            fileName: sampleEncString(0x02),
            key: sampleEncString(0x03)
        )]

        let body = try encodedBody(CipherCollectionRequest(cipher: cipher, collectionIds: ["col-1"]))
        let nested = try XCTUnwrap(body["cipher"] as? [String: Any])
        let attachments2 = try XCTUnwrap(nested["attachments2"] as? [String: Any])
        let entry = try XCTUnwrap(attachments2["att-1"] as? [String: Any])

        XCTAssertEqual(entry["fileName"] as? String, sampleEncString(0x02).serialized())
        XCTAssertEqual(entry["key"] as? String, sampleEncString(0x03).serialized())
    }

    func testNoAttachments2KeyWhenThereAreNoAttachments() throws {
        var cipher = Cipher(type: .login)
        cipher.id = "cipher-1"
        cipher.organizationId = "org-1"
        cipher.name = sampleEncString(0x01)

        let body = try encodedBody(CipherCollectionRequest(cipher: cipher, collectionIds: ["col-1"]))
        let nested = try XCTUnwrap(body["cipher"] as? [String: Any])

        XCTAssertNil(nested["attachments2"])
    }
}
