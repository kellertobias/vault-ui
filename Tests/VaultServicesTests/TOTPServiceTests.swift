// Characterization tests for TOTPService using the RFC 6238 SHA-1 test vector
// (secret = ASCII "12345678901234567890", base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).

import XCTest
@testable import VaultServices

final class TOTPServiceTests: XCTestCase {

    private let rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    func testRFC6238VectorAt59Seconds() {
        let code = TOTPService.generateCode(from: rfc6238Secret, at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(code?.code, "287082")
        XCTAssertEqual(code?.digits, 6)
        XCTAssertEqual(code?.period, 30)
    }

    func testRFC6238VectorAtLaterCounter() {
        let code = TOTPService.generateCode(from: rfc6238Secret, at: Date(timeIntervalSince1970: 1_111_111_109))
        XCTAssertEqual(code?.code, "081804")
    }

    func testRemainingSecondsWithinPeriod() {
        // At t=59s, 29s into the 30s window → 1s remaining.
        let code = TOTPService.generateCode(from: rfc6238Secret, at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(code?.remaining, 1)
    }

    func testInvalidBase32ReturnsNil() {
        XCTAssertNil(TOTPService.generateCode(from: "!!! not base32 !!!"))
    }
}
