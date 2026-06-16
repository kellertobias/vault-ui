// Characterization tests for PasswordGenerator — pins length/charset/passphrase
// behavior and the relative ordering of the strength estimator.

import XCTest
@testable import VaultServices

final class PasswordGeneratorTests: XCTestCase {

    func testGeneratedPasswordHasRequestedLength() {
        for length in [8, 16, 32, 64] {
            let pw = PasswordGenerator.generatePassword(length: length)
            XCTAssertEqual(pw.count, length)
        }
    }

    func testLowercaseOnlyProducesOnlyLowercaseLetters() {
        let pw = PasswordGenerator.generatePassword(
            length: 40, uppercase: false, lowercase: true,
            numbers: false, symbols: false, minNumbers: 0, minSymbols: 0
        )
        XCTAssertEqual(pw.count, 40)
        XCTAssertTrue(pw.allSatisfy { $0.isLowercase && $0.isLetter })
    }

    func testAvoidAmbiguousExcludesAmbiguousCharacters() {
        let ambiguous = Set("0OoIl1|")
        let pw = PasswordGenerator.generatePassword(
            length: 200, uppercase: true, lowercase: true,
            numbers: true, symbols: false, avoidAmbiguous: true
        )
        XCTAssertFalse(pw.contains { ambiguous.contains($0) })
    }

    func testMinimumsAreHonored() {
        let pw = PasswordGenerator.generatePassword(
            length: 20, uppercase: true, lowercase: true,
            numbers: true, symbols: true, minNumbers: 3, minSymbols: 2
        )
        let digits = pw.filter { $0.isNumber }.count
        let symbols = pw.filter { !$0.isLetter && !$0.isNumber }.count
        XCTAssertGreaterThanOrEqual(digits, 3)
        XCTAssertGreaterThanOrEqual(symbols, 2)
    }

    func testEmptyCharsetYieldsEmptyPassword() {
        let pw = PasswordGenerator.generatePassword(
            length: 16, uppercase: false, lowercase: false,
            numbers: false, symbols: false
        )
        XCTAssertEqual(pw, "")
    }

    func testPassphraseWordCountAndSeparator() {
        let phrase = PasswordGenerator.generatePassphrase(
            wordCount: 5, separator: "-", capitalize: false, includeNumber: false
        )
        XCTAssertEqual(phrase.components(separatedBy: "-").count, 5)
    }

    func testPassphraseIncludeNumberAddsADigit() {
        let phrase = PasswordGenerator.generatePassphrase(
            wordCount: 4, separator: ".", capitalize: true, includeNumber: true
        )
        XCTAssertTrue(phrase.contains { $0.isNumber })
    }

    func testStrengthIncreasesWithComplexity() {
        let weak = PasswordGenerator.calculateStrength("abc")
        let strong = PasswordGenerator.calculateStrength("Abcdef1!xyzKLMNOPq")
        XCTAssertGreaterThan(strong.rawValue, weak.rawValue)
    }
}
