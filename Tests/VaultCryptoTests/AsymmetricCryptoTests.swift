// MARK: - AsymmetricCryptoTests
// RSA key-format conversion and organization-key unwrapping.
//
// Fixtures are a real OpenSSL-generated RSA-2048 key emitted in all four
// encodings, plus an OAEP-SHA1 ciphertext of a known 64-byte symmetric key —
// the exact shape of an organization key as Vaultwarden serves it.

import XCTest
import Foundation
@testable import VaultCrypto

final class ASN1DERTests: XCTestCase {

    func testPKCS8UnwrapsToPKCS1() throws {
        let unwrapped = try ASN1DER.rsaPrivateKeyPKCS1(from: RSAFixtures.privateKeyPKCS8)
        XCTAssertEqual(unwrapped, RSAFixtures.privateKeyPKCS1)
    }

    func testSPKIUnwrapsToPKCS1() throws {
        let unwrapped = try ASN1DER.rsaPublicKeyPKCS1(from: RSAFixtures.publicKeySPKI)
        XCTAssertEqual(unwrapped, RSAFixtures.publicKeyPKCS1)
    }

    func testAlreadyPKCS1PassesThroughUnchanged() throws {
        XCTAssertEqual(
            try ASN1DER.rsaPrivateKeyPKCS1(from: RSAFixtures.privateKeyPKCS1),
            RSAFixtures.privateKeyPKCS1
        )
        XCTAssertEqual(
            try ASN1DER.rsaPublicKeyPKCS1(from: RSAFixtures.publicKeyPKCS1),
            RSAFixtures.publicKeyPKCS1
        )
    }

    func testPKCS1RewrapsToPKCS8() {
        XCTAssertEqual(
            ASN1DER.pkcs8PrivateKey(fromPKCS1: RSAFixtures.privateKeyPKCS1),
            RSAFixtures.privateKeyPKCS8
        )
    }

    func testPKCS1RewrapsToSPKI() {
        XCTAssertEqual(
            ASN1DER.spkiPublicKey(fromPKCS1: RSAFixtures.publicKeyPKCS1),
            RSAFixtures.publicKeySPKI
        )
    }

    func testModulusBitCount() throws {
        XCTAssertEqual(try ASN1DER.rsaModulusBitCount(pkcs1PrivateKey: RSAFixtures.privateKeyPKCS1), 2048)
        XCTAssertEqual(try ASN1DER.rsaModulusBitCount(pkcs1PublicKey: RSAFixtures.publicKeyPKCS1), 2048)
    }

    func testTruncatedDataThrows() {
        let truncated = RSAFixtures.publicKeySPKI.prefix(20)
        XCTAssertThrowsError(try ASN1DER.rsaPublicKeyPKCS1(from: Data(truncated)))
    }

    func testNonSequenceThrows() {
        XCTAssertThrowsError(try ASN1DER.rsaPrivateKeyPKCS1(from: Data([0x02, 0x01, 0x00])))
    }
}

final class AsymmetricCryptoTests: XCTestCase {

    /// The org-key path end to end: an RSA-OAEP-SHA1 EncString (type 4) unwrapped
    /// with a PKCS#8 account private key must yield the original 64-byte key.
    func testDecryptOrganizationKeyKnownAnswer() throws {
        let encString = try EncString(serialized: "4.\(RSAFixtures.wrappedSymmetricKeyBase64)")
        let key = try AsymmetricCrypto.decryptKey(
            encString: encString,
            privateKeyData: RSAFixtures.privateKeyPKCS8
        )
        XCTAssertEqual(key.keyData, RSAFixtures.symmetricKey)
    }

    /// The same ciphertext must also unwrap when the private key is PKCS#1.
    func testDecryptOrganizationKeyAcceptsPKCS1PrivateKey() throws {
        let encString = try EncString(serialized: "4.\(RSAFixtures.wrappedSymmetricKeyBase64)")
        let key = try AsymmetricCrypto.decryptKey(
            encString: encString,
            privateKeyData: RSAFixtures.privateKeyPKCS1
        )
        XCTAssertEqual(key.keyData, RSAFixtures.symmetricKey)
    }

    func testEncryptWithSPKIThenDecryptWithPKCS8() throws {
        let plaintext = Data("organization key material".utf8)
        let ciphertext = try AsymmetricCrypto.encrypt(
            data: plaintext,
            publicKeyData: RSAFixtures.publicKeySPKI
        )
        let encString = EncString(type: .rsa2048_OAEPSHA1_B64, iv: nil, ciphertext: ciphertext, mac: nil)
        let decrypted = try AsymmetricCrypto.decrypt(
            encString: encString,
            privateKeyData: RSAFixtures.privateKeyPKCS8
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testGeneratedKeyPairIsBitwardenShapedAndUsable() throws {
        let pair = try AsymmetricCrypto.generateRSAKeyPair()

        // Generated halves must be the wrapped forms Bitwarden exchanges…
        XCTAssertNotEqual(try ASN1DER.rsaPublicKeyPKCS1(from: pair.publicKey), pair.publicKey)
        XCTAssertNotEqual(try ASN1DER.rsaPrivateKeyPKCS1(from: pair.privateKey), pair.privateKey)

        // …and must still round-trip through encrypt/decrypt.
        let plaintext = Data("round trip".utf8)
        let ciphertext = try AsymmetricCrypto.encrypt(data: plaintext, publicKeyData: pair.publicKey)
        let encString = EncString(type: .rsa2048_OAEPSHA1_B64, iv: nil, ciphertext: ciphertext, mac: nil)
        XCTAssertEqual(
            try AsymmetricCrypto.decrypt(encString: encString, privateKeyData: pair.privateKey),
            plaintext
        )
    }

    func testDecryptRejectsNonRSAEncStringType() throws {
        let aesEncString = EncString(
            type: .aesCBC256_HMACSHA256_B64,
            iv: Data(repeating: 0, count: 16),
            ciphertext: Data(repeating: 1, count: 16),
            mac: Data(repeating: 2, count: 32)
        )
        XCTAssertThrowsError(
            try AsymmetricCrypto.decrypt(encString: aesEncString, privateKeyData: RSAFixtures.privateKeyPKCS8)
        )
    }
}

// MARK: - Fixtures

private enum RSAFixtures {
    static let symmetricKey = Data((0..<64).map { UInt8($0) })

    static let wrappedSymmetricKeyBase64 =
        "CXjZsFxrOiundb3qjuSI2ay9W2R8YLds5B+W2oJ3mhE34/sVZAzR7xUplC/qLnThJW4eneRHcDphiKCSURUOWCUy6o3RJUPNb3Vj" +
        "pweNXInZG1mQGp5ZO9a+sdHv2tyyTdqQtJSqoO1qTy6NOlGLsbE4Cn+bVAYUESF/GGrESQVJ0CsAhct79IF2JvcZzSR8VCY2SD5Y" +
        "lyEGap+s30j/eKsoDMZ6uDTGvUlgb1kCz4Tjc9vJ8Ao9SkOyQQvNRRIymGBf5YcVXhWI8a7r37X9mqFTdXT6+oP7EGFHQYPpeHaQ" +
        "zCQo6LzsqFR4gfKqA0JDYZrNuvP7qrOQOnF2gBM8pA=="

    static let privateKeyPKCS8 = decode(
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTr3li3QF6JPxG2OuJ10OUdVXIaEiVcKoow8OFTblUpl3EbWEM" +
        "yUWZAVFARWRG5m5HsJXZ3UdRBO3oSeZDCbT53rlQlEnebQeu7qLWrRf2SNL/RfVu9ZppPriGrZTETLkJqBfxMnnTcs3J2sUVvv94" +
        "V1dJUGmOUNicPgu+tCn4KUo1m8y+EEVXe6OBkRjTQA66k17DJAcGorag8HUXQc5sLIdqkCYzaompTrS799nJxECURE922OZc9ZKG" +
        "MZP2PqetNL7gcu91sU4rOhzTvfQ3/WEyq9Z2JbImvXUupv2Ks4gxGQT09SleDTNyRfB6VDqxEL8cpvv9mwje2Nj7a+PVAgMBAAEC" +
        "ggEAL686MdYrGm2juRpkHssPCnnCO2WUfg/1GRlwYXPBkdfvsbMhYVgBbVA0FFzzbkMLu4EEOWaNltbRHC30N5QER6OG0UI4AaXR" +
        "k8WAdXFJKd/EpODJSMzrUO0L9oxIWwNswXXxWRMTq9bHJFRLS2SypwAIcmcQ1f87mWMdNrOEU5g/x+BepJzs69L1mYlvBIwg9Myl" +
        "18NP8F235HLK4OWI2zt79MnX6bAogNmaZ/6dy+RjxvIMh7FbF9KhU9A0uEAIC4mnQ5FF6C/32TYdz9IN0nOSdzp5XEJbi5fpKvKb" +
        "UVIwgPxQ8a4fG8f1Vnju7rm2Jde7foOIGpLwl/cEEPhjtwKBgQDEo6VH6MoOmzfYuebQqEKurs4vxgVKQZ7oUbS28x0M20Yb+64n" +
        "CXISDzYtVFed0GDHR7AL555XiHyO16ORoggxdV6MwPAyDKH9Rltwga7XDo1feTN+tpXe5mHEWl2yQwEBrt1l9AqXfOiI7U+nI14s" +
        "RmvrRnTjKns/TPBo4hQ5fwKBgQDARKkwKlWmhJ2KyZzPYzzY7JSPVqGirAlfuDShlmwmRELXE/ThGZnh8w0cgWy2HAwQSlZKyP35" +
        "QpR/zuLh3tpZmXQCvp4Fbiqs2tpj4N8kwNhuhjrMkea6Q3fHd2HhS9parO3QR2Ff+GURhENdM+Sw70Bqe/ZckoIWd1CxL7yEqwKB" +
        "gQCiT7IOOUkP5W+jpU+wzDK+nevz4zBaqu/QNCFHIkXIZvboAkcuUc2muoetwwDPc0FvPO1D5lv9RNwLzFNn0qeQq6Dv7hJWPbc4" +
        "qOqxY1o+ifSH6jNnVK9A3km1GiJdEpGyIfT+QwK7KI+I9tnYzIjfYwGRowa4vEgfaBLJgFPRYQKBgCocX7oO66eHEEJfmhrKL3+L" +
        "gZZLcSeB6qOuYsipe5J+DO2yj0XmJ5AXfd2qczcHuZSv02qZzxaTAJdlpse12bkaJRCc01t5H5uwa3jIvdb87ep3N9WqdxCAynFD" +
        "sop35KFLkuK1X5x3eRt3DpIRVZtzK3anI/RumlN1WpUUUYP1AoGAPYpx9BpyNq1E1QQUW6jUHIIVM93Cn0eu5pnEtRISRNAa1lXS" +
        "lI4JLRaDl8svavQLQUObIRUty75yhCNyU6EmSXoTFJXqC3xrbeQDejjndk93zV409T7Q+VPX3FBOn7E4LGf/pSDY5SZEXTtR2NHN" +
        "SRH7/s9q06wInebUYQXkVP8="
    )

    static let publicKeySPKI = decode(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk695Yt0BeiT8RtjriddDlHVVyGhIlXCqKMPDhU25VKZdxG1hDMlFmQFR" +
        "QEVkRuZuR7CV2d1HUQTt6EnmQwm0+d65UJRJ3m0Hru6i1q0X9kjS/0X1bvWaaT64hq2UxEy5CagX8TJ503LNydrFFb7/eFdXSVBp" +
        "jlDYnD4LvrQp+ClKNZvMvhBFV3ujgZEY00AOupNewyQHBqK2oPB1F0HObCyHapAmM2qJqU60u/fZycRAlERPdtjmXPWShjGT9j6n" +
        "rTS+4HLvdbFOKzoc0730N/1hMqvWdiWyJr11Lqb9irOIMRkE9PUpXg0zckXwelQ6sRC/HKb7/ZsI3tjY+2vj1QIDAQAB"
    )

    static let privateKeyPKCS1 = decode(
        "MIIEowIBAAKCAQEAk695Yt0BeiT8RtjriddDlHVVyGhIlXCqKMPDhU25VKZdxG1hDMlFmQFRQEVkRuZuR7CV2d1HUQTt6EnmQwm0" +
        "+d65UJRJ3m0Hru6i1q0X9kjS/0X1bvWaaT64hq2UxEy5CagX8TJ503LNydrFFb7/eFdXSVBpjlDYnD4LvrQp+ClKNZvMvhBFV3uj" +
        "gZEY00AOupNewyQHBqK2oPB1F0HObCyHapAmM2qJqU60u/fZycRAlERPdtjmXPWShjGT9j6nrTS+4HLvdbFOKzoc0730N/1hMqvW" +
        "diWyJr11Lqb9irOIMRkE9PUpXg0zckXwelQ6sRC/HKb7/ZsI3tjY+2vj1QIDAQABAoIBAC+vOjHWKxpto7kaZB7LDwp5wjtllH4P" +
        "9RkZcGFzwZHX77GzIWFYAW1QNBRc825DC7uBBDlmjZbW0Rwt9DeUBEejhtFCOAGl0ZPFgHVxSSnfxKTgyUjM61DtC/aMSFsDbMF1" +
        "8VkTE6vWxyRUS0tksqcACHJnENX/O5ljHTazhFOYP8fgXqSc7OvS9ZmJbwSMIPTMpdfDT/Bdt+RyyuDliNs7e/TJ1+mwKIDZmmf+" +
        "ncvkY8byDIexWxfSoVPQNLhACAuJp0ORRegv99k2Hc/SDdJzknc6eVxCW4uX6Srym1FSMID8UPGuHxvH9VZ47u65tiXXu36DiBqS" +
        "8Jf3BBD4Y7cCgYEAxKOlR+jKDps32Lnm0KhCrq7OL8YFSkGe6FG0tvMdDNtGG/uuJwlyEg82LVRXndBgx0ewC+eeV4h8jtejkaII" +
        "MXVejMDwMgyh/UZbcIGu1w6NX3kzfraV3uZhxFpdskMBAa7dZfQKl3zoiO1PpyNeLEZr60Z04yp7P0zwaOIUOX8CgYEAwESpMCpV" +
        "poSdismcz2M82OyUj1ahoqwJX7g0oZZsJkRC1xP04RmZ4fMNHIFsthwMEEpWSsj9+UKUf87i4d7aWZl0Ar6eBW4qrNraY+DfJMDY" +
        "boY6zJHmukN3x3dh4UvaWqzt0EdhX/hlEYRDXTPksO9Aanv2XJKCFndQsS+8hKsCgYEAok+yDjlJD+Vvo6VPsMwyvp3r8+MwWqrv" +
        "0DQhRyJFyGb26AJHLlHNprqHrcMAz3NBbzztQ+Zb/UTcC8xTZ9KnkKug7+4SVj23OKjqsWNaPon0h+ozZ1SvQN5JtRoiXRKRsiH0" +
        "/kMCuyiPiPbZ2MyI32MBkaMGuLxIH2gSyYBT0WECgYAqHF+6DuunhxBCX5oayi9/i4GWS3EngeqjrmLIqXuSfgztso9F5ieQF33d" +
        "qnM3B7mUr9Nqmc8WkwCXZabHtdm5GiUQnNNbeR+bsGt4yL3W/O3qdzfVqncQgMpxQ7KKd+ShS5LitV+cd3kbdw6SEVWbcyt2pyP0" +
        "bppTdVqVFFGD9QKBgD2KcfQacjatRNUEFFuo1ByCFTPdwp9HruaZxLUSEkTQGtZV0pSOCS0Wg5fLL2r0C0FDmyEVLcu+coQjclOh" +
        "Jkl6ExSV6gt8a23kA3o453ZPd81eNPU+0PlT19xQTp+xOCxn/6Ug2OUmRF07UdjRzUkR+/7PatOsCJ3m1GEF5FT/"
    )

    static let publicKeyPKCS1 = decode(
        "MIIBCgKCAQEAk695Yt0BeiT8RtjriddDlHVVyGhIlXCqKMPDhU25VKZdxG1hDMlFmQFRQEVkRuZuR7CV2d1HUQTt6EnmQwm0+d65" +
        "UJRJ3m0Hru6i1q0X9kjS/0X1bvWaaT64hq2UxEy5CagX8TJ503LNydrFFb7/eFdXSVBpjlDYnD4LvrQp+ClKNZvMvhBFV3ujgZEY" +
        "00AOupNewyQHBqK2oPB1F0HObCyHapAmM2qJqU60u/fZycRAlERPdtjmXPWShjGT9j6nrTS+4HLvdbFOKzoc0730N/1hMqvWdiWy" +
        "Jr11Lqb9irOIMRkE9PUpXg0zckXwelQ6sRC/HKb7/ZsI3tjY+2vj1QIDAQAB"
    )

    private static func decode(_ base64: String) -> Data {
        Data(base64Encoded: base64)!
    }
}
