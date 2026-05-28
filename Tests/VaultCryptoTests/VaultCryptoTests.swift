// MARK: - VaultCryptoTests
// Tests for the Bitwarden-compatible crypto engine

import XCTest
import Foundation
import CryptoKit
@testable import VaultCrypto

final class KeyDerivationTests: XCTestCase {

    func testPBKDF2OutputLength() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)

        let key = try KeyDerivation.derivePBKDF2(
            password: password,
            salt: salt,
            iterations: 1000
        )

        XCTAssertEqual(key.count, 32, "PBKDF2 should produce 32 bytes")
    }

    func testPBKDF2Deterministic() throws {
        let password = Data("test@example.com".utf8)
        let salt = Data("test@example.com".utf8)

        let key1 = try KeyDerivation.derivePBKDF2(password: password, salt: salt, iterations: 5000)
        let key2 = try KeyDerivation.derivePBKDF2(password: password, salt: salt, iterations: 5000)

        XCTAssertEqual(key1, key2, "Same inputs should produce same output")
    }

    func testDifferentPasswordsDifferentKeys() throws {
        let salt = Data("salt".utf8)

        let key1 = try KeyDerivation.derivePBKDF2(
            password: Data("password1".utf8), salt: salt, iterations: 1000
        )
        let key2 = try KeyDerivation.derivePBKDF2(
            password: Data("password2".utf8), salt: salt, iterations: 1000
        )

        XCTAssertNotEqual(key1, key2, "Different passwords should produce different keys")
    }

    func testArgon2idProducesValidKey() throws {
        let key = try KeyDerivation.deriveArgon2id(
            password: Data("password".utf8),
            salt: Data("salt@example.com".utf8),
            iterations: 3,
            memory: 64,
            parallelism: 4
        )

        XCTAssertEqual(key.count, 32, "Argon2id should produce 32 bytes")
    }

    func testArgon2idDeterministic() throws {
        let password = Data("password".utf8)
        let salt = Data("user@example.com".utf8)

        let key1 = try KeyDerivation.deriveArgon2id(
            password: password, salt: salt,
            iterations: 3, memory: 64, parallelism: 4
        )
        let key2 = try KeyDerivation.deriveArgon2id(
            password: password, salt: salt,
            iterations: 3, memory: 64, parallelism: 4
        )

        XCTAssertEqual(key1, key2, "Same inputs should produce same Argon2id output")
    }
}

final class MasterKeyTests: XCTestCase {

    func testMasterKeyDerivation() throws {
        let masterKey = try MasterKey.derive(
            password: "master_password",
            email: "user@example.com",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )

        XCTAssertEqual(masterKey.keyData.count, 32, "Master key should be 32 bytes")
    }

    func testEmailCaseInsensitive() throws {
        let key1 = try MasterKey.derive(
            password: "password",
            email: "User@Example.COM",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )
        let key2 = try MasterKey.derive(
            password: "password",
            email: "user@example.com",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )

        XCTAssertEqual(key1.keyData, key2.keyData, "Email should be lowercased")
    }

    func testStretchedMasterKeyLength() throws {
        let masterKey = try MasterKey.derive(
            password: "password",
            email: "user@example.com",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )

        let stretched = try masterKey.stretch()

        XCTAssertEqual(stretched.keyData.count, 64, "Stretched key should be 64 bytes")
        XCTAssertEqual(stretched.encryptionKey.count, 32)
        XCTAssertEqual(stretched.macKey.count, 32)
    }
}

final class MasterPasswordHashTests: XCTestCase {

    func testHashDeterministic() throws {
        let masterKey = try MasterKey.derive(
            password: "password",
            email: "user@example.com",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )

        let hash1 = try MasterPasswordHash.compute(masterKey: masterKey, password: "password")
        let hash2 = try MasterPasswordHash.compute(masterKey: masterKey, password: "password")

        XCTAssertEqual(hash1, hash2, "Same inputs should produce same hash")
    }

    func testHashIsValidBase64() throws {
        let masterKey = try MasterKey.derive(
            password: "password",
            email: "user@example.com",
            kdfConfig: KDFConfig(type: .pbkdf2, iterations: 5000)
        )

        let hash = try MasterPasswordHash.compute(masterKey: masterKey, password: "password")
        let decoded = Data(base64Encoded: hash)

        XCTAssertNotNil(decoded, "Hash should be valid Base64")
        XCTAssertEqual(decoded?.count, 32, "Decoded hash should be 32 bytes")
    }
}

final class SymmetricCryptoKeyTests: XCTestCase {

    func testGenerateKey() throws {
        let key = try SymmetricCryptoKey.generate()

        XCTAssertEqual(key.keyData.count, 64)
        XCTAssertEqual(key.encryptionKey.count, 32)
        XCTAssertEqual(key.macKey.count, 32)
    }

    func testGeneratedKeysAreDifferent() throws {
        let key1 = try SymmetricCryptoKey.generate()
        let key2 = try SymmetricCryptoKey.generate()

        XCTAssertNotEqual(key1.keyData, key2.keyData, "Random keys should be different")
    }

    func testInvalidKeyLength() {
        XCTAssertThrowsError(
            try SymmetricCryptoKey(keyData: Data(repeating: 0, count: 48))
        )
    }

    func testConstructFromParts() throws {
        let encKey = Data(repeating: 0xAA, count: 32)
        let macKey = Data(repeating: 0xBB, count: 32)

        let key = try SymmetricCryptoKey(encryptionKey: encKey, macKey: macKey)

        XCTAssertEqual(key.encryptionKey, encKey)
        XCTAssertEqual(key.macKey, macKey)
        XCTAssertEqual(key.keyData, encKey + macKey)
    }
}

final class EncStringTests: XCTestCase {

    func testParseType2() throws {
        let iv = Data(repeating: 0x01, count: 16).base64EncodedString()
        let ct = Data(repeating: 0x02, count: 32).base64EncodedString()
        let mac = Data(repeating: 0x03, count: 32).base64EncodedString()
        let serialized = "2.\(iv)|\(ct)|\(mac)"

        let encString = try EncString(serialized: serialized)

        XCTAssertEqual(encString.type, .aesCBC256_HMACSHA256_B64)
        XCTAssertEqual(encString.iv?.count, 16)
        XCTAssertEqual(encString.ciphertext.count, 32)
        XCTAssertEqual(encString.mac?.count, 32)
    }

    func testRoundtripSerialization() throws {
        let iv = Data(repeating: 0x01, count: 16).base64EncodedString()
        let ct = Data(repeating: 0x02, count: 32).base64EncodedString()
        let mac = Data(repeating: 0x03, count: 32).base64EncodedString()
        let original = "2.\(iv)|\(ct)|\(mac)"

        let encString = try EncString(serialized: original)
        let reserialized = encString.serialized()

        XCTAssertEqual(reserialized, original)
    }

    func testInvalidFormat() {
        XCTAssertThrowsError(try EncString(serialized: "no-type-prefix"))
        XCTAssertThrowsError(try EncString(serialized: "99.invalid"))
    }

    func testJSONCodable() throws {
        let iv = Data(repeating: 0x01, count: 16).base64EncodedString()
        let ct = Data(repeating: 0x02, count: 32).base64EncodedString()
        let mac = Data(repeating: 0x03, count: 32).base64EncodedString()
        let serialized = "2.\(iv)|\(ct)|\(mac)"

        let original = try EncString(serialized: serialized)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(EncString.self, from: encoded)

        XCTAssertEqual(decoded, original)
    }
}

final class WebAuthnGeneratorTests: XCTestCase {

    func testGeneratedAttestationPublicKeyVerifiesAssertionSignature() throws {
        let relyingPartyId = "paypal.com"
        let clientDataHash = Data(SHA256.hash(data: Data("client-data".utf8)))

        let passkey = try XCTUnwrap(WebAuthnGenerator.generatePasskey(relyingPartyId: relyingPartyId))
        let assertion = try XCTUnwrap(WebAuthnGenerator.generateAssertion(
            privateKeyBase64: passkey.privateKey,
            relyingPartyId: relyingPartyId,
            clientDataHash: clientDataHash
        ))

        let publicKey = try extractPublicKey(fromAttestationObject: passkey.attestationObject)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)

        var signedData = Data()
        signedData.append(assertion.authenticatorData)
        signedData.append(clientDataHash)

        XCTAssertTrue(publicKey.isValidSignature(signature, for: signedData))
    }

    private func extractPublicKey(fromAttestationObject attestationObject: Data) throws -> P256.Signing.PublicKey {
        let bytes = [UInt8](attestationObject)
        let xMarker: [UInt8] = [0x21, 0x58, 0x20]
        let yMarker: [UInt8] = [0x22, 0x58, 0x20]

        guard let xMarkerIndex = bytes.indices.first(where: { index in
            bytes[index...].starts(with: xMarker)
        }) else {
            XCTFail("COSE public key x-coordinate marker not found")
            return try P256.Signing.PublicKey(rawRepresentation: Data())
        }

        let xStart = xMarkerIndex + xMarker.count
        let xEnd = xStart + 32
        let yMarkerStart = xEnd
        let yStart = yMarkerStart + yMarker.count
        let yEnd = yStart + 32

        guard yEnd <= bytes.count,
              Array(bytes[yMarkerStart..<yStart]) == yMarker else {
            XCTFail("COSE public key y-coordinate marker not found")
            return try P256.Signing.PublicKey(rawRepresentation: Data())
        }

        var rawPublicKey = Data(bytes[xStart..<xEnd])
        rawPublicKey.append(contentsOf: bytes[yStart..<yEnd])

        return try P256.Signing.PublicKey(rawRepresentation: rawPublicKey)
    }
}

final class AESCBCEncryptionTests: XCTestCase {

    func testEncryptDecryptRoundtrip() throws {
        let key = try SymmetricCryptoKey.generate()
        let plaintext = Data("Hello, Vault UI! 🔐".utf8)

        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: plaintext, key: key)

        XCTAssertEqual(iv.count, 16)
        XCTAssertFalse(ciphertext.isEmpty)
        XCTAssertEqual(mac.count, 32)

        let decrypted = try AESCBCEngine.decrypt(iv: iv, ciphertext: ciphertext, mac: mac, key: key)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testHMACTamperDetection() throws {
        let key = try SymmetricCryptoKey.generate()
        let plaintext = Data("secret data".utf8)

        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: plaintext, key: key)

        var tampered = ciphertext
        tampered[0] ^= 0xFF

        XCTAssertThrowsError(
            try AESCBCEngine.decrypt(iv: iv, ciphertext: tampered, mac: mac, key: key)
        )
    }

    func testWrongKeyFails() throws {
        let key1 = try SymmetricCryptoKey.generate()
        let key2 = try SymmetricCryptoKey.generate()
        let plaintext = Data("secret".utf8)

        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: plaintext, key: key1)

        XCTAssertThrowsError(
            try AESCBCEngine.decrypt(iv: iv, ciphertext: ciphertext, mac: mac, key: key2)
        )
    }

    func testEncryptEmptyData() throws {
        let key = try SymmetricCryptoKey.generate()
        let plaintext = Data()

        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: plaintext, key: key)
        let decrypted = try AESCBCEngine.decrypt(iv: iv, ciphertext: ciphertext, mac: mac, key: key)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptLargeData() throws {
        let key = try SymmetricCryptoKey.generate()
        let plaintext = Data(repeating: 0xAB, count: 100_000)

        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: plaintext, key: key)
        let decrypted = try AESCBCEngine.decrypt(iv: iv, ciphertext: ciphertext, mac: mac, key: key)

        XCTAssertEqual(decrypted, plaintext)
    }
}

final class CipherEncryptionHighLevelTests: XCTestCase {

    func testEncryptDecryptString() throws {
        let key = try SymmetricCryptoKey.generate()
        let original = "MySecretPassword123!"

        let encString = try CipherEncryption.encrypt(string: original, key: key)
        let decrypted = try CipherEncryption.decryptString(encString, key: key)

        XCTAssertEqual(decrypted, original)
        XCTAssertEqual(encString.type, .aesCBC256_HMACSHA256_B64)
    }

    func testFullRoundtrip() throws {
        let key = try SymmetricCryptoKey.generate()
        let original = "test password"

        let encrypted = try CipherEncryption.encrypt(string: original, key: key)
        let serialized = encrypted.serialized()
        let parsed = try EncString(serialized: serialized)
        let decrypted = try CipherEncryption.decryptString(parsed, key: key)

        XCTAssertEqual(decrypted, original)
    }

    func testProtectedSymmetricKeyDecryption() throws {
        let stretchedKey = try SymmetricCryptoKey.generate()
        let vaultKey = try SymmetricCryptoKey.generate()

        let protectedKey = try CipherEncryption.encrypt(data: vaultKey.keyData, key: stretchedKey)
        let recoveredKey = try CipherEncryption.decryptProtectedSymmetricKey(
            protectedKey, stretchedMasterKey: stretchedKey
        )

        XCTAssertEqual(recoveredKey.keyData, vaultKey.keyData)
    }

    func testDecryptOptionalNil() throws {
        let key = try SymmetricCryptoKey.generate()
        let result = try CipherEncryption.decryptStringOptional(nil, key: key)
        XCTAssertNil(result)
    }
}

final class FullKeyDerivationChainTests: XCTestCase {

    func testCompleteKeyDerivationChain() throws {
        let email = "user@example.com"
        let password = "correct horse battery staple"
        let kdfConfig = KDFConfig(type: .pbkdf2, iterations: 5000)

        // Step 1: Derive master key
        let masterKey = try MasterKey.derive(password: password, email: email, kdfConfig: kdfConfig)
        XCTAssertEqual(masterKey.keyData.count, 32)

        // Step 2: Stretch master key
        let stretchedKey = try masterKey.stretch()
        XCTAssertEqual(stretchedKey.keyData.count, 64)

        // Step 3: Compute auth hash
        let hash = try MasterPasswordHash.compute(masterKey: masterKey, password: password)
        XCTAssertFalse(hash.isEmpty)
        XCTAssertNotNil(Data(base64Encoded: hash))

        // Step 4: Simulate protected symmetric key
        let vaultKey = try SymmetricCryptoKey.generate()
        let protectedKey = try CipherEncryption.encrypt(data: vaultKey.keyData, key: stretchedKey)

        // Step 5: Decrypt vault key
        let recoveredVaultKey = try CipherEncryption.decryptProtectedSymmetricKey(
            protectedKey, stretchedMasterKey: stretchedKey
        )
        XCTAssertEqual(recoveredVaultKey.keyData, vaultKey.keyData)

        // Step 6: Use vault key to encrypt/decrypt a cipher
        let secretPassword = "P@ssw0rd!2024"
        let encrypted = try CipherEncryption.encrypt(string: secretPassword, key: recoveredVaultKey)
        let decrypted = try CipherEncryption.decryptString(encrypted, key: recoveredVaultKey)
        XCTAssertEqual(decrypted, secretPassword)
    }
}
