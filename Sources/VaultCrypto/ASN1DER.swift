// MARK: - VaultCrypto/ASN1DER.swift
// Minimal ASN.1 DER reader/writer for RSA key format conversion.
//
// Security's `SecKeyCreateWithData` only accepts *PKCS#1* RSA keys
// (`RSAPublicKey` / `RSAPrivateKey`), while Bitwarden/Vaultwarden hand out the
// account public key as **SPKI** (`SubjectPublicKeyInfo`) and the decrypted
// account private key as **PKCS#8** (`PrivateKeyInfo`). This file strips and
// re-applies those wrappers so `AsymmetricCrypto` can import real server keys.

import Foundation

/// DER encoding/decoding for the small slice of ASN.1 that RSA key blobs need.
public enum ASN1DER {

    // MARK: - Tags

    private enum Tag {
        static let integer: UInt8 = 0x02
        static let bitString: UInt8 = 0x03
        static let octetString: UInt8 = 0x04
        static let null: UInt8 = 0x05
        static let objectIdentifier: UInt8 = 0x06
        static let sequence: UInt8 = 0x30
    }

    /// `AlgorithmIdentifier` for `rsaEncryption` (1.2.840.113549.1.1.1) with the
    /// required NULL parameters, pre-encoded: `SEQUENCE { OID, NULL }`.
    private static let rsaAlgorithmIdentifier = Data([
        0x30, 0x0D,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        0x05, 0x00,
    ])

    // MARK: - Errors

    public enum ASN1Error: Error, LocalizedError, Sendable {
        case truncated
        case unexpectedTag(expected: UInt8, actual: UInt8)
        case unsupportedStructure(String)

        public var errorDescription: String? {
            switch self {
            case .truncated:
                return "DER data ended unexpectedly"
            case .unexpectedTag(let expected, let actual):
                return String(format: "Unexpected DER tag: expected 0x%02X, got 0x%02X", expected, actual)
            case .unsupportedStructure(let detail):
                return "Unsupported DER structure: \(detail)"
            }
        }
    }

    // MARK: - Reading

    /// One parsed TLV triple plus the byte range it occupied in its parent.
    struct Element {
        let tag: UInt8
        /// The value bytes (V), excluding tag and length.
        let contents: [UInt8]
        /// Offset just past this element in the buffer it was read from.
        let endIndex: Int
    }

    /// Read a single TLV element starting at `index`.
    static func readElement(_ bytes: [UInt8], at index: Int) throws -> Element {
        guard index < bytes.count else { throw ASN1Error.truncated }
        let tag = bytes[index]
        let (length, lengthEnd) = try readLength(bytes, at: index + 1)
        let valueEnd = lengthEnd + length
        guard valueEnd <= bytes.count else { throw ASN1Error.truncated }
        return Element(tag: tag, contents: Array(bytes[lengthEnd..<valueEnd]), endIndex: valueEnd)
    }

    /// Read a DER length field, returning the length and the offset of the value.
    private static func readLength(_ bytes: [UInt8], at index: Int) throws -> (length: Int, valueStart: Int) {
        guard index < bytes.count else { throw ASN1Error.truncated }
        let first = bytes[index]

        // Short form: bit 7 clear, length is the byte itself.
        if first & 0x80 == 0 {
            return (Int(first), index + 1)
        }

        // Long form: low 7 bits give the number of subsequent length bytes.
        let byteCount = Int(first & 0x7F)
        guard byteCount > 0, byteCount <= 4 else {
            throw ASN1Error.unsupportedStructure("length field of \(byteCount) bytes")
        }
        guard index + byteCount < bytes.count else { throw ASN1Error.truncated }

        var length = 0
        for offset in 1...byteCount {
            length = (length << 8) | Int(bytes[index + offset])
        }
        return (length, index + 1 + byteCount)
    }

    /// Read the children of a top-level SEQUENCE.
    private static func sequenceChildren(_ der: Data) throws -> [Element] {
        let bytes = [UInt8](der)
        let outer = try readElement(bytes, at: 0)
        guard outer.tag == Tag.sequence else {
            throw ASN1Error.unexpectedTag(expected: Tag.sequence, actual: outer.tag)
        }

        var children: [Element] = []
        var index = 0
        while index < outer.contents.count {
            let child = try readElement(outer.contents, at: index)
            children.append(child)
            index = child.endIndex
        }
        return children
    }

    // MARK: - Private key: PKCS#8 → PKCS#1

    /// Return a PKCS#1 `RSAPrivateKey` DER blob, unwrapping PKCS#8 if needed.
    ///
    /// Accepts either format so callers can pass through keys that other parts
    /// of the app already hold as PKCS#1 (e.g. imported OpenSSH keys).
    public static func rsaPrivateKeyPKCS1(from der: Data) throws -> Data {
        let children = try sequenceChildren(der)

        // Both structures start with an INTEGER version. They diverge at the
        // second element: PKCS#1 continues with the modulus INTEGER, PKCS#8 with
        // the AlgorithmIdentifier SEQUENCE.
        guard children.count >= 2, children[0].tag == Tag.integer else {
            throw ASN1Error.unsupportedStructure("RSA private key is not a versioned SEQUENCE")
        }

        switch children[1].tag {
        case Tag.integer:
            return der // already PKCS#1
        case Tag.sequence:
            guard children.count >= 3, children[2].tag == Tag.octetString else {
                throw ASN1Error.unsupportedStructure("PKCS#8 PrivateKeyInfo has no privateKey OCTET STRING")
            }
            return Data(children[2].contents)
        default:
            throw ASN1Error.unsupportedStructure("unrecognized RSA private key encoding")
        }
    }

    /// Wrap a PKCS#1 `RSAPrivateKey` in a PKCS#8 `PrivateKeyInfo`.
    public static func pkcs8PrivateKey(fromPKCS1 pkcs1: Data) -> Data {
        var body = Data()
        body.append(encode(tag: Tag.integer, contents: Data([0x00]))) // version
        body.append(rsaAlgorithmIdentifier)
        body.append(encode(tag: Tag.octetString, contents: pkcs1))
        return encode(tag: Tag.sequence, contents: body)
    }

    // MARK: - Public key: SPKI → PKCS#1

    /// Return a PKCS#1 `RSAPublicKey` DER blob, unwrapping SPKI if needed.
    public static func rsaPublicKeyPKCS1(from der: Data) throws -> Data {
        let children = try sequenceChildren(der)
        guard let first = children.first else {
            throw ASN1Error.unsupportedStructure("empty RSA public key SEQUENCE")
        }

        switch first.tag {
        case Tag.integer:
            return der // already PKCS#1: SEQUENCE { modulus, exponent }
        case Tag.sequence:
            guard children.count >= 2, children[1].tag == Tag.bitString else {
                throw ASN1Error.unsupportedStructure("SubjectPublicKeyInfo has no subjectPublicKey BIT STRING")
            }
            // A BIT STRING's first content byte counts the unused trailing bits;
            // for a DER-encapsulated key that is always 0.
            let bits = children[1].contents
            guard let unusedBits = bits.first, unusedBits == 0 else {
                throw ASN1Error.unsupportedStructure("subjectPublicKey BIT STRING is not byte-aligned")
            }
            return Data(bits.dropFirst())
        default:
            throw ASN1Error.unsupportedStructure("unrecognized RSA public key encoding")
        }
    }

    /// Wrap a PKCS#1 `RSAPublicKey` in a `SubjectPublicKeyInfo`.
    public static func spkiPublicKey(fromPKCS1 pkcs1: Data) -> Data {
        var bitString = Data([0x00]) // zero unused trailing bits
        bitString.append(pkcs1)

        var body = Data()
        body.append(rsaAlgorithmIdentifier)
        body.append(encode(tag: Tag.bitString, contents: bitString))
        return encode(tag: Tag.sequence, contents: body)
    }

    // MARK: - Key size

    /// Bit length of the modulus in a PKCS#1 private key, for `kSecAttrKeySizeInBits`.
    ///
    /// The modulus is the second INTEGER of `RSAPrivateKey`; in a public key it is
    /// the first. Hard-coding 2048 breaks 3072/4096-bit accounts, so measure it.
    public static func rsaModulusBitCount(pkcs1PrivateKey der: Data) throws -> Int {
        let children = try sequenceChildren(der)
        guard children.count >= 2, children[1].tag == Tag.integer else {
            throw ASN1Error.unsupportedStructure("RSAPrivateKey has no modulus")
        }
        return bitCount(ofINTEGER: children[1].contents)
    }

    /// Bit length of the modulus in a PKCS#1 public key.
    public static func rsaModulusBitCount(pkcs1PublicKey der: Data) throws -> Int {
        let children = try sequenceChildren(der)
        guard let modulus = children.first, modulus.tag == Tag.integer else {
            throw ASN1Error.unsupportedStructure("RSAPublicKey has no modulus")
        }
        return bitCount(ofINTEGER: modulus.contents)
    }

    /// Bit length of a DER INTEGER's magnitude, ignoring the sign-padding zero.
    private static func bitCount(ofINTEGER contents: [UInt8]) -> Int {
        let magnitude = Array(contents.drop { $0 == 0x00 })
        guard let leading = magnitude.first else { return 0 }
        return (magnitude.count - 1) * 8 + (8 - leading.leadingZeroBitCount)
    }

    // MARK: - Writing

    private static func encode(tag: UInt8, contents: Data) -> Data {
        var out = Data([tag])
        out.append(encodeLength(contents.count))
        out.append(contents)
        return out
    }

    private static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }

        var lengthBytes = Data()
        var remaining = length
        while remaining > 0 {
            lengthBytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(lengthBytes.count)]) + lengthBytes
    }
}
