// MARK: - VaultServices/ImportService.swift
// Import vault data from various sources

import Foundation
import VaultModels
import VaultCrypto
import CryptoKit
import AuthenticationServices
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "Import")

/// Service for importing vault data from external sources.
public enum ImportService {

    // MARK: - Bitwarden JSON Import

    /// Import from a Bitwarden JSON export (unencrypted).
    ///
    /// Bitwarden exports have this structure:
    /// ```json
    /// {
    ///   "encrypted": false,
    ///   "folders": [...],
    ///   "items": [...]
    /// }
    /// ```
    public static func importBitwardenJSON(
        data: Data,
        encryptionKey: SymmetricCryptoKey
    ) throws -> ImportResult {
        let export = try JSONDecoder().decode(BitwardenExport.self, from: data)

        // Reject encrypted exports — importing them without decryption first
        // would double-encrypt the data, making it permanently unrecoverable.
        guard export.encrypted != true else {
            throw ImportError.invalidFormat("This is an encrypted Bitwarden export. Please export as unencrypted JSON, or decrypt the export first.")
        }

        var result = ImportResult()

        // Import folders — encrypt the plaintext names
        for folder in export.folders ?? [] {
            guard let name = folder.name else { continue }
            let encName = try CipherEncryption.encrypt(string: name, key: encryptionKey)
            let importedFolder = Folder(
                id: folder.id ?? UUID().uuidString,
                name: encName,
                revisionDate: Date()
            )
            result.folders.append(importedFolder)
        }

        // Import items — encrypt all plaintext fields
        for item in export.items ?? [] {
            let cipher = try encryptBitwardenItem(item, key: encryptionKey)
            result.ciphers.append(cipher)
        }

        result.totalImported = result.ciphers.count + result.folders.count
        logger.info("Imported \(result.totalImported) items from Bitwarden JSON")
        return result
    }

    /// Encrypt a plaintext Bitwarden export item into a Cipher.
    private static func encryptBitwardenItem(
        _ item: BitwardenExportItem,
        key: SymmetricCryptoKey
    ) throws -> Cipher {
        let encryptStr: (String?) throws -> EncString? = { value in
            guard let v = value, !v.isEmpty else { return nil }
            return try CipherEncryption.encrypt(string: v, key: key)
        }

        let type = CipherType(rawValue: item.type ?? 1) ?? .login

        var cipher = Cipher(type: type)
        cipher.id = item.id ?? UUID().uuidString
        cipher.name = try encryptStr(item.name)
        cipher.notes = try encryptStr(item.notes)
        cipher.favorite = item.favorite ?? false
        cipher.folderId = item.folderId

        // Type-specific data
        switch type {
        case .login:
            if let login = item.login {
                var loginData = LoginData()
                loginData.username = try encryptStr(login.username)
                loginData.password = try encryptStr(login.password)
                loginData.totp = try encryptStr(login.totp)

                if let uris = login.uris {
                    loginData.uris = try uris.map { uri in
                        let match = uri.match.flatMap { UriMatchType(rawValue: $0) }
                        guard let value = uri.uri, !value.isEmpty else {
                            return LoginUri(uri: nil, match: match)
                        }
                        return try LoginUri.encrypted(value, match: match, key: key)
                    }
                }
                cipher.login = loginData
            }

        case .secureNote:
            cipher.secureNote = SecureNoteData(type: .generic)

        case .card:
            if let card = item.card {
                cipher.card = CardData(
                    cardholderName: try encryptStr(card.cardholderName),
                    brand: try encryptStr(card.brand),
                    number: try encryptStr(card.number),
                    expMonth: try encryptStr(card.expMonth),
                    expYear: try encryptStr(card.expYear),
                    code: try encryptStr(card.code)
                )
            }

        case .identity:
            if let id = item.identity {
                var identity = IdentityData()
                identity.title = try encryptStr(id.title)
                identity.firstName = try encryptStr(id.firstName)
                identity.middleName = try encryptStr(id.middleName)
                identity.lastName = try encryptStr(id.lastName)
                identity.username = try encryptStr(id.username)
                identity.company = try encryptStr(id.company)
                identity.email = try encryptStr(id.email)
                identity.phone = try encryptStr(id.phone)
                identity.address1 = try encryptStr(id.address1)
                identity.address2 = try encryptStr(id.address2)
                identity.city = try encryptStr(id.city)
                identity.state = try encryptStr(id.state)
                identity.postalCode = try encryptStr(id.postalCode)
                identity.country = try encryptStr(id.country)
                identity.ssn = try encryptStr(id.ssn)
                identity.passportNumber = try encryptStr(id.passportNumber)
                identity.licenseNumber = try encryptStr(id.licenseNumber)
                cipher.identity = identity
            }

        case .sshKey:
            break // SSH keys aren't in standard Bitwarden exports
        }

        // Custom fields
        if let fields = item.fields {
            cipher.fields = try fields.map { field in
                CustomField(
                    name: try encryptStr(field.name),
                    value: try encryptStr(field.value),
                    type: FieldType(rawValue: field.type ?? 0) ?? .text,
                    linkedId: nil
                )
            }
        }

        return cipher
    }

    // MARK: - macOS Passwords CSV Import

    /// Import from macOS Passwords app CSV export.
    ///
    /// macOS Passwords exports with columns:
    /// Title, URL, Username, Password, Notes, OTPAuth
    public static func importMacOSPasswordsCSV(
        data: Data,
        encryptionKey: SymmetricCryptoKey
    ) throws -> ImportResult {
        guard let csvString = String(data: data, encoding: .utf8) else {
            throw ImportError.invalidFormat("Cannot read CSV as UTF-8")
        }

        let rows = parseCSV(csvString)
        guard rows.count > 1 else {
            throw ImportError.invalidFormat("CSV is empty or has no data rows")
        }

        // Detect header row
        let headers = rows[0].map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
        let titleIdx = headers.firstIndex(of: "title") ?? headers.firstIndex(of: "name")
        let urlIdx = headers.firstIndex(of: "url") ?? headers.firstIndex(of: "website")
        let usernameIdx = headers.firstIndex(of: "username") ?? headers.firstIndex(of: "user")
        let passwordIdx = headers.firstIndex(of: "password")
        let notesIdx = headers.firstIndex(of: "notes") ?? headers.firstIndex(of: "note")
        let otpIdx = headers.firstIndex(of: "otpauth") ?? headers.firstIndex(of: "otp") ?? headers.firstIndex(of: "totp")

        var result = ImportResult()

        let encryptStr: (String?) throws -> EncString? = { value in
            guard let v = value, !v.isEmpty else { return nil }
            return try CipherEncryption.encrypt(string: v, key: encryptionKey)
        }

        for i in 1..<rows.count {
            let cols = rows[i]
            guard !cols.allSatisfy({ $0.isEmpty }) else { continue }

            let title = titleIdx.flatMap { $0 < cols.count ? cols[$0] : nil } ?? "Imported"
            let url = urlIdx.flatMap { $0 < cols.count ? cols[$0] : nil }
            let username = usernameIdx.flatMap { $0 < cols.count ? cols[$0] : nil }
            let password = passwordIdx.flatMap { $0 < cols.count ? cols[$0] : nil }
            let notes = notesIdx.flatMap { $0 < cols.count ? cols[$0] : nil }
            let otp = otpIdx.flatMap { $0 < cols.count ? cols[$0] : nil }

            var cipher = Cipher(type: .login)
            cipher.id = UUID().uuidString
            cipher.name = try encryptStr(title)
            cipher.notes = try encryptStr(notes)

            var loginData = LoginData()
            loginData.username = try encryptStr(username)
            loginData.password = try encryptStr(password)
            loginData.totp = try encryptStr(otp)

            if let url = url, !url.isEmpty {
                loginData.uris = [try LoginUri.encrypted(url, key: encryptionKey)]
            }

            cipher.login = loginData
            result.ciphers.append(cipher)
        }

        result.totalImported = result.ciphers.count
        logger.info("Imported \(result.totalImported) items from macOS Passwords CSV")
        return result
    }

    // MARK: - Apple Direct Import
    
    @available(macOS 26.0, iOS 26.0, *)
    public static func importAppleCredentialExchange(
        exportedData: ASExportedCredentialData,
        encryptionKey: SymmetricCryptoKey
    ) throws -> ImportResult {
        var result = ImportResult()
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .short
        let importDateString = dateFormatter.string(from: Date())
        
        let encryptStr: (String?) throws -> EncString? = { value in
            guard let v = value, !v.isEmpty else { return nil }
            return try CipherEncryption.encrypt(string: v, key: encryptionKey)
        }
        
        for account in exportedData.accounts {
            for item in account.items {
                var cipher = Cipher(type: .login)
                cipher.id = UUID().uuidString
                cipher.name = try encryptStr(item.title)
                
                let existingNotes = item.subtitle ?? ""
                let importNote = "Imported from Apple Passwords on \(importDateString)"
                let newNotes = existingNotes.isEmpty ? importNote : "\(existingNotes)\n\n\(importNote)"
                cipher.notes = try encryptStr(newNotes)
                
                cipher.favorite = item.favorite
                
                var loginData = LoginData()
                
                if let scope = item.scope {
                    loginData.uris = try scope.urls.compactMap { url in
                        let value = url.absoluteString
                        guard !value.isEmpty else { return nil }
                        return try LoginUri.encrypted(value, key: encryptionKey)
                    }
                }
                
                for credential in item.credentials {
                    switch credential {
                    case .basicAuthentication(let basic):
                        if let u = basic.userName?.value {
                            loginData.username = try encryptStr(u)
                        }
                        if let p = basic.password?.value {
                            loginData.password = try encryptStr(p)
                        }
                    case .passkey(let passkey):
                        loginData.username = try encryptStr(passkey.userName)
                        var fido = Fido2Credential()
                        fido.credentialId = try encryptStr(passkey.credentialID.bitwardenFido2CredentialId())
                        fido.keyType = try encryptStr("public-key")
                        fido.keyAlgorithm = try encryptStr("ECDSA")
                        fido.keyCurve = try encryptStr("P-256")
                        fido.rpId = try encryptStr(passkey.relyingPartyIdentifier)
                        fido.rpName = try encryptStr(passkey.relyingPartyIdentifier)
                        fido.userName = try encryptStr(passkey.userName)
                        fido.userDisplayName = try encryptStr(passkey.userDisplayName)
                        fido.userHandle = try encryptStr(passkey.userHandle.base64URLEncodedString())
                        fido.keyValue = try encryptStr(passkey.key.base64URLEncodedString())
                        fido.discoverable = try encryptStr("true")
                        fido.counter = try encryptStr("0")
                        fido.creationDate = Date()
                        loginData.fido2Credentials = [fido]
                        
                        // Fallback to RPID for website URI if none was provided by scope
                        if loginData.uris == nil || loginData.uris!.isEmpty {
                            loginData.uris = [
                                try LoginUri.encrypted("https://\(passkey.relyingPartyIdentifier)", key: encryptionKey),
                            ]
                        }
                    case .totp(let totp):
                        let base32 = base32Encode(totp.secret)
                        loginData.totp = try encryptStr(base32)
                    default:
                        break
                    }
                }
                
                cipher.login = loginData
                result.ciphers.append(cipher)
            }
        }
        
        result.totalImported = result.ciphers.count
        logger.info("Imported \(result.totalImported) items from Apple Direct Import")
        return result
    }

    /// Helper to convert Data to Base32 string (needed for Bitwarden TOTP)
    private static func base32Encode(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var result = ""
        var buffer: UInt32 = 0
        var bitsLeft: Int = 0
        
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitsLeft += 8
            
            while bitsLeft >= 5 {
                let index = Int((buffer >> (bitsLeft - 5)) & 0x1F)
                result.append(alphabet[index])
                bitsLeft -= 5
            }
        }
        
        if bitsLeft > 0 {
            let index = Int((buffer << (5 - bitsLeft)) & 0x1F)
            result.append(alphabet[index])
        }
        
        let paddingLength = (8 - (result.count % 8)) % 8
        if paddingLength < 8 {
            result += String(repeating: "=", count: paddingLength)
        }
        
        return result
    }

    // MARK: - SSH Key Import

    /// Import an SSH key file into the vault.
    public static func importSSHKey(
        privateKeyData: Data,
        publicKeyData: Data?,
        name: String,
        encryptionKey: SymmetricCryptoKey
    ) throws -> Cipher {
        guard let rawKeyString = String(data: privateKeyData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw ImportError.invalidFormat("SSH key is not valid UTF-8")
        }

        // Normalize format (auto-converts PKCS#1 RSA to OpenSSH)
        let processed = processImportedSSHKey(rawKeyString)
        let privateKeyString = processed.privateKey

        let itemKey = try SymmetricCryptoKey.generate()
        let encryptStr: (String) throws -> EncString = { value in
            try CipherEncryption.encrypt(string: value, key: itemKey)
        }

        // Detect key type (for logging)
        let keyType: String
        if privateKeyString.contains("BEGIN OPENSSH PRIVATE KEY") {
            keyType = rawKeyString.contains("BEGIN RSA PRIVATE KEY") ? "RSA (converted)" : "OpenSSH"
        } else if privateKeyString.contains("BEGIN RSA PRIVATE KEY") {
            keyType = "RSA"
        } else if privateKeyString.contains("BEGIN EC PRIVATE KEY") {
            keyType = "ECDSA"
        } else {
            keyType = "Unknown"
        }

        // Build public key string: prefer provided data, then extracted from private key
        var publicKeyString: String?
        if let pubData = publicKeyData {
            publicKeyString = String(data: pubData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if (publicKeyString ?? "").isEmpty {
            publicKeyString = processed.publicKey
        }

        // Compute fingerprint from public key
        let fingerprint = publicKeyString.flatMap { computeSSHFingerprint($0) }

        var cipher = Cipher(type: .sshKey)
        cipher.id = UUID().uuidString
        cipher.name = try encryptStr(name)
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: encryptionKey)
        cipher.sshKey = SSHKeyData(
            privateKey: try encryptStr(privateKeyString),
            publicKey: publicKeyString.map { try? encryptStr($0) } ?? nil,
            keyFingerprint: fingerprint.map { try? encryptStr($0) } ?? nil
        )

        logger.info("Imported SSH key: \(name) (\(keyType))")
        return cipher
    }

    /// Generate a new Ed25519 SSH key pair.
    public static func generateSSHKey(
        name: String,
        comment: String = "",
        encryptionKey: SymmetricCryptoKey
    ) throws -> (cipher: Cipher, publicKeyString: String) {
        // Generate Ed25519 key pair using CryptoKit
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        // Format as OpenSSH public key
        let publicKeyBlob = formatEd25519PublicKeyBlob(publicKey.rawRepresentation)
        let publicKeyBase64 = publicKeyBlob.base64EncodedString()
        let publicKeyString = "ssh-ed25519 \(publicKeyBase64) \(comment)".trimmingCharacters(in: .whitespaces)

        // Format as OpenSSH private key
        let privateKeyPEM = formatOpenSSHPrivateKey(
            privateKey: privateKey.rawRepresentation,
            publicKey: publicKey.rawRepresentation,
            comment: comment
        )

        let fingerprint = computeSSHFingerprint(publicKeyString) ?? ""

        let itemKey = try SymmetricCryptoKey.generate()
        let encryptStr: (String) throws -> EncString = { value in
            try CipherEncryption.encrypt(string: value, key: itemKey)
        }

        var cipher = Cipher(type: .sshKey)
        cipher.id = UUID().uuidString
        cipher.name = try encryptStr(name)
        cipher.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: encryptionKey)
        cipher.sshKey = SSHKeyData(
            privateKey: try encryptStr(privateKeyPEM),
            publicKey: try encryptStr(publicKeyString),
            keyFingerprint: try encryptStr(fingerprint)
        )

        return (cipher, publicKeyString)
    }

    // MARK: - SSH Key Helpers

    /// Format an Ed25519 public key as an SSH wire-format blob.
    public static func formatEd25519PublicKeyBlob(_ rawPublicKey: Data) -> Data {
        var blob = Data()
        let keyType = "ssh-ed25519"
        // string key_type
        var typeLen = UInt32(keyType.utf8.count).bigEndian
        blob.append(Data(bytes: &typeLen, count: 4))
        blob.append(Data(keyType.utf8))
        // string public_key
        var keyLen = UInt32(rawPublicKey.count).bigEndian
        blob.append(Data(bytes: &keyLen, count: 4))
        blob.append(rawPublicKey)
        return blob
    }

    /// Format an Ed25519 keypair as OpenSSH private key PEM.
    public static func formatOpenSSHPrivateKey(
        privateKey: Data,
        publicKey: Data,
        comment: String
    ) -> String {
        let magic = "openssh-key-v1\0"
        var data = Data(magic.utf8)

        func writeString(_ s: Data) {
            var len = UInt32(s.count).bigEndian
            data.append(Data(bytes: &len, count: 4))
            data.append(s)
        }

        func writeStringUTF8(_ s: String) {
            writeString(Data(s.utf8))
        }

        // ciphername, kdfname, kdfoptions (none = unencrypted)
        writeStringUTF8("none")
        writeStringUTF8("none")
        writeString(Data())  // empty kdf options

        // number of keys
        var numKeys: UInt32 = 1
        var numKeysBE = numKeys.bigEndian
        data.append(Data(bytes: &numKeysBE, count: 4))

        // public key blob
        let pubBlob = formatEd25519PublicKeyBlob(publicKey)
        writeString(pubBlob)

        // private section
        var privSection = Data()
        func privWriteString(_ s: Data) {
            var len = UInt32(s.count).bigEndian
            privSection.append(Data(bytes: &len, count: 4))
            privSection.append(s)
        }
        func privWriteStringUTF8(_ s: String) {
            privWriteString(Data(s.utf8))
        }

        // Check integers (random, must match)
        let check = UInt32.random(in: 0...UInt32.max)
        var checkBE = check.bigEndian
        privSection.append(Data(bytes: &checkBE, count: 4))
        privSection.append(Data(bytes: &checkBE, count: 4))

        // Key type
        privWriteStringUTF8("ssh-ed25519")

        // Public key
        privWriteString(publicKey)

        // Private key (64 bytes: 32 private + 32 public)
        privWriteString(privateKey + publicKey)

        // Comment
        privWriteStringUTF8(comment)

        // Padding (1, 2, 3, ...)
        let padLen = (8 - (privSection.count % 8)) % 8
        for i in 1...max(padLen, 1) {
            if padLen > 0 {
                privSection.append(UInt8(i))
            }
        }

        writeString(privSection)

        // Encode to PEM
        let base64 = data.base64EncodedString(options: .lineLength76Characters)
        return """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(base64)
        -----END OPENSSH PRIVATE KEY-----
        """
    }

    /// Extract the public key line from an OpenSSH private key PEM string.
    ///
    /// OpenSSH private key format:
    /// ```
    /// "openssh-key-v1\0" || string ciphername || string kdfname ||
    /// string kdfoptions || uint32 number-of-keys ||
    /// string public-key-blob || string private-key-blob
    /// ```
    /// The public key blob is in SSH wire format: `string key-type || string key-data`
    public static func extractPublicKeyFromOpenSSHPrivateKey(_ pem: String) -> String? {
        // Strip PEM armor
        let lines = pem.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64String = lines.joined()
        guard let data = Data(base64Encoded: base64String) else { return nil }
        
        let magic = "openssh-key-v1\0"
        guard data.count > magic.utf8.count else { return nil }
        
        // Verify magic
        let magicData = Data(magic.utf8)
        guard data.prefix(magicData.count) == magicData else { return nil }
        
        var offset = magicData.count
        
        // Helper to read a uint32 big-endian (safe byte-by-byte)
        func readUInt32() -> UInt32? {
            guard offset + 4 <= data.count else { return nil }
            let value = UInt32(data[offset]) << 24
                      | UInt32(data[offset+1]) << 16
                      | UInt32(data[offset+2]) << 8
                      | UInt32(data[offset+3])
            offset += 4
            return value
        }
        
        // Helper to read a string (uint32 length + bytes)
        func readString() -> Data? {
            guard let len = readUInt32() else { return nil }
            let length = Int(len)
            guard length >= 0, offset + length <= data.count else { return nil }
            let result = Data(data[offset..<offset+length])
            offset += length
            return result
        }
        
        // Skip: ciphername, kdfname, kdfoptions
        guard readString() != nil else { return nil }  // ciphername
        guard readString() != nil else { return nil }  // kdfname
        guard readString() != nil else { return nil }  // kdfoptions
        
        // Read number of keys
        guard let numKeys = readUInt32(), numKeys >= 1 else { return nil }
        
        // Read public key blob
        guard let pubBlob = readString() else { return nil }
        
        // The public key blob is in SSH wire format: string key-type || string key-data
        // Parse the key type from the blob
        var blobOffset = 0
        func readBlobUInt32() -> UInt32? {
            guard blobOffset + 4 <= pubBlob.count else { return nil }
            let value = UInt32(pubBlob[blobOffset]) << 24
                      | UInt32(pubBlob[blobOffset+1]) << 16
                      | UInt32(pubBlob[blobOffset+2]) << 8
                      | UInt32(pubBlob[blobOffset+3])
            blobOffset += 4
            return value
        }
        func readBlobString() -> Data? {
            guard let len = readBlobUInt32() else { return nil }
            let length = Int(len)
            guard length >= 0, blobOffset + length <= pubBlob.count else { return nil }
            let result = Data(pubBlob[blobOffset..<blobOffset+length])
            blobOffset += length
            return result
        }
        
        guard let keyTypeData = readBlobString(),
              let keyType = String(data: keyTypeData, encoding: .utf8) else { return nil }
        
        // Return as "key-type base64(blob)"
        return "\(keyType) \(pubBlob.base64EncodedString())"
    }

    /// Compute SSH key fingerprint (SHA-256).
    public static func computeSSHFingerprint(_ publicKeyLine: String) -> String? {
        let parts = publicKeyLine.split(separator: " ")
        guard parts.count >= 2,
              let keyData = Data(base64Encoded: String(parts[1])) else {
            return nil
        }

        let hash = SHA256.hash(data: keyData)
        let base64 = Data(hash).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        return "SHA256:\(base64)"
    }

    // MARK: - PKCS#1 RSA Key Conversion

    /// RSA key components from a PKCS#1 DER structure.
    private struct RSAComponents {
        let n: Data      // modulus
        let e: Data      // public exponent
        let d: Data      // private exponent
        let p: Data      // prime1
        let q: Data      // prime2
        let dp: Data     // d mod (p-1)
        let dq: Data     // d mod (q-1)
        let iqmp: Data   // q^(-1) mod p
    }

    /// Parse an ASN.1 DER length field.
    /// Returns (length, bytesConsumed) or nil.
    private static func parseDERLength(_ data: Data, at offset: Int) -> (Int, Int)? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        if first < 0x80 {
            return (Int(first), 1)
        }
        let numBytes = Int(first & 0x7F)
        guard numBytes > 0, numBytes <= 4, offset + 1 + numBytes <= data.count else { return nil }
        var length = 0
        for i in 0..<numBytes {
            length = (length << 8) | Int(data[offset + 1 + i])
        }
        return (length, 1 + numBytes)
    }

    /// Parse an ASN.1 DER INTEGER, returning its value bytes and total consumed bytes.
    private static func parseDERInteger(_ data: Data, at offset: Int) -> (Data, Int)? {
        guard offset < data.count, data[offset] == 0x02 else { return nil }  // INTEGER tag
        guard let (length, lenConsumed) = parseDERLength(data, at: offset + 1) else { return nil }
        let valueStart = offset + 1 + lenConsumed
        guard valueStart + length <= data.count else { return nil }
        return (Data(data[valueStart..<valueStart + length]), 1 + lenConsumed + length)
    }

    /// Parse a PKCS#1 RSAPrivateKey DER structure.
    ///
    /// ```
    /// RSAPrivateKey ::= SEQUENCE {
    ///   version, n, e, d, p, q, dp, dq, iqmp : INTEGER
    /// }
    /// ```
    private static func parsePKCS1DER(_ der: Data) -> RSAComponents? {
        guard der.count > 2, der[0] == 0x30 else { return nil }  // SEQUENCE tag
        guard let (_, seqLenConsumed) = parseDERLength(der, at: 1) else { return nil }
        var offset = 1 + seqLenConsumed

        // Skip version (INTEGER, should be 0)
        guard let (_, versionConsumed) = parseDERInteger(der, at: offset) else { return nil }
        offset += versionConsumed

        // Parse 8 integers: n, e, d, p, q, dp, dq, iqmp
        var integers: [Data] = []
        for _ in 0..<8 {
            guard let (value, consumed) = parseDERInteger(der, at: offset) else { return nil }
            integers.append(value)
            offset += consumed
        }

        return RSAComponents(
            n: integers[0], e: integers[1], d: integers[2],
            p: integers[3], q: integers[4],
            dp: integers[5], dq: integers[6], iqmp: integers[7]
        )
    }

    /// Strip PEM armor and optional encryption headers, returning the base64-decoded DER data.
    private static func decodePEM(_ pem: String) -> Data? {
        let lines = pem.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter {
                !$0.hasPrefix("-----") &&
                !$0.hasPrefix("Proc-Type") &&
                !$0.hasPrefix("DEK-Info") &&
                !$0.isEmpty
            }
        return Data(base64Encoded: lines.joined())
    }

    /// Convert a PKCS#1 RSA private key PEM to OpenSSH format.
    ///
    /// Input:  `-----BEGIN RSA PRIVATE KEY-----`
    /// Output: `-----BEGIN OPENSSH PRIVATE KEY-----`
    ///
    /// Passphrase-encrypted PKCS#1 keys are not supported (returns nil).
    public static func convertPKCS1ToOpenSSH(_ pem: String) -> String? {
        // Encrypted PKCS#1 keys have Proc-Type/DEK-Info headers
        if pem.contains("ENCRYPTED") { return nil }

        guard let der = decodePEM(pem) else { return nil }
        guard let rsa = parsePKCS1DER(der) else { return nil }

        // Helper to append a big-endian uint32
        func appendUInt32(_ value: UInt32, to data: inout Data) {
            data.append(UInt8((value >> 24) & 0xFF))
            data.append(UInt8((value >> 16) & 0xFF))
            data.append(UInt8((value >> 8) & 0xFF))
            data.append(UInt8(value & 0xFF))
        }
        // Helper to write a length-prefixed string/blob
        func appendString(_ s: Data, to data: inout Data) {
            appendUInt32(UInt32(s.count), to: &data)
            data.append(s)
        }

        // --- Build outer structure ---
        var out = Data("openssh-key-v1\0".utf8)

        // ciphername, kdfname, kdfoptions (unencrypted)
        appendString(Data("none".utf8), to: &out)
        appendString(Data("none".utf8), to: &out)
        appendString(Data(), to: &out)

        // number of keys
        appendUInt32(1, to: &out)

        // --- Public key blob: string "ssh-rsa" || mpint e || mpint n ---
        var pubBlob = Data()
        appendString(Data("ssh-rsa".utf8), to: &pubBlob)
        appendString(rsa.e, to: &pubBlob)  // ASN.1 integer bytes match SSH mpint encoding
        appendString(rsa.n, to: &pubBlob)
        appendString(pubBlob, to: &out)

        // --- Private section ---
        var priv = Data()
        let check = UInt32.random(in: 0...UInt32.max)
        appendUInt32(check, to: &priv)
        appendUInt32(check, to: &priv)

        appendString(Data("ssh-rsa".utf8), to: &priv)
        appendString(rsa.n, to: &priv)
        appendString(rsa.e, to: &priv)
        appendString(rsa.d, to: &priv)
        appendString(rsa.iqmp, to: &priv)
        appendString(rsa.p, to: &priv)
        appendString(rsa.q, to: &priv)
        appendString(Data("".utf8), to: &priv)  // comment

        // Padding (1, 2, 3, ...)
        let padLen = (8 - (priv.count % 8)) % 8
        for i in 1...max(padLen, 1) {
            if padLen > 0 { priv.append(UInt8(i)) }
        }

        appendString(priv, to: &out)

        let base64 = out.base64EncodedString(options: .lineLength76Characters)
        return """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(base64)
        -----END OPENSSH PRIVATE KEY-----
        """
    }

    /// Extract the public key from a PKCS#1 RSA private key PEM.
    /// Returns `"ssh-rsa {base64(blob)}"` or nil.
    public static func extractPublicKeyFromPKCS1(_ pem: String) -> String? {
        if pem.contains("ENCRYPTED") { return nil }
        guard let der = decodePEM(pem) else { return nil }
        guard let rsa = parsePKCS1DER(der) else { return nil }

        // Build SSH public key blob: string "ssh-rsa" || mpint e || mpint n
        var blob = Data()
        func appendUInt32(_ value: UInt32) {
            blob.append(UInt8((value >> 24) & 0xFF))
            blob.append(UInt8((value >> 16) & 0xFF))
            blob.append(UInt8((value >> 8) & 0xFF))
            blob.append(UInt8(value & 0xFF))
        }
        func appendString(_ s: Data) {
            appendUInt32(UInt32(s.count))
            blob.append(s)
        }

        appendString(Data("ssh-rsa".utf8))
        appendString(rsa.e)
        appendString(rsa.n)

        return "ssh-rsa \(blob.base64EncodedString())"
    }

    // MARK: - Unified SSH Key Processing

    /// Process an imported SSH private key: normalize to OpenSSH format and extract public key.
    ///
    /// Handles:
    /// - OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`): passed through, public key extracted
    /// - PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`): converted to OpenSSH, public key extracted
    /// - Other formats: passed through as-is
    ///
    /// Returns `(normalizedPrivateKey, publicKeyLine?)`.
    public static func processImportedSSHKey(_ privateKeyPEM: String) -> (privateKey: String, publicKey: String?) {
        let trimmed = privateKeyPEM.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.contains("BEGIN RSA PRIVATE KEY") {
            if let converted = convertPKCS1ToOpenSSH(trimmed) {
                let pubKey = extractPublicKeyFromPKCS1(trimmed)
                return (converted, pubKey)
            }
            // Conversion failed (e.g., encrypted key) — return as-is
            return (trimmed, nil)
        }

        if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
            let pubKey = extractPublicKeyFromOpenSSHPrivateKey(trimmed)
            return (trimmed, pubKey)
        }

        // Unknown format — return as-is
        return (trimmed, nil)
    }

    // MARK: - CSV Parser

    /// Simple RFC 4180 CSV parser with quoted field support.
    static func parseCSV(_ input: String) -> [[String]] {
        var rows: [[String]] = []
        var currentRow: [String] = []
        var currentField = ""
        var inQuotes = false

        let chars = Array(input)
        var i = 0

        while i < chars.count {
            let c = chars[i]

            if inQuotes {
                if c == "\"" {
                    if i + 1 < chars.count && chars[i + 1] == "\"" {
                        currentField.append("\"")
                        i += 2
                        continue
                    } else {
                        inQuotes = false
                    }
                } else {
                    currentField.append(c)
                }
            } else {
                if c == "\"" {
                    inQuotes = true
                } else if c == "," {
                    currentRow.append(currentField)
                    currentField = ""
                } else if c == "\n" || (c == "\r" && i + 1 < chars.count && chars[i + 1] == "\n") {
                    currentRow.append(currentField)
                    currentField = ""
                    rows.append(currentRow)
                    currentRow = []
                    if c == "\r" { i += 1 }
                } else {
                    currentField.append(c)
                }
            }
            i += 1
        }

        // Last field/row
        if !currentField.isEmpty || !currentRow.isEmpty {
            currentRow.append(currentField)
            rows.append(currentRow)
        }

        return rows
    }
}

// MARK: - Import Models

/// Result of an import operation.
public struct ImportResult: Sendable {
    public var ciphers: [Cipher] = []
    public var folders: [Folder] = []
    public var totalImported: Int = 0
    public var warnings: [String] = []

    public init(
        ciphers: [Cipher] = [],
        folders: [Folder] = [],
        totalImported: Int = 0,
        warnings: [String] = []
    ) {
        self.ciphers = ciphers
        self.folders = folders
        self.totalImported = totalImported
        self.warnings = warnings
    }
}

/// Import errors.
public enum ImportError: Error, LocalizedError {
    case invalidFormat(String)
    case encryptionError(String)
    case fileNotFound(String)

    public var errorDescription: String? {
        switch self {
        case .invalidFormat(let msg): return "Invalid format: \(msg)"
        case .encryptionError(let msg): return "Encryption error: \(msg)"
        case .fileNotFound(let path): return "File not found: \(path)"
        }
    }
}

// MARK: - Bitwarden Export Format

/// Bitwarden JSON export root.
struct BitwardenExport: Decodable {
    let encrypted: Bool?
    let folders: [BitwardenExportFolder]?
    let items: [BitwardenExportItem]?
}

struct BitwardenExportFolder: Decodable {
    let id: String?
    let name: String?
}

struct BitwardenExportItem: Decodable {
    let id: String?
    let folderId: String?
    let organizationId: String?
    let type: Int?
    let name: String?
    let notes: String?
    let favorite: Bool?
    let login: BitwardenExportLogin?
    let card: BitwardenExportCard?
    let identity: BitwardenExportIdentity?
    let fields: [BitwardenExportField]?
}

struct BitwardenExportLogin: Decodable {
    let username: String?
    let password: String?
    let totp: String?
    let uris: [BitwardenExportUri]?
}

struct BitwardenExportUri: Decodable {
    let uri: String?
    let match: Int?
}

struct BitwardenExportCard: Decodable {
    let cardholderName: String?
    let brand: String?
    let number: String?
    let expMonth: String?
    let expYear: String?
    let code: String?
}

struct BitwardenExportIdentity: Decodable {
    let title: String?
    let firstName: String?
    let middleName: String?
    let lastName: String?
    let username: String?
    let company: String?
    let email: String?
    let phone: String?
    let address1: String?
    let address2: String?
    let city: String?
    let state: String?
    let postalCode: String?
    let country: String?
    let ssn: String?
    let passportNumber: String?
    let licenseNumber: String?
}

struct BitwardenExportField: Decodable {
    let name: String?
    let value: String?
    let type: Int?
}
