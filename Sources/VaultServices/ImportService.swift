// MARK: - VaultServices/ImportService.swift
// Import vault data from various sources

import Foundation
import VaultModels
import VaultCrypto
import CryptoKit
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
                        LoginUri(
                            uri: try encryptStr(uri.uri),
                            match: uri.match.flatMap { UriMatchType(rawValue: $0) }
                        )
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
                loginData.uris = [LoginUri(uri: try encryptStr(url), match: nil)]
            }

            cipher.login = loginData
            result.ciphers.append(cipher)
        }

        result.totalImported = result.ciphers.count
        logger.info("Imported \(result.totalImported) items from macOS Passwords CSV")
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
        guard let privateKeyString = String(data: privateKeyData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw ImportError.invalidFormat("SSH key is not valid UTF-8")
        }

        let itemKey = try SymmetricCryptoKey.generate()
        let encryptStr: (String) throws -> EncString = { value in
            try CipherEncryption.encrypt(string: value, key: itemKey)
        }

        // Detect key type
        let keyType: String
        if privateKeyString.contains("BEGIN OPENSSH PRIVATE KEY") {
            keyType = "OpenSSH"
        } else if privateKeyString.contains("BEGIN RSA PRIVATE KEY") {
            keyType = "RSA"
        } else if privateKeyString.contains("BEGIN EC PRIVATE KEY") {
            keyType = "ECDSA"
        } else {
            keyType = "Unknown"
        }

        // Build public key string
        var publicKeyString: String?
        if let pubData = publicKeyData {
            publicKeyString = String(data: pubData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        
        // If no public key data provided, extract from the private key
        if (publicKeyString ?? "").isEmpty {
            publicKeyString = extractPublicKeyFromOpenSSHPrivateKey(privateKeyString)
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
