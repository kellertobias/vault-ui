// MARK: - VaultServices/VaultAttachmentService.swift
// Encrypted Bitwarden attachment upload/download helpers.

import Foundation
import VaultAPI
import VaultCrypto
import VaultModels

public struct DecryptedAttachment: Sendable, Equatable {
    public let fileName: String
    public let data: Data

    public init(fileName: String, data: Data) {
        self.fileName = fileName
        self.data = data
    }
}

public enum VaultAttachmentService {
    @MainActor
    public static func uploadAttachment(
        to cipher: Cipher,
        fileURL: URL,
        session: SessionManager
    ) async throws -> Cipher? {
        guard let cipherId = cipher.id else {
            throw AttachmentTransferError.missingCipherId
        }

        let accessGranted = fileURL.startAccessingSecurityScopedResource()
        defer {
            if accessGranted {
                fileURL.stopAccessingSecurityScopedResource()
            }
        }

        let fileName = fileURL.lastPathComponent
        let rawData = try Data(contentsOf: fileURL)
        let itemKey = try session.getItemKey(for: cipher)
        let attachmentKey = try SymmetricCryptoKey.generate()

        let encryptedFileName = try CipherEncryption.encrypt(string: fileName, key: itemKey)
        let encryptedAttachmentKey = try CipherEncryption.encrypt(data: attachmentKey.keyData, key: itemKey)
        guard let encryptedPayload = try CipherEncryption.encrypt(data: rawData, key: attachmentKey)
            .serialized()
            .data(using: .utf8) else {
            throw AttachmentTransferError.invalidEncryptedPayload
        }

        let api = AttachmentAPI(client: try session.getAPIClient())
        let upload = try await api.requestUpload(
            cipherId: cipherId,
            fileName: encryptedFileName.serialized(),
            fileSize: encryptedPayload.count,
            key: encryptedAttachmentKey.serialized()
        )

        try await api.uploadFile(
            cipherId: cipherId,
            attachmentId: upload.attachmentId,
            data: encryptedPayload,
            fileName: encryptedFileName.serialized()
        )

        return upload.cipher
    }

    @MainActor
    public static func downloadAttachment(
        _ attachment: Attachment,
        from cipher: Cipher,
        session: SessionManager
    ) async throws -> DecryptedAttachment {
        guard let urlString = attachment.url,
              let url = URL(string: urlString) else {
            throw AttachmentTransferError.missingDownloadURL
        }
        guard let encryptedAttachmentKey = attachment.key else {
            throw AttachmentTransferError.missingAttachmentKey
        }

        let itemKey = try session.getItemKey(for: cipher)
        let attachmentKeyData = try CipherEncryption.decryptData(encryptedAttachmentKey, key: itemKey)
        let attachmentKey = try SymmetricCryptoKey(keyData: attachmentKeyData)
        let encryptedPayloadData = try await AttachmentAPI(client: try session.getAPIClient()).download(url: url)

        guard let serializedPayload = String(data: encryptedPayloadData, encoding: .utf8) else {
            throw AttachmentTransferError.invalidEncryptedPayload
        }

        let encryptedPayload = try EncString(serialized: serializedPayload)
        let decryptedData = try CipherEncryption.decryptData(encryptedPayload, key: attachmentKey)
        let decryptedFileName = attachment.fileName.flatMap { try? CipherEncryption.decryptString($0, key: itemKey) }
            ?? attachment.id
            ?? "attachment"

        return DecryptedAttachment(fileName: decryptedFileName, data: decryptedData)
    }
}

public enum AttachmentTransferError: LocalizedError {
    case missingCipherId
    case missingDownloadURL
    case missingAttachmentKey
    case invalidEncryptedPayload

    public var errorDescription: String? {
        switch self {
        case .missingCipherId:
            return "The item must be synced before a file can be attached."
        case .missingDownloadURL:
            return "The attachment has no download URL."
        case .missingAttachmentKey:
            return "The attachment has no encryption key."
        case .invalidEncryptedPayload:
            return "The encrypted attachment payload could not be decoded."
        }
    }
}
