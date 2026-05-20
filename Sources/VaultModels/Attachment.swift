// MARK: - VaultModels/Attachment.swift
// File attachment model

import Foundation
import VaultCrypto

/// A file attachment on a cipher.
public struct Attachment: Codable, Sendable, Equatable, Identifiable {
    public var id: String?
    public var url: String?
    public var fileName: EncString?
    public var key: EncString?
    public var size: String?
    public var sizeName: String?

    public init(
        id: String? = nil,
        url: String? = nil,
        fileName: EncString? = nil,
        key: EncString? = nil,
        size: String? = nil,
        sizeName: String? = nil
    ) {
        self.id = id
        self.url = url
        self.fileName = fileName
        self.key = key
        self.size = size
        self.sizeName = sizeName
    }
}
