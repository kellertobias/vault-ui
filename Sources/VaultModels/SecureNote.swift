// MARK: - VaultModels/SecureNote.swift
// Secure note cipher sub-model

import Foundation

/// Secure note type.
public enum SecureNoteType: Int, Codable, Sendable {
    case generic = 0
}

/// Secure note-specific cipher data.
public struct SecureNoteData: Codable, Sendable, Equatable {
    public var type: SecureNoteType

    public init(type: SecureNoteType = .generic) {
        self.type = type
    }
}
