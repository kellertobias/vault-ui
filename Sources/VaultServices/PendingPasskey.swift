// MARK: - VaultServices/PendingPasskey.swift
// Pending passkeys to save from the AutoFill extension

import Foundation

/// A passkey generated in the AutoFill Extension that needs to be encrypted and saved by the main app.
public struct PendingPasskey: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    
    /// The ID of the existing cipher to assign this passkey to, or nil if a new cipher should be created.
    public let targetCipherId: String?
    
    /// Optional name for the new cipher if one is being created.
    public let targetCipherName: String?
    
    public let relyingPartyId: String
    public let userHandle: Data
    public let userName: String?
    public let credentialId: Data
    public let privateKeyBase64: String

    public let creationDate: Date

    /// The vault account this passkey belongs to (nil = active account / legacy).
    public let accountId: String?

    public init(id: String = UUID().uuidString, targetCipherId: String?, targetCipherName: String? = nil, relyingPartyId: String, userHandle: Data, userName: String?, credentialId: Data, privateKeyBase64: String, creationDate: Date = Date(), accountId: String? = nil) {
        self.id = id
        self.targetCipherId = targetCipherId
        self.targetCipherName = targetCipherName
        self.relyingPartyId = relyingPartyId
        self.userHandle = userHandle
        self.userName = userName
        self.credentialId = credentialId
        self.privateKeyBase64 = privateKeyBase64
        self.creationDate = creationDate
        self.accountId = accountId
    }
}
