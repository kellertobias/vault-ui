// MARK: - VaultModels/SSHKey.swift
// SSH key cipher sub-model

import Foundation
import VaultCrypto

/// SSH key-specific cipher data.
public struct SSHKeyData: Codable, Sendable, Equatable {
    /// The encrypted private key (PEM format)
    public var privateKey: EncString?

    /// The encrypted public key (OpenSSH format)
    public var publicKey: EncString?

    /// The key fingerprint (SHA256 hash, not encrypted — for display)
    public var keyFingerprint: EncString?

    public init(
        privateKey: EncString? = nil,
        publicKey: EncString? = nil,
        keyFingerprint: EncString? = nil
    ) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.keyFingerprint = keyFingerprint
    }
}
