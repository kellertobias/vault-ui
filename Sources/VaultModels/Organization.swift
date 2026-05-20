// MARK: - VaultModels/Organization.swift
// Organization and profile models

import Foundation
import VaultCrypto

/// An organization the user belongs to.
public struct Organization: Codable, Sendable, Identifiable, Equatable {
    public var id: String?
    public var name: String?
    public var key: EncString?
    public var status: Int?
    public var type: Int?
    public var enabled: Bool?
    public var usePolicies: Bool?
    public var useTotp: Bool?
    public var selfHost: Bool?
    public var hasPublicAndPrivateKeys: Bool?
    public var identifier: String?

    public init(id: String? = nil, name: String? = nil) {
        self.id = id
        self.name = name
    }
}

/// User profile data returned from sync.
public struct Profile: Codable, Sendable, Equatable {
    public var id: String?
    public var name: String?
    public var email: String?
    public var emailVerified: Bool?
    public var premium: Bool?
    public var masterPasswordHint: String?
    public var culture: String?
    public var twoFactorEnabled: Bool?
    public var key: EncString?
    public var privateKey: EncString?
    public var securityStamp: String?
    public var organizations: [Organization]?

    public init() {}
}
