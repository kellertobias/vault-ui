// MARK: - VaultModels/Identity.swift
// Identity cipher sub-model

import Foundation
import VaultCrypto

/// Identity-specific cipher data.
public struct IdentityData: Codable, Sendable, Equatable {
    public var title: EncString?
    public var firstName: EncString?
    public var middleName: EncString?
    public var lastName: EncString?
    public var address1: EncString?
    public var address2: EncString?
    public var address3: EncString?
    public var city: EncString?
    public var state: EncString?
    public var postalCode: EncString?
    public var country: EncString?
    public var company: EncString?
    public var email: EncString?
    public var phone: EncString?
    public var ssn: EncString?
    public var username: EncString?
    public var passportNumber: EncString?
    public var licenseNumber: EncString?

    public init() {}
}
