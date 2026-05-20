// MARK: - VaultModels/Card.swift
// Card cipher sub-model

import Foundation
import VaultCrypto

/// Card-specific cipher data.
public struct CardData: Codable, Sendable, Equatable {
    public var cardholderName: EncString?
    public var brand: EncString?
    public var number: EncString?
    public var expMonth: EncString?
    public var expYear: EncString?
    public var code: EncString?

    public init(
        cardholderName: EncString? = nil,
        brand: EncString? = nil,
        number: EncString? = nil,
        expMonth: EncString? = nil,
        expYear: EncString? = nil,
        code: EncString? = nil
    ) {
        self.cardholderName = cardholderName
        self.brand = brand
        self.number = number
        self.expMonth = expMonth
        self.expYear = expYear
        self.code = code
    }
}
