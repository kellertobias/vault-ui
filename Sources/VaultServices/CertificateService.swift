// MARK: - VaultServices/CertificateService.swift
// Certificate metadata helpers for PFX/P12 login attachments.

import Foundation
import Security
import CryptoKit
import VaultModels
import VaultCrypto

public struct CertificateMetadata: Codable, Sendable, Equatable {
    public static let expiryFieldName = "vaultui-certificate-expires-at"
    public static let subjectFieldName = "vaultui-certificate-subject"
    public static let fingerprintFieldName = "vaultui-certificate-sha256"
    public static let fileNameFieldName = "vaultui-certificate-file-name"

    public let expiresAt: Date?
    public let subject: String?
    public let fingerprintSHA256: String?
    public let fileName: String?

    private nonisolated(unsafe) static let dateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    public init(expiresAt: Date?, subject: String?, fingerprintSHA256: String?, fileName: String?) {
        self.expiresAt = expiresAt
        self.subject = subject
        self.fingerprintSHA256 = fingerprintSHA256
        self.fileName = fileName
    }

    public var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt < Date()
    }

    public var expiresSoon: Bool {
        guard let expiresAt else { return false }
        let warningDate = Calendar.current.date(byAdding: .day, value: 30, to: Date()) ?? Date()
        return expiresAt < warningDate && !isExpired
    }

    public static func isCertificateField(_ name: String) -> Bool {
        [
            expiryFieldName,
            subjectFieldName,
            fingerprintFieldName,
            fileNameFieldName
        ].contains(name)
    }

    public static func isCertificateFileName(_ fileName: String) -> Bool {
        let lower = fileName.lowercased()
        return lower.hasSuffix(".pfx") || lower.hasSuffix(".p12")
    }

    public static func extract(from data: Data, password: String, fileName: String? = nil) throws -> CertificateMetadata {
        var importedItems: CFArray?
        let options = [kSecImportExportPassphrase as String: password] as CFDictionary
        let status = SecPKCS12Import(data as CFData, options, &importedItems)
        guard status == errSecSuccess,
              let items = importedItems as? [[String: Any]],
              let firstItem = items.first,
              let identityValue = firstItem[kSecImportItemIdentity as String] else {
            throw CertificateError.importFailed(status)
        }
        let identity = identityValue as! SecIdentity

        var certificate: SecCertificate?
        let certStatus = SecIdentityCopyCertificate(identity, &certificate)
        guard certStatus == errSecSuccess, let certificate else {
            throw CertificateError.certificateMissing(certStatus)
        }

        return CertificateMetadata(
            expiresAt: certificateNotAfter(certificate),
            subject: SecCertificateCopySubjectSummary(certificate) as String?,
            fingerprintSHA256: sha256Fingerprint(for: certificate),
            fileName: fileName
        )
    }

    public static func read(
        fields: [CustomField]?,
        decrypt: (EncString?) -> String?
    ) -> CertificateMetadata? {
        guard let fields else { return nil }

        var values: [String: String] = [:]
        for field in fields {
            guard let name = decrypt(field.name),
                  isCertificateField(name),
                  let value = decrypt(field.value),
                  !value.isEmpty else { continue }
            values[name] = value
        }

        if values.isEmpty { return nil }
        let expiresAt = values[expiryFieldName].flatMap { dateFormatter.date(from: $0) }

        return CertificateMetadata(
            expiresAt: expiresAt,
            subject: values[subjectFieldName],
            fingerprintSHA256: values[fingerprintFieldName],
            fileName: values[fileNameFieldName]
        )
    }

    public func encryptedFields(encrypt: (String) throws -> EncString?) rethrows -> [CustomField] {
        var fields: [CustomField] = []

        if let expiresAt {
            fields.append(CustomField(
                name: try encrypt(Self.expiryFieldName),
                value: try encrypt(Self.string(from: expiresAt)),
                type: .hidden
            ))
        }
        if let subject, !subject.isEmpty {
            fields.append(CustomField(
                name: try encrypt(Self.subjectFieldName),
                value: try encrypt(subject),
                type: .hidden
            ))
        }
        if let fingerprintSHA256, !fingerprintSHA256.isEmpty {
            fields.append(CustomField(
                name: try encrypt(Self.fingerprintFieldName),
                value: try encrypt(fingerprintSHA256),
                type: .hidden
            ))
        }
        if let fileName, !fileName.isEmpty {
            fields.append(CustomField(
                name: try encrypt(Self.fileNameFieldName),
                value: try encrypt(fileName),
                type: .hidden
            ))
        }

        return fields
    }

    public static func string(from date: Date) -> String {
        dateFormatter.string(from: date)
    }

    private static func certificateNotAfter(_ certificate: SecCertificate) -> Date? {
        guard let values = SecCertificateCopyValues(
            certificate,
            [kSecOIDX509V1ValidityNotAfter] as CFArray,
            nil
        ) as? [String: Any],
              let property = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any] else {
            return nil
        }

        if let date = property[kSecPropertyKeyValue as String] as? Date {
            return date
        }

        if let timeInterval = property[kSecPropertyKeyValue as String] as? TimeInterval {
            return Date(timeIntervalSinceReferenceDate: timeInterval)
        }

        return nil
    }

    private static func sha256Fingerprint(for certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: data)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
    }
}

public enum CertificateError: LocalizedError {
    case importFailed(OSStatus)
    case certificateMissing(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .importFailed(let status):
            return "Could not read the PFX/P12 certificate. Check the certificate password. (Security status \(status))"
        case .certificateMissing(let status):
            return "The PFX/P12 file did not contain a readable certificate. (Security status \(status))"
        }
    }
}
