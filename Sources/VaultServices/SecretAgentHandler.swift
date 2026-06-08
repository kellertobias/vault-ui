// MARK: - VaultServices/SecretAgentHandler.swift
// Secret agent request handler — processes CLI secret lookup requests

import Foundation
import VaultCrypto
import VaultModels
import OSLog
import CryptoKit

private let logger = Logger(subsystem: "com.vaultui", category: "SecretAgentHandler")

// MARK: - Protocol Types

/// A secret agent request from the CLI.
public struct SecretRequest: Codable, Sendable {
    public let type: String          // "get" or "extend"
    public var slug: String?         // for get
    public var field: String?        // for get (optional)
    public var envContent: String?   // for extend
    public var requester: String?    // best-effort caller description

    public init(type: String, slug: String? = nil, field: String? = nil, envContent: String? = nil, requester: String? = nil) {
        self.type = type
        self.slug = slug
        self.field = field
        self.envContent = envContent
        self.requester = requester
    }
}

/// A secret agent response to the CLI.
public struct SecretResponse: Codable, Sendable {
    public let ok: Bool
    public var value: String?
    public var error: String?

    public init(ok: Bool, value: String? = nil, error: String? = nil) {
        self.ok = ok
        self.value = value
        self.error = error
    }
}

// MARK: - Decrypted Cipher Representation

/// A fully decrypted cipher for JSON output from `secret get`.
private struct DecryptedCipherOutput: Codable {
    let name: String?
    let type: String
    var username: String?
    var password: String?
    var totp: String?
    var totpKey: String?
    var uris: [String]?
    var notes: String?
    var fields: [String: String]?
}

// MARK: - Handler

/// Handles secret agent requests from the CLI.
///
/// Supports two request types:
/// - `get`: Look up a secret by its `vaultui-slug` custom field
/// - `extend`: Parse a `.env` file and resolve `vaultui://` references
///
/// Results are cached with a sliding TTL to avoid repeated biometric prompts.
public final class SecretAgentHandler: @unchecked Sendable {

    /// Callback that returns all ciphers with their decryption keys.
    /// If the vault is locked, the callback handles biometric unlock internally,
    /// using `reason` as the Touch ID prompt text so the user sees what is being
    /// requested. Returns nil if unlock fails.
    private let cipherProvider: @Sendable (_ reason: String?) async -> [(cipher: Cipher, key: SymmetricCryptoKey)]?

    /// Response cache: cacheKey → (result, expiresAt)
    private var cache: [String: (result: String, expiresAt: Date)] = [:]

    /// Lock for thread safety
    private let lock = NSLock()

    public init(cipherProvider: @escaping @Sendable (_ reason: String?) async -> [(cipher: Cipher, key: SymmetricCryptoKey)]?) {
        self.cipherProvider = cipherProvider
    }

    /// Build the Touch ID prompt text for a secret request. The requester is
    /// supplied by the client and therefore untrusted, so it is phrased as a
    /// claim ("requested by …") rather than an asserted identity.
    private func unlockReason(action: String, requester: String?) -> String {
        if let requester = requester, !requester.isEmpty {
            return "\(action) (requested by \(requester))"
        }
        return action
    }

    // MARK: - Request Processing

    /// Process an incoming request and return a JSON response.
    public func processRequest(_ data: Data) async -> Data {
        let response: SecretResponse

        do {
            let request = try JSONDecoder().decode(SecretRequest.self, from: data)

            switch request.type {
            case "get":
                guard let slug = request.slug else {
                    response = SecretResponse(ok: false, error: "Missing 'slug' field in get request")
                    break
                }
                response = await handleGet(slug: slug, field: request.field, requester: request.requester)

            case "extend":
                guard let envContent = request.envContent else {
                    response = SecretResponse(ok: false, error: "Missing 'envContent' field in extend request")
                    break
                }
                response = await handleExtend(envContent: envContent, requester: request.requester)

            default:
                response = SecretResponse(ok: false, error: "Unknown request type: '\(request.type)'")
            }
        } catch {
            response = SecretResponse(ok: false, error: "Invalid request: \(error.localizedDescription)")
        }

        let responseData = (try? JSONEncoder().encode(response)) ?? Data()
        return responseData
    }

    // MARK: - Get Handler

    private func handleGet(slug: String, field: String?, requester: String?) async -> SecretResponse {
        // Validate slug
        guard VaultUISlug.isValid(slug) else {
            return SecretResponse(ok: false, error: "Invalid slug format: '\(slug)'. Use only a-zA-Z0-9, hyphens, underscores, and dots.")
        }

        // Check cache
        let cacheKey = field != nil ? "get:\(slug)/\(field!)" : "get:\(slug)"
        if let cached = getCachedResult(for: cacheKey) {
            logger.debug("Cache hit for \(cacheKey)")
            notifySecretAccess(slugs: [slug], field: field, requester: requester)
            return SecretResponse(ok: true, value: cached)
        }

        // Fetch and decrypt ciphers
        let reason = unlockReason(action: "Reveal secret \"\(slug)\"", requester: requester)
        guard let ciphers = await cipherProvider(reason) else {
            return SecretResponse(ok: false, error: "Vault is locked and biometric unlock failed")
        }

        // Find cipher with matching vaultui-slug
        guard let match = findCipherBySlug(slug, in: ciphers) else {
            return SecretResponse(ok: false, error: "No secret found with slug '\(slug)'")
        }

        let (cipher, key) = match

        // Extract the requested value
        let result: String
        if let field = field {
            guard let value = extractField(field, from: cipher, key: key) else {
                return SecretResponse(ok: false, error: "Field '\(field)' not found or empty in secret '\(slug)'")
            }
            result = value
        } else {
            result = buildFullJSON(from: cipher, key: key)
        }

        // Cache the result
        setCachedResult(result, for: cacheKey)
        notifySecretAccess(slugs: [slug], field: field, requester: requester)
        return SecretResponse(ok: true, value: result)
    }

    // MARK: - Extend Handler

    private func handleExtend(envContent: String, requester: String?) async -> SecretResponse {
        let lines = envContent.components(separatedBy: "\n")

        // First pass: collect all vaultui:// references and regular lines
        var entries: [(key: String, rawValue: String, vaultuiURI: String?)] = []
        var slugsNeeded: Set<String> = []

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines and comment-only lines
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Parse KEY="value" or KEY='value' or KEY=value
            guard let (key, rawValue) = parseEnvLine(trimmed) else { continue }

            // Check if the value is a vaultui:// URI
            let cleanValue = stripInlineComment(rawValue)
            if cleanValue.hasPrefix(VaultUISlug.uriPrefix) {
                entries.append((key: key, rawValue: cleanValue, vaultuiURI: cleanValue))
                if let parsed = VaultUISlug.parseURI(cleanValue) {
                    slugsNeeded.insert(parsed.slug)
                }
            } else {
                entries.append((key: key, rawValue: cleanValue, vaultuiURI: nil))
            }
        }

        // Build cache key from sorted slug set
        let sortedSlugs = slugsNeeded.sorted()
        let cacheKey = "extend:\(sortedSlugs.joined(separator: ","))"

        if let cached = getCachedResult(for: cacheKey) {
            logger.debug("Cache hit for extend request")
            notifySecretAccess(slugs: sortedSlugs, field: nil, requester: requester)
            return SecretResponse(ok: true, value: cached)
        }

        // Fetch ciphers if we have any vaultui:// references
        var resolvedCiphers: [(cipher: Cipher, key: SymmetricCryptoKey)]?
        if !slugsNeeded.isEmpty {
            let reason = unlockReason(
                action: "Resolve \(slugsNeeded.count) secret\(slugsNeeded.count == 1 ? "" : "s") for an env file",
                requester: requester
            )
            resolvedCiphers = await cipherProvider(reason)
            if resolvedCiphers == nil {
                return SecretResponse(ok: false, error: "Vault is locked and biometric unlock failed")
            }
        }

        // Second pass: build export lines
        var exportLines: [String] = []

        for entry in entries {
            if let uri = entry.vaultuiURI {
                guard let parsed = VaultUISlug.parseURI(uri) else {
                    return SecretResponse(ok: false, error: "Invalid vaultui:// URI: '\(uri)'")
                }

                guard let ciphers = resolvedCiphers,
                      let match = findCipherBySlug(parsed.slug, in: ciphers) else {
                    return SecretResponse(ok: false, error: "No secret found with slug '\(parsed.slug)'")
                }

                let (cipher, key) = match
                let value: String
                if let field = parsed.field {
                    guard let fieldValue = extractField(field, from: cipher, key: key) else {
                        return SecretResponse(ok: false, error: "Field '\(field)' not found in secret '\(parsed.slug)'")
                    }
                    value = fieldValue
                } else {
                    value = buildFullJSON(from: cipher, key: key)
                }

                exportLines.append("export \(entry.key)=\(shellEscape(value))")
            } else {
                exportLines.append("export \(entry.key)=\(shellEscape(entry.rawValue))")
            }
        }

        let result = exportLines.joined(separator: "\n")

        // Cache if we resolved any slugs
        if !slugsNeeded.isEmpty {
            setCachedResult(result, for: cacheKey)
            notifySecretAccess(slugs: sortedSlugs, field: nil, requester: requester)
        }

        return SecretResponse(ok: true, value: result)
    }

    private func notifySecretAccess(slugs: [String], field: String?, requester: String?) {
        guard !slugs.isEmpty else { return }

        let names = slugs.map { slug in
            if let field {
                return "\(slug)/\(field)"
            }
            return slug
        }
        let requesterName = requester?.isEmpty == false ? requester! : "vaultui CLI"
        let visibleNames = names.prefix(3).joined(separator: ", ")
        let remainder = names.count > 3 ? " and \(names.count - 3) more" : ""

        VaultNotificationCenter.notify(
            title: "Secret decoded",
            body: "\(requesterName) decoded \(visibleNames)\(remainder)"
        )
    }

    // MARK: - Cache

    /// Clear all cached results (called when vault is locked).
    public func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        cache.removeAll()
        logger.debug("Secret agent cache cleared")
    }

    private func getCachedResult(for key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }

        let policy = AgentUnlockPolicyStore.current()
        // "Ask every time" never serves from cache — force a fresh Touch ID.
        guard policy.mode != .everyTime else { return nil }

        let now = Date()

        // Purge expired entries
        cache = cache.filter { $0.value.expiresAt >= now }

        if let entry = cache[key], entry.expiresAt >= now {
            // Sliding window extends the TTL on use; fixed window does not.
            if policy.mode == .sliding {
                cache[key] = (result: entry.result, expiresAt: now.addingTimeInterval(policy.window))
            }
            return entry.result
        }
        return nil
    }

    private func setCachedResult(_ result: String, for key: String) {
        lock.lock()
        defer { lock.unlock() }

        let policy = AgentUnlockPolicyStore.current()
        // Nothing is cached when the user asked to be prompted every time.
        guard policy.mode != .everyTime else { return }

        cache[key] = (result: result, expiresAt: Date().addingTimeInterval(policy.window))
    }

    // MARK: - Cipher Lookup

    /// Find a cipher by its `vaultui-slug` custom field value.
    private func findCipherBySlug(
        _ slug: String,
        in ciphers: [(cipher: Cipher, key: SymmetricCryptoKey)]
    ) -> (cipher: Cipher, key: SymmetricCryptoKey)? {
        for (cipher, key) in ciphers {
            guard let fields = cipher.fields else { continue }
            for field in fields {
                guard let fieldName = try? CipherEncryption.decryptString(field.name!, key: key),
                      fieldName == VaultUISlug.fieldName else { continue }
                guard let fieldValue = try? CipherEncryption.decryptString(field.value!, key: key),
                      fieldValue == slug else { continue }
                return (cipher, key)
            }
        }
        return nil
    }

    // MARK: - Field Extraction

    /// Extract a specific field from a decrypted cipher.
    private func extractField(_ field: String, from cipher: Cipher, key: SymmetricCryptoKey) -> String? {
        switch field.lowercased() {
        case "username":
            return cipher.login?.username.flatMap { try? CipherEncryption.decryptString($0, key: key) }
        case "password":
            return cipher.login?.password.flatMap { try? CipherEncryption.decryptString($0, key: key) }
        case "totp":
            if let totpEnc = cipher.login?.totp,
               let secret = try? CipherEncryption.decryptString(totpEnc, key: key) {
                return TOTPService.generateCode(from: secret)?.code
            }
            return nil
        case "totpkey":
            if let totpEnc = cipher.login?.totp,
               let secret = try? CipherEncryption.decryptString(totpEnc, key: key) {
                return secret
            }
            return nil
        case "notes":
            return cipher.notes.flatMap { try? CipherEncryption.decryptString($0, key: key) }
        case "uri", "url":
            return cipher.login?.uris?.first?.uri.flatMap { try? CipherEncryption.decryptString($0, key: key) }
        default:
            // Look in custom fields
            if let fields = cipher.fields {
                for customField in fields {
                    guard let name = try? CipherEncryption.decryptString(customField.name!, key: key) else { continue }
                    if name == field || name.lowercased() == field.lowercased() {
                        return customField.value.flatMap { try? CipherEncryption.decryptString($0, key: key) }
                    }
                }
            }
            return nil
        }
    }

    // MARK: - JSON Output

    /// Build a full JSON representation of a decrypted cipher.
    private func buildFullJSON(from cipher: Cipher, key: SymmetricCryptoKey) -> String {
        var output = DecryptedCipherOutput(
            name: cipher.name.flatMap { try? CipherEncryption.decryptString($0, key: key) },
            type: cipher.type.displayName
        )

        if let login = cipher.login {
            output.username = login.username.flatMap { try? CipherEncryption.decryptString($0, key: key) }
            output.password = login.password.flatMap { try? CipherEncryption.decryptString($0, key: key) }
            if let totpEnc = login.totp, let secret = try? CipherEncryption.decryptString(totpEnc, key: key) {
                output.totpKey = secret
                output.totp = TOTPService.generateCode(from: secret)?.code
            }
            output.uris = login.uris?.compactMap { $0.uri.flatMap { try? CipherEncryption.decryptString($0, key: key) } }
        }

        output.notes = cipher.notes.flatMap { try? CipherEncryption.decryptString($0, key: key) }

        // Include custom fields (excluding vaultui-slug itself)
        if let fields = cipher.fields {
            var fieldMap: [String: String] = [:]
            for field in fields {
                guard let name = try? CipherEncryption.decryptString(field.name!, key: key) else { continue }
                if name == VaultUISlug.fieldName { continue }
                let value = field.value.flatMap { try? CipherEncryption.decryptString($0, key: key) } ?? ""
                fieldMap[name] = value
            }
            if !fieldMap.isEmpty {
                output.fields = fieldMap
            }
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(output) {
            return String(data: data, encoding: .utf8) ?? "{}"
        }
        return "{}"
    }

    // MARK: - Env File Parsing

    /// Parse a KEY="value" line from an env file.
    private func parseEnvLine(_ line: String) -> (key: String, value: String)? {
        // Find the first = sign
        guard let eqIndex = line.firstIndex(of: "=") else { return nil }
        let key = String(line[line.startIndex..<eqIndex]).trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }

        var value = String(line[line.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)

        // Strip quotes
        if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
           (value.hasPrefix("'") && value.hasSuffix("'")) {
            value = String(value.dropFirst().dropLast())
        }

        return (key, value)
    }

    /// Strip inline comments (# ...) from a value, being careful with quoted strings.
    private func stripInlineComment(_ value: String) -> String {
        // Simple heuristic: if there's a # preceded by whitespace outside quotes, strip from there
        var result = value
        if let hashRange = result.range(of: " #") {
            result = String(result[result.startIndex..<hashRange.lowerBound])
        }
        return result.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - Shell Escaping

    /// Escape a value for safe use in a shell `export` statement.
    /// Uses single quotes with proper escaping of embedded single quotes.
    private func shellEscape(_ value: String) -> String {
        // Replace ' with '\'' (end quote, escaped quote, start quote)
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }
}
