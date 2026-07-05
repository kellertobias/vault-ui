// MARK: - VaultSSH/SSHAgentHandler.swift
// SSH agent message handler — processes client requests

import Foundation
import Security
import CryptoKit
import OSLog
import VaultModels

private let logger = Logger(subsystem: "com.vaultui", category: "SSHAgentHandler")

/// Handles SSH agent protocol messages.
///
/// This is the core logic that processes incoming requests from SSH clients
/// and returns appropriate responses. It maintains a list of available keys
/// from the vault and performs signing operations.
public final class SSHAgentHandler: @unchecked Sendable {

    /// Available SSH identities (loaded from vault)
    private var identities: [SSHIdentity] = []

    /// Callback to get the private key data for a cipher ID. `reason` is the
    /// authentication prompt text (naming the connecting client and the key) so the
    /// user can see who is asking before authorizing.
    private let privateKeyProvider: @Sendable (_ cipherId: String, _ reason: String?, _ requiresUserPresence: Bool) async -> Data?

    /// Whether the agent is locked
    private var isLocked = false
    private var lockPassphrase: String?
    
    /// Cached private keys for local-auth unlock (cipherId -> (keyData, expiresAt))
    private var cachedPrivateKeys: [String: (keyData: Data, expiresAt: Date)] = [:]

    /// Lock for thread safety
    private let lock = NSLock()

    public init(
        privateKeyProvider: @escaping @Sendable (_ cipherId: String, _ reason: String?, _ requiresUserPresence: Bool) async -> Data?
    ) {
        self.privateKeyProvider = privateKeyProvider
    }

    // MARK: - Identity Management

    /// Update the available identities (called when vault is unlocked/synced).
    public func setIdentities(_ identities: [SSHIdentity]) {
        lock.lock()
        defer { lock.unlock() }
        self.identities = identities
    }

    /// Clear all identities (called when vault is locked).
    public func clearIdentities() {
        lock.lock()
        defer { lock.unlock() }
        identities.removeAll()
        clearCachedPrivateKeysLocked(preservingAuthenticationBypass: false)
    }

    /// Clear private key material while keeping public identities available.
    public func clearCachedPrivateKeys() {
        lock.lock()
        defer { lock.unlock() }
        clearCachedPrivateKeysLocked(preservingAuthenticationBypass: true)
    }

    private func clearCachedPrivateKeysLocked(preservingAuthenticationBypass: Bool) {
        let now = Date()
        for (cipherId, cacheEntry) in cachedPrivateKeys {
            if preservingAuthenticationBypass,
               cacheEntry.expiresAt > now,
               SSHAgentKeyAccessStore.access(for: cipherId).authenticationBypassUntil != nil {
                continue
            }
            var cacheEntry = cacheEntry
            cacheEntry.keyData.resetBytes(in: cacheEntry.keyData.startIndex..<cacheEntry.keyData.endIndex)
            cachedPrivateKeys.removeValue(forKey: cipherId)
        }
    }

    // MARK: - Message Processing

    /// Process an incoming SSH agent message and return the response.
    ///
    /// `peer` is a best-effort description of the connecting client process
    /// (e.g. "ssh (pid 1234)"), used only for the authentication prompt text.
    public func processMessage(_ data: Data, peer: String? = nil) async -> Data {
        guard let (type, payload) = SSHWireFormat.parseMessage(data) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        switch type {
        case .requestIdentities:
            return handleRequestIdentities()
        case .signRequest:
            return await handleSignRequest(payload, peer: peer)
        case .lock:
            return handleLock(payload)
        case .unlock:
            return handleUnlock(payload)
        case .removeAllIdentities:
            return handleRemoveAll()
        case .extension_:
            return await handleExtension(payload, peer: peer)
        default:
            // Unsupported message type
            return SSHWireFormat.buildMessage(type: .failure)
        }
    }

    // MARK: - Request Handlers

    /// Handle SSH_AGENTC_REQUEST_IDENTITIES — return all available public keys.
    private func handleRequestIdentities() -> Data {
        lock.lock()
        let ids = identities.filter { SSHAgentKeyAccessStore.isVisible(cipherId: $0.cipherId) }
        let locked = isLocked
        lock.unlock()

        guard !locked else {
            // Return empty list when locked
            var payload = Data()
            payload.append(SSHWireFormat.writeUInt32(0))
            return SSHWireFormat.buildMessage(type: .identitiesAnswer, payload: payload)
        }

        var payload = Data()
        payload.append(SSHWireFormat.writeUInt32(UInt32(ids.count)))

        for identity in ids {
            payload.append(SSHWireFormat.writeString(identity.publicKeyBlob))
            payload.append(SSHWireFormat.writeString(identity.comment))
        }

        return SSHWireFormat.buildMessage(type: .identitiesAnswer, payload: payload)
    }

    /// Handle SSH_AGENTC_SIGN_REQUEST — sign data with a private key.
    private func handleSignRequest(_ payload: Data, peer: String? = nil) async -> Data {
        // Parse: string key_blob, string data, uint32 flags
        var offset = 0

        guard let (keyBlob, nextOffset) = SSHWireFormat.readString(payload, at: offset) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }
        offset = nextOffset

        guard let (dataToSign, nextOffset2) = SSHWireFormat.readString(payload, at: offset) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }
        offset = nextOffset2

        let flags: SSHSignFlags
        if let flagsRaw = SSHWireFormat.readUInt32(payload, at: offset) {
            flags = SSHSignFlags(rawValue: flagsRaw)
        } else {
            flags = []
        }

        // Find the matching identity (sync snapshot)
        let matchingIdentity = findIdentity(for: keyBlob)

        guard let identity = matchingIdentity else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        VaultNotificationCenter.notify(
            title: "SSH key requested",
            body: "SSH client requested \(identity.comment)"
        )

        // Get the private key (either from cache or provider)
        let privateKeyData: Data
        
        if let cachedKey = getCachedPrivateKey(for: identity.cipherId) {
            privateKeyData = cachedKey
        } else {
            // Cache miss (or expired), request from provider. The prompt names
            // the connecting client (peer) and the key being used.
            let who = (peer?.isEmpty == false) ? peer! : "An SSH client"
            let reason = "\(who) wants to use SSH key \"\(identity.comment)\""
            guard let fetchedKey = await privateKeyProvider(identity.cipherId, reason, false) else {
                return SSHWireFormat.buildMessage(type: .failure)
            }
            privateKeyData = fetchedKey
            
            // Cache the newly fetched key
            cachePrivateKey(privateKeyData, for: identity.cipherId)
        }

        // Perform the signature
        var signatureResponse: Data?
        do {
            let signature = try performSignature(
                privateKey: privateKeyData,
                data: dataToSign,
                flags: flags
            )
            SSHAgentKeyAccessStore.recordUse(cipherId: identity.cipherId, peer: peer)
            let responsePayload = SSHWireFormat.writeString(signature)
            signatureResponse = SSHWireFormat.buildMessage(type: .signResponse, payload: responsePayload)
        } catch {
            logger.error("SSH signing failed for \(identity.comment, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
        
        return signatureResponse ?? SSHWireFormat.buildMessage(type: .failure)
    }

    /// Thread-safe identity lookup (called from async context without holding the lock across await).
    private func findIdentity(for keyBlob: Data) -> SSHIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return identities.first {
            $0.publicKeyBlob == keyBlob && SSHAgentKeyAccessStore.isVisible(cipherId: $0.cipherId)
        }
    }

    private func getCachedPrivateKey(for cipherId: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }

        let access = SSHAgentKeyAccessStore.access(for: cipherId)
        guard access.isVisible else { return nil }

        let policy = AgentUnlockPolicyStore.current()
        // "Ask every time" never serves a cached key — force fresh authentication.
        guard policy.mode != .everyTime || access.authenticationBypassUntil != nil else { return nil }

        let now = Date()
        // Purge expired keys first
        for (id, cacheEntry) in cachedPrivateKeys {
            if cacheEntry.expiresAt < now {
                var entry = cacheEntry
                entry.keyData.resetBytes(in: entry.keyData.startIndex..<entry.keyData.endIndex)
                cachedPrivateKeys.removeValue(forKey: id)
            }
        }

        if let cacheEntry = cachedPrivateKeys[cipherId], cacheEntry.expiresAt >= now {
            // Sliding window extends the TTL on use; fixed window does not.
            if policy.mode == .sliding, access.authenticationBypassUntil == nil {
                cachedPrivateKeys[cipherId] = (keyData: cacheEntry.keyData, expiresAt: now.addingTimeInterval(policy.window))
            }
            return cacheEntry.keyData
        }
        return nil
    }

    private func cachedPrivateKeyExpiration(for cipherId: String) -> Date? {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()
        for (id, cacheEntry) in cachedPrivateKeys {
            if cacheEntry.expiresAt <= now {
                var entry = cacheEntry
                entry.keyData.resetBytes(in: entry.keyData.startIndex..<entry.keyData.endIndex)
                cachedPrivateKeys.removeValue(forKey: id)
            }
        }

        guard SSHAgentKeyAccessStore.isVisible(cipherId: cipherId),
              let cacheEntry = cachedPrivateKeys[cipherId],
              cacheEntry.expiresAt > now else {
            return nil
        }

        return cacheEntry.expiresAt
    }

    private func cachePrivateKey(_ keyData: Data, for cipherId: String) {
        lock.lock()
        defer { lock.unlock() }

        let access = SSHAgentKeyAccessStore.access(for: cipherId)
        guard access.isVisible else { return }

        let policy = AgentUnlockPolicyStore.current()
        // Don't retain key material when the user asked to be prompted every time.
        guard policy.mode != .everyTime || access.authenticationBypassUntil != nil else { return }

        let expiresAt = access.authenticationBypassUntil ?? Date().addingTimeInterval(policy.window)
        cachedPrivateKeys[cipherId] = (keyData: keyData, expiresAt: expiresAt)
    }

    private func cachePrivateKey(_ keyData: Data, for cipherId: String, until expiresAt: Date) {
        lock.lock()
        defer { lock.unlock() }
        cachedPrivateKeys[cipherId] = (keyData: keyData, expiresAt: expiresAt)
    }

    private func clearCachedPrivateKey(for cipherId: String) {
        lock.lock()
        defer { lock.unlock() }

        guard var cacheEntry = cachedPrivateKeys.removeValue(forKey: cipherId) else { return }
        cacheEntry.keyData.resetBytes(in: cacheEntry.keyData.startIndex..<cacheEntry.keyData.endIndex)
    }

    private func handleExtension(_ payload: Data, peer: String? = nil) async -> Data {
        var offset = 0
        guard let (extensionNameData, nextOffset) = SSHWireFormat.readString(payload, at: offset),
              let extensionName = String(data: extensionNameData, encoding: .utf8) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }
        offset = nextOffset

        switch extensionName {
        case "vaultui@authorize-key":
            return await handleAuthorizeKeyExtension(payload, offset: offset)
        case "vaultui@key-status":
            return handleKeyStatusExtension(payload, offset: offset)
        case "vaultui@lock-key":
            return handleLockKeyExtension(payload, offset: offset)
        default:
            return SSHWireFormat.buildMessage(type: .failure)
        }
    }

    private func handleAuthorizeKeyExtension(_ payload: Data, offset initialOffset: Int) async -> Data {
        var offset = initialOffset
        guard let (cipherIdData, nextOffset2) = SSHWireFormat.readString(payload, at: offset),
              let cipherId = String(data: cipherIdData, encoding: .utf8) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }
        offset = nextOffset2

        guard let minutesRaw = SSHWireFormat.readUInt32(payload, at: offset) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        guard SSHAgentKeyAccessStore.isVisible(cipherId: cipherId),
              let comment = identityComment(for: cipherId) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        let minutes = min(max(1, Int(minutesRaw)), 12 * 60)
        let until = Date().addingTimeInterval(TimeInterval(minutes * 60))
        let reason = "Authorize SSH key \"\(comment)\" without fingerprint prompts until \(until.formatted(date: .omitted, time: .shortened))"
        guard let keyData = await privateKeyProvider(cipherId, reason, true) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        cachePrivateKey(keyData, for: cipherId, until: until)
        SSHAgentKeyAccessStore.setAuthenticationBypass(cipherId: cipherId, until: until)
        return SSHWireFormat.buildMessage(type: .success)
    }

    private func handleKeyStatusExtension(_ payload: Data, offset: Int) -> Data {
        guard let (cipherIdData, _) = SSHWireFormat.readString(payload, at: offset),
              let cipherId = String(data: cipherIdData, encoding: .utf8) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        let secondsRemaining: UInt32
        if let expiresAt = cachedPrivateKeyExpiration(for: cipherId) {
            secondsRemaining = UInt32(max(1, Int(ceil(expiresAt.timeIntervalSinceNow))))
        } else {
            secondsRemaining = 0
        }

        return SSHWireFormat.buildMessage(
            type: .success,
            payload: SSHWireFormat.writeUInt32(secondsRemaining)
        )
    }

    private func handleLockKeyExtension(_ payload: Data, offset: Int) -> Data {
        guard let (cipherIdData, _) = SSHWireFormat.readString(payload, at: offset),
              let cipherId = String(data: cipherIdData, encoding: .utf8) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        clearCachedPrivateKey(for: cipherId)
        SSHAgentKeyAccessStore.clearAuthenticationBypass(cipherId: cipherId)
        return SSHWireFormat.buildMessage(type: .success)
    }

    private func identityComment(for cipherId: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return identities.first(where: { $0.cipherId == cipherId })?.comment
    }

    // MARK: - Handlers for Lock/Unlock

    /// Handle SSH_AGENTC_LOCK.
    private func handleLock(_ payload: Data) -> Data {
        guard let (passphraseData, _) = SSHWireFormat.readString(payload, at: 0) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        lock.lock()
        lockPassphrase = String(data: passphraseData, encoding: .utf8)
        isLocked = true
        lock.unlock()

        return SSHWireFormat.buildMessage(type: .success)
    }

    /// Handle SSH_AGENTC_UNLOCK.
    private func handleUnlock(_ payload: Data) -> Data {
        guard let (passphraseData, _) = SSHWireFormat.readString(payload, at: 0) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        let passphrase = String(data: passphraseData, encoding: .utf8)

        lock.lock()
        defer { lock.unlock() }

        guard isLocked else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        if constantTimeEqual(lockPassphrase, passphrase) {
            isLocked = false
            lockPassphrase = nil
            return SSHWireFormat.buildMessage(type: .success)
        }

        return SSHWireFormat.buildMessage(type: .failure)
    }

    /// Constant-time string comparison to prevent timing attacks on the lock passphrase.
    private func constantTimeEqual(_ a: String?, _ b: String?) -> Bool {
        guard let a = a?.utf8, let b = b?.utf8 else {
            return a == nil && b == nil
        }
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for (x, y) in zip(a, b) {
            result |= x ^ y
        }
        return result == 0
    }

    /// Handle SSH_AGENTC_REMOVE_ALL_IDENTITIES.
    private func handleRemoveAll() -> Data {
        clearIdentities()
        return SSHWireFormat.buildMessage(type: .success)
    }

    // MARK: - Cryptographic Signing

    /// Sign data with the private key.
    private func performSignature(
        privateKey: Data,
        data: Data,
        flags: SSHSignFlags
    ) throws -> Data {
        // Detect key type from the PEM/OpenSSH format
        let keyString = String(data: privateKey, encoding: .utf8) ?? ""
        let firstKeyLine = keyString
            .components(separatedBy: .newlines)
            .first(where: { $0.hasPrefix("-----BEGIN ") }) ?? "<unknown>"
        logger.debug("SSH private key format: \(firstKeyLine, privacy: .public), encrypted=\(keyString.contains("ENCRYPTED"), privacy: .public)")

        if keyString.contains("BEGIN OPENSSH PRIVATE KEY") {
            return try signWithOpenSSHKey(keyString, data: data, flags: flags)
        } else if keyString.contains("BEGIN RSA PRIVATE KEY") || keyString.contains("BEGIN PRIVATE KEY") {
            return try signWithPEMKey(keyString, data: data, flags: flags)
        }

        throw SSHAgentError.unsupportedKeyFormat
    }

    /// Sign using an Ed25519 or ECDSA key from OpenSSH format.
    private func signWithOpenSSHKey(_ pemString: String, data: Data, flags: SSHSignFlags) throws -> Data {
        // Parse OpenSSH private key format
        guard let keyData = parseOpenSSHPrivateKey(pemString) else {
            throw SSHAgentError.invalidKey
        }

        switch keyData.algorithm {
        case "ssh-ed25519":
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData.privateKeyRaw)
            let signature = try privateKey.signature(for: data)

            // Build SSH signature blob: string "ssh-ed25519", string signature
            var sigBlob = Data()
            sigBlob.append(SSHWireFormat.writeString("ssh-ed25519"))
            sigBlob.append(SSHWireFormat.writeString(Data(signature)))
            return sigBlob

        case "ssh-rsa":
            guard let rsaComponents = keyData.rsaComponents else {
                throw SSHAgentError.invalidKey
            }
            let der = try buildRSAPrivateKeyDER(from: rsaComponents)
            return try signWithRSADER(der, data: data, flags: flags)

        default:
            throw SSHAgentError.unsupportedKeyType(keyData.algorithm)
        }
    }

    /// Sign using an RSA key from PEM format.
    private func signWithPEMKey(_ pemString: String, data: Data, flags: SSHSignFlags) throws -> Data {
        guard let der = decodePEM(pemString) else {
            throw SSHAgentError.invalidKey
        }

        return try signWithRSADER(der, data: data, flags: flags)
    }

    private func signWithRSADER(_ der: Data, data: Data, flags: SSHSignFlags) throws -> Data {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            if let error {
                logger.error("RSA key import failed: \(String(describing: error.takeRetainedValue()), privacy: .public)")
            } else {
                logger.error("RSA key import failed without Security error; derLength=\(der.count, privacy: .public)")
            }
            throw SSHAgentError.invalidKey
        }

        let algorithm: SecKeyAlgorithm
        let sigAlgorithmName: String

        if flags.contains(.rsaSHA512) {
            algorithm = .rsaSignatureMessagePKCS1v15SHA512
            sigAlgorithmName = "rsa-sha2-512"
        } else if flags.contains(.rsaSHA256) {
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
            sigAlgorithmName = "rsa-sha2-256"
        } else {
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
            sigAlgorithmName = "rsa-sha2-256"
        }

        guard let signature = SecKeyCreateSignature(secKey, algorithm, data as CFData, &error) else {
            if let error {
                logger.error("RSA signature failed: \(String(describing: error.takeRetainedValue()), privacy: .public)")
            }
            throw SSHAgentError.signingFailed
        }

        var sigBlob = Data()
        sigBlob.append(SSHWireFormat.writeString(sigAlgorithmName))
        sigBlob.append(SSHWireFormat.writeString(signature as Data))
        return sigBlob
    }

    // MARK: - OpenSSH Key Parsing

    struct ParsedKey {
        let algorithm: String
        let privateKeyRaw: Data
        let rsaComponents: RSAComponents?

        init(algorithm: String, privateKeyRaw: Data, rsaComponents: RSAComponents? = nil) {
            self.algorithm = algorithm
            self.privateKeyRaw = privateKeyRaw
            self.rsaComponents = rsaComponents
        }
    }

    struct RSAComponents {
        let n: Data
        let e: Data
        let d: Data
        let iqmp: Data
        let p: Data
        let q: Data
    }

    /// Parse an OpenSSH private key.
    private func parseOpenSSHPrivateKey(_ pem: String) -> ParsedKey? {
        // Strip PEM headers
        let lines = pem.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64 = lines.joined()

        guard let decoded = Data(base64Encoded: base64) else {
            logger.error("OpenSSH private key rejected: invalid base64 body")
            return nil
        }

        // OpenSSH format: "openssh-key-v1\0" magic + ciphername + kdfname + ...
        let magic = "openssh-key-v1\0"
        guard decoded.count > magic.count,
              String(data: decoded[0..<magic.count], encoding: .utf8) == magic else {
            return nil
        }

        // Parse the key structure (simplified — handles unencrypted Ed25519 only)
        var offset = magic.count

        // ciphername
        guard let (cipherNameData, next1) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next1
        let cipherName = String(data: cipherNameData, encoding: .utf8) ?? "<invalid>"

        // kdfname
        guard let (kdfNameData, next2) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next2
        let kdfName = String(data: kdfNameData, encoding: .utf8) ?? "<invalid>"

        // kdfoptions
        guard let (_, next3) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next3

        // number of keys
        guard let _ = SSHWireFormat.readUInt32(decoded, at: offset) else { return nil }
        offset += 4

        // public key (skip)
        guard let (_, next5) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next5

        // private section (contains check ints + key data)
        guard let (privateSection, _) = SSHWireFormat.readString(decoded, at: offset) else { return nil }

        // Parse private section
        var privOffset = 0

        // Two check integers (must match)
        guard let check1 = SSHWireFormat.readUInt32(privateSection, at: privOffset) else { return nil }
        privOffset += 4
        guard let check2 = SSHWireFormat.readUInt32(privateSection, at: privOffset) else { return nil }
        privOffset += 4

        guard check1 == check2 else {
            logger.error("OpenSSH private key rejected before key data; cipher=\(cipherName, privacy: .public), kdf=\(kdfName, privacy: .public)")
            return nil
        }

        // Key type
        guard let (keyTypeData, next) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
        privOffset = next
        let keyType = String(data: keyTypeData, encoding: .utf8) ?? ""
        logger.debug("OpenSSH private key parsed with cipher=\(cipherName, privacy: .public), kdf=\(kdfName, privacy: .public), type=\(keyType, privacy: .public)")

        if keyType == "ssh-ed25519" {
            // Ed25519 public key (32 bytes)
            guard let (_, next2) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = next2

            // Ed25519 private key (64 bytes: 32 private + 32 public)
            guard let (privKeyData, _) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }

            // The actual private key is the first 32 bytes
            let rawPrivateKey = privKeyData.prefix(32)
            return ParsedKey(algorithm: keyType, privateKeyRaw: Data(rawPrivateKey))
        }

        if keyType == "ssh-rsa" {
            guard let (n, nOffset) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = nOffset
            guard let (e, eOffset) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = eOffset
            guard let (d, dOffset) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = dOffset
            guard let (iqmp, iqmpOffset) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = iqmpOffset
            guard let (p, pOffset) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
            privOffset = pOffset
            guard let (q, _) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }

            let rsa = RSAComponents(n: n, e: e, d: d, iqmp: iqmp, p: p, q: q)
            return ParsedKey(algorithm: keyType, privateKeyRaw: Data(), rsaComponents: rsa)
        }

        return nil
    }

    private func decodePEM(_ pem: String) -> Data? {
        let base64 = pem.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.contains(":") && !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .joined()
        return Data(base64Encoded: base64)
    }

    private func buildRSAPrivateKeyDER(from rsa: RSAComponents) throws -> Data {
        let pMinusOne = subtractOne(from: unsignedInteger(rsa.p))
        let qMinusOne = subtractOne(from: unsignedInteger(rsa.q))
        let dmp1 = mod(unsignedInteger(rsa.d), pMinusOne)
        let dmq1 = mod(unsignedInteger(rsa.d), qMinusOne)

        let integers = [
            Data([0]),
            rsa.n,
            rsa.e,
            rsa.d,
            rsa.p,
            rsa.q,
            dmp1,
            dmq1,
            rsa.iqmp,
        ]

        var sequence = Data()
        for integer in integers {
            sequence.append(asn1Integer(integer))
        }

        var der = Data([0x30])
        der.append(asn1Length(sequence.count))
        der.append(sequence)
        return der
    }

    private func asn1Integer(_ value: Data) -> Data {
        var integer = unsignedInteger(value)
        if integer.isEmpty {
            integer = Data([0])
        }
        if let first = integer.first, first & 0x80 != 0 {
            integer.insert(0, at: 0)
        }

        var encoded = Data([0x02])
        encoded.append(asn1Length(integer.count))
        encoded.append(integer)
        return encoded
    }

    private func asn1Length(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }

        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }

        var data = Data([0x80 | UInt8(bytes.count)])
        data.append(contentsOf: bytes)
        return data
    }

    private func unsignedInteger(_ data: Data) -> Data {
        var bytes = Array(data)
        while bytes.count > 1 && bytes.first == 0 {
            bytes.removeFirst()
        }
        return Data(bytes)
    }

    private func subtractOne(from data: Data) -> Data {
        var bytes = Array(unsignedInteger(data))
        guard !bytes.isEmpty else { return Data([0]) }

        var index = bytes.count - 1
        while bytes[index] == 0 {
            bytes[index] = 0xFF
            guard index > 0 else { return Data([0]) }
            index -= 1
        }
        bytes[index] -= 1
        return unsignedInteger(Data(bytes))
    }

    private func mod(_ dividend: Data, _ divisor: Data) -> Data {
        let modulus = unsignedInteger(divisor)
        guard !modulus.isEmpty, modulus != Data([0]) else { return Data([0]) }

        var remainder = Data()
        for byte in unsignedInteger(dividend) {
            remainder.append(byte)
            remainder = unsignedInteger(remainder)
            while compareUnsigned(remainder, modulus) >= 0 {
                remainder = subtractUnsigned(remainder, modulus)
            }
        }
        return unsignedInteger(remainder)
    }

    private func compareUnsigned(_ lhs: Data, _ rhs: Data) -> Int {
        let left = Array(unsignedInteger(lhs))
        let right = Array(unsignedInteger(rhs))
        if left.count != right.count {
            return left.count < right.count ? -1 : 1
        }
        for (l, r) in zip(left, right) {
            if l != r { return l < r ? -1 : 1 }
        }
        return 0
    }

    private func subtractUnsigned(_ lhs: Data, _ rhs: Data) -> Data {
        var left = Array(unsignedInteger(lhs))
        let right = Array(unsignedInteger(rhs))
        var borrow = 0
        var li = left.count - 1
        var ri = right.count - 1

        while true {
            let rv = ri >= 0 ? Int(right[ri]) : 0
            var value = Int(left[li]) - rv - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            left[li] = UInt8(value)

            if li == 0 { break }
            li -= 1
            ri -= 1
        }

        return unsignedInteger(Data(left))
    }
}

// MARK: - SSH Agent Errors

public enum SSHAgentError: Error, LocalizedError {
    case unsupportedKeyFormat
    case unsupportedKeyType(String)
    case invalidKey
    case signingFailed
    case socketError(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedKeyFormat: return "Unsupported key format"
        case .unsupportedKeyType(let t): return "Unsupported key type: \(t)"
        case .invalidKey: return "Invalid private key"
        case .signingFailed: return "Signing operation failed"
        case .socketError(let msg): return "Socket error: \(msg)"
        }
    }
}
