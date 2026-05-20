// MARK: - VaultSSH/SSHAgentHandler.swift
// SSH agent message handler — processes client requests

import Foundation
import Security
import CryptoKit

/// Handles SSH agent protocol messages.
///
/// This is the core logic that processes incoming requests from SSH clients
/// and returns appropriate responses. It maintains a list of available keys
/// from the vault and performs signing operations.
public final class SSHAgentHandler: @unchecked Sendable {

    /// Available SSH identities (loaded from vault)
    private var identities: [SSHIdentity] = []

    /// Callback to get the private key data for a cipher ID
    private let privateKeyProvider: @Sendable (String) async -> Data?

    /// Whether the agent is locked
    private var isLocked = false
    private var lockPassphrase: String?

    /// Lock for thread safety
    private let lock = NSLock()

    public init(privateKeyProvider: @escaping @Sendable (String) async -> Data?) {
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
    }

    // MARK: - Message Processing

    /// Process an incoming SSH agent message and return the response.
    public func processMessage(_ data: Data) async -> Data {
        guard let (type, payload) = SSHWireFormat.parseMessage(data) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        switch type {
        case .requestIdentities:
            return handleRequestIdentities()
        case .signRequest:
            return await handleSignRequest(payload)
        case .lock:
            return handleLock(payload)
        case .unlock:
            return handleUnlock(payload)
        case .removeAllIdentities:
            return handleRemoveAll()
        default:
            // Unsupported message type
            return SSHWireFormat.buildMessage(type: .failure)
        }
    }

    // MARK: - Request Handlers

    /// Handle SSH_AGENTC_REQUEST_IDENTITIES — return all available public keys.
    private func handleRequestIdentities() -> Data {
        lock.lock()
        let ids = identities
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
    private func handleSignRequest(_ payload: Data) async -> Data {
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

        // Get the private key
        guard let privateKeyData = await privateKeyProvider(identity.cipherId) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        // Perform the signature
        guard let signature = try? performSignature(
            privateKey: privateKeyData,
            data: dataToSign,
            flags: flags
        ) else {
            return SSHWireFormat.buildMessage(type: .failure)
        }

        // Build response: string signature
        let responsePayload = SSHWireFormat.writeString(signature)
        return SSHWireFormat.buildMessage(type: .signResponse, payload: responsePayload)
    }

    /// Thread-safe identity lookup (called from async context without holding the lock across await).
    private func findIdentity(for keyBlob: Data) -> SSHIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return identities.first { $0.publicKeyBlob == keyBlob }
    }

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

        default:
            throw SSHAgentError.unsupportedKeyType(keyData.algorithm)
        }
    }

    /// Sign using an RSA key from PEM format.
    private func signWithPEMKey(_ pemString: String, data: Data, flags: SSHSignFlags) throws -> Data {
        // Use Security framework for RSA signing
        let pemData = pemString.data(using: .utf8)!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(pemData as CFData, attributes as CFDictionary, &error) else {
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
    }

    /// Parse an OpenSSH private key (simplified for Ed25519 keys).
    private func parseOpenSSHPrivateKey(_ pem: String) -> ParsedKey? {
        // Strip PEM headers
        let lines = pem.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64 = lines.joined()

        guard let decoded = Data(base64Encoded: base64) else { return nil }

        // OpenSSH format: "openssh-key-v1\0" magic + ciphername + kdfname + ...
        let magic = "openssh-key-v1\0"
        guard decoded.count > magic.count,
              String(data: decoded[0..<magic.count], encoding: .utf8) == magic else {
            return nil
        }

        // Parse the key structure (simplified — handles unencrypted Ed25519 only)
        var offset = magic.count

        // ciphername
        guard let (_, next1) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next1

        // kdfname
        guard let (_, next2) = SSHWireFormat.readString(decoded, at: offset) else { return nil }
        offset = next2

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

        guard check1 == check2 else { return nil }  // Key is encrypted if these don't match

        // Key type
        guard let (keyTypeData, next) = SSHWireFormat.readString(privateSection, at: privOffset) else { return nil }
        privOffset = next
        let keyType = String(data: keyTypeData, encoding: .utf8) ?? ""

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

        return nil
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
