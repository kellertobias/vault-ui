// MARK: - VaultSSH/SSHAgentProtocol.swift
// SSH agent protocol message types per draft-miller-ssh-agent

import Foundation

/// SSH agent protocol message types.
///
/// Reference: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
public enum SSHAgentMessageType: UInt8, Sendable {
    // Requests from client
    case requestIdentities = 11        // SSH_AGENTC_REQUEST_IDENTITIES
    case signRequest = 13              // SSH_AGENTC_SIGN_REQUEST
    case addIdentity = 17              // SSH_AGENTC_ADD_IDENTITY
    case removeIdentity = 18           // SSH_AGENTC_REMOVE_IDENTITY
    case removeAllIdentities = 19      // SSH_AGENTC_REMOVE_ALL_IDENTITIES
    case addSmartcardKey = 20          // SSH_AGENTC_ADD_SMARTCARD_KEY
    case removeSmartcardKey = 21       // SSH_AGENTC_REMOVE_SMARTCARD_KEY
    case lock = 22                     // SSH_AGENTC_LOCK
    case unlock = 23                   // SSH_AGENTC_UNLOCK
    case addIdConstrained = 25         // SSH_AGENTC_ADD_ID_CONSTRAINED
    case extension_ = 27               // SSH_AGENTC_EXTENSION

    // Responses from agent
    case failure = 5                   // SSH_AGENT_FAILURE
    case success = 6                   // SSH_AGENT_SUCCESS
    case identitiesAnswer = 12         // SSH_AGENT_IDENTITIES_ANSWER
    case signResponse = 14             // SSH_AGENT_SIGN_RESPONSE
}

/// SSH key algorithm identifiers.
public enum SSHKeyAlgorithm: String, Sendable {
    case rsaSHA256 = "rsa-sha2-256"
    case rsaSHA512 = "rsa-sha2-512"
    case ed25519 = "ssh-ed25519"
    case ecdsaSHA256 = "ecdsa-sha2-nistp256"
    case ecdsaSHA384 = "ecdsa-sha2-nistp384"
    case ecdsaSHA512 = "ecdsa-sha2-nistp521"
}

/// SSH agent sign flags.
public struct SSHSignFlags: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let rsaSHA256 = SSHSignFlags(rawValue: 2)
    public static let rsaSHA512 = SSHSignFlags(rawValue: 4)
}

/// An SSH identity (public key + comment) for the agent.
public struct SSHIdentity: Sendable, Equatable {
    /// The public key blob (wire format)
    public let publicKeyBlob: Data

    /// The comment (usually the key fingerprint or vault item name)
    public let comment: String

    /// The vault cipher ID this key belongs to (for lookup during sign)
    public let cipherId: String

    public init(publicKeyBlob: Data, comment: String, cipherId: String) {
        self.publicKeyBlob = publicKeyBlob
        self.comment = comment
        self.cipherId = cipherId
    }
}

// MARK: - Wire Format Helpers

/// SSH wire format serialization/deserialization.
public enum SSHWireFormat {

    /// Read a uint32 from data at the given offset.
    public static func readUInt32(_ data: Data, at offset: Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        return data.withUnsafeBytes { buffer in
            buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian
        }
    }

    /// Read a string (length-prefixed) from data at the given offset.
    /// Returns the string data and the new offset.
    public static func readString(_ data: Data, at offset: Int) -> (Data, Int)? {
        guard let length = readUInt32(data, at: offset) else { return nil }
        let nextOffset = offset + 4 + Int(length)
        guard nextOffset <= data.count else { return nil }
        
        let start = data.startIndex + offset + 4
        let end = data.startIndex + nextOffset
        return (Data(data[start..<end]), nextOffset)
    }

    /// Write a uint32 in big-endian.
    public static func writeUInt32(_ value: UInt32) -> Data {
        var be = value.bigEndian
        return Data(bytes: &be, count: 4)
    }

    /// Write a length-prefixed string.
    public static func writeString(_ data: Data) -> Data {
        writeUInt32(UInt32(data.count)) + data
    }

    /// Write a length-prefixed UTF-8 string.
    public static func writeString(_ string: String) -> Data {
        writeString(Data(string.utf8))
    }

    /// Build a complete agent message (length + type + payload).
    public static func buildMessage(type: SSHAgentMessageType, payload: Data = Data()) -> Data {
        let totalLength = UInt32(1 + payload.count)
        return writeUInt32(totalLength) + Data([type.rawValue]) + payload
    }

    /// Parse an incoming agent message.
    /// Returns (message type, payload) or nil.
    public static func parseMessage(_ data: Data) -> (SSHAgentMessageType, Data)? {
        guard data.count >= 5 else { return nil }
        guard let length = readUInt32(data, at: 0) else { return nil }
        guard data.count >= 4 + Int(length) else { return nil }

        let typeByte = data[data.startIndex + 4]
        guard let type = SSHAgentMessageType(rawValue: typeByte) else { return nil }

        let payloadStart = data.startIndex + 5
        let payloadEnd = data.startIndex + 4 + Int(length)
        let payload = payloadEnd > payloadStart ? Data(data[payloadStart..<payloadEnd]) : Data()

        return (type, payload)
    }
}
