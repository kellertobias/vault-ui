// MARK: - VaultSSH/SSHAgentControlClient.swift
// Internal control client for Vault UI menu actions.

import Darwin
import Foundation

public enum SSHAgentControlClient {
    private static let authorizeKeyExtension = "vaultui@authorize-key"
    private static let keyStatusExtension = "vaultui@key-status"
    private static let lockKeyExtension = "vaultui@lock-key"

    public struct KeyStatus: Sendable, Equatable {
        public let expiresAt: Date?

        public init(expiresAt: Date?) {
            self.expiresAt = expiresAt
        }
    }

    public static func authorizeKey(
        cipherId: String,
        comment: String,
        minutes: Int,
        socketPath: String = SSHAgentServer.defaultSocketPath
    ) async -> Bool {
        await Task.detached {
            authorizeKeySync(
                cipherId: cipherId,
                comment: comment,
                minutes: minutes,
                socketPath: socketPath
            )
        }.value
    }

    public static func keyStatus(
        cipherId: String,
        socketPath: String = SSHAgentServer.defaultSocketPath
    ) async -> KeyStatus? {
        await Task.detached {
            keyStatusSync(cipherId: cipherId, socketPath: socketPath)
        }.value
    }

    public static func lockKey(
        cipherId: String,
        socketPath: String = SSHAgentServer.defaultSocketPath
    ) async -> Bool {
        await Task.detached {
            lockKeySync(cipherId: cipherId, socketPath: socketPath)
        }.value
    }

    private static func authorizeKeySync(
        cipherId: String,
        comment: String,
        minutes: Int,
        socketPath: String
    ) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return false }

        withUnsafeMutableBytes(of: &addr.sun_path) { buffer in
            for (index, byte) in pathBytes.enumerated() {
                buffer[index] = byte
            }
            buffer[pathBytes.count] = 0
        }

        let connected = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { return false }

        var payload = Data()
        payload.append(SSHWireFormat.writeString(authorizeKeyExtension))
        payload.append(SSHWireFormat.writeString(cipherId))
        payload.append(SSHWireFormat.writeUInt32(UInt32(max(1, minutes))))
        payload.append(SSHWireFormat.writeString(comment))
        let message = SSHWireFormat.buildMessage(type: .extension_, payload: payload)

        guard writeAll(fd: fd, data: message) else { return false }
        guard let response = readMessage(fd: fd),
              let (type, _) = SSHWireFormat.parseMessage(response) else {
            return false
        }
        return type == .success
    }

    private static func lockKeySync(cipherId: String, socketPath: String) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        guard connect(fd: fd, socketPath: socketPath) else { return false }

        var payload = Data()
        payload.append(SSHWireFormat.writeString(lockKeyExtension))
        payload.append(SSHWireFormat.writeString(cipherId))
        let message = SSHWireFormat.buildMessage(type: .extension_, payload: payload)

        guard writeAll(fd: fd, data: message) else { return false }
        guard let response = readMessage(fd: fd),
              let (type, _) = SSHWireFormat.parseMessage(response) else {
            return false
        }
        return type == .success
    }

    private static func keyStatusSync(cipherId: String, socketPath: String) -> KeyStatus? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        guard connect(fd: fd, socketPath: socketPath) else { return nil }

        var payload = Data()
        payload.append(SSHWireFormat.writeString(keyStatusExtension))
        payload.append(SSHWireFormat.writeString(cipherId))
        let message = SSHWireFormat.buildMessage(type: .extension_, payload: payload)

        guard writeAll(fd: fd, data: message) else { return nil }
        guard let response = readMessage(fd: fd),
              let (type, responsePayload) = SSHWireFormat.parseMessage(response),
              type == .success,
              let secondsRemaining = SSHWireFormat.readUInt32(responsePayload, at: 0) else {
            return nil
        }

        guard secondsRemaining > 0 else {
            return KeyStatus(expiresAt: nil)
        }

        return KeyStatus(expiresAt: Date().addingTimeInterval(TimeInterval(secondsRemaining)))
    }

    private static func connect(fd: Int32, socketPath: String) -> Bool {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return false }

        withUnsafeMutableBytes(of: &addr.sun_path) { buffer in
            for (index, byte) in pathBytes.enumerated() {
                buffer[index] = byte
            }
            buffer[pathBytes.count] = 0
        }

        let connected = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        return connected == 0
    }

    private static func writeAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return false }
            var sent = 0
            while sent < rawBuffer.count {
                let written = Darwin.write(fd, base.advanced(by: sent), rawBuffer.count - sent)
                guard written > 0 else { return false }
                sent += written
            }
            return true
        }
    }

    private static func readMessage(fd: Int32) -> Data? {
        guard let lengthData = readExactly(fd: fd, count: 4),
              let length = SSHWireFormat.readUInt32(lengthData, at: 0),
              let body = readExactly(fd: fd, count: Int(length)) else {
            return nil
        }
        return lengthData + body
    }

    private static func readExactly(fd: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        let ok = data.withUnsafeMutableBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return false }
            var readBytes = 0
            while readBytes < count {
                let result = Darwin.read(fd, base.advanced(by: readBytes), count - readBytes)
                guard result > 0 else { return false }
                readBytes += result
            }
            return true
        }
        return ok ? data : nil
    }
}
