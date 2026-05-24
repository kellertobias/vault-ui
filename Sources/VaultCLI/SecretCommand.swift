// MARK: - VaultCLI/SecretCommand.swift
// CLI commands for accessing vault secrets by slug

import ArgumentParser
import Foundation
import VaultModels
import VaultServices

// MARK: - Get Command

/// Get a secret value from the vault by its slug.
struct GetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Get a secret by its CLI slug",
        discussion: """
            Retrieve a full secret as JSON or a specific field value.
            Secrets must have a 'vaultui-slug' custom field set in the Vault UI app.
            The Vault UI app must be running.
            
            Examples:
              vaultui get my-app.database          # full JSON
              vaultui get my-app.database/password  # just the password
              vaultui get my-app.database/username   # just the username
            
            Supported fields: username, password, totp, notes, uri, or any custom field name.
            """
    )

    @Argument(help: "Secret slug, optionally followed by /field (e.g. my-slug or my-slug/password)")
    var query: String

    func run() async throws {
        guard let parsed = VaultUISlug.parseArgument(query) else {
            FileHandle.standardError.write(Data("Error: Invalid slug format '\(query)'. Use only a-zA-Z0-9, hyphens, underscores, and dots.\n".utf8))
            throw ExitCode.failure
        }

        var request = SecretRequest(type: "get", slug: parsed.slug)
        request.field = parsed.field

        let response = try sendRequest(request)

        if response.ok, let value = response.value {
            print(value)
        } else {
            let errorMsg = response.error ?? "Unknown error"
            FileHandle.standardError.write(Data("Error: \(errorMsg)\n".utf8))
            throw ExitCode.failure
        }
    }
}

// MARK: - Env Command

/// Extend a .env file by resolving vaultui:// references.
struct EnvCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "env",
        abstract: "Resolve vault secrets in a .env file",
        discussion: """
            Reads a .env file and outputs shell export commands with vault secrets resolved.
            
            Lines containing vaultui://<slug> or vaultui://<slug>/<field> will be looked up
            from the vault. Regular lines are passed through as-is.
            
            Usage:
              eval "$(vaultui env my.env)" && ./my-app
            
            Example .env file:
              DB_HOST="localhost"
              DB_PASSWORD="vaultui://my-app.database/password"
              API_KEY="vaultui://my-app.api-key/password"
            """
    )

    @Argument(help: "Path to .env file")
    var envFile: String

    func run() async throws {
        let path = (envFile as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: path)

        guard FileManager.default.fileExists(atPath: url.path) else {
            FileHandle.standardError.write(Data("Error: File not found: \(envFile)\n".utf8))
            throw ExitCode.failure
        }

        let content: String
        do {
            content = try String(contentsOf: url, encoding: .utf8)
        } catch {
            FileHandle.standardError.write(Data("Error: Cannot read file: \(error.localizedDescription)\n".utf8))
            throw ExitCode.failure
        }

        let request = SecretRequest(type: "extend", envContent: content)
        let response = try sendRequest(request)

        if response.ok, let value = response.value {
            print(value)
        } else {
            let errorMsg = response.error ?? "Unknown error"
            FileHandle.standardError.write(Data("Error: \(errorMsg)\n".utf8))
            throw ExitCode.failure
        }
    }
}

// MARK: - Socket Client

/// Send a request to the secret agent Unix domain socket and return the response.
private func sendRequest(_ request: SecretRequest) throws -> SecretResponse {
    let socketPath = (("~/.vaultui/secret.sock" as NSString).expandingTildeInPath)

    guard FileManager.default.fileExists(atPath: socketPath) else {
        FileHandle.standardError.write(Data("Error: Vault UI is not running. Start the app first.\n".utf8))
        throw ExitCode.failure
    }

    // Encode request
    let requestData = try JSONEncoder().encode(request)

    // Create Unix domain socket
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        throw SecretClientError.socketCreationFailed
    }
    defer { close(fd) }

    // Connect
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = socketPath.utf8CString
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: Int8.self, capacity: Int(104)) { dest in
            pathBytes.withUnsafeBufferPointer { src in
                let count = min(src.count, 104)
                for i in 0..<count {
                    dest[i] = src[i]
                }
            }
        }
    }

    let connectResult = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
            connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }

    guard connectResult == 0 else {
        throw SecretClientError.connectionFailed(String(cString: strerror(errno)))
    }

    // Set read timeout (30 seconds, to allow for Touch ID prompt)
    var timeout = timeval(tv_sec: 30, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

    // Send: [4-byte big-endian length][request data]
    var length = UInt32(requestData.count).bigEndian
    let lengthData = Data(bytes: &length, count: 4)

    try lengthData.withUnsafeBytes { ptr in
        let sent = send(fd, ptr.baseAddress!, ptr.count, 0)
        guard sent == ptr.count else { throw SecretClientError.sendFailed }
    }

    try requestData.withUnsafeBytes { ptr in
        let sent = send(fd, ptr.baseAddress!, ptr.count, 0)
        guard sent == ptr.count else { throw SecretClientError.sendFailed }
    }

    // Read response: [4-byte big-endian length][response data]
    var responseLengthBytes = Data(count: 4)
    let headerRead = responseLengthBytes.withUnsafeMutableBytes { ptr in
        recv(fd, ptr.baseAddress!, 4, MSG_WAITALL)
    }
    guard headerRead == 4 else {
        throw SecretClientError.readFailed
    }

    let responseLength = responseLengthBytes.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    guard responseLength > 0, responseLength < 10_000_000 else {
        throw SecretClientError.invalidResponse
    }

    var responseData = Data(count: Int(responseLength))
    let bodyRead = responseData.withUnsafeMutableBytes { ptr in
        recv(fd, ptr.baseAddress!, Int(responseLength), MSG_WAITALL)
    }
    guard bodyRead == Int(responseLength) else {
        throw SecretClientError.readFailed
    }

    return try JSONDecoder().decode(SecretResponse.self, from: responseData)
}

/// Errors from the socket client.
private enum SecretClientError: Error, LocalizedError {
    case socketCreationFailed
    case connectionFailed(String)
    case sendFailed
    case readFailed
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .socketCreationFailed: return "Failed to create socket"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .sendFailed: return "Failed to send request"
        case .readFailed: return "Failed to read response (timeout or connection closed)"
        case .invalidResponse: return "Invalid response from server"
        }
    }
}
