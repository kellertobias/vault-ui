// MARK: - VaultCLI/VaultCLI.swift
// Command-line interface for Vault UI

import ArgumentParser
import Foundation
import VaultServices
import VaultCrypto
import VaultModels
import VaultAPI
import VaultSSH
import Darwin

/// Vault UI command-line tool.
@main
struct VaultCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vaultui",
        abstract: "Vault UI — Native macOS Password Manager CLI",
        version: "1.5.26",
        subcommands: [
            GetCommand.self,
            EnvCommand.self,
            AgentCommand.self,
            GenerateCommand.self,
            StatusCommand.self,
        ]
    )
}

// MARK: - Generate Command

/// Generate a password.
struct GenerateCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "generate",
        abstract: "Generate a secure password or passphrase"
    )

    @Option(name: .shortAndLong, help: "Password length (default: 20)")
    var length: Int = 20

    @Flag(name: .long, help: "Generate a passphrase instead")
    var passphrase = false

    @Option(name: .shortAndLong, help: "Number of words for passphrase (default: 4)")
    var words: Int = 4

    @Option(name: .long, help: "Passphrase separator (default: -)")
    var separator: String = "-"

    @Flag(name: .long, help: "Exclude symbols")
    var noSymbols = false

    @Flag(name: .long, help: "Exclude numbers")
    var noNumbers = false

    func run() throws {
        let result: String
        if passphrase {
            result = PasswordGenerator.generatePassphrase(
                wordCount: words,
                separator: separator,
                capitalize: true,
                includeNumber: true
            )
        } else {
            result = PasswordGenerator.generatePassword(
                length: length,
                uppercase: true,
                lowercase: true,
                numbers: !noNumbers,
                symbols: !noSymbols
            )
        }
        print(result)
    }
}

// MARK: - Status Command

/// Show vault status.
struct StatusCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show vault and agent status"
    )

    func run() throws {
        print("Vault UI v1.5.26")
        print()

        let agentPath = SSHAgentServer.defaultSocketPath
        if socketHasListener(atPath: agentPath) {
            print("SSH Agent:    ✅ running (\(agentPath))")
        } else {
            print("SSH Agent:    ⏸ not running")
        }

        let secretPath = SecretAgentServer.defaultSocketPath
        if socketHasListener(atPath: secretPath) {
            print("Secret Agent: ✅ running (\(secretPath))")
        } else {
            print("Secret Agent: ⏸ not running")
        }
    }
}

private func socketHasListener(atPath socketPath: String) -> Bool {
    guard FileManager.default.fileExists(atPath: socketPath) else {
        return false
    }

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = socketPath.utf8CString
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: Int8.self, capacity: 104) { dest in
            pathBytes.withUnsafeBufferPointer { src in
                for i in 0..<min(src.count, 104) {
                    dest[i] = src[i]
                }
            }
        }
    }

    return withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
            connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    } == 0
}
