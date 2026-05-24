// MARK: - VaultCLI/VaultCLI.swift
// Command-line interface for Vault UI

import ArgumentParser
import Foundation
import VaultServices
import VaultCrypto
import VaultModels
import VaultAPI
import VaultSSH

/// Vault UI command-line tool.
@main
struct VaultCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vaultui",
        abstract: "Vault UI — Native macOS Password Manager CLI",
        version: "0.1.0",
        subcommands: [
            GetCommand.self,
            EnvCommand.self,
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
        print("Vault UI v0.1.0")
        print()

        let agentPath = SSHAgentServer.defaultSocketPath
        if FileManager.default.fileExists(atPath: agentPath) {
            print("SSH Agent:    ✅ running (\(agentPath))")
        } else {
            print("SSH Agent:    ⏸ not running")
        }

        let secretPath = SecretAgentServer.defaultSocketPath
        if FileManager.default.fileExists(atPath: secretPath) {
            print("Secret Agent: ✅ running (\(secretPath))")
        } else {
            print("Secret Agent: ⏸ not running")
        }
    }
}
