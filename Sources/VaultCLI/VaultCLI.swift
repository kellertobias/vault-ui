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
///
/// Provides CLI access to vault operations including:
/// - Getting passwords for scripts
/// - SSH agent management
/// - Password generation
@main
struct VaultCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vaultui",
        abstract: "Vault UI — Native macOS Password Manager CLI",
        version: "0.1.0",
        subcommands: [
            GetCommand.self,
            ListCommand.self,
            GenerateCommand.self,
            AgentCommand.self,
            StatusCommand.self,
        ]
    )
}

// MARK: - Get Command

/// Get a password or field from the vault.
struct GetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Get a password or field value from the vault"
    )

    @Argument(help: "Search term (name, URL, or ID)")
    var query: String

    @Option(name: .shortAndLong, help: "Field to retrieve (password, username, totp, notes, uri)")
    var field: String = "password"

    @Option(name: .shortAndLong, help: "Server URL")
    var server: String?

    @Option(name: .shortAndLong, help: "Email address")
    var email: String?

    func run() async throws {
        // For CLI usage, we authenticate inline and fetch the requested value
        guard let serverURL = server.flatMap(URL.init(string:)), let email = email else {
            print("Error: --server and --email are required for CLI access")
            throw ExitCode.failure
        }

        // Read password from stdin (piped) or prompt
        let password: String
        if isatty(fileno(stdin)) == 0 {
            // Reading from pipe
            password = (readLine(strippingNewline: true) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            // Interactive prompt
            print("Master password: ", terminator: "")
            password = String(cString: getpass(""))
        }

        guard !password.isEmpty else {
            print("Error: No password provided")
            throw ExitCode.failure
        }

        // Authenticate
        let account = Account(email: email, serverURL: serverURL)
        let client = APIClient(account: account)
        let authService = AuthService(client: client)

        // Prelogin
        let kdfConfig = try await authService.prelogin(email: email)

        // Derive keys
        let masterKey = try MasterKey.derive(password: password, email: email, kdfConfig: kdfConfig)
        let passwordHash = try MasterPasswordHash.compute(masterKey: masterKey, password: password)

        // Login
        let updatedAccount = Account(id: account.id, email: email, serverURL: serverURL, kdfConfig: kdfConfig)
        let loginClient = APIClient(account: updatedAccount)
        let loginAuth = AuthService(client: loginClient)
        let result = try await loginAuth.login(
            AuthService.LoginRequest(email: email, masterPasswordHash: passwordHash, deviceId: APIClient.getOrCreateDeviceId(for: updatedAccount))
        )

        // Decrypt vault key
        let stretchedKey = try masterKey.stretch()
        guard let encKeyStr = result.tokens.encryptedKey else {
            print("Error: No encrypted key received")
            throw ExitCode.failure
        }
        let protectedKey = try EncString(serialized: encKeyStr)
        let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(protectedKey, stretchedMasterKey: stretchedKey)

        // Sync
        let syncAPI = SyncAPI(client: loginClient)
        let syncResponse = try await syncAPI.fullSync()

        // Search
        guard let ciphers = syncResponse.ciphers else {
            print("Error: No ciphers in vault")
            throw ExitCode.failure
        }

        let queryLower = query.lowercased()
        let matches = ciphers.filter { cipher in
            if cipher.id == query { return true }
            if let name = cipher.name, let dec = try? CipherEncryption.decryptString(name, key: vaultKey) {
                if dec.lowercased().contains(queryLower) { return true }
            }
            if let uris = cipher.login?.uris {
                for uri in uris {
                    if let encUri = uri.uri, let dec = try? CipherEncryption.decryptString(encUri, key: vaultKey) {
                        if dec.lowercased().contains(queryLower) { return true }
                    }
                }
            }
            return false
        }

        guard let match = matches.first else {
            print("Error: No matching item found for '\(query)'")
            throw ExitCode.failure
        }

        // Extract the requested field
        let value: String?
        switch field.lowercased() {
        case "password":
            value = match.login?.password.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) }
        case "username":
            value = match.login?.username.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) }
        case "totp":
            if let totpEnc = match.login?.totp,
               let secret = try? CipherEncryption.decryptString(totpEnc, key: vaultKey),
               let code = TOTPService.generateCode(from: secret) {
                value = code.code
            } else {
                value = nil
            }
        case "notes":
            value = match.notes.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) }
        case "uri", "url":
            value = match.login?.uris?.first?.uri.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) }
        default:
            print("Error: Unknown field '\(field)'. Use: password, username, totp, notes, uri")
            throw ExitCode.failure
        }

        if let value = value {
            print(value)
        } else {
            print("Error: Field '\(field)' is empty or not available")
            throw ExitCode.failure
        }
    }
}

// MARK: - List Command

/// List vault items.
struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List vault items"
    )

    @Option(name: .shortAndLong, help: "Filter by type (login, note, card, identity, ssh)")
    var type: String?

    @Option(name: .shortAndLong, help: "Server URL")
    var server: String?

    @Option(name: .shortAndLong, help: "Email address")
    var email: String?

    func run() async throws {
        guard let serverURL = server.flatMap(URL.init(string:)), let email = email else {
            print("Error: --server and --email are required")
            throw ExitCode.failure
        }

        let password = String(cString: getpass("Master password: "))

        // Quick auth + sync (same as get command)
        let account = Account(email: email, serverURL: serverURL)
        let client = APIClient(account: account)
        let auth = AuthService(client: client)
        let kdfConfig = try await auth.prelogin(email: email)
        let masterKey = try MasterKey.derive(password: password, email: email, kdfConfig: kdfConfig)
        let hash = try MasterPasswordHash.compute(masterKey: masterKey, password: password)

        let updatedAccount = Account(id: account.id, email: email, serverURL: serverURL, kdfConfig: kdfConfig)
        let loginClient = APIClient(account: updatedAccount)
        let loginAuth = AuthService(client: loginClient)
        let result = try await loginAuth.login(AuthService.LoginRequest(email: email, masterPasswordHash: hash, deviceId: APIClient.getOrCreateDeviceId(for: updatedAccount)))

        let stretchedKey = try masterKey.stretch()
        let protectedKey = try EncString(serialized: result.tokens.encryptedKey!)
        let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(protectedKey, stretchedMasterKey: stretchedKey)

        let syncResponse = try await SyncAPI(client: loginClient).fullSync()

        guard let ciphers = syncResponse.ciphers else { return }

        // Filter by type
        let typeFilter: CipherType?
        switch type?.lowercased() {
        case "login": typeFilter = .login
        case "note", "securenote": typeFilter = .secureNote
        case "card": typeFilter = .card
        case "identity": typeFilter = .identity
        case "ssh", "sshkey": typeFilter = .sshKey
        default: typeFilter = nil
        }

        let filtered = typeFilter != nil ? ciphers.filter { $0.type == typeFilter } : ciphers

        for cipher in filtered {
            let name = cipher.name.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) } ?? "?"
            let typeStr = cipher.type.displayName.padding(toLength: 12, withPad: " ", startingAt: 0)
            let id = cipher.id ?? "?"
            print("\(typeStr) \(name.padding(toLength: 40, withPad: " ", startingAt: 0)) [\(id)]")
        }
    }
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

// MARK: - Agent Command

/// SSH agent management.
struct AgentCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "agent",
        abstract: "SSH agent management",
        subcommands: [
            AgentStartCommand.self,
            AgentStatusCommand.self,
            AgentInstallCommand.self,
        ]
    )
}

/// Start the SSH agent.
struct AgentStartCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "start",
        abstract: "Start the SSH agent"
    )

    @Option(name: .long, help: "Socket path (default: ~/.vaultui/agent.sock)")
    var socket: String?

    func run() async throws {
        let handler = SSHAgentHandler { _ in nil }
        let server = SSHAgentServer(handler: handler, socketPath: socket)

        print("SSH agent listening on \(server.agentSocketPath)")
        print("Export: export SSH_AUTH_SOCK=\(server.agentSocketPath)")

        // Set up signal handling for graceful shutdown
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler {
            Task {
                await server.stop()
                Foundation.exit(0)
            }
        }
        sigintSource.resume()

        try await server.start()
        try await server.waitUntilClosed()
    }
}

/// Check SSH agent status.
struct AgentStatusCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check SSH agent status"
    )

    func run() throws {
        let path = SSHAgentServer.defaultSocketPath
        if FileManager.default.fileExists(atPath: path) {
            print("SSH agent socket: \(path) (exists)")
            print("Export: export SSH_AUTH_SOCK=\(path)")
        } else {
            print("SSH agent is not running")
            print("Start with: vaultui agent start")
        }
    }
}

/// Install SSH agent LaunchAgent.
struct AgentInstallCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "install",
        abstract: "Install LaunchAgent for auto-start"
    )

    func run() throws {
        let cliPath = CommandLine.arguments[0]
        try SSHAgentServer.installLaunchAgent(cliPath: cliPath)
        print("LaunchAgent installed. The SSH agent will start automatically on login.")
        print("Socket: \(SSHAgentServer.defaultSocketPath)")
        print("\nAdd to your shell profile:")
        print("  export SSH_AUTH_SOCK=\(SSHAgentServer.defaultSocketPath)")
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
            print("SSH Agent: ✅ running (\(agentPath))")
        } else {
            print("SSH Agent: ⏸ not running")
        }

        let launchAgentPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.vaultui.ssh-agent.plist")
        if FileManager.default.fileExists(atPath: launchAgentPath.path) {
            print("LaunchAgent: ✅ installed")
        } else {
            print("LaunchAgent: ⏸ not installed")
        }
    }
}
