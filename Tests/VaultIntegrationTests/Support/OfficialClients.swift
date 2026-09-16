// MARK: - VaultIntegrationTests/Support/OfficialClients.swift
// Official Bitwarden clients, driven from the Swift tests.
//
// The Bitwarden CLI (`bw`) and the web vault Vaultwarden serves are built from
// the same bitwarden/clients code as the browser extension and desktop app, so
// "an official client can read what the app wrote, and vice versa" is checked
// with them. Both live in Tests/Interop (`npm ci` there); tests skip when they
// are not installed.

import XCTest
import Foundation

enum InteropTooling {
    /// Tests/Interop, found relative to this file.
    static let directory: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // Support
        .deletingLastPathComponent() // VaultIntegrationTests
        .deletingLastPathComponent() // Tests
        .appendingPathComponent("Interop")

    static var bwScript: URL {
        directory.appendingPathComponent("node_modules/@bitwarden/cli/build/bw.js")
    }

    static var webVaultScript: URL {
        directory.appendingPathComponent("webvault.mjs")
    }

    static func requireBitwardenCLI() throws {
        guard FileManager.default.fileExists(atPath: bwScript.path) else {
            throw XCTSkip("Bitwarden CLI not installed: run `npm ci` in Tests/Interop")
        }
    }

    static func requirePlaywright() throws {
        let playwright = directory.appendingPathComponent("node_modules/playwright/package.json")
        guard FileManager.default.fileExists(atPath: playwright.path) else {
            throw XCTSkip("Playwright not installed: run `npm ci` in Tests/Interop")
        }
    }

    struct CommandError: Error, CustomStringConvertible {
        let command: String
        let status: Int32
        let output: String

        var description: String {
            "`\(command)` exited with \(status):\n\(output)"
        }
    }

    /// Run `node <script> <arguments>` and return stdout.
    ///
    /// `node` is resolved from PATH, so the version manager's choice applies.
    static func runNode(
        script: URL,
        arguments: [String],
        environment extra: [String: String]
    ) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["node", script.path] + arguments
            process.currentDirectoryURL = directory

            var environment = ProcessInfo.processInfo.environment
            environment.merge(extra) { _, new in new }
            // The test server's certificate is issued by a throwaway CA.
            if let ca = IntegrationEnvironment.caCertificatePath {
                environment["NODE_EXTRA_CA_CERTS"] = ca
            }
            process.environment = environment

            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr

            // Drain both pipes while the process runs, so a chatty child can't
            // block on a full pipe buffer.
            let outputBox = OutputBox()
            stdout.fileHandleForReading.readabilityHandler = { handle in
                outputBox.appendOut(handle.availableData)
            }
            stderr.fileHandleForReading.readabilityHandler = { handle in
                outputBox.appendErr(handle.availableData)
            }

            process.terminationHandler = { finished in
                stdout.fileHandleForReading.readabilityHandler = nil
                stderr.fileHandleForReading.readabilityHandler = nil
                outputBox.appendOut(stdout.fileHandleForReading.readDataToEndOfFile())
                outputBox.appendErr(stderr.fileHandleForReading.readDataToEndOfFile())

                let (out, err) = outputBox.strings()
                if finished.terminationStatus == 0 {
                    continuation.resume(returning: out)
                } else {
                    let visibleArguments = arguments.map { $0.count > 60 ? "<\($0.count) chars>" : $0 }
                    continuation.resume(throwing: CommandError(
                        command: ([script.lastPathComponent] + visibleArguments).joined(separator: " "),
                        status: finished.terminationStatus,
                        output: err.isEmpty ? out : err
                    ))
                }
            }

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private final class OutputBox: @unchecked Sendable {
        private let lock = NSLock()
        private var out = Data()
        private var err = Data()

        func appendOut(_ data: Data) { lock.withLock { out.append(data) } }
        func appendErr(_ data: Data) { lock.withLock { err.append(data) } }

        func strings() -> (String, String) {
            lock.withLock {
                (String(decoding: out, as: UTF8.self), String(decoding: err, as: UTF8.self))
            }
        }
    }
}

// MARK: - Bitwarden CLI

/// One logged-in `bw` session, with its own isolated data directory.
///
/// Never touches the user's real Bitwarden CLI state: every instance gets a
/// fresh `BITWARDENCLI_APPDATA_DIR` that is deleted with `logout()`.
struct BitwardenCLI: Sendable {
    let email: String
    let appDataDirectory: URL
    let session: String

    static func login(as user: TestUser, serverURL: URL) async throws -> BitwardenCLI {
        try InteropTooling.requireBitwardenCLI()

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vault-ui-bw-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let unauthenticated = BitwardenCLI(email: user.email, appDataDirectory: directory, session: "")
        _ = try await unauthenticated.run(["config", "server", serverURL.absoluteString])
        let session = try await unauthenticated.run(["login", user.email, TestUser.password, "--raw"])
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let cli = BitwardenCLI(email: user.email, appDataDirectory: directory, session: session)
        _ = try await cli.run(["sync"])
        return cli
    }

    func logout() async {
        _ = try? await run(["logout"])
        try? FileManager.default.removeItem(at: appDataDirectory)
    }

    @discardableResult
    func run(_ arguments: [String]) async throws -> String {
        var environment = [
            "BITWARDENCLI_APPDATA_DIR": appDataDirectory.path,
            "BW_NOINTERACTION": "true",
        ]
        if !session.isEmpty {
            environment["BW_SESSION"] = session
        }
        return try await InteropTooling.runNode(
            script: InteropTooling.bwScript,
            arguments: arguments,
            environment: environment
        )
    }

    /// Run a command and decode its JSON output.
    func json<T: Decodable>(_ arguments: [String], as type: T.Type = T.self) async throws -> T {
        let output = try await run(arguments)
        do {
            return try JSONDecoder().decode(T.self, from: Data(output.utf8))
        } catch {
            throw InteropTooling.CommandError(
                command: "bw " + arguments.joined(separator: " "),
                status: 0,
                output: "Could not decode output as \(T.self): \(error)\n\(output)"
            )
        }
    }

    func sync() async throws {
        try await run(["sync"])
    }

    func item(id: String) async throws -> CLIItem {
        try await sync()
        return try await json(["get", "item", id])
    }

    func items() async throws -> [CLIItem] {
        try await sync()
        return try await json(["list", "items"])
    }

    /// Create an item from a JSON object (the shape `bw get template item` shows).
    func createItem(_ item: [String: Any]) async throws -> CLIItem {
        try await json(["create", "item", try Self.encoded(item)])
    }

    func editItem(id: String, _ item: [String: Any]) async throws -> CLIItem {
        try await json(["edit", "item", id, try Self.encoded(item)])
    }

    /// Share a personal item into an organization (`bw move`).
    func moveItem(id: String, toOrganization organizationId: String, collectionIds: [String]) async throws -> CLIItem {
        try await json(["move", id, organizationId, try Self.encoded(collectionIds)])
    }

    /// The raw JSON of an item, for editing with `editItem`.
    func rawItem(id: String) async throws -> [String: Any] {
        try await sync()
        let output = try await run(["get", "item", id])
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any])
    }

    /// `bw` takes JSON arguments base64-encoded.
    private static func encoded(_ value: Any) throws -> String {
        try JSONSerialization.data(withJSONObject: value).base64EncodedString()
    }
}

/// The subset of `bw get item` output the tests read.
struct CLIItem: Decodable, Sendable {
    struct Login: Decodable, Sendable {
        struct URI: Decodable, Sendable {
            let uri: String?
        }

        let username: String?
        let password: String?
        let totp: String?
        let uris: [URI]?
    }

    struct Field: Decodable, Sendable {
        let name: String?
        let value: String?
        let type: Int
    }

    let id: String
    let organizationId: String?
    let collectionIds: [String]?
    let folderId: String?
    let type: Int
    let name: String
    let notes: String?
    let login: Login?
    let fields: [Field]?
}

// MARK: - Web vault

/// The web vault Vaultwarden serves, driven by Playwright in local Chrome.
enum WebVault {
    struct VisibleItem: Decodable, Sendable {
        let name: String
        let username: String?
        let password: String?
    }

    /// Log in through the web UI and read one item's details as a user would.
    static func readItem(named name: String, as user: TestUser, serverURL: URL) async throws -> VisibleItem {
        try InteropTooling.requirePlaywright()
        let output = try await InteropTooling.runNode(
            script: InteropTooling.webVaultScript,
            arguments: [
                "read-item",
                "--url", serverURL.absoluteString,
                "--email", user.email,
                "--password", TestUser.password,
                "--item", name,
            ],
            environment: [:]
        )
        let lastLine = output.split(separator: "\n").last.map(String.init) ?? ""
        return try JSONDecoder().decode(VisibleItem.self, from: Data(lastLine.utf8))
    }
}
