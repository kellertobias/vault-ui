// MARK: - VaultSSH/SSHAgentServer.swift
// Unix domain socket server for SSH agent protocol

import Foundation
import Darwin
import NIO
import NIOFoundationCompat
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SSHAgent")

/// SSH agent Unix domain socket server.
///
/// Listens on the shared app-group socket and handles SSH agent protocol messages
/// from SSH clients (ssh, git, etc.).
public final class SSHAgentServer: @unchecked Sendable {
    public let handler: SSHAgentHandler
    private let socketPath: String
    private let group: EventLoopGroup
    private var channel: Channel?

    /// The actual socket path being used.
    public var agentSocketPath: String { socketPath }

    public init(handler: SSHAgentHandler, socketPath: String? = nil) {
        self.handler = handler
        self.socketPath = socketPath ?? Self.defaultSocketPath
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    }

    /// Default socket path.
    public static var defaultSocketPath: String {
        VaultAgentSocketDirectory.socketPath(named: "agent.sock")
    }

    /// Start the SSH agent server.
    public func start() async throws {
        // Ensure directory exists
        let socketDir = (socketPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: socketDir,
            withIntermediateDirectories: true
        )

        // Remove stale socket, but never unlink a live listener owned by another process.
        if FileManager.default.fileExists(atPath: socketPath) {
            if socketHasListener() {
                throw POSIXError(.EADDRINUSE)
            }
            try unlinkStaleSocket()
        }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 16)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(SSHAgentChannelHandler(agentHandler: self.handler))
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.maxMessagesPerRead, value: 16)

        // Set restrictive umask before bind() so the socket is created with
        // owner-only permissions atomically, eliminating the TOCTOU window.
        let previousUmask = umask(0o077)
        defer { umask(previousUmask) }
        self.channel = try await bootstrap.bind(
            unixDomainSocketPath: socketPath
        ).get()

        // Ensure socket permissions are owner-only (belt-and-suspenders)
        chmod(socketPath, 0o600)

        logger.info("SSH agent listening on \(self.socketPath)")
    }

    /// Block until the server stops.
    public func waitUntilClosed() async throws {
        try await channel?.closeFuture.get()
    }

    /// Stop the server.
    public func stop() async {
        try? await group.shutdownGracefully()

        // Clean up socket file
        try? FileManager.default.removeItem(atPath: socketPath)
        logger.info("SSH agent stopped")
    }

    private func socketHasListener() -> Bool {
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

    private func unlinkStaleSocket() throws {
        var info = stat()
        guard lstat(socketPath, &info) == 0 else {
            if errno == ENOENT { return }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        guard (info.st_mode & S_IFMT) == S_IFSOCK else {
            throw POSIXError(.EEXIST)
        }

        guard unlink(socketPath) == 0 || errno == ENOENT else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    /// Generate a LaunchAgent plist for auto-starting the SSH agent.
    public static func generateLaunchAgentPlist(cliPath: String) -> String {
        let socketPath = Self.defaultSocketPath
        let logDirectory = launchAgentLogDirectoryPath
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.vaultui.ssh-agent</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(xmlEscaped(cliPath))</string>
                <string>agent</string>
                <string>start</string>
                <string>--ssh-only</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardOutPath</key>
            <string>\(xmlEscaped(logDirectory))/agent.log</string>
            <key>StandardErrorPath</key>
            <string>\(xmlEscaped(logDirectory))/agent.err</string>
            <key>EnvironmentVariables</key>
            <dict>
                <key>SSH_AUTH_SOCK</key>
                <string>\(xmlEscaped(socketPath))</string>
            </dict>
        </dict>
        </plist>
        """
    }

    public static var launchAgentPlistPath: String {
        "\(FileManager.default.homeDirectoryForCurrentUser.path)/Library/LaunchAgents/com.vaultui.ssh-agent.plist"
    }

    private static var launchAgentLogDirectoryPath: String {
        "\(FileManager.default.homeDirectoryForCurrentUser.path)/.vaultui"
    }

    /// Install the LaunchAgent plist.
    public static func installLaunchAgent(cliPath: String) throws {
        let plistPath = launchAgentPlistPath
        guard FileManager.default.isExecutableFile(atPath: cliPath) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSFilePathErrorKey: cliPath])
        }

        try FileManager.default.createDirectory(
            atPath: (plistPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            atPath: launchAgentLogDirectoryPath,
            withIntermediateDirectories: true
        )

        let plist = generateLaunchAgentPlist(cliPath: cliPath)
        try plist.write(toFile: plistPath, atomically: true, encoding: .utf8)

        let domain = "gui/\(getuid())"
        try runLaunchctl(["bootout", domain, plistPath], allowFailure: true)
        try runLaunchctl(["bootstrap", domain, plistPath])
        try kickstartLaunchAgent()

        logger.info("LaunchAgent installed at \(plistPath)")
    }

    public static func kickstartLaunchAgent() throws {
        let domain = "gui/\(getuid())"
        try runLaunchctl(["kickstart", "-k", "\(domain)/com.vaultui.ssh-agent"])
    }

    public static func isLaunchAgentRunning() -> Bool {
        let domain = "gui/\(getuid())"
        return (try? runLaunchctl(["print", "\(domain)/com.vaultui.ssh-agent"])) != nil
    }

    private static func runLaunchctl(_ arguments: [String], allowFailure: Bool = false) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments

        let errorPipe = Pipe()
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()

        guard allowFailure || process.terminationStatus == 0 else {
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let message = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw NSError(
                domain: "VaultUI.LaunchAgent",
                code: Int(process.terminationStatus),
                userInfo: [
                    NSLocalizedDescriptionKey: message?.isEmpty == false
                        ? message!
                        : "launchctl failed with status \(process.terminationStatus)"
                ]
            )
        }
    }

    private static func xmlEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}

// MARK: - NIO Channel Handler

/// SwiftNIO channel handler for SSH agent protocol.
final class SSHAgentChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let agentHandler: SSHAgentHandler
    private var buffer = Data()

    /// Best-effort description of the connecting client, resolved once on
    /// connect and used only for the Touch ID prompt text.
    private var peerDescription: String?
    private let peerLock = NSLock()

    init(agentHandler: SSHAgentHandler) {
        self.agentHandler = agentHandler
    }

    func channelActive(context: ChannelHandlerContext) {
        AgentPeerInfo.describe(channel: context.channel).whenSuccess { [weak self] desc in
            guard let self = self else { return }
            self.peerLock.lock()
            self.peerDescription = desc
            self.peerLock.unlock()
        }
        context.fireChannelActive()
    }

    private func currentPeer() -> String? {
        peerLock.lock()
        defer { peerLock.unlock() }
        return peerDescription
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var inBuffer = unwrapInboundIn(data)
        if let bytes = inBuffer.readBytes(length: inBuffer.readableBytes) {
            buffer.append(contentsOf: bytes)
        }

        // Process complete messages
        processBuffer(context: context)
    }

    private func processBuffer(context: ChannelHandlerContext) {
        while buffer.count >= 4 {
            // Read message length
            guard let messageLength = SSHWireFormat.readUInt32(buffer, at: 0) else { break }

            // Reject oversized messages to prevent memory exhaustion (10 MB limit)
            guard messageLength > 0, messageLength < 10_000_000 else {
                logger.error("SSH agent: rejecting oversized message (\(messageLength) bytes)")
                buffer.removeAll()
                context.close(promise: nil)
                return
            }

            let totalLength = 4 + Int(messageLength)

            guard buffer.count >= totalLength else { break }

            // Extract complete message
            let messageData = Data(buffer.prefix(totalLength))
            buffer.removeFirst(totalLength)

            // Process asynchronously — capture all needed values as sendable locals
            let handler = agentHandler
            let channel = context.channel
            let peer = currentPeer()
            Task {
                let response = await handler.processMessage(messageData, peer: peer)
                try? await channel.eventLoop.submit {
                    var outBuffer = channel.allocator.buffer(capacity: response.count)
                    outBuffer.writeBytes(response)
                    channel.writeAndFlush(outBuffer, promise: nil)
                }.get()
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("SSH agent channel error: \(error.localizedDescription)")
        context.close(promise: nil)
    }
}
