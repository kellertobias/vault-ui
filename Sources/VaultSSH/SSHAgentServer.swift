// MARK: - VaultSSH/SSHAgentServer.swift
// Unix domain socket server for SSH agent protocol

import Foundation
import NIO
import NIOFoundationCompat
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SSHAgent")

/// SSH agent Unix domain socket server.
///
/// Listens on `~/.vaultui/agent.sock` and handles SSH agent protocol messages
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
        // Use the real home directory, not the sandboxed container path
        let home = realHomeDirectory
        return "\(home)/.vaultui/agent.sock"
    }

    /// The real user home directory (bypasses sandbox container redirection).
    private static var realHomeDirectory: String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return String(cString: dir)
        }
        return NSHomeDirectory()
    }

    /// Start the SSH agent server.
    public func start() async throws {
        // Ensure directory exists
        let socketDir = (socketPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: socketDir,
            withIntermediateDirectories: true
        )

        // Remove stale socket
        if FileManager.default.fileExists(atPath: socketPath) {
            try FileManager.default.removeItem(atPath: socketPath)
        }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 16)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(SSHAgentChannelHandler(agentHandler: self.handler))
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.maxMessagesPerRead, value: 16)

        self.channel = try await bootstrap.bind(
            unixDomainSocketPath: socketPath
        ).get()

        // Set socket permissions (only owner can access)
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

    /// Generate a LaunchAgent plist for auto-starting the SSH agent.
    public static func generateLaunchAgentPlist(cliPath: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.vaultui.ssh-agent</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(cliPath)</string>
                <string>agent</string>
                <string>start</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardOutPath</key>
            <string>\(home)/.vaultui/agent.log</string>
            <key>StandardErrorPath</key>
            <string>\(home)/.vaultui/agent.err</string>
            <key>EnvironmentVariables</key>
            <dict>
                <key>SSH_AUTH_SOCK</key>
                <string>\(home)/.vaultui/agent.sock</string>
            </dict>
        </dict>
        </plist>
        """
    }

    /// Install the LaunchAgent plist.
    public static func installLaunchAgent(cliPath: String) throws {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let plistPath = "\(home)/Library/LaunchAgents/com.vaultui.ssh-agent.plist"
        let plist = generateLaunchAgentPlist(cliPath: cliPath)
        try plist.write(toFile: plistPath, atomically: true, encoding: .utf8)
        logger.info("LaunchAgent installed at \(plistPath)")
    }
}

// MARK: - NIO Channel Handler

/// SwiftNIO channel handler for SSH agent protocol.
final class SSHAgentChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let agentHandler: SSHAgentHandler
    private var buffer = Data()

    init(agentHandler: SSHAgentHandler) {
        self.agentHandler = agentHandler
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
            let totalLength = 4 + Int(messageLength)

            guard buffer.count >= totalLength else { break }

            // Extract complete message
            let messageData = Data(buffer.prefix(totalLength))
            buffer.removeFirst(totalLength)

            // Process asynchronously — capture all needed values as sendable locals
            let handler = agentHandler
            let channel = context.channel
            Task {
                let response = await handler.processMessage(messageData)
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
