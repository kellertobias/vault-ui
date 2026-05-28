// MARK: - VaultServices/SecretAgentServer.swift
// Unix domain socket server for the secret agent protocol

import Foundation
import NIO
import NIOFoundationCompat
import OSLog
import VaultSSH

private let logger = Logger(subsystem: "com.vaultui", category: "SecretAgent")

/// Secret agent Unix domain socket server.
///
/// Listens on the shared app-group socket and handles secret lookup requests
/// from the `vaultui secret` CLI commands. Uses a simple length-prefixed
/// JSON framing protocol.
public final class SecretAgentServer: @unchecked Sendable {
    public let handler: SecretAgentHandler
    private let socketPath: String
    private let group: EventLoopGroup
    private var channel: Channel?

    /// The actual socket path being used.
    public var agentSocketPath: String { socketPath }

    public init(handler: SecretAgentHandler, socketPath: String? = nil) {
        self.handler = handler
        self.socketPath = socketPath ?? Self.defaultSocketPath
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    }

    /// Default socket path.
    public static var defaultSocketPath: String {
        VaultAgentSocketDirectory.socketPath(named: "secret.sock")
    }

    /// Start the secret agent server.
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
                channel.pipeline.addHandler(SecretAgentChannelHandler(agentHandler: self.handler))
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.maxMessagesPerRead, value: 16)

        // Set restrictive umask before bind() so the socket is created with
        // owner-only permissions atomically, eliminating the TOCTOU window.
        let previousUmask = umask(0o077)
        self.channel = try await bootstrap.bind(
            unixDomainSocketPath: socketPath
        ).get()
        umask(previousUmask)

        // Ensure socket permissions are owner-only (belt-and-suspenders)
        chmod(socketPath, 0o600)

        logger.info("Secret agent listening on \(self.socketPath)")
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
        logger.info("Secret agent stopped")
    }
}

// MARK: - NIO Channel Handler

/// SwiftNIO channel handler for secret agent protocol.
///
/// Uses length-prefixed framing: [4-byte big-endian length][JSON payload].
final class SecretAgentChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let agentHandler: SecretAgentHandler
    private var buffer = Data()

    init(agentHandler: SecretAgentHandler) {
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
            // Read message length (big-endian uint32)
            let length = buffer.withUnsafeBytes { ptr -> UInt32 in
                ptr.load(as: UInt32.self).bigEndian
            }

            // Reject oversized messages to prevent memory exhaustion (10 MB limit)
            guard length > 0, length < 10_000_000 else {
                logger.error("Secret agent: rejecting oversized message (\(length) bytes)")
                buffer.removeAll()
                context.close(promise: nil)
                return
            }

            let totalLength = 4 + Int(length)

            guard buffer.count >= totalLength else { break }

            // Extract complete message payload (after length prefix)
            let messageData = Data(buffer[4..<totalLength])
            buffer.removeFirst(totalLength)

            // Process asynchronously
            let handler = agentHandler
            let channel = context.channel
            Task {
                let response = await handler.processRequest(messageData)

                // Write length-prefixed response
                var frameData = Data()
                var responseLen = UInt32(response.count).bigEndian
                frameData.append(Data(bytes: &responseLen, count: 4))
                frameData.append(response)

                try? await channel.eventLoop.submit {
                    var outBuffer = channel.allocator.buffer(capacity: frameData.count)
                    outBuffer.writeBytes(frameData)
                    channel.writeAndFlush(outBuffer, promise: nil)
                }.get()
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Secret agent channel error: \(error.localizedDescription)")
        context.close(promise: nil)
    }
}
