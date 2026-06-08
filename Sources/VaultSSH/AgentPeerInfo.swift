// MARK: - VaultSSH/AgentPeerInfo.swift
// Best-effort identification of the process connected to the agent socket.
//
// Used only to enrich the Touch ID prompt ("ssh (pid 1234) wants to use …").
// Resolution is best-effort: any failure yields nil and the prompt falls back
// to a generic description.

import Foundation
import NIOCore
import Darwin

enum AgentPeerInfo {

    // `SOL_LOCAL` / `LOCAL_PEERPID` from <sys/un.h>, defined here so we do not
    // depend on them being surfaced by the Darwin overlay.
    private static let solLocal: CInt = 0
    private static let localPeerPID: CInt = 0x002

    /// Resolve a human-readable description of the peer process for a Unix
    /// domain socket channel, e.g. "ssh (pid 1234)". Resolves to nil when the
    /// peer cannot be determined.
    static func describe(channel: Channel) -> EventLoopFuture<String?> {
        guard let provider = channel as? SocketOptionProvider else {
            return channel.eventLoop.makeSucceededFuture(nil)
        }

        let level = NIOBSDSocket.OptionLevel(rawValue: solLocal)
        let name = NIOBSDSocket.Option(rawValue: localPeerPID)
        let pidFuture: EventLoopFuture<pid_t> = provider.unsafeGetSocketOption(level: level, name: name)

        return pidFuture.map { pid -> String? in
            guard pid > 0 else { return nil }
            if let name = processName(pid: pid) {
                return "\(name) (pid \(pid))"
            }
            return "pid \(pid)"
        }.recover { _ in nil }
    }

    /// Look up a process's executable name via sysctl (no libproc dependency).
    private static func processName(pid: pid_t) -> String? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride

        let result = mib.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, u_int(buffer.count), &info, &size, nil, 0)
        }
        guard result == 0, size > 0 else { return nil }

        let name = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN) + 1) {
                String(cString: $0)
            }
        }
        return name.isEmpty ? nil : name
    }
}
