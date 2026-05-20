// MARK: - VaultServices/ClipboardService.swift
// Clipboard management with auto-clear functionality

import Foundation
import AppKit
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "ClipboardService")

/// Manages clipboard operations with optional auto-clear.
@MainActor
public final class ClipboardService {
    public static let shared = ClipboardService()

    private var clearTask: Task<Void, Never>?

    private init() {}

    /// Copy a string to the clipboard, optionally clearing it after a timeout.
    /// - Parameters:
    ///   - string: The string to copy
    ///   - clearAfter: Seconds after which to clear (0 = never)
    public func copy(_ string: String, clearAfter: Int = 0) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)

        // Cancel any pending clear
        clearTask?.cancel()
        clearTask = nil

        guard clearAfter > 0 else { return }

        clearTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(clearAfter) * 1_000_000_000)
            guard !Task.isCancelled else { return }

            // Only clear if the clipboard still contains our content
            if let current = NSPasteboard.general.string(forType: .string),
               current == string {
                NSPasteboard.general.clearContents()
                logger.debug("Clipboard cleared after \(clearAfter)s")
            }
        }
    }
}
