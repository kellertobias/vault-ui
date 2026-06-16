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

    // De-facto standard markers (nspasteboard.org) that ask clipboard managers
    // and history features to neither record nor sync the value. ConcealedType
    // is honored by password managers and tools like Maccy/Paste; TransientType
    // signals the value is short-lived. They are the best-available signal to
    // keep a copied secret out of clipboard history and (where honored) off
    // Universal Clipboard.
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    private init() {}

    /// Copy a string to the clipboard, optionally clearing it after a timeout.
    /// - Parameters:
    ///   - string: The string to copy
    ///   - clearAfter: Seconds after which to clear (0 = never)
    public func copy(_ string: String, clearAfter: Int = 0) {
        // Write the value and the concealment markers on a single item so a
        // clipboard manager sees the "do not record" flags alongside the string.
        let item = NSPasteboardItem()
        item.setString(string, forType: .string)
        item.setString(string, forType: Self.concealedType)
        item.setString("", forType: Self.transientType)

        NSPasteboard.general.clearContents()
        NSPasteboard.general.writeObjects([item])

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
