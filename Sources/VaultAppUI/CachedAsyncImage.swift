// MARK: - VaultAppUI/CachedAsyncImage.swift
// AsyncImage replacement with disk caching

import SwiftUI
import AppKit
import CryptoKit
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "IconCache")

/// A drop-in replacement for AsyncImage that caches images to disk.
struct CachedAsyncImage: View {
    let url: URL?
    let placeholder: AnyView

    init(url: URL?, @ViewBuilder placeholder: () -> some View) {
        self.url = url
        self.placeholder = AnyView(placeholder())
    }

    @State private var image: NSImage?
    @State private var failed = false

    var body: some View {
        Group {
            if let image = image {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
            } else if failed {
                placeholder
            } else {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .task(id: url) {
            guard let url = url else {
                failed = true
                return
            }
            await loadImage(from: url)
        }
    }

    private func loadImage(from url: URL) async {
        // 1. Check memory/disk cache
        if let cached = IconCache.shared.loadFromDisk(for: url) {
            self.image = cached
            return
        }

        // 2. Download
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let nsImage = NSImage(data: data) else {
                failed = true
                return
            }

            // 3. Cache to disk
            IconCache.shared.saveToDisk(data: data, for: url)

            self.image = nsImage
        } catch {
            failed = true
        }
    }
}

/// Simple file-based icon cache.
final class IconCache: @unchecked Sendable {
    static let shared = IconCache()

    private let cacheDir: URL
    private let maxAge: TimeInterval = 7 * 24 * 3600  // 7 days

    private init() {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        cacheDir = base.appendingPathComponent("com.vaultui.icons", isDirectory: true)
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
    }

    func cacheKey(for url: URL) -> String {
        let hash = SHA256.hash(data: Data(url.absoluteString.utf8))
        return hash.compactMap { String(format: "%02x", $0) }.joined().prefix(32) + ".png"
    }

    func loadFromDisk(for url: URL) -> NSImage? {
        let file = cacheDir.appendingPathComponent(String(cacheKey(for: url)))
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }

        // Check age
        if let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
           let modified = attrs[.modificationDate] as? Date,
           Date().timeIntervalSince(modified) > maxAge {
            try? FileManager.default.removeItem(at: file)
            return nil
        }

        guard let data = try? Data(contentsOf: file),
              let image = NSImage(data: data) else { return nil }
        return image
    }

    func saveToDisk(data: Data, for url: URL) {
        let file = cacheDir.appendingPathComponent(String(cacheKey(for: url)))
        try? data.write(to: file)
    }

    /// Clear all cached icons.
    func clearAll() {
        try? FileManager.default.removeItem(at: cacheDir)
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        logger.info("Icon cache cleared")
    }
}
