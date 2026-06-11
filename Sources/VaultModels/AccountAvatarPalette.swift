// MARK: - VaultModels/AccountAvatarPalette.swift
// Stable per-account avatar gradient colors.

import Foundation
#if canImport(SwiftUI)
import SwiftUI
#endif

/// A fixed palette of visually distinct gradient pairs for account avatars.
/// Each account is assigned a stable index at creation time so its color
/// never changes; the index is shared with the AutoFill extension via
/// `SharedAccountInfo`.
public enum AccountAvatarPalette {
    /// Gradient pairs as RGB hex strings (start, end).
    /// Index 0 matches the original blue→purple gradient for continuity.
    public static let gradients: [(start: String, end: String)] = [
        ("007AFF", "AF52DE"), // blue → purple (legacy default)
        ("FF9500", "FF3B30"), // orange → red
        ("34C759", "00C7BE"), // green → teal
        ("FF2D55", "FF9500"), // pink → orange
        ("5856D6", "32ADE6"), // indigo → light blue
        ("AF52DE", "FF2D55"), // purple → pink
        ("00C7BE", "30B0C7"), // teal → cyan
        ("FFCC00", "FF9500"), // yellow → orange
        ("32ADE6", "34C759"), // light blue → green
        ("8E8E93", "48484A"), // gray → dark gray
    ]

    public static var count: Int { gradients.count }

    /// Picks the lowest palette index not used by `usedIndices`; when the
    /// palette is exhausted, returns the least-used index (lowest wins ties)
    /// so colors stay as distinct as possible and remain stable per account.
    public static func nextIndex(usedIndices: [Int]) -> Int {
        var usage = [Int: Int]()
        for index in usedIndices where index >= 0 {
            usage[index % gradients.count, default: 0] += 1
        }
        var best = 0
        var bestCount = Int.max
        for candidate in 0..<gradients.count {
            let count = usage[candidate] ?? 0
            if count == 0 { return candidate }
            if count < bestCount {
                best = candidate
                bestCount = count
            }
        }
        return best
    }
}

#if canImport(SwiftUI)
public extension AccountAvatarPalette {
    /// SwiftUI gradient colors for the given palette index (wraps around).
    static func gradient(for index: Int) -> (start: Color, end: Color) {
        let pair = gradients[abs(index) % gradients.count]
        return (Color(hex: pair.start), Color(hex: pair.end))
    }
}

private extension Color {
    init(hex: String) {
        var value: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&value)
        self.init(
            .sRGB,
            red: Double((value >> 16) & 0xFF) / 255,
            green: Double((value >> 8) & 0xFF) / 255,
            blue: Double(value & 0xFF) / 255
        )
    }
}
#endif
