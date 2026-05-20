// MARK: - VaultAppUI/IDNDecoder.swift
// Internationalized Domain Name (IDN) decoding for display
//
// Converts Punycode-encoded domains (e.g. xn--mnchen-3ya.de) to their
// Unicode representation (münchen.de) per RFC 3492.

import Foundation

/// Punycode decoder per RFC 3492 (bootstring algorithm).
enum Punycode {
    // Bootstring parameters for Punycode
    private static let base = 36
    private static let tmin = 1
    private static let tmax = 26
    private static let skew = 38
    private static let damp = 700
    private static let initialBias = 72
    private static let initialN = 0x80

    /// Bias adaptation function.
    private static func adapt(delta: Int, numPoints: Int, firstTime: Bool) -> Int {
        var delta = firstTime ? delta / damp : delta / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= base - tmin
            k += base
        }
        return k + ((base - tmin + 1) * delta) / (delta + skew)
    }

    /// Decode a single digit code point to its numeric value.
    private static func digitValue(_ cp: UnicodeScalar) -> Int? {
        let v = cp.value
        if v >= 0x61 && v <= 0x7A { return Int(v) - 0x61 }       // a-z → 0-25
        if v >= 0x41 && v <= 0x5A { return Int(v) - 0x41 }       // A-Z → 0-25
        if v >= 0x30 && v <= 0x39 { return Int(v) - 22 }          // 0-9 → 26-35
        return nil
    }

    /// Decode a Punycode-encoded string (without the "xn--" prefix) to Unicode.
    static func decode(_ input: String) -> String? {
        let scalars = Array(input.unicodeScalars)
        var output: [UnicodeScalar] = []
        var n = initialN
        var i = 0
        var bias = initialBias

        // Find last delimiter — everything before it is literal ASCII
        let lastDelimIdx = scalars.lastIndex(of: "-")
        if let delim = lastDelimIdx, delim > scalars.startIndex {
            for j in scalars.startIndex..<delim {
                output.append(scalars[j])
            }
        }

        var pos = lastDelimIdx.map { $0 + 1 } ?? scalars.startIndex

        while pos < scalars.endIndex {
            let oldi = i
            var w = 1
            var k = base

            while true {
                guard pos < scalars.endIndex else { return nil }
                guard let digit = digitValue(scalars[pos]) else { return nil }
                pos += 1

                i += digit * w

                let t: Int
                if k <= bias { t = tmin }
                else if k >= bias + tmax { t = tmax }
                else { t = k - bias }

                if digit < t { break }

                // Guard against overflow
                guard w <= Int.max / (base - t) else { return nil }
                w *= (base - t)
                k += base
            }

            let count = output.count + 1
            bias = adapt(delta: i - oldi, numPoints: count, firstTime: oldi == 0)
            n += i / count
            i = i % count

            guard let scalar = UnicodeScalar(n) else { return nil }
            output.insert(scalar, at: i)
            i += 1
        }

        return String(output.map { Character($0) })
    }
}

// MARK: - String Extensions for IDN Display

extension String {
    /// Decodes a Punycode-encoded hostname to its Unicode form.
    ///
    /// Example: `"xn--mnchen-3ya.de"` → `"münchen.de"`
    var idnDecodedHost: String {
        let labels = self.split(separator: ".", omittingEmptySubsequences: false)
        let decoded = labels.map { label -> String in
            let s = String(label)
            if s.lowercased().hasPrefix("xn--") {
                let encoded = String(s.dropFirst(4))
                if let decoded = Punycode.decode(encoded) {
                    return decoded
                }
            }
            return s
        }
        return decoded.joined(separator: ".")
    }

    /// Returns the URL string with any Punycode-encoded host decoded to Unicode for display.
    ///
    /// Example: `"https://xn--mnchen-3ya.de/login"` → `"https://münchen.de/login"`
    var displayURL: String {
        // Try parsing as a full URL
        if let url = URL(string: self), let host = url.host {
            let decoded = host.idnDecodedHost
            if decoded != host, let range = self.range(of: host) {
                var result = self
                result.replaceSubrange(range, with: decoded)
                return result
            }
        }
        // If not a valid URL, try treating the whole string as a host
        let decoded = self.idnDecodedHost
        return decoded != self ? decoded : self
    }
}
