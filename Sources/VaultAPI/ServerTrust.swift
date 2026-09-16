// MARK: - VaultAPI/ServerTrust.swift
// TLS server-trust evaluation for the API client.

import Foundation
import Security

/// Extra certificate authorities to trust, for the integration tests only.
///
/// The tests run a throwaway Vaultwarden behind a certificate issued by a
/// per-run test CA. Rather than install that CA in the system keychain, the tests
/// hand it to the client here. This is `internal`, so only `@testable import` can
/// set it; in the shipped app it is always empty and trust evaluation is the
/// system's default, unchanged.
enum TestTrustAnchors {
    nonisolated(unsafe) static var certificates: [SecCertificate] = []
}

/// `URLSession` delegate that adds `TestTrustAnchors` to server-trust evaluation.
///
/// With no test anchors configured it defers every challenge to the system
/// (`.performDefaultHandling`), exactly as a session without a delegate would.
/// With anchors, it still evaluates the full chain *and* the hostname — the trust
/// object URLSession supplies already carries the SSL policy for the host — and
/// keeps the system roots trusted alongside the test CA.
final class ServerTrustDelegate: NSObject, URLSessionDelegate, Sendable {

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let anchors = TestTrustAnchors.certificates
        guard !anchors.isEmpty,
              challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return (.performDefaultHandling, nil)
        }

        guard Self.evaluate(trust, withAdditionalAnchors: anchors) else {
            return (.cancelAuthenticationChallenge, nil)
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Evaluate `trust` with the system roots plus `anchors`.
    static func evaluate(_ trust: SecTrust, withAdditionalAnchors anchors: [SecCertificate]) -> Bool {
        guard SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, false) == errSecSuccess else {
            return false
        }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}
