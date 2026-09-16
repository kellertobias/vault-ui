// MARK: - VaultIntegrationTests/TransportSecurityTests.swift
// The test server's certificate must only be trusted because the tests say so.

import XCTest
import Foundation
import VaultModels
@testable import VaultAPI

final class TransportSecurityTests: VaultwardenIntegrationTestCase {

    /// Without the test CA the app must refuse the server: the certificate is
    /// untrusted, and there is no fallback to accepting it anyway. This also
    /// proves the trust hook is what makes every other test connect.
    func testServerIsRejectedWithoutTheTestCA() async throws {
        TestTrustAnchors.certificates = []

        do {
            _ = try await TestUser.register(on: serverURL, label: "untrusted")
            XCTFail("Registration must fail against an untrusted certificate")
        } catch APIError.networkError {
            // Expected: TLS evaluation failed.
        }
    }

    /// Plain HTTP is never allowed, even to loopback.
    func testPlainHTTPIsRefused() async throws {
        var components = try XCTUnwrap(URLComponents(url: serverURL, resolvingAgainstBaseURL: false))
        components.scheme = "http"
        let httpURL = try XCTUnwrap(components.url)

        do {
            _ = try await TestUser.register(on: httpURL, label: "plaintext")
            XCTFail("Plain HTTP must be rejected")
        } catch APIError.invalidServerURL {
            // Expected: refused before any request is sent.
        }
    }
}
