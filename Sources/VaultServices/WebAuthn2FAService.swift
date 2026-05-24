// MARK: - VaultServices/WebAuthn2FAService.swift
// Hardware security key (FIDO2) assertion for two-factor authentication

import Foundation
import AuthenticationServices
import VaultModels
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "WebAuthn2FA")

/// Performs FIDO2 hardware security key assertions for 2FA login.
///
/// Uses `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` to prompt the
/// user to tap their security key (e.g. YubiKey). Does NOT require Associated
/// Domains, so it works with any Vaultwarden server.
@MainActor
public final class WebAuthn2FAService: NSObject, ObservableObject {

    @Published public var isWaiting: Bool = false
    @Published public var error: String?

    private var continuation: CheckedContinuation<String, Error>?
    private var authController: ASAuthorizationController?

    /// Perform a WebAuthn assertion using a hardware security key.
    ///
    /// - Parameter challenge: The WebAuthn challenge data from the server.
    /// - Returns: A JSON string formatted as a Bitwarden-compatible 2FA token.
    /// - Throws: If the user cancels, the key fails, or the assertion is invalid.
    public func performAssertion(challenge: WebAuthnChallengeData) async throws -> String {
        // Cancel any pending request
        authController?.cancel()

        isWaiting = true
        error = nil

        defer { isWaiting = false }

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
                relyingPartyIdentifier: challenge.rpId
            )

            let request = provider.createCredentialAssertionRequest(
                challenge: challenge.challenge
            )

            // Map allowed credentials to security key descriptors
            if !challenge.allowCredentials.isEmpty {
                request.allowedCredentials = challenge.allowCredentials.map { cred in
                    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                        credentialID: cred.id,
                        transports: Self.mapTransports(cred.transports)
                    )
                }
            }

            // Set user verification preference
            switch challenge.userVerification {
            case "required":
                request.userVerificationPreference = .required
            case "discouraged":
                request.userVerificationPreference = .discouraged
            default:
                request.userVerificationPreference = .preferred
            }

            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            self.authController = controller

            logger.info("Starting security key assertion for rpId=\(challenge.rpId)")
            controller.performRequests()
        }
    }

    /// Cancel any pending assertion request.
    public func cancel() {
        authController?.cancel()
        authController = nil

        if let continuation = self.continuation {
            self.continuation = nil
            continuation.resume(throwing: CancellationError())
        }

        isWaiting = false
    }

    // MARK: - Helpers

    /// Map transport strings from the server to ASAuthorization transport values.
    private static func mapTransports(_ transports: [String]?) -> [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] {
        guard let transports = transports, !transports.isEmpty else {
            return [.usb, .nfc, .bluetooth]
        }

        var result: [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] = []
        for transport in transports {
            switch transport.lowercased() {
            case "usb": result.append(.usb)
            case "nfc": result.append(.nfc)
            case "ble", "bluetooth": result.append(.bluetooth)
            default: break
            }
        }

        return result.isEmpty ? [.usb, .nfc, .bluetooth] : result
    }

    /// Format the assertion response as a Bitwarden-compatible JSON token string.
    ///
    /// The Bitwarden API expects the 2FA token for WebAuthn (provider type 7) to be
    /// a JSON string containing the credential ID, raw assertion data, and signature.
    private static func formatAssertionToken(
        credentialID: Data,
        rawAuthenticatorData: Data,
        rawClientDataJSON: Data,
        signature: Data,
        userID: Data?
    ) -> String? {
        let response: [String: Any] = {
            var resp: [String: Any] = [
                "authenticatorData": rawAuthenticatorData.base64URLEncodedString(),
                "clientDataJSON": rawClientDataJSON.base64URLEncodedString(),
                "signature": signature.base64URLEncodedString(),
            ]
            if let uid = userID, !uid.isEmpty {
                resp["userHandle"] = uid.base64URLEncodedString()
            }
            return resp
        }()

        let token: [String: Any] = [
            "id": credentialID.base64URLEncodedString(),
            "rawId": credentialID.base64URLEncodedString(),
            "type": "public-key",
            "extensions": [String: Any](),
            "response": response,
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: token),
              let jsonString = String(data: data, encoding: .utf8) else {
            return nil
        }

        return jsonString
    }
}

// MARK: - ASAuthorizationControllerDelegate

extension WebAuthn2FAService: ASAuthorizationControllerDelegate {

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let credential = authorization.credential as? ASAuthorizationPublicKeyCredentialAssertion else {
            logger.error("Unexpected credential type: \(type(of: authorization.credential))")
            continuation?.resume(throwing: WebAuthn2FAError.unexpectedCredentialType)
            continuation = nil
            return
        }

        logger.info("Security key assertion completed successfully")

        guard let token = Self.formatAssertionToken(
            credentialID: credential.credentialID,
            rawAuthenticatorData: credential.rawAuthenticatorData,
            rawClientDataJSON: credential.rawClientDataJSON,
            signature: credential.signature,
            userID: credential.userID
        ) else {
            logger.error("Failed to format assertion token")
            continuation?.resume(throwing: WebAuthn2FAError.tokenFormatError)
            continuation = nil
            return
        }

        continuation?.resume(returning: token)
        continuation = nil
    }

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        let nsError = error as NSError
        logger.error("Security key assertion failed: \(nsError.localizedDescription) (code=\(nsError.code))")

        if nsError.domain == ASAuthorizationError.errorDomain {
            switch nsError.code {
            case ASAuthorizationError.canceled.rawValue:
                self.error = nil  // User cancelled — not an error
                continuation?.resume(throwing: CancellationError())
            case ASAuthorizationError.failed.rawValue:
                self.error = "Security key authentication failed."
                continuation?.resume(throwing: WebAuthn2FAError.authenticationFailed)
            case ASAuthorizationError.notHandled.rawValue:
                self.error = "Security key request was not handled."
                continuation?.resume(throwing: WebAuthn2FAError.notHandled)
            default:
                self.error = error.localizedDescription
                continuation?.resume(throwing: error)
            }
        } else {
            self.error = error.localizedDescription
            continuation?.resume(throwing: error)
        }

        continuation = nil
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding

extension WebAuthn2FAService: ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // Return the key window for macOS
        return NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first ?? NSWindow()
    }
}

// MARK: - Errors

public enum WebAuthn2FAError: Error, LocalizedError, Sendable {
    case unexpectedCredentialType
    case tokenFormatError
    case authenticationFailed
    case notHandled
    case noChallenge

    public var errorDescription: String? {
        switch self {
        case .unexpectedCredentialType: return "Unexpected credential type from security key"
        case .tokenFormatError: return "Failed to format security key response"
        case .authenticationFailed: return "Security key authentication failed"
        case .notHandled: return "Security key request was not handled"
        case .noChallenge: return "No WebAuthn challenge data available"
        }
    }
}

// MARK: - Base64URL Encoding

extension Data {
    /// Encode data to a base64url string (used by WebAuthn).
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
