// MARK: - VaultAppUI/UnlockView.swift
// Unlock screen with Touch ID and password fallback

import SwiftUI
import VaultServices
import VaultModels
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "UnlockView")

/// Unlock view — shown when the vault is locked but an account exists.
struct UnlockView: View {
    @EnvironmentObject var session: SessionManager
    @AppStorage("useTouchID") private var useTouchID = true
    @State private var isAuthenticating = false
    @State private var showPasswordLogin = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            if let account = session.activeAccount {
                AccountAvatarView(email: account.email, colorIndex: account.avatarColorIndex, size: 56)
            } else {
                Image(systemName: "lock.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(.secondary)
            }

            VStack(spacing: 8) {
                Text("Vault Locked")
                    .font(.title2.bold())

                if let account = session.activeAccount {
                    Text(account.email)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Text(account.serverURL.host ?? account.serverURL.absoluteString)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }

            VStack(spacing: 12) {
                if useTouchID && session.canUnlockWithBiometrics {
                    Button {
                        unlockWithBiometrics()
                    } label: {
                        Label("Unlock with Touch ID", systemImage: "touchid")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(isAuthenticating)
                }

                Button("Use Master Password") {
                    showPasswordLogin = true
                }
                .buttonStyle(.plain)
                .foregroundStyle(.blue)

                Menu {
                    ForEach(otherAccounts) { account in
                        Button {
                            session.switchAccount(to: account.id)
                        } label: {
                            Label("\(account.displayName) — \(account.serverURL.host ?? "")", systemImage: "person.circle")
                        }
                    }
                    if !otherAccounts.isEmpty {
                        Divider()
                    }
                    Button {
                        session.beginAddAccount()
                    } label: {
                        Label("Add Account…", systemImage: "plus")
                    }
                } label: {
                    Text(otherAccounts.isEmpty ? "Add Account" : "Switch Account")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            .frame(width: 260)

            Spacer()
        }
        .frame(width: 440)
        .onAppear {
            if !session.biometricAttempted {
                // Auto-trigger biometric unlock when the view appears.
                // Use a short delay to let SwiftUI finish the view transition.
                triggerBiometricUnlockIfActive()
            }
        }
        // Re-trigger when app becomes active (e.g., user clicks Dock icon)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            triggerBiometricUnlockIfActive()
        }
        // Re-trigger when app is un-hidden after CMD+H
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didUnhideNotification)) { _ in
            triggerBiometricUnlockIfActive()
        }
        // Handle the app-restart case: session may not have loaded the account
        // by the time onAppear fires. When canUnlockWithBiometrics becomes true,
        // automatically trigger Touch ID if we haven't already.
        .onChange(of: session.canUnlockWithBiometrics) { _, canUnlock in
            if canUnlock && !session.biometricAttempted {
                triggerBiometricUnlockIfActive()
            }
        }
        .sheet(isPresented: $showPasswordLogin) {
            // We provide a way to dismiss the password login sheet if they change their mind
            VStack {
                HStack {
                    Button("Cancel") {
                        showPasswordLogin = false
                    }
                    .padding()
                    Spacer()
                }
                LoginView()
                    .environmentObject(session)
            }
            .frame(minWidth: 440, minHeight: 560)
        }
    }

    /// All on-device accounts except the one currently awaiting unlock.
    private var otherAccounts: [Account] {
        session.accounts.filter { $0.id != session.activeAccount?.id }
    }

    /// Trigger biometric unlock when conditions are right.
    ///
    /// Skips the trigger if the app is not active (to avoid Touch ID prompts
    /// when the user can't see the app). Uses a delay to let SwiftUI settle.
    private func triggerBiometricUnlockIfActive() {
        guard NSApplication.shared.isActive else {
            logger.debug("Skipping biometric trigger — app is not active")
            return
        }
        // Small delay to let SwiftUI settle and avoid racing with view transitions
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            triggerBiometricUnlockIfNeeded()
        }
    }

    private func triggerBiometricUnlockIfNeeded() {
        guard useTouchID && session.canUnlockWithBiometrics && !session.biometricAttempted && !isAuthenticating else {
            return
        }
        unlockWithBiometrics()
    }

    private func unlockWithBiometrics() {
        isAuthenticating = true
        session.biometricAttempted = true
        Task {
            do {
                try await session.unlockWithBiometrics()
            } catch {
                logger.error("Biometric unlock failed: \(error.localizedDescription)")
                // Let the user choose to retry Touch ID or click "Use Master Password".
            }
            isAuthenticating = false
        }
    }
}

/// Two-factor authentication view — supports multiple provider types.
struct TwoFactorView: View {
    @EnvironmentObject var session: SessionManager
    let challenge: TwoFactorChallenge

    @State private var selectedProvider: TwoFactorProviderType?
    @State private var code = ""
    @State private var remember = true
    @State private var isLoading = false
    @State private var errorMessage: String?

    @StateObject private var webAuthnService = WebAuthn2FAService()

    /// The available providers that we can handle.
    private var supportedProviders: [TwoFactorProviderType] {
        challenge.availableProviders.filter { provider in
            switch provider {
            case .authenticator, .email, .yubikey, .webAuthn: return true
            default: return false
            }
        }
    }

    /// The currently active provider (defaults to first supported).
    private var activeProvider: TwoFactorProviderType {
        selectedProvider ?? supportedProviders.first ?? .authenticator
    }

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            // Icon
            Image(systemName: activeProvider.iconName)
                .font(.system(size: 48))
                .foregroundStyle(.blue)
                .contentTransition(.symbolEffect(.replace))

            Text("Two-Factor Authentication")
                .font(.title2.bold())

            // Provider-specific instruction text
            instructionText
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            // Provider picker (only if multiple methods available)
            if supportedProviders.count > 1 {
                Picker("Method", selection: Binding(
                    get: { activeProvider },
                    set: { selectedProvider = $0; code = ""; errorMessage = nil }
                )) {
                    ForEach(supportedProviders, id: \.rawValue) { provider in
                        Label(provider.displayName, systemImage: provider.iconName)
                            .tag(provider)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 320)
            }

            // Provider-specific input
            if activeProvider.isCodeBased {
                codeInput
            } else if activeProvider == .webAuthn {
                webAuthnInput
            }

            // Remember toggle
            Toggle("Remember this device", isOn: $remember)
                .toggleStyle(.checkbox)

            // Error message
            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .transition(.opacity)
            }

            // Submit / Cancel
            if activeProvider.isCodeBased {
                Button("Verify") {
                    verifyCode()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(code.count < 6 || isLoading)
                .keyboardShortcut(.return, modifiers: [])
            }

            Button("Cancel") {
                webAuthnService.cancel()
                session.cancelPendingLogin()
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)

            Spacer()
        }
        .frame(width: 440)
        .padding()
        .animation(.easeInOut(duration: 0.2), value: activeProvider)
    }

    // MARK: - Instruction Text

    @ViewBuilder
    private var instructionText: some View {
        switch activeProvider {
        case .authenticator:
            Text("Enter the 6-digit code from your authenticator app.")

        case .email:
            if let data = challenge.providerData[TwoFactorProviderType.email.rawValue],
               case .email(let obfuscated) = data {
                Text("A verification code was sent to **\(obfuscated)**.")
            } else {
                Text("A verification code was sent to your email.")
            }

        case .yubikey:
            Text("Insert your YubiKey and tap it, or press the button to emit the code.")

        case .webAuthn:
            if webAuthnService.isWaiting {
                Text("Tap your security key now...")
            } else {
                Text("Click the button below and tap your security key when prompted.")
            }

        default:
            Text("Enter your verification code.")
        }
    }

    // MARK: - Code Input

    private var codeInput: some View {
        VStack(spacing: 8) {
            TextField(activeProvider == .yubikey ? "Touch your YubiKey" : "000000", text: $code)
                .textFieldStyle(.roundedBorder)
                .frame(width: activeProvider == .yubikey ? 260 : 200)
                .multilineTextAlignment(.center)
                .font(.system(size: 24, design: .monospaced))
                .onSubmit {
                    if code.count >= 6 {
                        verifyCode()
                    }
                }
        }
    }

    // MARK: - WebAuthn Input

    private var webAuthnInput: some View {
        VStack(spacing: 12) {
            if webAuthnService.isWaiting {
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(1.2)
            } else {
                Button {
                    performWebAuthn()
                } label: {
                    Label("Use Security Key", systemImage: "person.badge.key.fill")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(width: 260)
            }

            if let error = webAuthnService.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    // MARK: - Actions

    private func verifyCode() {
        isLoading = true
        errorMessage = nil

        Task {
            do {
                try await session.loginWithTwoFactor(
                    provider: activeProvider,
                    token: code,
                    remember: remember
                )
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }

    private func performWebAuthn() {
        guard let data = challenge.providerData[TwoFactorProviderType.webAuthn.rawValue],
              case .webAuthn(let challengeData) = data else {
            errorMessage = "No WebAuthn challenge available."
            return
        }

        errorMessage = nil

        Task {
            do {
                let token = try await webAuthnService.performAssertion(challenge: challengeData)
                try await session.loginWithTwoFactor(
                    provider: .webAuthn,
                    token: token,
                    remember: remember
                )
            } catch is CancellationError {
                // User cancelled — not an error
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
