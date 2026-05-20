// MARK: - VaultAppUI/UnlockView.swift
// Unlock screen with Touch ID and password fallback

import SwiftUI
import VaultServices
import VaultModels

/// Unlock view — shown when the vault is locked but an account exists.
struct UnlockView: View {
    @EnvironmentObject var session: SessionManager
    @AppStorage("useTouchID") private var useTouchID = true
    @State private var isAuthenticating = false
    @State private var showPasswordLogin = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 52))
                .foregroundStyle(.secondary)

            VStack(spacing: 8) {
                Text("Vault Locked")
                    .font(.title2.bold())

                if let account = session.activeAccount {
                    Text(account.email)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
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

                Button("Switch Account") {
                    session.lock()
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .font(.caption)
            }
            .frame(width: 260)

            Spacer()
        }
        .frame(width: 440)
        .onAppear {
            // Auto-trigger biometric unlock if available
            triggerBiometricUnlockIfNeeded()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            triggerBiometricUnlockIfNeeded()
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

    private func triggerBiometricUnlockIfNeeded() {
        if useTouchID && session.canUnlockWithBiometrics && !isAuthenticating {
            unlockWithBiometrics()
        }
    }

    private func unlockWithBiometrics() {
        isAuthenticating = true
        Task {
            do {
                try await session.unlockWithBiometrics()
            } catch {
                // If biometric fails or is canceled, do not automatically open the password sheet.
                // Let the user choose to retry Touch ID or click "Use Master Password".
            }
            isAuthenticating = false
        }
    }
}

/// Two-factor authentication view.
struct TwoFactorView: View {
    @EnvironmentObject var session: SessionManager
    let providers: [Int]

    @AppStorage("lastServerURL") private var serverURL = "https://"
    @AppStorage("lastEmail") private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var remember = false
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.badge.clock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.blue)

            Text("Two-Factor Authentication")
                .font(.title2.bold())

            Text("Enter the verification code from your authenticator app.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(spacing: 12) {
                SecureField("Master Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)

                TextField("000000", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
                    .multilineTextAlignment(.center)
                    .font(.system(size: 24, design: .monospaced))
            }

            Toggle("Remember this device", isOn: $remember)
                .toggleStyle(.checkbox)

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Button("Verify") {
                verify()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(code.count < 6 || password.isEmpty || isLoading)

            Button("Cancel") {
                session.lock()
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)

            Spacer()
        }
        .frame(width: 440)
        .padding()
    }

    private func verify() {
        guard let url = URL(string: serverURL) else {
            errorMessage = "Invalid server URL"
            return
        }

        isLoading = true
        errorMessage = nil

        // Determine the provider type (0 = Authenticator / TOTP is the most common)
        let providerType = TwoFactorProviderType(rawValue: providers.first ?? 0)

        Task {
            do {
                try await session.login(
                    email: email,
                    password: password,
                    serverURL: url,
                    twoFactorProvider: providerType,
                    twoFactorToken: code
                )
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}
