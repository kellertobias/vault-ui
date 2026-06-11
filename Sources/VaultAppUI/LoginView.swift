// MARK: - VaultAppUI/LoginView.swift
// Login screen with server URL, email, password

import SwiftUI
import AppKit
import VaultModels
import VaultServices

/// Login view for authenticating with a Vaultwarden/Bitwarden server.
struct LoginView: View {
    enum Mode {
        /// Sign in to the active account (first launch, re-login, session expiry).
        case standard
        /// Add another account while keeping the existing ones; cancellable.
        case addAccount
    }

    var mode: Mode = .standard

    @EnvironmentObject var session: SessionManager

    @AppStorage("lastServerURL") private var storedServerURL = "https://"
    @AppStorage("lastEmail") private var storedEmail = ""
    @State private var serverURL = "https://"
    @State private var email = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var showPassword = false
    @State private var copiedError = false

    enum Field: Hashable {
        case serverURL, email, password
    }
    @FocusState private var focusedField: Field?

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(
                        .linearGradient(
                            colors: [.blue, .cyan],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .shadow(color: .blue.opacity(0.3), radius: 12, y: 4)

                Text("Vault UI")
                    .font(.system(size: 28, weight: .bold, design: .rounded))

                Text(mode == .addAccount ? "Add another account" : "Sign in to your vault")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 40)
            .padding(.bottom, 32)

            // Form
            VStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Server URL")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("https://vault.example.com", text: $serverURL)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.URL)
                        .focused($focusedField, equals: .serverURL)

                    if OfficialBitwardenServer.isOfficial(urlString: serverURL) {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                                .padding(.top, 1)
                            Text(OfficialBitwardenServer.warningMessage)
                                .font(.caption)
                                .foregroundStyle(.orange)
                                .fixedSize(horizontal: false, vertical: true)
                            Spacer(minLength: 0)
                        }
                        .padding(.top, 2)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Email")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("user@example.com", text: $email)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.emailAddress)
                        .focused($focusedField, equals: .email)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Master Password")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        if showPassword {
                            TextField("Master password", text: $password)
                                .textFieldStyle(.roundedBorder)
                                .focused($focusedField, equals: .password)
                        } else {
                            SecureField("Master password", text: $password)
                                .textFieldStyle(.roundedBorder)
                                .focused($focusedField, equals: .password)
                        }
                        Button {
                            showPassword.toggle()
                        } label: {
                            Image(systemName: showPassword ? "eye.slash" : "eye")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.bottom, 24)

                if let error = errorMessage {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundStyle(.red)
                            .padding(.top, 2)
                        
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .lineLimit(nil)
                            .fixedSize(horizontal: false, vertical: true)
                        
                        Spacer()
                        
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(error, forType: .string)
                            withAnimation { copiedError = true }
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                withAnimation { copiedError = false }
                            }
                        } label: {
                            Image(systemName: copiedError ? "checkmark" : "doc.on.doc")
                                .font(.caption)
                                .foregroundStyle(copiedError ? .green : .secondary)
                        }
                        .buttonStyle(.plain)
                        .help("Copy error message")
                    }
                    .padding(.vertical, 4)
                }
            }
            .padding(.horizontal, 40)

            Spacer()

            // Login button
            VStack(spacing: 12) {
                Button(action: performLogin) {
                    if isLoading {
                        ProgressView()
                            .controlSize(.small)
                            .frame(maxWidth: .infinity)
                    } else {
                        Text("Sign In")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!isFormValid || isLoading)
                .keyboardShortcut(.defaultAction)

                if isLoading && !session.authStatusMessage.isEmpty {
                    Text(session.authStatusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 40)
            .padding(.bottom, 40)
        }
        .frame(width: 440)
        .overlay(alignment: .topLeading) {
            if mode == .addAccount {
                Button("Cancel") {
                    session.cancelAddAccount()
                }
                .keyboardShortcut(.cancelAction)
                .padding(12)
            }
        }
        .onAppear {
            seedFields()
            if !serverURL.isEmpty && serverURL != "https://" && !email.isEmpty {
                focusedField = .password
            } else if serverURL.isEmpty || serverURL == "https://" {
                focusedField = .serverURL
            } else {
                focusedField = .email
            }
        }
    }

    /// Prefill server/email: blank when adding an account; otherwise from the
    /// account awaiting re-login, falling back to the last-used values.
    private func seedFields() {
        switch mode {
        case .addAccount:
            serverURL = "https://"
            email = ""
        case .standard:
            if let account = session.activeAccount {
                serverURL = account.serverURL.absoluteString
                email = account.email
            } else {
                serverURL = storedServerURL
                email = storedEmail
            }
        }
    }

    private var isFormValid: Bool {
        !serverURL.isEmpty && !email.isEmpty && !password.isEmpty
            && URL(string: serverURL) != nil
    }

    private func performLogin() {
        guard let url = URL(string: serverURL) else {
            errorMessage = "Invalid server URL"
            return
        }

        // Enforce HTTPS to prevent cleartext credential transmission
        guard url.scheme?.lowercased() == "https" else {
            errorMessage = "Server URL must use HTTPS"
            return
        }

        isLoading = true
        errorMessage = nil

        Task {
            do {
                try await session.login(email: email, password: password, serverURL: url)
                storedServerURL = serverURL
                storedEmail = email
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}
