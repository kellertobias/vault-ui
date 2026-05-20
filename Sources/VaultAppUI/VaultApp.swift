// MARK: - VaultAppUI/VaultApp.swift
// Main SwiftUI app entry point

import SwiftUI
import SwiftData
import VaultServices
import VaultSync

/// The main Vault UI application.
public struct VaultAppView: View {
    @StateObject private var session = SessionManager()
    @State private var modelContainer: ModelContainer?
    @State private var initError: String?

    public init() {}

    public var body: some View {
        Group {
            if let error = initError {
                ErrorInitView(message: error)
            } else if let container = modelContainer {
                ContentRouter()
                    .environmentObject(session)
                    .modelContainer(container)
            } else {
                ProgressView("Initializing Vault…")
                    .frame(width: 300, height: 200)
            }
        }
        .task {
            await initialize()
        }
    }

    private func initialize() async {
        do {
            let container = try VaultDataStore.createModelContainer()
            self.modelContainer = container
            await session.setup(modelContainer: container)
        } catch {
            initError = error.localizedDescription
        }
    }
}

/// Routes between auth and main vault views based on session state.
struct ContentRouter: View {
    @EnvironmentObject var session: SessionManager

    var body: some View {
        switch session.authState {
        case .noAccount, .loginRequired:
            LoginView()
                .frame(minWidth: 440, minHeight: 520)
        case .locked:
            UnlockView()
                .frame(minWidth: 440, minHeight: 400)
        case .unlocking:
            VStack(spacing: 16) {
                ProgressView()
                    .controlSize(.large)
                Text("Authenticating…")
                    .font(.headline)
                if !session.authStatusMessage.isEmpty {
                    Text(session.authStatusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            .frame(width: 300, height: 200)
        case .twoFactorRequired(let providers):
            TwoFactorView(providers: providers)
                .frame(minWidth: 440, minHeight: 400)
        case .unlocked:
            MainVaultView()
                .frame(minWidth: 900, minHeight: 600)
        case .error(let message):
            ErrorView(message: message) {
                session.lock()
            }
            .frame(minWidth: 440, minHeight: 300)
        }
    }
}

/// Error view for initialization failures.
struct ErrorInitView: View {
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(.red)
            Text("Failed to Initialize")
                .font(.title2.bold())
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
        .frame(width: 400, height: 300)
    }
}

/// Generic error view with retry.
struct ErrorView: View {
    let message: String
    let onDismiss: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.octagon.fill")
                .font(.system(size: 44))
                .foregroundStyle(.red)
            Text("Error")
                .font(.title2.bold())
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Button("Back to Login") {
                onDismiss()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
    }
}
