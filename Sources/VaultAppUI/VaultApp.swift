// MARK: - VaultAppUI/VaultApp.swift
// Main SwiftUI app entry point

import SwiftUI
import SwiftData
import VaultServices
import VaultSync
import AuthenticationServices

/// The main Vault UI application.
public struct VaultAppView: View {
    @StateObject private var session = SessionManager()
    @State private var modelContainer: ModelContainer?
    @State private var initError: String?

    @State private var pendingTOTPSetup: TOTPSetupData?

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
        .onOpenURL { url in
            handleIncomingURL(url)
        }
        .onReceive(NotificationCenter.default.publisher(for: NSNotification.Name("VaultUIHandleCredentialExchange"))) { notification in
            // Force the app to become active and bring all windows to the front
            NSApp.activate(ignoringOtherApps: true)
            for window in NSApplication.shared.windows {
                window.makeKeyAndOrderFront(nil)
            }
            
            if #available(macOS 26.0, *) {
                if let userInfo = notification.userInfo as? [String: Any],
                   let token = userInfo[ASCredentialImportToken] as? UUID {
                    session.pendingImportToken = token
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { pendingTOTPSetup != nil && session.authState == .unlocked },
            set: { isPresented in
                if !isPresented {
                    pendingTOTPSetup = nil
                }
            }
        )) {
            if let setupData = pendingTOTPSetup {
                TOTPSetupSheet(setupData: setupData)
                    .environmentObject(session)
            }
        }
        .sheet(isPresented: Binding(
            get: { session.pendingImportToken != nil && session.authState == .unlocked },
            set: { isPresented in
                if !isPresented {
                    session.pendingImportToken = nil
                }
            }
        )) {
            if let token = session.pendingImportToken {
                ImportView(importToken: token)
                    .environmentObject(session)
            }
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
    
    private func handleIncomingURL(_ url: URL) {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "otpauth" || scheme == "apple-otpauth" else {
            return
        }
        
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }
        
        // Extract parameters
        var secret: String?
        var issuer: String?
        var domain: String?
        
        for queryItem in components.queryItems ?? [] {
            let name = queryItem.name.lowercased()
            if name == "secret" {
                secret = queryItem.value
            } else if name == "issuer" {
                issuer = queryItem.value
            } else if name == "domain" || name == "origin" || name == "url" {
                if domain == nil {
                    domain = queryItem.value
                }
            }
        }
        
        guard let validSecret = secret else { return }
        
        // Extract account name from path
        var accountName: String?
        let path = url.path
        if !path.isEmpty {
            // Path is usually like /Issuer:accountname
            let trimmedPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
            let parts = trimmedPath.split(separator: ":", maxSplits: 1)
            if parts.count == 2 {
                accountName = String(parts[1])
                if issuer == nil {
                    issuer = String(parts[0])
                }
            } else {
                accountName = trimmedPath
            }
        }
        
        // If we still don't have a domain but issuer looks like one
        if domain == nil, let issuerDomain = issuer, issuerDomain.contains(".") && !issuerDomain.contains(" ") {
            domain = issuerDomain
        }
        
        pendingTOTPSetup = TOTPSetupData(
            secret: validSecret,
            issuer: issuer,
            accountName: accountName,
            domain: domain
        )
    }
}

/// Routes between auth and main vault views based on session state.
struct ContentRouter: View {
    @EnvironmentObject var session: SessionManager
    @AppStorage("lockOnSleep") private var lockOnSleep = true
    @AppStorage("lockOnScreenSaver") private var lockOnScreenSaver = true
    @AppStorage("useTouchID") private var useTouchID = true

    var body: some View {
        Group {
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
            case .twoFactorRequired(let challenge):
                TwoFactorView(challenge: challenge)
                    .frame(minWidth: 440, minHeight: 400)
            case .unlocked:
                MainVaultView()
                    .frame(minWidth: 900, minHeight: 600)
            case .error(let message):
                ErrorView(message: message) {
                    session.lock(requirePassword: true)
                }
                .frame(minWidth: 440, minHeight: 300)
            }
        }
        // Lock vault when user hides the app with CMD+H (Touch ID allowed)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didHideNotification)) { _ in
            if session.authState == .unlocked {
                session.lock()
            }
        }
        // Lock vault on system sleep if setting is enabled (Touch ID allowed)
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
            if lockOnSleep && session.authState == .unlocked {
                session.lock()
            }
        }
        // Lock vault on screen saver / display sleep if setting is enabled (Touch ID allowed)
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            if lockOnScreenSaver && session.authState == .unlocked {
                session.lock()
            }
        }
        // Trigger biometric unlock when app becomes active while locked.
        // This catches the case where the notification fires before UnlockView is mounted.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            if session.authState == .unlocked, let engine = try? session.getSyncEngine(), let key = try? session.getVaultKey() {
                Task {
                    await PendingPasskeyManager.processPendingPasskeys(syncEngine: engine, vaultKey: key)
                }
            }
            triggerBiometricFromRouter()
        }
        // Trigger biometric unlock when app is un-hidden while locked.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didUnhideNotification)) { _ in
            triggerBiometricFromRouter()
        }
    }

    /// Attempt biometric unlock from the router level.
    ///
    /// This provides a safety net for the race condition where `didUnhideNotification`
    /// or `didBecomeActiveNotification` fires before `UnlockView` is mounted in the
    /// view hierarchy (and therefore before its own `.onReceive` handlers are active).
    /// We use a delay to give SwiftUI time to mount `UnlockView` first — if `UnlockView`
    /// handles it, this becomes a no-op because the state will no longer be `.locked`.
    private func triggerBiometricFromRouter() {
        guard session.authState == .locked,
              useTouchID,
              session.canUnlockWithBiometrics,
              !session.biometricAttempted else { return }

        // Delay to let UnlockView mount and potentially handle this itself
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            // Double-check state — UnlockView may have already triggered biometrics
            guard session.authState == .locked,
                  useTouchID,
                  session.canUnlockWithBiometrics,
                  !session.biometricAttempted else { return }

            Task {
                try? await session.unlockWithBiometrics()
            }
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
