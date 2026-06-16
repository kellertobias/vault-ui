// MARK: - VaultAppUI/VaultApp.swift
// Main SwiftUI app entry point

import SwiftUI
import SwiftData
import Combine
import VaultServices
import VaultSync
import AuthenticationServices

/// App-owned runtime for work that must survive closing the main window.
@MainActor
public final class VaultAppRuntime: ObservableObject {
    @Published public private(set) var session = SessionManager()
    @Published public private(set) var modelContainer: ModelContainer?
    @Published public private(set) var initError: String?

    private var hasInitialized = false
    private var appLifecycleCancellables = Set<AnyCancellable>()

    public init() {
        setupApplicationLifecycleObservers()
    }

    public func start() {
        guard !hasInitialized else { return }
        hasInitialized = true

        Task {
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

    private func setupApplicationLifecycleObservers() {
        NotificationCenter.default.publisher(for: NSApplication.didHideNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                if self.session.authState == .unlocked {
                    self.session.lock()
                }
            }
            .store(in: &appLifecycleCancellables)

        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                if self.defaultedBool(forKey: "lockOnSleep", defaultValue: true),
                   self.session.authState == .unlocked {
                    self.session.lock()
                }
            }
            .store(in: &appLifecycleCancellables)

        // Display sleep plus an explicit screen lock (Ctrl-Cmd-Q, hot corner, or
        // screensaver start) all count as the screen being secured. The screen-lock
        // and screensaver-start events are delivered as distributed notifications and
        // fire even when the displays stay awake.
        let screenSecuredPublishers: [AnyPublisher<Notification, Never>] = [
            NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)
                .eraseToAnyPublisher(),
            DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screenIsLocked"))
                .eraseToAnyPublisher(),
            DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screensaver.didstart"))
                .eraseToAnyPublisher(),
        ]
        for publisher in screenSecuredPublishers {
            publisher
                .receive(on: DispatchQueue.main)
                .sink { [weak self] _ in
                    guard let self else { return }
                    if self.defaultedBool(forKey: "lockOnScreenSaver", defaultValue: true),
                       self.session.authState == .unlocked {
                        self.session.lock()
                    }
                }
                .store(in: &appLifecycleCancellables)
        }

        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in
                    await self.session.processPendingSharedQueuesIfPossible()
                    self.triggerBiometricFromLifecycleObserver()
                }
            }
            .store(in: &appLifecycleCancellables)

        NotificationCenter.default.publisher(for: NSApplication.didUnhideNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.triggerBiometricFromLifecycleObserver()
            }
            .store(in: &appLifecycleCancellables)
    }

    private func defaultedBool(forKey key: String, defaultValue: Bool) -> Bool {
        UserDefaults.standard.object(forKey: key) == nil
            ? defaultValue
            : UserDefaults.standard.bool(forKey: key)
    }

    private func triggerBiometricFromLifecycleObserver() {
        guard session.authState == .locked,
              defaultedBool(forKey: "useTouchID", defaultValue: true),
              session.canUnlockWithBiometrics,
              !session.biometricAttempted else { return }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            guard self.session.authState == .locked,
                  self.defaultedBool(forKey: "useTouchID", defaultValue: true),
                  self.session.canUnlockWithBiometrics,
                  !self.session.biometricAttempted else { return }

            Task {
                try? await self.session.unlockWithBiometrics()
            }
        }
    }
}

/// The main Vault UI application.
public struct VaultAppView: View {
    @ObservedObject private var runtime: VaultAppRuntime

    @State private var pendingTOTPSetup: TOTPSetupData?

    public init(runtime: VaultAppRuntime) {
        self.runtime = runtime
    }

    public var body: some View {
        Group {
            if let error = runtime.initError {
                ErrorInitView(message: error)
            } else if let container = runtime.modelContainer {
                ContentRouter()
                    .environmentObject(runtime.session)
                    .modelContainer(container)
            } else {
                ProgressView("Initializing Vault…")
                    .frame(width: 300, height: 200)
            }
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
                    runtime.session.pendingImportToken = token
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { pendingTOTPSetup != nil && runtime.session.authState == .unlocked },
            set: { isPresented in
                if !isPresented {
                    pendingTOTPSetup = nil
                }
            }
        )) {
            if let setupData = pendingTOTPSetup {
                TOTPSetupSheet(setupData: setupData)
                    .environmentObject(runtime.session)
            }
        }
        .sheet(isPresented: Binding(
            get: { runtime.session.pendingImportToken != nil && runtime.session.authState == .unlocked },
            set: { isPresented in
                if !isPresented {
                    runtime.session.pendingImportToken = nil
                }
            }
        )) {
            if let token = runtime.session.pendingImportToken {
                ImportView(importToken: token)
                    .environmentObject(runtime.session)
            }
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

    var body: some View {
        Group {
            switch session.authState {
            case .noAccount, .loginRequired:
                LoginView()
                    .frame(minWidth: 440, minHeight: 520)
            case .addingAccount:
                LoginView(mode: .addAccount)
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
        // App-lifecycle locking and biometric re-unlock are handled once, in
        // VaultAppRuntime.setupApplicationLifecycleObservers(). That runtime is
        // always alive (owned by VaultUIApplication as a @StateObject), so it
        // covers every auth state without depending on this view being mounted.
        // Registering the same observers here too would double-fire — most
        // visibly a duplicate Touch ID prompt, since the 0.5s-delayed guards can
        // both pass before `biometricAttempted` flips.
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
