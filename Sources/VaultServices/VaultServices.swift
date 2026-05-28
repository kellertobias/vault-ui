// MARK: - VaultServices/SessionManager.swift
// Manages the authenticated session and vault unlock state

import Foundation
import VaultCrypto
import VaultModels
import VaultAPI
import VaultSync
import SwiftData
import LocalAuthentication
import OSLog
import Network
import VaultSSH
import Combine

private let logger = Logger(subsystem: "com.vaultui", category: "SessionManager")

/// Manages the full application session: login, unlock, lock, and vault key state.
///
/// This is the central coordinator that the UI interacts with for auth state.
@MainActor
public final class SessionManager: ObservableObject {

    /// Current authentication state
    @Published public var authState: AuthState = .locked
    @Published public var authStatusMessage: String = ""
    @Published public var biometricAttempted: Bool = false
    @Published public var activeAccount: Account?
    @Published public var accounts: [Account] = []
    @Published public var isSSHAgentRunning: Bool = false
    @Published public var isSecretAgentRunning: Bool = false
    
    /// Token used to signal the UI that cipher data has changed.
    @Published public var dataUpdateToken: Int = 0
    @Published public var isSyncing: Bool = false
    @Published public var pendingImportToken: UUID? = nil

    @Published public var isOffline: Bool = false
    @Published public var forceOffline: Bool = false {
        didSet { updateOfflineState() }
    }
    private var networkOffline: Bool = false {
        didSet { updateOfflineState() }
    }
    private let pathMonitor = NWPathMonitor()

    private func updateOfflineState() {
        isOffline = forceOffline || networkOffline
    }

    /// When true, the unlock screen requires the master password (set by manual lock).
    /// Resets to false on app launch and after a successful password-based login.
    @Published public var requiresPasswordUnlock: Bool = false

    /// The decrypted vault key — only in memory, never persisted
    private var vaultKey: SymmetricCryptoKey?

    /// The decrypted private key for org operations
    private var privateKeyData: Data?

    private var apiClient: APIClient?
    private var syncEngine: SyncEngine?
    private var syncScheduler: SyncScheduler?
    private var modelContainer: ModelContainer?
    private var lockTimer: Timer?
    private var sshAgentServer: SSHAgentServer?
    private var secretAgentServer: SecretAgentServer?
    private var cancellables = Set<AnyCancellable>()

    private let tokenStorage = TokenStorage()
    private let biometricKeyStorage = BiometricKeyStorage()

    // MARK: - Two-Factor Authentication State

    /// Cached credentials during the 2FA flow so the user
    /// doesn't have to re-enter their password after entering the code.
    private var pendingPasswordHash: String?
    private var pendingMasterKey: MasterKey?
    private var pendingEmail: String?
    private var pendingServerURL: URL?
    private var pendingAccount: Account?

    /// Whether this is a fresh process start (resets to false after first successful unlock).
    /// Used by the 2FA policy to determine whether to require 2FA.
    private var isFreshProcessStart: Bool = true

    public enum AuthState: Equatable {
        case noAccount
        case locked
        case unlocking
        case unlocked
        case loginRequired
        case twoFactorRequired(challenge: TwoFactorChallenge)
        case error(String)
    }

    public init() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in
                self?.networkOffline = path.status != .satisfied
            }
        }
        pathMonitor.pathUpdateHandler?(pathMonitor.currentPath)
        pathMonitor.start(queue: DispatchQueue.global(qos: .background))

        // Clean stale sockets from previous runs and start both agent
        // servers immediately so the CLI can connect even before vault unlock.
        // Biometric unlock handles secret retrieval when the vault is locked.
        Task.detached { [weak self] in
            Self.cleanStaleSockets()
            await self?.syncSecretAgentState()
            await self?.syncSSHAgentState()
        }
    }

    /// Remove stale socket files left behind from a previous crash or unclean exit.
    private nonisolated static func cleanStaleSockets() {
        let sshPath = SSHAgentServer.defaultSocketPath
        let secretPath = SecretAgentServer.defaultSocketPath

        for path in [sshPath, secretPath] {
            // Only remove if the file exists but nothing is listening
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { continue }
            defer { close(fd) }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = path.utf8CString
            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                ptr.withMemoryRebound(to: Int8.self, capacity: 104) { dest in
                    pathBytes.withUnsafeBufferPointer { src in
                        for i in 0..<min(src.count, 104) { dest[i] = src[i] }
                    }
                }
            }
            let result = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                // Connection refused — stale socket, remove it
                try? FileManager.default.removeItem(atPath: path)
            }
        }
    }

    /// Whether biometric unlock is available for the current account.
    public var canUnlockWithBiometrics: Bool {
        guard !requiresPasswordUnlock else {
            logger.debug("canUnlockWithBiometrics: false — requiresPasswordUnlock is set")
            return false
        }
        guard let account = activeAccount else {
            logger.debug("canUnlockWithBiometrics: false — no active account")
            return false
        }
        let hasKeys = biometricKeyStorage.hasStoredKeys(for: account.id)
        if !hasKeys {
            logger.debug("canUnlockWithBiometrics: false — no stored keys for \(account.email)")
        }
        return hasKeys
    }

    // MARK: - Setup

    /// Initialize with a model container.
    public func setup(modelContainer: ModelContainer) async {
        self.modelContainer = modelContainer
        await loadAccounts()
    }

    /// Load persisted accounts from SwiftData.
    private func loadAccounts() async {
        guard let container = modelContainer else { return }
        let context = container.mainContext

        let descriptor = FetchDescriptor<PersistedAccount>()
        guard let persistedAccounts = try? context.fetch(descriptor) else { return }

        accounts = persistedAccounts.compactMap { $0.toAccount() }

        if let active = persistedAccounts.first(where: { $0.isActive }),
           let account = active.toAccount() {
            activeAccount = account
            // Try to restore session from stored tokens
            if let tokens = try? tokenStorage.loadTokens(for: account.id) {
                let client = APIClient(account: account, tokens: tokens)
                setupAPIClient(client)
                syncEngine = nil // Clear engine
        
        biometricAttempted = false
        authState = .locked  // Require unlock (Touch ID or password)
            } else {
                authState = .loginRequired
            }
        } else if accounts.isEmpty {
            authState = .noAccount
        } else {
            authState = .loginRequired
        }
    }

    // MARK: - Login

    /// Perform full login flow.
    public func login(
        email: String,
        password: String,
        serverURL: URL,
        twoFactorProvider: TwoFactorProviderType? = nil,
        twoFactorToken: String? = nil,
        twoFactorRemember: Bool = false
    ) async throws {
        authStatusMessage = "Connecting to server..."

        do {
            // Create temporary account for prelogin.
            // If we already have an active account for this email+server, reuse its ID
            // so that the persisted device identifier is found (keyed by account ID).
            let matchedAccount = accounts.first { $0.email.lowercased() == email.lowercased() && $0.serverURL == serverURL }
            let existingId = activeAccount?.id ?? matchedAccount?.id
            var account = Account(id: existingId ?? UUID().uuidString, email: email, serverURL: serverURL)
            let tempClient = APIClient(account: account)
            let authService = AuthService(client: tempClient)

            // Step 1: Prelogin — get KDF config
            let kdfConfig: KDFConfig
            if isOffline {
                guard let storedKdf = matchedAccount?.kdfConfig else {
                    throw APIError.serverMessage("Cannot login offline for the first time.")
                }
                kdfConfig = storedKdf
            } else {
                kdfConfig = try await authService.prelogin(email: email)
            }
            
            account = Account(
                id: account.id,
                email: email,
                serverURL: serverURL,
                kdfConfig: kdfConfig
            )

            authStatusMessage = "Deriving master key..."
            // Step 2: Derive master key
            let masterKey = try MasterKey.derive(
                password: password,
                email: email,
                kdfConfig: kdfConfig
            )

            authStatusMessage = "Logging in..."
            // Step 3: Compute auth hash
            let passwordHash = try MasterPasswordHash.compute(
                masterKey: masterKey,
                password: password
            )

            if isOffline {
                authStatusMessage = "Authenticating offline..."
                guard let tokens = try? tokenStorage.loadTokens(for: account.id),
                      let encKeyString = tokens.encryptedKey else {
                    throw APIError.serverMessage("Cannot login offline: no cached vault data available.")
                }
                
                // Decrypt the vault key
                let stretchedKey = try masterKey.stretch()
                let protectedKey = try EncString(serialized: encKeyString)
                let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(
                    protectedKey,
                    stretchedMasterKey: stretchedKey
                )
                
                // Decrypt private key if available
                var privKeyData: Data?
                if let encPrivKey = tokens.encryptedPrivateKey {
                    let privKeyEnc = try EncString(serialized: encPrivKey)
                    privKeyData = try CipherEncryption.decryptData(privKeyEnc, key: vaultKey)
                }
                
                // Setup client without network call
                let client = APIClient(account: account, tokens: tokens)
                setupAPIClient(client)
                self.apiClient = client
                self.activeAccount = account
                self.vaultKey = vaultKey
                self.privateKeyData = privKeyData
                
                // Restore sync engine
                if let container = modelContainer {
                    let engine = SyncEngine(
                        apiClient: client,
                        modelContainer: container,
                        accountId: account.id
                    )
                    self.syncEngine = engine
                    setupSyncObserver(engine)
                    // Export decrypted credential metadata for AutoFill extension
                    SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
                }
                
                requiresPasswordUnlock = false
                isFreshProcessStart = false
                authStatusMessage = ""
                authState = .unlocked
                startBackgroundServices()
                logger.info("Offline login successful for \(email)")
                return
            }

            // Determine 2FA handling
            var effectiveTwoFactorProvider = twoFactorProvider
            var effectiveTwoFactorToken = twoFactorToken
            var effectiveTwoFactorRemember = twoFactorRemember

            // If no explicit 2FA provider, send the remember token to skip 2FA if possible
            if twoFactorProvider == nil,
               let rememberToken = tokenStorage.loadRememberToken(for: account.id) {
                effectiveTwoFactorProvider = .remember
                effectiveTwoFactorToken = rememberToken
                effectiveTwoFactorRemember = false
                logger.info("Sending remember token for \(email)")
            }

            // Step 4: Login to server
            let client = APIClient(account: account)
            setupAPIClient(client)
            let loginService = AuthService(client: client)

            let loginResult: AuthService.LoginResult
            let persistedDeviceId = APIClient.getOrCreateDeviceId(for: account)
            do {
                loginResult = try await loginService.login(
                    AuthService.LoginRequest(
                        email: email,
                        masterPasswordHash: passwordHash,
                        deviceId: persistedDeviceId,
                        twoFactorProvider: effectiveTwoFactorProvider,
                        twoFactorToken: effectiveTwoFactorToken,
                        twoFactorRemember: effectiveTwoFactorRemember
                    )
                )
            } catch let error as APIError {
                if case .twoFactorRequired(let challenge) = error {
                    // Cache credentials for 2FA retry so user doesn't re-enter password
                    self.pendingPasswordHash = passwordHash
                    self.pendingMasterKey = masterKey
                    self.pendingEmail = email
                    self.pendingServerURL = serverURL
                    self.pendingAccount = account
                    self.apiClient = client
                    self.activeAccount = account
                    authState = .twoFactorRequired(challenge: challenge)
                    authStatusMessage = ""
                    return
                }
                throw error
            }

            // Complete the login
            try await completeLogin(
                loginResult: loginResult,
                masterKey: masterKey,
                client: client,
                account: account,
                email: email
            )

        } catch {
            authStatusMessage = ""
            throw error
        }
    }

    /// Complete a 2FA login using cached credentials and the user's 2FA code.
    ///
    /// Called from `TwoFactorView` after the user enters their code, taps
    /// a security key, etc. Uses the cached master key from the initial
    /// login attempt so the user doesn't re-enter their master password.
    public func loginWithTwoFactor(
        provider: TwoFactorProviderType,
        token: String,
        remember: Bool
    ) async throws {
        guard let passwordHash = pendingPasswordHash,
              let masterKey = pendingMasterKey,
              let email = pendingEmail,
              let account = pendingAccount else {
            throw APIError.serverMessage("No pending 2FA session. Please log in again.")
        }

        authStatusMessage = "Verifying..."

        do {
            let client = apiClient ?? APIClient(account: account)
            setupAPIClient(client)
            let loginService = AuthService(client: client)
            let persistedDeviceId = APIClient.getOrCreateDeviceId(for: account)

            let loginResult = try await loginService.login(
                AuthService.LoginRequest(
                    email: email,
                    masterPasswordHash: passwordHash,
                    deviceId: persistedDeviceId,
                    twoFactorProvider: provider,
                    twoFactorToken: token,
                    twoFactorRemember: remember
                )
            )

            // Use the cached master key to complete login
            try await completeLogin(
                loginResult: loginResult,
                masterKey: masterKey,
                client: client,
                account: account,
                email: email
            )
        } catch {
            authStatusMessage = ""
            throw error
        }
    }

    /// Complete login after successful authentication (shared by normal and 2FA flows).
    private func completeLogin(
        loginResult: AuthService.LoginResult,
        masterKey: MasterKey,
        client: APIClient,
        account: Account,
        email: String
    ) async throws {
        authStatusMessage = "Decrypting vault..."
        // Step 5: Decrypt the vault key
        let stretchedKey = try masterKey.stretch()
        guard let encKeyString = loginResult.tokens.encryptedKey else {
            throw APIError.serverMessage("Server did not return encrypted key")
        }
        let protectedKey = try EncString(serialized: encKeyString)
        let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(
            protectedKey,
            stretchedMasterKey: stretchedKey
        )

        // Step 6: Decrypt private key if available
        var privKeyData: Data?
        if let encPrivKey = loginResult.tokens.encryptedPrivateKey {
            let privKeyEnc = try EncString(serialized: encPrivKey)
            privKeyData = try CipherEncryption.decryptData(privKeyEnc, key: vaultKey)
        }

        authStatusMessage = "Syncing vault data..."
        // Step 7: Save state
        self.apiClient = client
        self.activeAccount = account
        self.vaultKey = vaultKey
        self.privateKeyData = privKeyData

        // Persist account and tokens
        try tokenStorage.saveTokens(loginResult.tokens, for: account.id)
        try persistAccount(account, isActive: true)

        // Store the 2FA remember token if the server returned one
        if let rememberToken = loginResult.twoFactorToken {
            try? tokenStorage.saveRememberToken(rememberToken, for: account.id)
            logger.info("Stored 2FA remember token for \(email)")
        }

        // Step 8: Perform initial sync
        if let container = modelContainer {
            let engine = SyncEngine(
                apiClient: client,
                modelContainer: container,
                accountId: account.id
            )
            self.syncEngine = engine
            setupSyncObserver(engine)
            try await engine.fullSync()
            await PendingPasskeyManager.repairPasskeyCompatibility(
                syncEngine: engine,
                vaultKey: vaultKey
            )

            // Export decrypted credential metadata for AutoFill extension
            SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
        }

        // Step 9: Store keys for future biometric unlock
        do {
            try biometricKeyStorage.storeKeys(
                vaultKey: vaultKey,
                privateKey: privKeyData,
                for: account.id
            )
        } catch {
            logger.error("Failed to store biometric keys: \(error.localizedDescription)")
        }

        // Clear the manual-lock flag and 2FA pending state after a successful login
        requiresPasswordUnlock = false
        isFreshProcessStart = false
        clearPendingTwoFactor()

        authStatusMessage = ""
        authState = .unlocked
        startBackgroundServices()
        logger.info("Login successful for \(email)")
    }

    /// Clear cached 2FA credentials.
    private func clearPendingTwoFactor() {
        pendingPasswordHash = nil
        pendingMasterKey = nil
        pendingEmail = nil
        pendingServerURL = nil
        pendingAccount = nil
    }

    // MARK: - Unlock (Touch ID / Password)

    /// Unlock the vault using Touch ID.
    ///
    /// Retrieves the vault key from the Keychain using a biometric-protected item.
    /// The key was stored there during the last successful password-based login.
    public func unlockWithBiometrics() async throws {
        guard let account = activeAccount else {
            logger.error("unlockWithBiometrics: no active account")
            throw BiometricError.noStoredKeys
        }

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            logger.error("unlockWithBiometrics: biometrics not available — \(error?.localizedDescription ?? "unknown")")
            throw BiometricError.biometricNotAvailable
        }

        // Check if we have stored keys before prompting Touch ID
        guard biometricKeyStorage.hasStoredKeys(for: account.id) else {
            // No stored keys — must sign in with password first
            logger.warning("unlockWithBiometrics: no stored biometric keys for \(account.email)")
            authState = .loginRequired
            return
        }

        logger.info("unlockWithBiometrics: starting Touch ID prompt for \(account.email)")

        biometricAttempted = true
        authState = .unlocking

        do {
            // Authenticate with Touch ID
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Unlock Vault UI"
            )

            guard success else {
                authState = .locked
                throw BiometricError.biometricFailed
            }

            // Retrieve vault key using the authenticated context (no second prompt)
            let (vaultKey, privateKey) = try biometricKeyStorage.retrieveKeys(
                for: account.id,
                context: context
            )

            self.vaultKey = vaultKey
            self.privateKeyData = privateKey

            // Restore API client from stored tokens
            let loadedTokens = try? tokenStorage.loadTokens(for: account.id)
            guard let tokens = loadedTokens.flatMap({ $0 }) else {
                // Tokens expired or missing — must re-authenticate with password
                self.vaultKey = nil
                self.privateKeyData = nil
                authState = .loginRequired
                logger.warning("Biometric unlock succeeded but tokens are missing — requiring password login")
                return
            }

            let client = APIClient(account: account, tokens: tokens)
            setupAPIClient(client)
            self.apiClient = client

            // Restore sync engine
            if let container = modelContainer {
                let engine = SyncEngine(
                    apiClient: client,
                    modelContainer: container,
                    accountId: account.id
                )
                self.syncEngine = engine
                setupSyncObserver(engine)

                // Background sync to pick up any changes while locked
                Task { [weak self] in
                    try? await engine.fullSync()
                    await PendingPasskeyManager.repairPasskeyCompatibility(
                        syncEngine: engine,
                        vaultKey: vaultKey
                    )
                    // Export decrypted credential metadata for AutoFill extension
                    if let self = self {
                        SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
                    }
                }
            }

            isFreshProcessStart = false
            authState = .unlocked
            startBackgroundServices()
            logger.info("Vault unlocked via Touch ID for \(account.email)")
        } catch {
            authState = .locked
            throw error
        }
    }

    // MARK: - Lock

    /// Lock the vault — zero key material from memory, then release references.
    ///
    /// - Parameter requirePassword: If `true`, the next unlock must use the master
    ///   password (Touch ID is suppressed). This flag is in-memory only, so a fresh
    ///   app launch always allows Touch ID.
    public func lock(requirePassword: Bool = false) {
        if requirePassword {
            requiresPasswordUnlock = true
            logger.info("Manual lock — master password required for next unlock")
        }

        // Zero key material before releasing (defense against memory forensics)
        if vaultKey != nil {
            vaultKey!.zeroize()
        }
        vaultKey = nil

        if privateKeyData != nil {
            privateKeyData!.resetBytes(in: privateKeyData!.startIndex ..< privateKeyData!.endIndex)
        }
        privateKeyData = nil

        stopBackgroundServices()
        cancellables.removeAll()
        syncEngine = nil
        authState = .locked
        logger.info("Vault locked")
    }

    // MARK: - Logout

    /// Fully log out: clear all local data for the active account.
    ///
    /// This is a destructive action that:
    /// - Zeros and discards all key material from memory
    /// - Deletes auth tokens, biometric keys, and 2FA remember tokens from Keychain
    /// - Removes the persisted device identifier
    /// - Deletes all local vault data (ciphers, folders, sends) from SwiftData
    /// - Clears the shared AutoFill credential store
    /// - Removes the account from the persisted account list
    ///
    /// Server-side data is **not** affected. Re-logging in will re-sync everything.
    public func logout() {
        guard let account = activeAccount else {
            logger.warning("Logout called with no active account")
            authState = .noAccount
            return
        }

        let accountId = account.id
        let email = account.email
        logger.info("Full logout for \(email) (id=\(accountId))")

        // 1. Lock first — zeros key material and stops background services
        lock(requirePassword: true)

        // 2. Delete Keychain secrets
        do {
            try tokenStorage.deleteTokens(for: accountId)
        } catch {
            logger.error("Failed to delete tokens during logout: \(error.localizedDescription)")
        }
        biometricKeyStorage.deleteKeys(for: accountId)
        tokenStorage.deleteRememberToken(for: accountId)

        // 3. Remove persisted device identifier
        UserDefaults.standard.removeObject(forKey: "device_id_\(accountId)")

        // 4. Delete all persisted vault data for this account from SwiftData
        if let container = modelContainer {
            let context = container.mainContext

            // Delete ciphers
            let cipherDescriptor = FetchDescriptor<PersistedCipher>(
                predicate: #Predicate { $0.accountId == accountId }
            )
            if let ciphers = try? context.fetch(cipherDescriptor) {
                for cipher in ciphers { context.delete(cipher) }
                logger.info("Deleted \(ciphers.count) persisted ciphers")
            }

            // Delete folders
            let folderDescriptor = FetchDescriptor<PersistedFolder>(
                predicate: #Predicate { $0.accountId == accountId }
            )
            if let folders = try? context.fetch(folderDescriptor) {
                for folder in folders { context.delete(folder) }
                logger.info("Deleted \(folders.count) persisted folders")
            }

            // Delete sends
            let sendDescriptor = FetchDescriptor<PersistedSend>(
                predicate: #Predicate { $0.accountId == accountId }
            )
            if let sends = try? context.fetch(sendDescriptor) {
                for send in sends { context.delete(send) }
                logger.info("Deleted \(sends.count) persisted sends")
            }

            // Delete the account record itself
            let accountDescriptor = FetchDescriptor<PersistedAccount>(
                predicate: #Predicate { $0.id == accountId }
            )
            if let persistedAccounts = try? context.fetch(accountDescriptor) {
                for acc in persistedAccounts { context.delete(acc) }
            }

            try? context.save()
        }

        // 5. Clear shared AutoFill credential data
        SharedCredentialStore.shared.clearAll()

        // 6. Remove from in-memory account list
        accounts.removeAll { $0.id == accountId }
        activeAccount = nil
        apiClient = nil

        // 7. Clear any pending 2FA state
        clearPendingTwoFactor()

        // 8. Transition to the appropriate auth state
        if accounts.isEmpty {
            authState = .noAccount
        } else {
            // Switch to next available account
            if let next = accounts.first {
                activeAccount = next
                authState = .loginRequired
            } else {
                authState = .noAccount
            }
        }

        logger.info("Full logout complete for \(email)")
    }

    // MARK: - Background Services

    /// Start background sync scheduler and lock timeout timer.
    private func startBackgroundServices() {
        // Sync scheduler
        if let engine = syncEngine {
            let scheduler = SyncScheduler(syncEngine: engine)
            let savedInterval = UserDefaults.standard.integer(forKey: "syncInterval")
            if savedInterval > 0 {
                scheduler.interval = TimeInterval(savedInterval * 60)  // stored in minutes
            }
            self.syncScheduler = scheduler

            // Repair passkeys before the scheduler's initial sync can publish stale malformed data.
            if let key = self.vaultKey {
                Task {
                    await PendingPasskeyManager.repairPasskeyCompatibility(
                        syncEngine: engine,
                        vaultKey: key
                    )
                    await PendingPasskeyManager.processPendingPasskeys(
                        syncEngine: engine,
                        vaultKey: key
                    )
                    await PendingCredentialManager.processPendingCredentials(
                        syncEngine: engine,
                        vaultKey: key
                    )
                    await MainActor.run {
                        scheduler.start()
                    }
                }
            } else {
                scheduler.start()
            }
        }

        // SSH Agent
        Task { await syncSSHAgentState() }

        // Lock timeout
        resetLockTimer()
    }

    /// Stop background services.
    private func stopBackgroundServices() {
        syncScheduler?.stop()
        syncScheduler = nil
        lockTimer?.invalidate()
        lockTimer = nil
        Task { await sshAgentServer?.stop() }
        sshAgentServer = nil
        isSSHAgentRunning = false
        // Only clear cache on lock — keep the socket alive for biometric unlock
        secretAgentServer?.handler.clearCache()
    }

    // MARK: - SSH Agent

    /// Synchronize the SSH agent state with user settings and start/stop as needed.
    public func syncSSHAgentState() async {
        let isEnabled = UserDefaults.standard.bool(forKey: "sshAgentEnabled")
        
        if isEnabled {
            if sshAgentServer == nil {
                let handler = SSHAgentHandler { [weak self] cipherId in
                    guard let self = self else { return nil }
                    return await self.getPrivateKeyData(for: cipherId)
                }
                let server = SSHAgentServer(handler: handler)
                do {
                    try await server.start()
                    self.sshAgentServer = server
                    self.isSSHAgentRunning = true
                    logger.info("SSH agent started successfully")
                } catch {
                    logger.error("Failed to start SSH agent: \(error.localizedDescription)")
                    self.isSSHAgentRunning = false
                }
            }
            if authState == .unlocked {
                try? updateSSHIdentities()
            }
        } else {
            if let server = sshAgentServer {
                await server.stop()
                self.sshAgentServer = nil
                self.isSSHAgentRunning = false
                logger.info("SSH agent stopped")
            }
        }
    }

    /// Update the SSH identities available to the agent.
    public func updateSSHIdentities() throws {
        guard let server = sshAgentServer, let accountId = activeAccount?.id, let vaultKey = vaultKey else { return }
        
        guard let container = modelContainer else { return }
        
        Task.detached {
            let context = ModelContext(container)
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })
            
            guard let ciphers = try? context.fetch(descriptor) else { return }
            
            var identities: [SSHIdentity] = []
            for persisted in ciphers {
                guard let cipher = try? persisted.toCipher(), cipher.type == .sshKey, let sshKey = cipher.sshKey else { continue }
                
                let cipherId = cipher.id ?? persisted.id
                guard let publicKeyEnc = sshKey.publicKey else { continue }
                
                // We need itemKey
                let itemKey: SymmetricCryptoKey?
                if let keyEnc = cipher.key,
                   let keyData = try? CipherEncryption.decryptData(keyEnc, key: vaultKey) {
                    itemKey = try? SymmetricCryptoKey(keyData: keyData)
                } else {
                    itemKey = vaultKey
                }
                
                guard let key = itemKey else { continue }
                guard let publicKeyStr = try? CipherEncryption.decryptString(publicKeyEnc, key: key) else { continue }
                
                let parts = publicKeyStr.split(separator: " ")
                if parts.count >= 2, let blobData = Data(base64Encoded: String(parts[1])) {
                    let comment: String
                    if parts.count >= 3 {
                        comment = String(parts[2...].joined(separator: " "))
                    } else {
                        let nameDecrypted = (try? CipherEncryption.decryptString(cipher.name!, key: key)) ?? "Vault Key"
                        comment = nameDecrypted
                    }
                    identities.append(SSHIdentity(publicKeyBlob: blobData, comment: comment, cipherId: cipherId))
                }
            }
            
            await MainActor.run {
                server.handler.setIdentities(identities)
                logger.debug("Loaded \(identities.count) SSH identities into agent")
            }
        }
    }

    // MARK: - Secret Agent

    /// Synchronize the secret agent state — starts the socket server and provides
    /// a cipher-provider callback that handles biometric unlock when the vault is locked.
    public func syncSecretAgentState() async {
        if secretAgentServer == nil {
            let handler = SecretAgentHandler { [weak self] in
                guard let self = self else { return nil }
                return await self.provideDecryptedCiphers()
            }
            let server = SecretAgentServer(handler: handler)
            do {
                try await server.start()
                self.secretAgentServer = server
                self.isSecretAgentRunning = true
                logger.info("Secret agent started successfully")
            } catch {
                logger.error("Failed to start secret agent: \(error.localizedDescription)")
                self.isSecretAgentRunning = false
            }
        }
    }

    /// Provide all ciphers with their decryption keys for the secret agent handler.
    /// If the vault is locked, attempts biometric unlock to get a temporary vault key.
    private func provideDecryptedCiphers() async -> [(cipher: Cipher, key: SymmetricCryptoKey)]? {
        guard let container = modelContainer, let accountId = activeAccount?.id else { return nil }

        // Determine vault key
        var vKey: SymmetricCryptoKey
        var isTemporaryKey = false

        if let currentKey = vaultKey {
            vKey = currentKey
        } else {
            // Vault is locked — attempt biometric unlock
            do {
                let storage = BiometricKeyStorage()
                guard storage.hasStoredKeys(for: accountId) else {
                    logger.error("Secret agent biometric unlock failed: no stored biometric keys")
                    return nil
                }

                let context = LAContext()
                context.localizedReason = "Unlock Secret"
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: "Unlock Secret"
                )
                guard success else { return nil }

                let keys = try storage.retrieveKeys(for: accountId, context: context)
                vKey = keys.vaultKey
                isTemporaryKey = true
            } catch {
                logger.error("Secret agent biometric unlock failed: \(error.localizedDescription)")
                return nil
            }
        }

        defer {
            if isTemporaryKey {
                vKey.zeroize()
            }
        }

        // Fetch all ciphers
        let ciphers = await MainActor.run { () -> [Cipher] in
            let context = container.mainContext
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })
            guard let persisted = try? context.fetch(descriptor) else { return [] }
            return persisted.compactMap { try? $0.toCipher() }
        }

        // Resolve item keys
        return ciphers.compactMap { cipher -> (cipher: Cipher, key: SymmetricCryptoKey)? in
            if let keyEnc = cipher.key,
               let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey),
               let itemKey = try? SymmetricCryptoKey(keyData: keyData) {
                return (cipher, itemKey)
            }
            return (cipher, vKey)
        }
    }

    /// Fetch and decrypt a private key for the SSH agent handler.
    private func getPrivateKeyData(for cipherId: String) async -> Data? {
        guard let container = modelContainer, let accountId = activeAccount?.id else { return nil }
        
        // Fetch cipher directly from ModelContainer, bypassing SyncEngine which might be nil when locked
        let cipherResult = await MainActor.run { () -> Cipher? in
            let context = container.mainContext
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate { $0.id == cipherId && $0.accountId == accountId })
            if let persisted = try? context.fetch(descriptor).first {
                return try? persisted.toCipher()
            }
            return nil
        }
        
        guard let cipher = cipherResult,
              let sshKey = cipher.sshKey,
              let privateKeyEnc = sshKey.privateKey else { return nil }
              
        // Determine Vault Key
        var vKey: SymmetricCryptoKey
        var isTemporaryKey = false
        
        if let currentKey = vaultKey {
            vKey = currentKey
        } else {
            // Vault is locked. Attempt Biometric Unlock for this request
            do {
                let storage = BiometricKeyStorage()
                guard storage.hasStoredKeys(for: accountId) else {
                    logger.error("SSH Biometric unlock failed: No stored biometric keys")
                    return nil
                }
                
                let context = LAContext()
                context.localizedReason = "Unlock SSH Key"
                let success = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock SSH Key")
                guard success else { return nil }
                
                let keys = try storage.retrieveKeys(for: accountId, context: context)
                vKey = keys.vaultKey
                isTemporaryKey = true
            } catch {
                logger.error("SSH Biometric unlock failed: \(error.localizedDescription)")
                return nil
            }
        }
        
        // Clean up temporary key
        defer {
            if isTemporaryKey {
                vKey.zeroize()
            }
        }
        
        // Derive item key
        let itemKey: SymmetricCryptoKey
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey) {
            itemKey = (try? SymmetricCryptoKey(keyData: keyData)) ?? vKey
        } else {
            itemKey = vKey
        }
        
        guard let privateKeyStr = try? CipherEncryption.decryptString(privateKeyEnc, key: itemKey) else { return nil }
        return privateKeyStr.data(using: .utf8)
    }

    /// Reset the lock timeout timer (call on user activity).
    public func resetLockTimer() {
        lockTimer?.invalidate()
        let timeout = UserDefaults.standard.integer(forKey: "lockTimeout")
        guard timeout > 0 else {
            lockTimer = nil
            return
        }

        lockTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(timeout * 60), repeats: false) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.lock()
                logger.info("Auto-locked after \(timeout) minute timeout")
            }
        }
    }

    // MARK: - Vault Key Access

    /// Get the vault key for decryption (only available when unlocked).
    public func getVaultKey() throws -> SymmetricCryptoKey {
        guard let key = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        return key
    }

    /// Get the API client.
    public func getAPIClient() throws -> APIClient {
        guard let client = apiClient else {
            throw APIError.noAccessToken
        }
        return client
    }

    /// Get the sync engine.
    public func getSyncEngine() throws -> SyncEngine {
        guard let engine = syncEngine else {
            throw SyncError.databaseError("Sync engine not initialized")
        }
        return engine
    }

    // MARK: - Decrypt Helpers

    /// Decrypt an EncString using the item key (if provided) or the vault key.
    public func decrypt(_ encString: EncString?, itemKey: EncString? = nil) -> String? {
        guard let encString = encString, let vaultKey = vaultKey else { return nil }
        
        let key: SymmetricCryptoKey
        if let itemKeyEnc = itemKey,
           let itemKeyData = try? CipherEncryption.decryptData(itemKeyEnc, key: vaultKey),
           let symKey = try? SymmetricCryptoKey(keyData: itemKeyData) {
            key = symKey
        } else {
            key = vaultKey
        }
        
        if let result = try? CipherEncryption.decryptString(encString, key: key) {
            return result
        }
        
        // Fallback: If itemKey failed (e.g. due to bug during passkey creation), try the vaultKey directly
        if itemKey != nil {
            return try? CipherEncryption.decryptString(encString, key: vaultKey)
        }
        
        return nil
    }

    /// Encrypt a string using the vault key.
    public func encrypt(_ string: String) throws -> EncString {
        guard let key = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        return try CipherEncryption.encrypt(string: string, key: key)
    }

    /// Generate a new 512-bit item key and return its encrypted format using the vault key.
    public func generateItemKey() throws -> (SymmetricCryptoKey, EncString) {
        guard let vKey = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        let itemKey = try SymmetricCryptoKey.generate()
        let encryptedItemKey = try CipherEncryption.encrypt(data: itemKey.keyData, key: vKey)
        return (itemKey, encryptedItemKey)
    }

    /// Encrypt a string using a specific item key.
    public func encrypt(_ string: String, using key: SymmetricCryptoKey) throws -> EncString {
        return try CipherEncryption.encrypt(string: string, key: key)
    }

    /// Extract the symmetric key for a cipher (falls back to vaultKey if cipher.key is nil)
    public func getItemKey(for cipher: Cipher) throws -> SymmetricCryptoKey {
        guard let vKey = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey) {
            return try SymmetricCryptoKey(keyData: keyData)
        }
        return vKey
    }

    // MARK: - Account Management

    private func persistAccount(_ account: Account, isActive: Bool) throws {
        guard let container = modelContainer else { return }
        let context = container.mainContext

        // Deactivate all other accounts
        if isActive {
            let allAccounts = FetchDescriptor<PersistedAccount>()
            if let existing = try? context.fetch(allAccounts) {
                for acc in existing { acc.isActive = false }
            }
        }

        // Upsert this account
        let accountId = account.id
        let descriptor = FetchDescriptor<PersistedAccount>(
            predicate: #Predicate { $0.id == accountId }
        )
        if let existing = try? context.fetch(descriptor).first {
            existing.email = account.email
            existing.serverURLString = account.serverURL.absoluteString
            existing.kdfTypeRawValue = account.kdfConfig.type.rawValue
            existing.kdfIterations = Int(account.kdfConfig.iterations)
            existing.isActive = isActive
        } else {
            let persisted = PersistedAccount.from(account: account)
            persisted.isActive = isActive
            context.insert(persisted)
        }

        try context.save()

        if !accounts.contains(where: { $0.id == account.id }) {
            accounts.append(account)
        }
    }

    // MARK: - API Client Setup

    private func setupAPIClient(_ client: APIClient) {
        Task {
            await client.setTokensUpdatedCallback { [weak self] tokens in
                guard let self = self else { return }
                Task { @MainActor in
                    if let account = self.activeAccount {
                        try? self.tokenStorage.saveTokens(tokens, for: account.id)
                    }
                }
            }
            await client.setSessionExpiredCallback { [weak self] in
                Task { @MainActor in
                    self?.handleSessionExpired()
                }
            }
        }
    }

    public func handleSessionExpired() {
        guard let account = activeAccount else { return }
        logger.warning("Session expired - logging out")
        try? tokenStorage.deleteTokens(for: account.id)
        self.lock(requirePassword: true)
        self.authState = .loginRequired
        self.authStatusMessage = "Session expired. Please log in again."
    }

    private func setupSyncObserver(_ engine: SyncEngine) {
        engine.$lastSyncDate
            .dropFirst()
            .debounce(for: .seconds(1), scheduler: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self else { return }
                self.dataUpdateToken += 1
                SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
                try? self.updateSSHIdentities()
            }
            .store(in: &cancellables)
            
        engine.$pendingOperationCount
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self else { return }
                self.dataUpdateToken += 1
            }
            .store(in: &cancellables)
            
        engine.$syncState
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in
                self?.isSyncing = (state == .syncing)
            }
            .store(in: &cancellables)
    }
}
