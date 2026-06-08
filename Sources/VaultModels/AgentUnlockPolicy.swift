// MARK: - VaultModels/AgentUnlockPolicy.swift
// Re-authentication policy for the SSH / secret agents.
//
// Controls how long a Touch-ID-authorized secret or SSH key may be reused by
// the agent before the user must authenticate again. This is the gate that
// limits how long a malicious same-user process could ride a single unlock.

import Foundation

/// How the agent re-authorizes access to secrets / SSH keys after the first
/// successful Touch ID prompt.
public enum AgentReauthMode: String, Codable, Sendable, CaseIterable {
    /// Prompt for Touch ID on every single request — nothing is cached.
    case everyTime
    /// Cache for a fixed window after the first unlock; the window does NOT
    /// extend on use, so access always expires `minutes` after authorization.
    case fixed
    /// Cache for a sliding window that resets on every use (legacy behavior).
    case sliding
}

/// The effective agent unlock policy (mode + window length).
public struct AgentUnlockPolicy: Sendable, Equatable {
    public var mode: AgentReauthMode
    /// Window length in minutes (ignored for `.everyTime`).
    public var minutes: Int

    public init(mode: AgentReauthMode, minutes: Int) {
        self.mode = mode
        self.minutes = minutes
    }

    /// The window length as a time interval.
    public var window: TimeInterval { TimeInterval(max(1, minutes) * 60) }

    /// The historical default (15-minute sliding window).
    public static let `default` = AgentUnlockPolicy(mode: .sliding, minutes: 15)
}

/// Reads the agent unlock policy from `UserDefaults`.
///
/// Stored as two keys so the existing `sshAgentUnlockTimeout` (minutes) keeps
/// working as the window length, with a new `agentReauthMode` selecting the
/// behavior. Absent/invalid values fall back to the historical default.
public enum AgentUnlockPolicyStore {
    public static let modeKey = "agentReauthMode"
    public static let timeoutKey = "sshAgentUnlockTimeout"

    public static func current(_ defaults: UserDefaults = .standard) -> AgentUnlockPolicy {
        let mode = defaults.string(forKey: modeKey).flatMap(AgentReauthMode.init(rawValue:)) ?? AgentUnlockPolicy.default.mode
        let minutes = defaults.integer(forKey: timeoutKey)
        return AgentUnlockPolicy(
            mode: mode,
            minutes: minutes > 0 ? minutes : AgentUnlockPolicy.default.minutes
        )
    }
}
