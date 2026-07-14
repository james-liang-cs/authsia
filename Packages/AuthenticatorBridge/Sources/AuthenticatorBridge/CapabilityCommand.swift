import Foundation

/// Which CLI command is driving an automation-credential-stamped bridge RPC.
/// Lives in the bridge package so both the CLI (which issues RPCs) and the
/// main-app service (which enforces them) can reference the same values.
public enum CapabilityCommand: String, Codable, CaseIterable, Equatable, Hashable, Sendable {
    case exec
    case load
    case read
    case get
    case inject
    case ssh
    case list
}
