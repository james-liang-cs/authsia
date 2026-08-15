import Foundation

public struct TerminalPairing: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let controllingTerminal: String
    public let anchorShellPID: Int32
    public let anchorShellStartTime: UInt64
    public let workspaceRoot: String
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        id: UUID,
        controllingTerminal: String,
        anchorShellPID: Int32,
        anchorShellStartTime: UInt64,
        workspaceRoot: String,
        createdAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.controllingTerminal = controllingTerminal
        self.anchorShellPID = anchorShellPID
        self.anchorShellStartTime = anchorShellStartTime
        self.workspaceRoot = workspaceRoot
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    /// Same attestation, later idle deadline. The anchor bindings are unchanged,
    /// so this extends an in-use pairing without re-establishing which terminal
    /// this is.
    public func renewed(expiresAt: Date) -> TerminalPairing {
        TerminalPairing(
            id: id,
            controllingTerminal: controllingTerminal,
            anchorShellPID: anchorShellPID,
            anchorShellStartTime: anchorShellStartTime,
            workspaceRoot: workspaceRoot,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }
}

public struct TerminalPairingApprovalRequest: Equatable, Sendable {
    public let id: UUID
    public let workspaceRoot: String
    /// Whether `workspaceRoot` also resolves for its subfolders. The prompt has
    /// to state the scope the human is approving.
    public let coversSubfolders: Bool
    public let controllingTerminal: String
    public let anchorShellPID: Int32
    public let fullCommand: String
    public let code: String
    public let expiresAt: Date

    public init(
        id: UUID,
        workspaceRoot: String,
        coversSubfolders: Bool,
        controllingTerminal: String,
        anchorShellPID: Int32,
        fullCommand: String,
        code: String,
        expiresAt: Date
    ) {
        self.id = id
        self.workspaceRoot = workspaceRoot
        self.coversSubfolders = coversSubfolders
        self.controllingTerminal = controllingTerminal
        self.anchorShellPID = anchorShellPID
        self.fullCommand = fullCommand
        self.code = code
        self.expiresAt = expiresAt
    }
}

public struct TerminalPairingCompletionRequest: Codable, Equatable, Sendable {
    public let pairingRequestID: UUID
    public let code: String

    public init(pairingRequestID: UUID, code: String) {
        self.pairingRequestID = pairingRequestID
        self.code = code
    }
}

public struct TerminalPairingSessionPayload: Codable, Equatable, Sendable {
    public let pairingID: UUID
    public let expiresAt: Date
    public let ttlSeconds: Int
    public let sessionToken: String

    public init(pairingID: UUID, expiresAt: Date, ttlSeconds: Int, sessionToken: String) {
        self.pairingID = pairingID
        self.expiresAt = expiresAt
        self.ttlSeconds = ttlSeconds
        self.sessionToken = sessionToken
    }
}
