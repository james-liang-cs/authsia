#if os(macOS)
import Foundation
import AuthenticatorBridge

enum TerminalPairingCompletionResult: Equatable {
    case paired(TerminalPairing)
    case retryRemaining
    case invalid
}

@MainActor
final class TerminalPairingCoordinator {
    nonisolated static let codeAlphabet = Array("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
    nonisolated static let codeLength = 4
    nonisolated static let pendingLifetime: TimeInterval = 60

    private struct Pending {
        let approvalRequest: TerminalPairingApprovalRequest
        let anchorShellStartTime: UInt64
        var wrongAttempts: Int
        var locallyApproved: Bool
    }

    private var pending: Pending?
    private let codeProvider: () -> String

    init(codeProvider: @escaping () -> String = TerminalPairingCoordinator.generateCode) {
        self.codeProvider = codeProvider
    }

    func begin(
        workspaceRoot: String,
        controllingTerminal: String,
        anchorShellPID: Int32,
        anchorShellStartTime: UInt64,
        fullCommand: String,
        now: Date = Date()
    ) -> (request: TerminalPairingApprovalRequest, supersededID: UUID?) {
        let supersededID = pending?.approvalRequest.id
        let request = TerminalPairingApprovalRequest(
            id: UUID(),
            workspaceRoot: workspaceRoot,
            controllingTerminal: controllingTerminal,
            anchorShellPID: anchorShellPID,
            fullCommand: fullCommand,
            code: codeProvider(),
            expiresAt: now.addingTimeInterval(Self.pendingLifetime)
        )
        pending = Pending(
            approvalRequest: request,
            anchorShellStartTime: anchorShellStartTime,
            wrongAttempts: 0,
            locallyApproved: false
        )
        return (request, supersededID)
    }

    func markLocallyApproved(id: UUID) -> Bool {
        guard pending?.approvalRequest.id == id else { return false }
        pending?.locallyApproved = true
        return true
    }

    func cancel(id: UUID) {
        guard pending?.approvalRequest.id == id else { return }
        pending = nil
    }

    func complete(
        id: UUID,
        code: String,
        callerIdentity: CallerIdentity?,
        pairingTTL: TimeInterval,
        now: Date = Date(),
        processStartTime: (Int32) -> UInt64? = { TerminalSessionScope.startTimeSeconds(pid: $0) }
    ) -> TerminalPairingCompletionResult {
        guard var pending else { return .invalid }
        guard pending.approvalRequest.id == id else { return .invalid }
        guard
              pending.approvalRequest.expiresAt > now,
              pending.locallyApproved,
              let callerIdentity,
              callerIdentity.controllingTerminal == pending.approvalRequest.controllingTerminal,
              callerIdentity.shellAncestryPrefix?.contains(where: {
                $0.pid == pending.approvalRequest.anchorShellPID
                    && $0.startTimeSeconds == pending.anchorShellStartTime
              }) == true,
              processStartTime(pending.approvalRequest.anchorShellPID) == pending.anchorShellStartTime else {
            self.pending = nil
            return .invalid
        }

        let normalizedCode = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard normalizedCode == pending.approvalRequest.code else {
            pending.wrongAttempts += 1
            if pending.wrongAttempts >= 2 {
                self.pending = nil
                return .invalid
            }
            self.pending = pending
            return .retryRemaining
        }

        self.pending = nil
        return .paired(TerminalPairing(
            id: UUID(),
            controllingTerminal: pending.approvalRequest.controllingTerminal,
            anchorShellPID: pending.approvalRequest.anchorShellPID,
            anchorShellStartTime: pending.anchorShellStartTime,
            workspaceRoot: pending.approvalRequest.workspaceRoot,
            createdAt: now,
            expiresAt: now.addingTimeInterval(pairingTTL)
        ))
    }

    func pendingRequest(id: UUID) -> TerminalPairingApprovalRequest? {
        guard pending?.approvalRequest.id == id else { return nil }
        return pending?.approvalRequest
    }

    nonisolated static func generateCode() -> String {
        var generator = SystemRandomNumberGenerator()
        return String((0..<codeLength).map { _ in codeAlphabet.randomElement(using: &generator)! })
    }
}
#endif
