import Foundation

enum MCPChildFailureReporter {
    static let environmentKey = "AUTHSIA_MCP_FAILURE_FILE"

    static func report(_ error: Error, environment: [String: String] = ProcessInfo.processInfo.environment) {
        guard let path = environment[environmentKey], !path.isEmpty else { return }
        let url = URL(fileURLWithPath: path)
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        do {
            try handle.truncate(atOffset: 0)
            try handle.write(contentsOf: Data(code(for: error).rawValue.utf8))
            try handle.synchronize()
        } catch {
            return
        }
    }

    static func code(for error: Error) -> MCPToolErrorCode {
        if let bridgeError = error as? BridgeClientError {
            return code(for: bridgeError)
        }
        if let resolutionErrors = error as? SecretResolutionErrors {
            let codes = resolutionErrors.errors.map { code(for: $0.error) }
            for preferred in [
                MCPToolErrorCode.cliAccessDisabled,
                .approvalDenied,
                .bridgeUnavailable,
            ] where codes.contains(preferred) {
                return preferred
            }
        }
        return .executionFailed
    }

    static func code(for error: BridgeClientError) -> MCPToolErrorCode {
        switch error {
        case .connectionFailed, .timeout, .invalidResponse, .appUnavailable,
             .incompatibleSecurityProtocol:
            return .bridgeUnavailable
        case .bridgeError(let code, let message, _):
            if code == "policyDenied",
               message.trimmingCharacters(in: .whitespacesAndNewlines)
                .localizedCaseInsensitiveCompare("CLI access is disabled") == .orderedSame {
                return .cliAccessDisabled
            }
            if code == "notAuthorized" || code == "policyDenied" {
                return .approvalDenied
            }
            return .executionFailed
        }
    }
}
