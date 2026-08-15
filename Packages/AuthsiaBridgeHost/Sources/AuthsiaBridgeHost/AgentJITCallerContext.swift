#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum AgentJITCallerContext {
    public static func fingerprint(
        for request: BridgeRequest,
        caller: CallerIdentity?
    ) -> AgentJITCallerFingerprint? {
        guard let caller else { return nil }
        return AgentJITCallerFingerprint(
            processName: caller.processName,
            bundleIdentifier: caller.bundleIdentifier,
            signingTeamId: caller.signingTeamId,
            signingIdentity: caller.signingIdentity,
            parentProcessName: caller.parentProcess?.processName,
            parentBundleIdentifier: caller.parentProcess?.bundleIdentifier,
            hostProcessName: caller.hostProcess?.processName,
            hostBundleIdentifier: caller.hostProcess?.bundleIdentifier,
            sessionScope: sessionScope(for: request, caller: caller),
            workingDirectory: WorkspaceAuthority.validatedRootPath(
                request.context.workspaceAuthorityPath,
                containing: request.context.workingDirectory
            ) ?? request.context.workingDirectory
        )
    }

    private static func sessionScope(for request: BridgeRequest, caller: CallerIdentity) -> String? {
        guard let requestedScope = request.context.sessionScope,
              let platform = agentSidPlatform(from: requestedScope),
              let parent = caller.parentProcess,
              parent.pid > 1,
              shouldRewriteToAgentProcessPID(parent: parent, host: caller.hostProcess) else {
            return request.context.sessionScope
        }
        return "agent:\(platform):pid:\(parent.pid)"
    }

    /// Parses `agent:<platform>:sid:<n>` where `<n>` is a positive Int32.
    private static func agentSidPlatform(from scope: String) -> String? {
        guard scope.hasPrefix("agent:"),
              let sidRange = scope.range(of: ":sid:", options: .backwards) else {
            return nil
        }
        let platform = String(scope["agent:".endIndex..<sidRange.lowerBound])
        let sessionValue = String(scope[sidRange.upperBound...])
        guard !platform.isEmpty,
              !platform.contains(":"),
              let sessionID = Int32(sessionValue),
              sessionID > 0 else {
            return nil
        }
        return platform
    }

    private static func shouldRewriteToAgentProcessPID(
        parent: ParentProcessInfo,
        host: ParentProcessInfo?
    ) -> Bool {
        if AgenticProcessDetector.isAgenticProcess(
            processName: parent.processName,
            bundleIdentifier: parent.bundleIdentifier
        ) {
            return true
        }
        // IDE extension hosts: only coalesce when the host identity is trusted.
        guard let host else { return false }
        return isCursorExtensionHost(parent) && isCursorHost(host)
    }

    private static func isCursorExtensionHost(_ process: ParentProcessInfo) -> Bool {
        process.processName.caseInsensitiveCompare("Cursor Helper (Plugin)") == .orderedSame
    }

    private static func isCursorHost(_ process: ParentProcessInfo) -> Bool {
        process.processName.caseInsensitiveCompare("Cursor") == .orderedSame
            && isCursorBundleIdentifier(process.bundleIdentifier)
    }

    private static func isCursorBundleIdentifier(_ bundleIdentifier: String?) -> Bool {
        guard let bundleIdentifier else { return false }
        return bundleIdentifier.caseInsensitiveCompare("com.todesktop.230313mzl4w4u92") == .orderedSame
            || bundleIdentifier.caseInsensitiveCompare("com.cursor") == .orderedSame
    }

    public static func hasAgenticCaller(_ callerIdentity: CallerIdentity?) -> Bool {
        AgenticProcessDetector.containsAgenticProcess(ancestry(for: callerIdentity))
    }

    public static func hasAutomationSuspectCaller(_ callerIdentity: CallerIdentity?) -> Bool {
        AgenticProcessDetector.containsAutomationSuspectProcess(ancestry(for: callerIdentity))
    }

    static func terminalPairingWorkspaceRoot(
        request: BridgeRequest,
        fileManager: FileManager = .default
    ) -> String? {
        guard let workingDirectory = request.context.workingDirectory else { return nil }
        return WorkspaceAuthority.validatedRootPath(
            request.context.workspaceAuthorityPath ?? workingDirectory,
            containing: workingDirectory,
            fileManager: fileManager
        )
    }

    public static func hasPairedHumanSession(
        request: BridgeRequest,
        callerIdentity: CallerIdentity?,
        pairings: [TerminalPairing],
        now: Date = Date(),
        processStartTime: (Int32) -> UInt64? = { TerminalSessionScope.startTimeSeconds(pid: $0) }
    ) -> Bool {
        pairedHumanSession(
            request: request,
            callerIdentity: callerIdentity,
            pairings: pairings,
            now: now,
            processStartTime: processStartTime
        ) != nil
    }

    static func pairedHumanSession(
        request: BridgeRequest,
        callerIdentity: CallerIdentity?,
        pairings: [TerminalPairing],
        now: Date = Date(),
        processStartTime: (Int32) -> UInt64? = { TerminalSessionScope.startTimeSeconds(pid: $0) }
    ) -> TerminalPairing? {
        // `agentRuntimeContext` is client-declared, so an agent simply omits it.
        // Host-derived agent evidence is the control that has to hold here, the
        // same way `terminalPairingEligible` and `terminalPairingsOwnedByCaller`
        // apply it: a shell-named agent stays inside the shell ancestry prefix
        // and would otherwise reach the anchor.
        guard request.context.agentRuntimeContext == nil,
              let callerIdentity,
              !hasAgenticCaller(callerIdentity),
              let controllingTerminal = callerIdentity.controllingTerminal,
              let shellAncestryPrefix = callerIdentity.shellAncestryPrefix,
              let workspaceRoot = terminalPairingWorkspaceRoot(request: request) else {
            return nil
        }

        return pairings.first { pairing in
            pairing.expiresAt > now
                && pairing.controllingTerminal == controllingTerminal
                && pairing.workspaceRoot == workspaceRoot
                && processStartTime(pairing.anchorShellPID) == pairing.anchorShellStartTime
                && shellAncestryPrefix.contains {
                    $0.pid == pairing.anchorShellPID
                        && $0.startTimeSeconds == pairing.anchorShellStartTime
                }
        }
    }

    public static func isTrustedHumanTerminal(_ callerIdentity: CallerIdentity?) -> Bool {
        guard let callerIdentity,
              let bundleIdentifier = callerIdentity.bundleIdentifier,
              trustedCLIBundleIdentifiers.contains(bundleIdentifier),
              callerIdentity.signingTeamId?.isEmpty == false,
              callerIdentity.signingIdentity?.isEmpty == false else {
            return false
        }

        if let host = callerIdentity.hostProcess {
            guard isTrustedTerminalHost(host) else {
                return false
            }
            guard let parent = callerIdentity.parentProcess else { return false }
            return trustedShellProcessNames.contains(parent.processName.lowercased())
                || isTrustedITermServer(parent, hostedBy: host)
        }

        guard let parent = callerIdentity.parentProcess else { return false }
        return isTrustedTerminalHost(parent)
    }

    private static func isTrustedTerminalHost(_ process: ParentProcessInfo) -> Bool {
        guard let bundleIdentifier = process.bundleIdentifier,
              trustedTerminalBundleIdentifiers.contains(bundleIdentifier) else {
            return false
        }
        if bundleIdentifier == "com.apple.Terminal" {
            return process.isPlatformBinary == true
        }
        return process.signingTeamId?.isEmpty == false
            && process.signingIdentity?.isEmpty == false
    }

    static func isTrustedITermServer(
        _ process: ParentProcessInfo,
        hostedBy host: ParentProcessInfo
    ) -> Bool {
        process.bundleIdentifier == "iTermServer"
            && process.signingTeamId == trustedITermTeamIdentifier
            && process.signingIdentity?.isEmpty == false
            && host.bundleIdentifier == "com.googlecode.iterm2"
            && host.signingTeamId == trustedITermTeamIdentifier
            && host.signingIdentity?.isEmpty == false
    }

    private static let trustedITermTeamIdentifier = "H7V7XYVQ7D"

    private static let trustedTerminalBundleIdentifiers: Set<String> = [
        "com.apple.Terminal",
        "com.googlecode.iterm2",
        "com.mitchellh.ghostty",
        "dev.warp.Warp",
        "dev.warp.Warp-Stable",
    ]

    private static let trustedCLIBundleIdentifiers: Set<String> = [
        "authsia",
        "com.authsia.cli",
    ]

    static let trustedShellProcessNames: Set<String> = [
        "bash",
        "fish",
        "nu",
        "sh",
        "tcsh",
        "zsh",
    ]

    private static func ancestry(for callerIdentity: CallerIdentity?) -> [AgenticProcessReference] {
        guard let callerIdentity else { return [] }

        var ancestry = [
            AgenticProcessReference(
                processName: callerIdentity.processName,
                bundleIdentifier: callerIdentity.bundleIdentifier
            ),
        ]
        if let parent = callerIdentity.parentProcess {
            ancestry.append(reference(for: parent))
        }
        if let host = callerIdentity.hostProcess {
            ancestry.append(reference(for: host))
        }
        return ancestry
    }

    private static func reference(for process: ParentProcessInfo) -> AgenticProcessReference {
        AgenticProcessReference(
            processName: process.processName,
            bundleIdentifier: process.bundleIdentifier,
            arguments: detectorArguments(for: process)
        )
    }

    /// The detector reads argv as `[executable path, arguments…]`, matching what the CLI
    /// collects, so agent and IDE identity carried only in argv stays visible on this side.
    /// The executable path alone still identifies the process when argv is unreadable.
    private static func detectorArguments(for process: ParentProcessInfo) -> [String] {
        if let arguments = process.arguments, !arguments.isEmpty {
            return arguments
        }
        return process.executablePath.map { [$0] } ?? []
    }
}
#endif
