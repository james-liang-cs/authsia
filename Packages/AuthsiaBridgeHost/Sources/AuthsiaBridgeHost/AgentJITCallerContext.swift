#if os(macOS)
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
            workingDirectory: request.context.workingDirectory
        )
    }

    private static func sessionScope(for request: BridgeRequest, caller: CallerIdentity) -> String? {
        let cursorSessionPrefix = "agent:cursor:sid:"
        guard let requestedScope = request.context.sessionScope,
              requestedScope.hasPrefix(cursorSessionPrefix),
              let sessionID = Int32(requestedScope.dropFirst(cursorSessionPrefix.count)),
              sessionID > 0,
              let parent = caller.parentProcess,
              parent.pid > 1,
              let host = caller.hostProcess,
              isCursorExtensionHost(parent),
              isCursorHost(host) else {
            return request.context.sessionScope
        }
        return "agent:cursor:pid:\(parent.pid)"
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

    private static func ancestry(for callerIdentity: CallerIdentity?) -> [AgenticProcessReference] {
        guard let callerIdentity else { return [] }

        var ancestry = [
            AgenticProcessReference(
                processName: callerIdentity.processName,
                bundleIdentifier: callerIdentity.bundleIdentifier
            ),
        ]
        if let parent = callerIdentity.parentProcess {
            ancestry.append(
                AgenticProcessReference(
                    processName: parent.processName,
                    bundleIdentifier: parent.bundleIdentifier
                )
            )
        }
        if let host = callerIdentity.hostProcess {
            ancestry.append(
                AgenticProcessReference(
                    processName: host.processName,
                    bundleIdentifier: host.bundleIdentifier
                )
            )
        }
        return ancestry
    }
}
#endif
