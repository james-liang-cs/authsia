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
            sessionScope: request.context.sessionScope,
            workingDirectory: request.context.workingDirectory
        )
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
