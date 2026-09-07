#if os(macOS)
import Foundation

public enum MCPDiscoveryProjection {
    public static func configurationHint(for finding: MCPClientServerFinding) -> String? {
        guard finding.precedence != .overridden else { return "A project configuration overrides this entry. Configure the effective entry instead." }
        guard MCPUpstreamValidator.isValidName(finding.serverName) else { return "This server name needs a valid Authsia declaration name. Use manual setup." }
        if finding.isAuthsiaProxyLaunch { return "This is already an Authsia proxy launch, but its upstream is not declared in this workspace. Use manual setup to name the original executable." }
        if finding.localHTTPEndpoint != nil { return nil }
        guard finding.isWrapEligible, finding.wrapCommand != nil else { return "This launch cannot be imported safely. Use manual setup and review the original client configuration." }
        guard AgentCommandRedactor.redactedArguments(finding.wrapArguments) == finding.wrapArguments else {
            return "The launch arguments contain sensitive values. Use manual setup with credential references instead."
        }
        return nil
    }

    public static func servers(findings: [MCPClientServerFinding], declared: [MCPServerIdentity],
                               workspaceRoots: [URL], homeDirectory: URL) -> [MCPDiscoveredServer] {
        let roots = Set(workspaceRoots.map(\.path))
        return findings.filter { $0.status != .skipped }.compactMap { finding in
            let workspace = finding.workspacePathLabel.map { label in
                let path = label == "~" ? homeDirectory.path
                    : label.hasPrefix("~/") ? homeDirectory.appendingPathComponent(String(label.dropFirst(2))).path : label
                return URL(fileURLWithPath: path).standardizedFileURL.path
            }
            let name = finding.declaredUpstreamName ?? finding.serverName
            if let workspace, declared.contains(MCPServerIdentity(workspacePath: workspace, upstreamName: name)) { return nil }
            let knownWorkspace = workspace.flatMap { roots.contains($0) ? $0 : nil }
            let disabled = finding.status == .disabled
            let reason = disabled
                ? "This client entry is disabled. Enable it in the client, then discover again. Disabled entries are not counted as active coverage."
                : configurationHint(for: finding)
            let http = finding.commandLabel == "HTTP"
            let enrollReason = http ? MCPClientActionSupport.httpEnrollmentReason(finding.source) : nil
            let environmentHint = finding.childEnvironmentCount > 0
                ? " \(finding.childEnvironmentCount) client environment value(s) will not be copied. Associate credential references before protecting the client."
                : " Client credentials and environment values are never imported."
            return MCPDiscoveredServer(id: MCPWorkspaceStore.digest(Data(finding.id.utf8)), findingID: finding.id,
                displayName: finding.serverName, workspaceID: knownWorkspace.map { MCPWorkspaceStore.digest(Data($0.utf8)) },
                workspacePath: knownWorkspace, client: finding.source, scope: finding.configScope, precedence: finding.precedence,
                commandLabel: finding.commandLabel, transportLabel: http ? "HTTP · local" : "STDIO",
                configPathLabel: finding.configPathLabel, canConfigure: knownWorkspace != nil && reason == nil && !disabled,
                configurationHint: reason ?? (knownWorkspace == nil ? "Select a managed workspace, then discover again." : "Configure creates an Authsia workspace declaration. It does not start a server or change the client launch." + environmentHint),
                isDisabled: disabled,
                canEnrollHTTP: http && MCPClientActionSupport.supportsHTTPEnrollment(finding.source),
                unsupportedActionReason: enrollReason)
        }
    }
}
#endif
