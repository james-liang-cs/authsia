#if os(macOS)
import Foundation

public enum MCPDiscoveryProjection {
    /// Reuse only a matching declaration for an effective, already-wrapped launch.
    /// Secrets, catalog observations, and runtime grants belong to their workspace.
    public static func reusableDeclaration(from source: MCPServerDefinition, for finding: MCPClientServerFinding,
                                           targetRoot: URL, homeDirectory: URL) throws -> MCPUpstreamConfig {
        let name = finding.declaredUpstreamName ?? finding.serverName
        guard finding.isAuthsiaProxyLaunch, finding.status != .disabled, finding.status != .skipped,
              finding.precedence != .overridden,
              finding.workspacePathLabel.map({ workspacePath($0, homeDirectory: homeDirectory) }) == targetRoot.path,
              source.identity.workspacePath != targetRoot.path, source.identity.upstreamName.lowercased() == name.lowercased(),
              source.upstream.requiresStdioPolicy, let command = source.upstream.command,
              URL(fileURLWithPath: command).lastPathComponent.lowercased() != "authsia",
              AgentCommandRedactor.redactedArguments(source.upstream.args) == source.upstream.args else {
            throw MCPManagementError.invalidRequest
        }
        let upstream = MCPUpstreamConfig(name: name, command: command, args: source.upstream.args, tools: source.upstream.tools)
        try MCPUpstreamValidator.validate(upstream)
        return upstream
    }

    /// Recover a launch for a confirmed declaration, never for runtime execution.
    public static func recoveredDeclaration(for finding: MCPClientServerFinding,
                                             findings: [MCPClientServerFinding] = []) -> MCPUpstreamConfig? {
        guard finding.isAuthsiaProxyLaunch, finding.precedence != .overridden,
              finding.status != .disabled, finding.status != .skipped,
              finding.unsupportedLaunchKeys.isEmpty else { return nil }
        let name = finding.declaredUpstreamName ?? finding.serverName
        if let value = MCPProxyClientLaunch.recoveryValue(name: name, command: finding.wrapCommand,
                                                         arguments: finding.wrapArguments) {
            return MCPProxyClientLaunch.recoveredLaunch(value, name: name)
        }
        if let source = recoverySource(for: finding, findings: findings),
           let value = MCPProxyClientLaunch.recoveryValue(name: name, command: source.wrapCommand, arguments: source.wrapArguments) {
            return MCPProxyClientLaunch.recoveredLaunch(value, name: name)
        }
        // Legacy Context7 wrappers predate saved launches. Offer the documented
        // preset for review, not a claim that we recovered the original command.
        // https://context7.com/docs/resources/all-clients
        guard name == "context7", finding.wrapCommand == nil else { return nil }
        return MCPUpstreamConfig(name: name, command: "npx", args: ["-y", "@upstash/context7-mcp"])
    }

    /// A legacy wrapper may have lost its launch while another client retained it.
    /// Use only one unambiguous launch in the same workspace, without authority.
    public static func recoverySource(for finding: MCPClientServerFinding,
                                       findings: [MCPClientServerFinding]) -> MCPClientServerFinding? {
        guard finding.isAuthsiaProxyLaunch, finding.wrapCommand == nil,
              finding.precedence == .effective, finding.status != .disabled, finding.status != .skipped,
              finding.unsupportedLaunchKeys.isEmpty, let workspace = finding.workspacePathLabel else { return nil }
        let name = finding.declaredUpstreamName ?? finding.serverName
        let candidates = findings.filter {
            !$0.isAuthsiaProxyLaunch && $0.isWrapEligible && $0.precedence == .effective
                && $0.status != .disabled && $0.status != .skipped && $0.unsupportedLaunchKeys.isEmpty
                && $0.workspacePathLabel == workspace
                && ($0.declaredUpstreamName ?? $0.serverName).lowercased() == name.lowercased()
        }.sorted { $0.id < $1.id }
        let launches = candidates.map {
            MCPProxyClientLaunch.recoveryValue(name: name, command: $0.wrapCommand, arguments: $0.wrapArguments)
        }
        guard let first = launches.first, let value = first,
              launches.allSatisfy({ $0 == value }) else { return nil }
        return candidates.first
    }

    private static func workspacePath(_ label: String, homeDirectory: URL) -> String {
        let path = label == "~" ? homeDirectory.path
            : label.hasPrefix("~/") ? homeDirectory.appendingPathComponent(String(label.dropFirst(2))).path : label
        return URL(fileURLWithPath: path).standardizedFileURL.path
    }

    public static func configurationHint(for finding: MCPClientServerFinding,
                                          findings: [MCPClientServerFinding] = []) -> String? {
        guard finding.precedence != .overridden else { return "A project configuration overrides this entry. Configure the effective entry instead." }
        guard MCPUpstreamValidator.isValidName(finding.declaredUpstreamName ?? finding.serverName) else { return "This server name needs a valid Authsia declaration name. Use manual setup." }
        if recoveredDeclaration(for: finding, findings: findings) != nil { return nil }
        if finding.isAuthsiaProxyLaunch { return "This is already an Authsia proxy launch, but its upstream is not declared in this workspace. Use manual setup to name the original executable." }
        if finding.localHTTPEndpoint != nil { return nil }
        guard finding.isWrapEligible, finding.wrapCommand != nil else { return "This launch cannot be imported safely. Use manual setup and review the original client configuration." }
        guard AgentCommandRedactor.redactedArguments(finding.wrapArguments) == finding.wrapArguments else {
            return "The launch arguments contain sensitive values. Use manual setup with credential references instead."
        }
        return nil
    }

    public static func servers(findings: [MCPClientServerFinding], declared: [MCPServerIdentity],
                               workspaceRoots: [URL], homeDirectory: URL,
                               definitions: [MCPServerDefinition] = [],
                               repairableDeclarations: [MCPServerIdentity] = []) -> [MCPDiscoveredServer] {
        let roots = Set(workspaceRoots.map(\.path))
        return findings.filter { $0.status != .skipped }.compactMap { finding in
            let workspace = finding.workspacePathLabel.map { workspacePath($0, homeDirectory: homeDirectory) }
            let name = finding.declaredUpstreamName ?? finding.serverName
            if let workspace, declared.contains(where: { $0.workspacePath == workspace && $0.upstreamName.lowercased() == name.lowercased() }) { return nil }
            let knownWorkspace = workspace.flatMap { roots.contains($0) ? $0 : nil }
            let disabled = finding.status == .disabled
            let canRepair = !disabled && finding.precedence != .overridden && knownWorkspace != nil
                && repairableDeclarations.contains { $0.workspacePath == workspace && $0.upstreamName.lowercased() == name.lowercased() }
            let reusableIDs = knownWorkspace.map { path in
                definitions.filter {
                    (try? reusableDeclaration(from: $0, for: finding, targetRoot: URL(fileURLWithPath: path), homeDirectory: homeDirectory)) != nil
                }.map(\.serverID).sorted()
            } ?? []
            let recovered = recoveredDeclaration(for: finding, findings: findings)
            let recoveryHint = recoverySource(for: finding, findings: findings).map {
                "Authsia can prepare setup from the matching \($0.source.displayName) launch in this workspace. No executable entry is needed. Credentials and tool permissions are not copied."
            }
            let reason = disabled
                ? "This client entry is disabled. Enable it in the client, then discover again. Disabled entries are not counted as active coverage."
                : configurationHint(for: finding, findings: findings)
            let http = finding.commandLabel == "HTTP"
            let enrollment = MCPClientActionSupport.httpEnrollment(for: finding, findings: findings)
            let environmentHint = finding.childEnvironmentCount > 0
                ? " \(finding.childEnvironmentCount) client environment value(s) will not be copied. Associate credential references before protecting the client."
                : " Client credentials and environment values are never imported."
            return MCPDiscoveredServer(id: MCPWorkspaceStore.digest(Data(finding.id.utf8)), findingID: finding.id,
                displayName: finding.serverName, workspaceID: knownWorkspace.map { MCPWorkspaceStore.digest(Data($0.utf8)) },
                workspacePath: knownWorkspace, client: finding.source, scope: finding.configScope, precedence: finding.precedence,
                commandLabel: finding.commandLabel, transportLabel: http ? "HTTP · local" : "STDIO",
                configPathLabel: finding.configPathLabel, canConfigure: canRepair || (knownWorkspace != nil && reason == nil && !disabled),
                configurationHint: canRepair
                    ? "This server is already declared. Redundant MCP declarations prevent Authsia from loading this workspace. Configure prepares a repair that preserves the existing server settings."
                    : !reusableIDs.isEmpty
                    ? "Your client already routes this server through Authsia. Choose an existing setup to add its launch and tool policy to this workspace. Credential bindings are not copied."
                    : reason ?? recoveryHint ?? (recovered != nil
                        ? (finding.wrapCommand != nil
                            ? "Authsia recovered the saved launch. Review it to restore setup in this workspace. Credentials and tool permissions are not copied."
                            : "Authsia can configure the official Context7 preset. The original launch was not retained; review this preset before applying. Credentials and tool permissions are not copied.")
                        : (knownWorkspace == nil ? "Select a managed workspace, then discover again." : "Configure creates an Authsia workspace declaration. It does not start a server or change the client launch." + environmentHint)),
                isDisabled: disabled,
                canEnrollHTTP: enrollment.canEnroll,
                unsupportedActionReason: enrollment.reason, reusableSourceServerIDs: canRepair ? [] : reusableIDs)
        }
    }
}
#endif
