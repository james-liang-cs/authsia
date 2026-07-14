import Foundation

public struct WorkspaceStatusManagedEnvFile: Equatable, Sendable {
    public let relativePath: String
    public let isMissing: Bool
    public let authsiaReferenceCount: Int

    public init(relativePath: String, isMissing: Bool, authsiaReferenceCount: Int) {
        self.relativePath = relativePath
        self.isMissing = isMissing
        self.authsiaReferenceCount = authsiaReferenceCount
    }
}

public struct WorkspaceStatusAgentRule: Equatable, Sendable {
    public let title: String
    public let isInstalled: Bool

    public init(title: String, isInstalled: Bool) {
        self.title = title
        self.isInstalled = isInstalled
    }
}

public struct WorkspaceStatusEnvBinding: Equatable, Sendable {
    public let name: String

    public init(name: String) {
        self.name = name
    }
}

public struct WorkspaceStatusWorkspaceFolder: Equatable, Sendable {
    public let isMissing: Bool

    public init(isMissing: Bool) {
        self.isMissing = isMissing
    }
}

public struct WorkspaceStatusSummary: Equatable, Sendable, CustomStringConvertible {
    public let managedEnvFilesText: String
    public let envBindingsText: String
    public let agentRulesText: String
    public let healthSummary: String
    public let healthDetail: String

    public var description: String {
        "\(managedEnvFilesText) \(envBindingsText) \(agentRulesText) \(healthSummary) \(healthDetail)"
    }
}

public enum WorkspaceStatusSummaryRenderer {
    public static func render(
        managedEnvFiles: [WorkspaceStatusManagedEnvFile],
        envBindings: [WorkspaceStatusEnvBinding] = [],
        agentRules: [WorkspaceStatusAgentRule],
        missingReferenceCount: Int = 0,
        workspaceFolder: WorkspaceStatusWorkspaceFolder? = nil
    ) -> WorkspaceStatusSummary {
        let missingEnvFileCount = managedEnvFiles.filter(\.isMissing).count
        let missingAgentRuleCount = agentRules.filter { !$0.isInstalled }.count
        let missingWorkspaceFolderCount = workspaceFolder?.isMissing == true ? 1 : 0
        let authsiaReferenceCount = managedEnvFiles.reduce(0) { $0 + $1.authsiaReferenceCount } + envBindings.count
        return WorkspaceStatusSummary(
            managedEnvFilesText: managedEnvFilesText(managedEnvFiles),
            envBindingsText: envBindingsText(envBindings),
            agentRulesText: agentRulesText(agentRules),
            healthSummary: healthSummary(
                missingEnvFileCount: missingEnvFileCount,
                missingAgentRuleCount: missingAgentRuleCount,
                missingReferenceCount: missingReferenceCount,
                missingWorkspaceFolderCount: missingWorkspaceFolderCount
            ),
            healthDetail: healthDetail(
                missingEnvFileCount: missingEnvFileCount,
                missingAgentRuleCount: missingAgentRuleCount,
                missingReferenceCount: missingReferenceCount,
                missingWorkspaceFolderCount: missingWorkspaceFolderCount,
                authsiaReferenceCount: authsiaReferenceCount
            )
        )
    }

    public static func managedEnvFilesText(_ envFiles: [WorkspaceStatusManagedEnvFile]) -> String {
        guard !envFiles.isEmpty else { return "none" }
        return envFiles.map(\.relativePath).joined(separator: ", ")
    }

    public static func envBindingsText(_ envBindings: [WorkspaceStatusEnvBinding]) -> String {
        guard !envBindings.isEmpty else { return "none" }
        return envBindings.map(\.name).joined(separator: ", ")
    }

    public static func agentRulesText(_ agentRules: [WorkspaceStatusAgentRule]) -> String {
        guard !agentRules.isEmpty else { return "none" }
        return agentRules.map { rule in
            "\(rule.title) \(rule.isInstalled ? "installed" : "missing")"
        }
        .joined(separator: ", ")
    }

    public static func healthSummary(
        missingEnvFileCount: Int,
        missingAgentRuleCount: Int,
        missingReferenceCount: Int = 0,
        missingWorkspaceFolderCount: Int = 0
    ) -> String {
        if missingEnvFileCount > 0 ||
            missingAgentRuleCount > 0 ||
            missingReferenceCount > 0 ||
            missingWorkspaceFolderCount > 0 {
            return "Needs attention"
        }
        return "Ready"
    }

    public static func healthDetail(
        missingEnvFileCount: Int,
        missingAgentRuleCount: Int,
        missingReferenceCount: Int = 0,
        missingWorkspaceFolderCount: Int = 0,
        authsiaReferenceCount: Int
    ) -> String {
        var parts: [String] = []
        if missingEnvFileCount > 0 {
            parts.append("\(missingEnvFileCount) missing env file\(missingEnvFileCount == 1 ? "" : "s")")
        }
        if missingAgentRuleCount > 0 {
            parts.append(
                "\(missingAgentRuleCount) missing agent rule\(missingAgentRuleCount == 1 ? "" : "s")"
            )
        }
        if missingReferenceCount > 0 {
            parts.append(
                "\(missingReferenceCount) missing Authsia reference\(missingReferenceCount == 1 ? "" : "s")"
            )
        }
        if missingWorkspaceFolderCount > 0 {
            parts.append("missing Authsia folder")
        }
        parts.append("\(authsiaReferenceCount) authsia:// ref\(authsiaReferenceCount == 1 ? "" : "s")")
        return parts.joined(separator: " - ")
    }
}
