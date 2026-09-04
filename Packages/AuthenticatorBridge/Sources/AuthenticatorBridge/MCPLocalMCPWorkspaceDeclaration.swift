import Foundation

public enum MCPLocalMCPWorkspaceDeclaration {
    public static let relativeConfigPath = ".authsia/workspace.json"
    private static let maximumConfigBytes: UInt64 = 1_048_576

    public enum Outcome: Equatable, Sendable {
        case declared
        case alreadyDeclared
    }

    public enum DeclarationError: Error, Equatable, LocalizedError {
        case notWrapEligible
        case missingWorkspace
        case missingConfig
        case configTooLarge
        case malformedConfig
        case duplicateName(String)
        case writeFailed

        public var errorDescription: String? {
            switch self {
            case .notWrapEligible:
                return "This local MCP server cannot be declared as stdio policy."
            case .missingWorkspace:
                return "Initialize a managed Authsia workspace first."
            case .missingConfig:
                return "Workspace config .authsia/workspace.json was not found."
            case .configTooLarge:
                return "Workspace config is larger than 1 MiB."
            case .malformedConfig:
                return "Workspace config is not valid JSON."
            case .duplicateName(let name):
                return "mcpUpstreams already has a different entry named \(name)."
            case .writeFailed:
                return "Could not write workspace config."
            }
        }
    }

    public struct CandidateWorkspace: Equatable, Identifiable, Sendable {
        public let root: URL
        public let displayName: String
        public let isPreferred: Bool

        public var id: String { root.path }

        public var configPathLabel: String {
            root.appendingPathComponent(MCPLocalMCPWorkspaceDeclaration.relativeConfigPath).path
        }

        public init(root: URL, displayName: String, isPreferred: Bool) {
            self.root = root
            self.displayName = displayName
            self.isPreferred = isPreferred
        }
    }

    public struct WorkspaceDeclaration: Equatable, Sendable {
        public let workspaceRoot: URL
        public let outcome: Result<Outcome, DeclarationError>

        public init(workspaceRoot: URL, outcome: Result<Outcome, DeclarationError>) {
            self.workspaceRoot = workspaceRoot
            self.outcome = outcome
        }
    }

    public static func candidateWorkspaceRoot(
        knownRoots: [String],
        grantWorkingDirectories: [String],
        fileManager: FileManager = .default
    ) -> URL? {
        candidateWorkspaces(
            knownRoots: knownRoots,
            grantWorkingDirectories: grantWorkingDirectories,
            fileManager: fileManager
        ).first?.root
    }

    public static func candidateWorkspaces(
        knownRoots: [String],
        grantWorkingDirectories: [String],
        fileManager: FileManager = .default
    ) -> [CandidateWorkspace] {
        var preferred: [CandidateWorkspace] = []
        var others: [CandidateWorkspace] = []
        var seen = Set<String>()

        func append(path: String, isPreferred: Bool) {
            guard let root = workspaceRoot(startingAt: path, fileManager: fileManager),
                  seen.insert(root.path).inserted else {
                return
            }
            let candidate = CandidateWorkspace(
                root: root,
                displayName: displayName(at: root, fileManager: fileManager),
                isPreferred: isPreferred
            )
            if isPreferred {
                preferred.append(candidate)
            } else {
                others.append(candidate)
            }
        }

        for path in grantWorkingDirectories {
            append(path: path, isPreferred: true)
        }
        for path in knownRoots {
            append(path: path, isPreferred: false)
        }
        return preferred + others
    }

    public static func preselectedRootPaths(in candidates: [CandidateWorkspace]) -> Set<String> {
        let preferred = candidates.filter(\.isPreferred).map(\.root.path)
        if !preferred.isEmpty {
            return Set(preferred)
        }
        if let first = candidates.first {
            return [first.root.path]
        }
        return []
    }

    public static func declare(
        finding: MCPClientServerFinding,
        workspaceRoots: [URL],
        fileManager: FileManager = .default
    ) -> [WorkspaceDeclaration] {
        var seen = Set<String>()
        var results: [WorkspaceDeclaration] = []
        for root in workspaceRoots {
            let standardized = root.standardizedFileURL
            guard seen.insert(standardized.path).inserted else { continue }
            do {
                let outcome = try declare(
                    finding: finding,
                    workspaceRoot: standardized,
                    fileManager: fileManager
                )
                results.append(WorkspaceDeclaration(workspaceRoot: standardized, outcome: .success(outcome)))
            } catch let error as DeclarationError {
                results.append(WorkspaceDeclaration(workspaceRoot: standardized, outcome: .failure(error)))
            } catch {
                results.append(WorkspaceDeclaration(workspaceRoot: standardized, outcome: .failure(.writeFailed)))
            }
        }
        return results
    }

    /// Declare an explicit child for a proxy launch that no longer records
    /// the argv it replaced. Wrap-eligible findings still go through
    /// `declare(finding:)`.
    public static func declare(
        name: String,
        command: String,
        arguments: [String],
        workspaceRoot: URL,
        fileManager: FileManager = .default
    ) throws -> Outcome {
        guard let policyCommand = MCPUpstreamCommandRules.policyCommand(fromScanned: command) else {
            throw DeclarationError.notWrapEligible
        }
        return try writeDeclaration(
            name: name,
            command: policyCommand,
            arguments: arguments,
            workspaceRoot: workspaceRoot,
            fileManager: fileManager
        )
    }

    public static func declare(
        finding: MCPClientServerFinding,
        workspaceRoot: URL,
        fileManager: FileManager = .default
    ) throws -> Outcome {
        guard finding.isWrapEligible,
              finding.status != .admittedWrapped,
              let command = finding.wrapCommand else {
            throw DeclarationError.notWrapEligible
        }
        return try declare(
            name: finding.serverName,
            command: command,
            arguments: finding.wrapArguments,
            workspaceRoot: workspaceRoot,
            fileManager: fileManager
        )
    }

    private static func writeDeclaration(
        name: String,
        command: String,
        arguments: [String],
        workspaceRoot: URL,
        fileManager: FileManager
    ) throws -> Outcome {
        let configURL = workspaceRoot.appendingPathComponent(relativeConfigPath)
        guard fileManager.fileExists(atPath: configURL.path) else {
            throw DeclarationError.missingConfig
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: configURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= maximumConfigBytes else {
            throw DeclarationError.configTooLarge
        }
        guard let data = try? Data(contentsOf: configURL),
              let raw = try? JSONSerialization.jsonObject(with: data),
              var root = raw as? [String: Any] else {
            throw DeclarationError.malformedConfig
        }

        var upstreams: [[String: Any]]
        if let existing = root["mcpUpstreams"] {
            guard let parsed = existing as? [[String: Any]] else {
                throw DeclarationError.malformedConfig
            }
            upstreams = parsed
        } else {
            upstreams = []
        }

        if let match = upstreams.first(where: { ($0["name"] as? String) == name }) {
            let existingCommand = match["command"] as? String
            let existingArgs = stringArray(match["args"]) ?? []
            if existingCommand == command, existingArgs == arguments {
                return .alreadyDeclared
            }
            throw DeclarationError.duplicateName(name)
        }

        var entry: [String: Any] = [
            "name": name,
            "command": command,
            "env": [:] as [String: String],
        ]
        if !arguments.isEmpty {
            entry["args"] = arguments
        }
        upstreams.append(entry)
        root["mcpUpstreams"] = upstreams

        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        do {
            try encoded.write(to: configURL, options: .atomic)
        } catch {
            throw DeclarationError.writeFailed
        }
        return .declared
    }

    #if os(macOS)
    /// The child launch a workspace declares for `name`. A protected client
    /// entry no longer records the launch it replaced, so this declaration is
    /// what a restore reads.
    public struct DeclaredLaunch: Equatable, Sendable {
        public let workspaceRoot: URL
        public let command: String
        public let arguments: [String]
        /// Environment values policy sets for the child. A restored client
        /// launch carries none of them: they may be `authsia://` references,
        /// which only the proxy resolves.
        public let environmentCount: Int

        public init(
            workspaceRoot: URL,
            command: String,
            arguments: [String],
            environmentCount: Int
        ) {
            self.workspaceRoot = workspaceRoot
            self.command = command
            self.arguments = arguments
            self.environmentCount = environmentCount
        }
    }

    /// The stdio launch named `name` in one exact workspace. An http or url
    /// upstream never replaced a local launch, so it is not a restore source.
    public static func declaredLaunch(
        named name: String,
        workspaceRoot: URL,
        fileManager: FileManager = .default
    ) -> DeclaredLaunch? {
        let standardized = workspaceRoot.standardizedFileURL
        let configURL = standardized.appendingPathComponent(relativeConfigPath)
        guard fileManager.fileExists(atPath: configURL.path),
              let attributes = try? fileManager.attributesOfItem(atPath: configURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= maximumConfigBytes,
              let data = try? Data(contentsOf: configURL),
              let object = try? JSONSerialization.jsonObject(with: data),
              let config = object as? [String: Any],
              let upstreams = config["mcpUpstreams"] as? [[String: Any]],
              let entry = upstreams.first(where: { ($0["name"] as? String) == name }),
              (entry["transport"] as? String ?? "stdio") == "stdio",
              entry["url"] == nil,
              let command = entry["command"] as? String else {
            return nil
        }
        let arguments: [String]
        if let value = entry["args"] {
            guard let parsed = stringArray(value) else { return nil }
            arguments = parsed
        } else {
            arguments = []
        }
        let environmentCount: Int
        if let value = entry["env"] {
            guard let environment = value as? [String: String] else { return nil }
            environmentCount = environment.count
        } else {
            environmentCount = 0
        }
        guard isRestorableLaunch(command: command, arguments: arguments) else {
            return nil
        }
        return DeclaredLaunch(
            workspaceRoot: standardized,
            command: command,
            arguments: arguments,
            environmentCount: environmentCount
        )
    }

    private static func isRestorableLaunch(command: String, arguments: [String]) -> Bool {
        guard MCPUpstreamCommandRules.policyCommand(fromScanned: command) == command,
              arguments.count <= 64,
              !MCPUpstreamCommandRules.containsShellCommandString([command] + arguments) else {
            return false
        }
        return arguments.allSatisfy { argument in
            argument.utf8.count <= 32 * 1_024
                && argument.unicodeScalars.allSatisfy {
                    !CharacterSet.controlCharacters.contains($0)
                }
                && !argument.lowercased().contains("authsia://")
        }
    }
    #endif

    private static func workspaceRoot(
        startingAt path: String,
        fileManager: FileManager
    ) -> URL? {
        var directory = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
        for _ in 0..<64 {
            let candidate = directory.appendingPathComponent(relativeConfigPath)
            if fileManager.fileExists(atPath: candidate.path) {
                return directory
            }
            let parent = directory.deletingLastPathComponent()
            guard parent.path != directory.path else { return nil }
            directory = parent
        }
        return nil
    }

    private static func displayName(at root: URL, fileManager: FileManager) -> String {
        let fallback = root.lastPathComponent
        let configURL = root.appendingPathComponent(relativeConfigPath)
        guard let attributes = try? fileManager.attributesOfItem(atPath: configURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= maximumConfigBytes,
              let data = try? Data(contentsOf: configURL, options: .mappedIfSafe),
              let identity = try? JSONDecoder().decode(ConfigIdentity.self, from: data),
              let name = identity.workspace?.name?.trimmingCharacters(in: .whitespacesAndNewlines),
              !name.isEmpty,
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return fallback
        }
        return String(name.prefix(128))
    }

    private static func stringArray(_ value: Any?) -> [String]? {
        if let strings = value as? [String] {
            return strings
        }
        guard let values = value as? [Any] else { return nil }
        let strings = values.compactMap { $0 as? String }
        return strings.count == values.count ? strings : nil
    }

    private struct ConfigIdentity: Decodable {
        struct Workspace: Decodable {
            let name: String?
        }

        let workspace: Workspace?
    }
}
