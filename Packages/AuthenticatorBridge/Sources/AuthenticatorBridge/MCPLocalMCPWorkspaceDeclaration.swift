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

        if let match = upstreams.first(where: { ($0["name"] as? String) == finding.serverName }) {
            let existingCommand = match["command"] as? String
            let existingArgs = stringArray(match["args"]) ?? []
            if existingCommand == command, existingArgs == finding.wrapArguments {
                return .alreadyDeclared
            }
            throw DeclarationError.duplicateName(finding.serverName)
        }

        var entry: [String: Any] = [
            "name": finding.serverName,
            "command": command,
            "env": [:] as [String: String],
        ]
        if !finding.wrapArguments.isEmpty {
            entry["args"] = finding.wrapArguments
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
