import Foundation

public enum AgentFileActivityInferrer {
    private static let correlationWindow: TimeInterval = 30
    private static let readExecutables: Set<String> = [
        "bat", "cat", "head", "less", "more", "tail", "type",
    ]
    private static let listExecutables: Set<String> = [
        "find", "ls", "tree",
    ]
    private static let createExecutables: Set<String> = [
        "mkdir", "touch",
    ]
    private static let modifyExecutables: Set<String> = [
        "cp", "install", "mv", "sed", "tee",
    ]
    private static let deleteExecutables: Set<String> = [
        "rm", "rmdir",
    ]

    /// Derives low-confidence file activity from command argv for grant-scoped display.
    /// Does not persist; callers merge into the Access Center snapshot.
    public static func events(
        from commands: [AgentCommandEvent],
        existingFileEvents: [AgentFileActivityEvent] = []
    ) -> [AgentFileActivityEvent] {
        let existingKeys = Set(existingFileEvents.compactMap(correlationKey(for:)))
        var emittedKeys = existingKeys
        var inferred: [AgentFileActivityEvent] = []

        for command in commands {
            guard let executable = executableName(from: command),
                  let action = action(for: executable) else {
                continue
            }
            let paths = pathCandidates(from: command)
            guard !paths.isEmpty else { continue }

            for path in paths {
                let event = AgentFileActivityEvent(
                    id: deterministicID(for: keyComponents(
                        grantID: command.agentJITGrantID,
                        path: path,
                        action: action,
                        recordedAt: command.recordedAt
                    )),
                    recordedAt: command.recordedAt,
                    agentPlatform: command.agentPlatform,
                    sessionID: command.sessionID,
                    turnID: command.turnID,
                    agentID: command.agentID,
                    agentType: command.agentType,
                    toolUseID: command.toolUseID,
                    agentJITGrantID: command.agentJITGrantID,
                    captureSource: .command,
                    workingDirectory: command.workingDirectory,
                    terminalSessionScope: command.terminalSessionScope,
                    workspaceRoot: command.workingDirectory,
                    path: path,
                    kind: pathLooksLikeDirectory(path, action: action) ? .directory : .file,
                    action: action,
                    status: status(from: command.exitStatus),
                    confidence: .inferred,
                    detail: "Inferred from command \(executable)"
                )
                guard let key = correlationKey(for: event), !emittedKeys.contains(key) else {
                    continue
                }
                if existingFileEvents.contains(where: { overlaps($0, with: event) }) {
                    continue
                }
                emittedKeys.insert(key)
                inferred.append(event)
            }
        }

        return inferred.sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id.uuidString < rhs.id.uuidString
            }
            return lhs.recordedAt < rhs.recordedAt
        }
    }

    public static func merging(
        commands: [AgentCommandEvent],
        fileEvents: [AgentFileActivityEvent]
    ) -> [AgentFileActivityEvent] {
        let inferred = events(from: commands, existingFileEvents: fileEvents)
        return (fileEvents + inferred).sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id.uuidString < rhs.id.uuidString
            }
            return lhs.recordedAt < rhs.recordedAt
        }
    }

    private static func action(for executable: String) -> AgentFileActivityAction? {
        if readExecutables.contains(executable) { return .read }
        if listExecutables.contains(executable) { return .list }
        if createExecutables.contains(executable) { return .create }
        if modifyExecutables.contains(executable) { return .modify }
        if deleteExecutables.contains(executable) { return .delete }
        return nil
    }

    private static func executableName(from event: AgentCommandEvent) -> String? {
        if let executable = event.executable?.trimmingCharacters(in: .whitespacesAndNewlines),
           !executable.isEmpty {
            return URL(fileURLWithPath: executable).lastPathComponent.lowercased()
        }
        let tokens = tokens(from: event)
        guard let first = tokens.first else { return nil }
        return URL(fileURLWithPath: first).lastPathComponent.lowercased()
    }

    private static func pathCandidates(from event: AgentCommandEvent) -> [String] {
        let base = event.workingDirectory
        var commandTokens = tokens(from: event)
        if let executable = executableName(from: event),
           let first = commandTokens.first,
           URL(fileURLWithPath: first).lastPathComponent.lowercased() == executable {
            commandTokens = Array(commandTokens.dropFirst())
        }
        var paths: [String] = []
        var seen = Set<String>()
        for token in commandTokens {
            guard isPathOperand(token) else { continue }
            let resolved = resolve(path: token, relativeTo: base)
            guard seen.insert(resolved).inserted else { continue }
            paths.append(resolved)
        }
        return paths
    }

    private static func tokens(from event: AgentCommandEvent) -> [String] {
        if !event.arguments.isEmpty {
            return event.arguments.map(normalizeToken).filter { !$0.isEmpty }
        }
        guard let command = event.command else { return [] }
        return command
            .split { $0 == " " || $0 == "\t" || $0 == "\n" }
            .map { normalizeToken(String($0)) }
            .filter { !$0.isEmpty }
    }

    private static func isPathOperand(_ token: String) -> Bool {
        if token.hasPrefix("-") { return false }
        if token == "." || token == ".." { return false }
        return true
    }

    private static func resolve(path: String, relativeTo base: String?) -> String {
        if path.hasPrefix("/") {
            return URL(fileURLWithPath: path).standardizedFileURL.path
        }
        if path.hasPrefix("~/") {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            return URL(fileURLWithPath: home)
                .appendingPathComponent(String(path.dropFirst(2)))
                .standardizedFileURL.path
        }
        guard let base, !base.isEmpty else {
            return URL(fileURLWithPath: path).standardizedFileURL.path
        }
        return URL(fileURLWithPath: path, relativeTo: URL(fileURLWithPath: base, isDirectory: true))
            .standardizedFileURL.path
    }

    private static func pathLooksLikeDirectory(_ path: String, action: AgentFileActivityAction) -> Bool {
        action == .list || path.hasSuffix("/")
    }

    private static func status(from exitStatus: Int32?) -> AgentFileActivityStatus {
        guard let exitStatus else { return .inferred }
        return exitStatus == 0 ? .succeeded : .failed
    }

    private static func correlationKey(for event: AgentFileActivityEvent) -> String? {
        keyComponents(
            grantID: event.agentJITGrantID,
            path: event.path,
            action: event.action,
            recordedAt: event.recordedAt
        )
    }

    private static func keyComponents(
        grantID: UUID?,
        path: String,
        action: AgentFileActivityAction,
        recordedAt: Date
    ) -> String {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        let grant = grantID?.uuidString ?? ""
        let bucket = Int(recordedAt.timeIntervalSince1970 / correlationWindow)
        return [grant, standardized, action.rawValue, String(bucket)].joined(separator: "|")
    }

    private static func deterministicID(for key: String) -> UUID {
        var hash = [UInt8](repeating: 0, count: 16)
        let bytes = Array(key.utf8)
        for (index, byte) in bytes.enumerated() {
            hash[index % 16] ^= byte
            hash[(index * 3) % 16] = hash[(index * 3) % 16] &+ byte &+ UInt8(index % 251)
        }
        hash[6] = (hash[6] & 0x0F) | 0x40
        hash[8] = (hash[8] & 0x3F) | 0x80
        return UUID(uuid: (
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11],
            hash[12], hash[13], hash[14], hash[15]
        ))
    }

    private static func overlaps(
        _ existing: AgentFileActivityEvent,
        with inferred: AgentFileActivityEvent
    ) -> Bool {
        let existingPath = URL(fileURLWithPath: existing.path).standardizedFileURL.path
        let inferredPath = URL(fileURLWithPath: inferred.path).standardizedFileURL.path
        guard existingPath == inferredPath else { return false }
        if let lhs = existing.agentJITGrantID, let rhs = inferred.agentJITGrantID, lhs != rhs {
            return false
        }
        return abs(existing.recordedAt.timeIntervalSince(inferred.recordedAt)) <= correlationWindow
    }

    private static func normalizeToken(_ value: String) -> String {
        value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\"'")))
    }
}
