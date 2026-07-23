import ArgumentParser
import Darwin
import Foundation
import AuthenticatorBridge

struct Agent: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "agent",
        abstract: "Configure AI agents to use Authsia safely",
        subcommands: [Init.self, RecordCommand.self]
    )

    struct Init: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "init",
            abstract: "Create local AI-agent rule files for Authsia",
            discussion: """
                Creates local project rule files that teach AI agents to use Authsia safely.
                This command writes rules only; it does not create automation credentials,
                JIT grants, or new secret access.

                Examples:
                  authsia agent init
                  authsia agent init --agent claude-code
                  authsia agent init --agent codex --dry-run
                  authsia agent init --all
                """
        )

        @Option(name: .long, help: "Agent to configure: claude-code, cursor, codex, windsurf, copilot")
        var agent: AgentTool?

        @Flag(name: .long, help: "Configure all supported agents")
        var all = false

        @Flag(name: .long, help: "Print planned changes without writing files")
        var dryRun = false

        func run() throws {
            let agents = try Self.resolveAgents(agent: agent, all: all)
            let result = try AgentRuleInstaller.install(
                projectRoot: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true),
                agents: agents,
                dryRun: dryRun
            )
            print(AgentRuleInstaller.renderResult(result))
        }

        static func resolveAgents(
            agent: AgentTool?,
            all: Bool,
            readLine: () -> String? = { Swift.readLine() }
        ) throws -> [AgentTool] {
            if all, agent != nil {
                throw ValidationError(
                    "Use either --agent or --all, not both. Example: authsia agent init --agent codex"
                )
            }
            if all {
                return AgentTool.allCases
            }
            if let agent {
                return [agent]
            }
            return try promptForAgent(readLine: readLine)
        }

        private static func promptForAgent(readLine: () -> String?) throws -> [AgentTool] {
            print("Which agent do you use?")
            print("")
            for (index, agent) in AgentTool.allCases.enumerated() {
                print("  \(index + 1). \(agent.title)")
            }
            print("  \(AgentTool.allCases.count + 1). All")
            print("")
            print("Selection: ", terminator: "")

            guard let answer = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !answer.isEmpty else {
                throw ValidationError(
                    "Choose an agent with --agent or use --all. Example: authsia agent init --agent codex"
                )
            }

            if let number = Int(answer) {
                if number == AgentTool.allCases.count + 1 {
                    return AgentTool.allCases
                }
                guard AgentTool.allCases.indices.contains(number - 1) else {
                    throw ValidationError(
                        "Unknown agent selection '\(answer)'. Choose a number from the prompt, " +
                            "or run `authsia agent init --all`."
                    )
                }
                return [AgentTool.allCases[number - 1]]
            }

            guard let selected = AgentTool(argument: answer) else {
                let known = AgentTool.allValueStrings.joined(separator: ", ")
                throw ValidationError(
                    "Unknown agent '\(answer)'. Known: \(known), all. " +
                        "Example: authsia agent init --agent codex"
                )
            }
            return [selected]
        }
    }

    struct RecordCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "record-command",
            abstract: "Record agent command metadata for Access Center",
            shouldDisplay: false
        )

        @Option(name: .long, help: "Agent platform, such as claude-code or codex")
        var platform: String?

        @Option(name: .long, help: "Capture source: hook or process")
        var source = AgentCommandCaptureSource.hook.rawValue

        @Option(name: .long, help: "Agent session identifier")
        var sessionID: String?

        @Option(name: .long, help: "Agent turn identifier")
        var turnID: String?

        @Option(name: .long, help: "Agent identifier")
        var agentID: String?

        @Option(name: .long, help: "Agent type")
        var agentType: String?

        @Option(name: .long, help: "Agent tool-use identifier")
        var toolUseID: String?

        @Option(name: .long, help: "Working directory")
        var cwd: String?

        @Option(name: .long, help: "Terminal session scope")
        var terminalSessionScope: String?

        @Option(name: .long, help: "Executable name or path")
        var executable: String?

        @Option(name: .long, help: "Redacted command text")
        var command: String?

        @Option(name: .long, help: "Argument vector JSON array")
        var argvJSON: String?

        @Option(name: .long, help: "Exit status when known")
        var exitStatus: Int32?

        func run() throws {
            _ = try run(
                store: AgentCommandHistoryStore(),
                fileActivityStore: AgentFileActivityStore(),
                stdinData: Self.stdinDataIfPiped()
            )
        }

        @discardableResult
        func run(
            store: AgentCommandHistoryStore,
            stdinData: Data? = nil,
            responseMode: AgentLeakResponseMode? = nil,
            decisionOutput: (Data) -> Void = { FileHandle.standardOutput.write($0) }
        ) throws -> AgentLeakResponseDecision {
            try run(
                store: store,
                fileActivityStore: nil,
                stdinData: stdinData,
                responseMode: responseMode,
                decisionOutput: decisionOutput
            )
        }

        @discardableResult
        func run(
            store: AgentCommandHistoryStore,
            fileActivityStore: AgentFileActivityStore?,
            stdinData: Data? = nil,
            responseMode: AgentLeakResponseMode? = nil,
            decisionOutput: (Data) -> Void = { FileHandle.standardOutput.write($0) }
        ) throws -> AgentLeakResponseDecision {
            let hookPayload = AgentCommandHookPayload(data: stdinData)
            let arguments = try Self.arguments(from: argvJSON) ?? hookPayload.arguments
            let commandText = command ?? hookPayload.command
            let captureSource = try Self.captureSource(from: source)

            let now = Date()
            let resolvedPlatform = platform
                ?? hookPayload.platform
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentPlatformKey]
            let resolvedSessionID = sessionID
                ?? hookPayload.sessionID
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentSessionIDKey]
            let resolvedTurnID = turnID
                ?? hookPayload.turnID
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentTurnIDKey]
            let resolvedAgentID = agentID
                ?? hookPayload.agentID
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentAgentIDKey]
            let resolvedAgentType = agentType
                ?? hookPayload.agentType
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentAgentTypeKey]
            let resolvedToolUseID = toolUseID
                ?? hookPayload.toolUseID
                ?? ProcessInfo.processInfo.environment[AgentRuntimeContextResolver.environmentToolUseIDKey]
            let resolvedWorkingDirectory = cwd ?? hookPayload.workingDirectory ?? FileManager.default.currentDirectoryPath
            let resolvedTerminalSessionScope = terminalSessionScope
                ?? hookPayload.terminalSessionScope
                ?? TerminalSessionScope.currentAncestralScope()
            let resolvedExitStatus = exitStatus ?? hookPayload.exitStatus
            let resolvedResponseMode = responseMode ?? Self.responseMode(
                for: resolvedWorkingDirectory
            )
            let responseDecision = AgentLeakResponsePolicy.decision(
                command: hookPayload.policyCommand ?? commandText,
                hookEventName: hookPayload.hookEventName,
                mode: resolvedResponseMode
            )

            if commandText != nil || !arguments.isEmpty || responseDecision.evidence != nil {
                let recordedCommand = commandText ?? hookPayload.policyCommand
                let event = AgentCommandEvent(
                    recordedAt: now,
                    agentPlatform: resolvedPlatform,
                    sessionID: resolvedSessionID,
                    turnID: resolvedTurnID,
                    agentID: resolvedAgentID,
                    agentType: resolvedAgentType,
                    toolUseID: resolvedToolUseID,
                    captureSource: captureSource,
                    contextExpiresAt: now.addingTimeInterval(60 * 60),
                    workingDirectory: resolvedWorkingDirectory,
                    terminalSessionScope: resolvedTerminalSessionScope,
                    executable: executable ?? hookPayload.executable ?? Self.executable(
                        from: arguments,
                        command: recordedCommand
                    ),
                    arguments: arguments,
                    command: recordedCommand,
                    exitStatus: resolvedExitStatus,
                    responseOutcome: responseDecision.outcome,
                    responseEvidence: responseDecision.evidence,
                    responsePreventedAction: responseDecision.preventedAction
                )
                try store.record(event)
                if responseDecision.evidence != nil {
                    DistributedNotificationCenter.default().post(
                        name: .agentLeakIncidentDidRecord,
                        object: nil
                    )
                }
            }

            if captureSource == .hook, let fileActivityStore {
                let fileActivities = hookPayload.fileActivities(
                    recordedAt: now,
                    agentPlatform: resolvedPlatform,
                    sessionID: resolvedSessionID,
                    turnID: resolvedTurnID,
                    agentID: resolvedAgentID,
                    agentType: resolvedAgentType,
                    toolUseID: resolvedToolUseID,
                    workingDirectory: resolvedWorkingDirectory,
                    terminalSessionScope: resolvedTerminalSessionScope,
                    exitStatus: resolvedExitStatus
                )
                for activity in fileActivities {
                    try fileActivityStore.record(activity)
                }
            }
            try Self.emitHookDecision(
                responseDecision,
                platform: resolvedPlatform,
                hookEventName: hookPayload.hookEventName,
                output: decisionOutput
            )
            return responseDecision
        }

        private static func stdinDataIfPiped() -> Data? {
            guard isatty(STDIN_FILENO) == 0 else { return nil }
            let data = FileHandle.standardInput.readDataToEndOfFile()
            return data.isEmpty ? nil : data
        }

        private static func arguments(from json: String?) throws -> [String]? {
            guard let json, !json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return nil
            }
            let data = Data(json.utf8)
            guard let values = try JSONSerialization.jsonObject(with: data) as? [String] else {
                throw ValidationError("--argv-json must be a JSON string array.")
            }
            return values
        }

        private static func captureSource(from value: String) throws -> AgentCommandCaptureSource {
            switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case AgentCommandCaptureSource.hook.rawValue:
                return .hook
            case AgentCommandCaptureSource.process.rawValue:
                return .process
            default:
                throw ValidationError("--source must be hook or process.")
            }
        }

        private static func executable(from arguments: [String], command: String?) -> String? {
            if let first = arguments.first, !first.isEmpty {
                return (first as NSString).lastPathComponent
            }
            guard let command else { return nil }
            return command.split(whereSeparator: \.isWhitespace).first.map { String($0) }
        }

        private static func responseMode(for workingDirectory: String) -> AgentLeakResponseMode {
            let start = URL(fileURLWithPath: workingDirectory, isDirectory: true)
            guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: start),
                  let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root) else {
                return .observe
            }
            return config.guardSettings.responseMode
        }

        private static func emitHookDecision(
            _ decision: AgentLeakResponseDecision,
            platform: String?,
            hookEventName: String?,
            output: (Data) -> Void
        ) throws {
            guard decision.phase == .preTool,
                  let permission = decision.hookPermissionDecision,
                  permission != .allow else {
                return
            }
            let reason = decision.reason
            let object: [String: Any]
            if platform?.lowercased().contains("copilot") == true {
                object = [
                    "permissionDecision": permission.rawValue,
                    "permissionDecisionReason": reason,
                ]
            } else {
                object = [
                    "hookSpecificOutput": [
                        "hookEventName": hookEventName ?? "PreToolUse",
                        "permissionDecision": permission.rawValue,
                        "permissionDecisionReason": reason,
                    ],
                ]
            }
            var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            data.append(0x0A)
            output(data)
        }
    }
}

private struct AgentCommandHookPayload {
    let platform: String?
    let sessionID: String?
    let turnID: String?
    let agentID: String?
    let agentType: String?
    let toolUseID: String?
    let workingDirectory: String?
    let terminalSessionScope: String?
    let workspaceRoot: String?
    let hookEventName: String?
    let executable: String?
    let arguments: [String]
    let command: String?
    let exitStatus: Int32?
    let toolName: String?
    let toolInput: [String: Any]?
    let toolResponse: [String: Any]?

    var policyCommand: String? {
        if let command { return command }
        guard toolName?.lowercased() == "read",
              let path = Self.string(
                toolInput,
                keys: ["file_path", "filePath", "path"]
              ) else {
            return nil
        }
        return "cat \(path)"
    }

    init(data: Data?) {
        guard let data,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            self.platform = nil
            self.sessionID = nil
            self.turnID = nil
            self.agentID = nil
            self.agentType = nil
            self.toolUseID = nil
            self.workingDirectory = nil
            self.terminalSessionScope = nil
            self.workspaceRoot = nil
            self.hookEventName = nil
            self.executable = nil
            self.arguments = []
            self.command = nil
            self.exitStatus = nil
            self.toolName = nil
            self.toolInput = nil
            self.toolResponse = nil
            return
        }

        let toolInput = Self.dictionary(object, keys: ["tool_input", "toolInput", "tool_args", "toolArgs"])
        let toolResponse = Self.dictionary(object, keys: ["tool_response", "toolResponse"])
        let command = Self.string(toolInput, keys: ["command"]) ?? Self.string(object, keys: ["command"])
        let arguments = Self.stringArray(toolInput, keys: ["argv", "arguments", "args"]) ?? []

        self.platform = Self.string(object, keys: ["platform", "agent_platform", "agentPlatform"])
        self.sessionID = Self.string(object, keys: ["session_id", "sessionID", "sessionId"])
        self.turnID = Self.string(object, keys: ["turn_id", "turnID", "turnId"])
        self.agentID = Self.string(object, keys: ["agent_id", "agentID", "agentId"])
        self.agentType = Self.string(object, keys: ["agent_type", "agentType"])
        self.toolUseID = Self.string(object, keys: ["tool_use_id", "toolUseID", "toolUseId"])
        self.workingDirectory = Self.string(object, keys: ["cwd", "working_directory", "workingDirectory"])
            ?? Self.string(toolInput, keys: ["cwd", "working_directory", "workingDirectory"])
        self.terminalSessionScope = Self.string(
            object,
            keys: ["terminal_session_scope", "terminalSessionScope"]
        ) ?? Self.string(toolInput, keys: ["terminal_session_scope", "terminalSessionScope"])
        self.workspaceRoot = Self.string(object, keys: ["workspace_root", "workspaceRoot", "project_root", "projectRoot"])
            ?? Self.string(toolInput, keys: ["workspace_root", "workspaceRoot", "project_root", "projectRoot"])
        self.hookEventName = Self.string(object, keys: ["hook_event_name", "hookEventName", "event_name", "eventName"])
        self.executable = Self.string(toolInput, keys: ["executable"])
            ?? arguments.first.map { ($0 as NSString).lastPathComponent }
            ?? command?.split(whereSeparator: \.isWhitespace).first.map(String.init)
        self.arguments = arguments
        self.command = command
        self.exitStatus = Self.int32(object, keys: ["exit_status", "exitStatus", "exit_code", "exitCode"])
            ?? Self.int32(toolResponse, keys: ["exit_status", "exitStatus", "exit_code", "exitCode"])
        self.toolName = Self.string(object, keys: ["tool_name", "toolName"])
        self.toolInput = toolInput
        self.toolResponse = toolResponse
    }

    func fileActivities(
        recordedAt: Date,
        agentPlatform: String?,
        sessionID: String?,
        turnID: String?,
        agentID: String?,
        agentType: String?,
        toolUseID: String?,
        workingDirectory: String?,
        terminalSessionScope: String?,
        exitStatus: Int32?
    ) -> [AgentFileActivityEvent] {
        guard let mapping = Self.fileActivityMapping(for: toolName),
              let path = Self.fileActivityPath(
                for: mapping.action,
                input: toolInput,
                workingDirectory: workingDirectory,
                workspaceRoot: workspaceRoot
              ) else {
            return []
        }
        let resolvedWorkspaceRoot = workspaceRoot ?? workingDirectory

        return [
            AgentFileActivityEvent(
                recordedAt: recordedAt,
                agentPlatform: agentPlatform,
                sessionID: sessionID,
                turnID: turnID,
                agentID: agentID,
                agentType: agentType,
                toolUseID: toolUseID,
                captureSource: .hook,
                workingDirectory: workingDirectory,
                terminalSessionScope: terminalSessionScope,
                workspaceRoot: resolvedWorkspaceRoot,
                path: path,
                kind: mapping.kind,
                action: mapping.action,
                status: Self.fileActivityStatus(
                    from: exitStatus,
                    hookEventName: hookEventName,
                    toolResponse: toolResponse
                ),
                confidence: Self.fileActivityConfidence(from: hookEventName, exitStatus: exitStatus)
            ),
        ]
    }

    private static func fileActivityMapping(
        for toolName: String?
    ) -> (kind: AgentFileActivityKind, action: AgentFileActivityAction)? {
        switch toolName?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "read":
            return (.file, .read)
        case "write":
            return (.file, .create)
        case "edit", "multiedit":
            return (.file, .modify)
        case "ls":
            return (.directory, .list)
        case "glob", "grep":
            return (.unknown, .search)
        default:
            return nil
        }
    }

    private static func fileActivityPath(
        for action: AgentFileActivityAction,
        input: [String: Any]?,
        workingDirectory: String?,
        workspaceRoot: String?
    ) -> String? {
        switch action {
        case .search:
            return string(input, keys: ["path"])
                ?? string(input, keys: ["cwd", "working_directory", "workingDirectory"])
                ?? workingDirectory
                ?? workspaceRoot
        case .read, .list, .create, .modify:
            return string(input, keys: ["file_path", "filePath", "path"])
        case .delete, .execute:
            return nil
        }
    }

    private static func fileActivityStatus(
        from exitStatus: Int32?,
        hookEventName: String?,
        toolResponse: [String: Any]?
    ) -> AgentFileActivityStatus {
        if Self.toolResponseIndicatesFailure(toolResponse) {
            return .failed
        }
        guard let exitStatus else {
            return isPostToolUse(hookEventName) ? .succeeded : .requested
        }
        return exitStatus == 0 ? .succeeded : .failed
    }

    private static func fileActivityConfidence(
        from hookEventName: String?,
        exitStatus: Int32?
    ) -> AgentFileActivityConfidence {
        if isPostToolUse(hookEventName), exitStatus == nil || exitStatus == 0 {
            return .confirmed
        }
        return .direct
    }

    private static func isPostToolUse(_ hookEventName: String?) -> Bool {
        hookEventName?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() == "posttooluse"
    }

    private static func toolResponseIndicatesFailure(_ object: [String: Any]?) -> Bool {
        if bool(object, keys: ["is_error", "isError", "failed"]) == true {
            return true
        }
        if bool(object, keys: ["success", "succeeded"]) == false {
            return true
        }
        return string(object, keys: ["error", "error_message", "errorMessage"]) != nil
    }

    private static func dictionary(_ object: [String: Any], keys: [String]) -> [String: Any]? {
        for key in keys {
            if let dictionary = object[key] as? [String: Any] {
                return dictionary
            }
            if let string = object[key] as? String,
               let data = string.data(using: .utf8),
               let dictionary = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return dictionary
            }
        }
        return nil
    }

    private static func string(_ object: [String: Any]?, keys: [String]) -> String? {
        guard let object else { return nil }
        for key in keys {
            if let value = object[key] as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return value
            }
        }
        return nil
    }

    private static func stringArray(_ object: [String: Any]?, keys: [String]) -> [String]? {
        guard let object else { return nil }
        for key in keys {
            if let values = object[key] as? [String] {
                return values
            }
        }
        return nil
    }

    private static func int32(_ object: [String: Any]?, keys: [String]) -> Int32? {
        guard let object else { return nil }
        for key in keys {
            if let value = object[key] as? Int {
                return Int32(value)
            }
            if let value = object[key] as? String, let parsed = Int32(value) {
                return parsed
            }
        }
        return nil
    }

    private static func bool(_ object: [String: Any]?, keys: [String]) -> Bool? {
        guard let object else { return nil }
        for key in keys {
            if let value = object[key] as? Bool {
                return value
            }
            if let value = object[key] as? String {
                switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
                case "true", "yes", "1":
                    return true
                case "false", "no", "0":
                    return false
                default:
                    continue
                }
            }
        }
        return nil
    }
}
