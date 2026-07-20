import ArgumentParser
import Foundation

enum AgentTool: CaseIterable, Equatable {
    case claudeCode
    case cursor
    case codex
    case windsurf
    case copilot

    var title: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .cursor: return "Cursor"
        case .codex: return "Codex"
        case .windsurf: return "Windsurf"
        case .copilot: return "GitHub Copilot"
        }
    }

    var rulePath: String {
        switch self {
        case .claudeCode: return "CLAUDE.md"
        case .cursor: return ".cursor/rules/authsia.mdc"
        case .codex: return "AGENTS.md"
        case .windsurf: return ".windsurf/rules/authsia.md"
        case .copilot: return "AGENTS.md"
        }
    }

    var platformName: String {
        switch self {
        case .claudeCode: return "claude-code"
        case .cursor: return "cursor"
        case .codex: return "codex"
        case .windsurf: return "windsurf"
        case .copilot: return "copilot"
        }
    }
}

extension AgentTool: ExpressibleByArgument {
    init?(argument: String) {
        switch argument.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "claude", "claude-code", "claudecode":
            self = .claudeCode
        case "cursor":
            self = .cursor
        case "codex":
            self = .codex
        case "windsurf":
            self = .windsurf
        case "copilot", "github-copilot", "githubcopilot":
            self = .copilot
        default:
            return nil
        }
    }

    static var allValueStrings: [String] {
        ["claude-code", "cursor", "codex", "windsurf", "copilot"]
    }
}

struct AgentRuleManualStep: Equatable {
    let path: String
    let reason: String
    let block: String
}

struct AgentRuleInstallResult: Equatable {
    var dryRun = false
    var created: [String] = []
    var updated: [String] = []
    var unchanged: [String] = []
    var manualSteps: [AgentRuleManualStep] = []
}

struct AgentRuleRemovalResult: Equatable {
    var dryRun = false
    var removed: [String] = []
    var updated: [String] = []
    var unchanged: [String] = []
    var manualSteps: [AgentRuleManualStep] = []
}

enum AgentRuleInstaller {
    static let managedStartMarker = "<!-- >>> Authsia agent rules >>> -->"
    static let managedEndMarker = "<!-- <<< Authsia agent rules <<< -->"
    private static let legacyClaudeMachLookupValues = ["Authsia.Bridge", "Authsia.SSHAgent"]
    private static let legacyClaudeUnixSocketValues = ["~/.authsia/agent.sock"]
    private static let agentShimWorkspaceGuidanceLine =
        "- Implicit guarded-terminal shims under agents do not resolve `authsia://` refs; use explicit " +
        "`authsia workspace run -- <command>` or `authsia exec` for any command that needs workspace secrets."

    static func install(
        projectRoot: URL,
        agents: [AgentTool],
        dryRun: Bool = false,
        fileManager: FileManager = .default
    ) throws -> AgentRuleInstallResult {
        var result = AgentRuleInstallResult(dryRun: dryRun)
        let selectedAgents = unique(agents)
        let includeWorkspaceGuidance = fileManager.fileExists(
            atPath: projectRoot.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath).path
        )

        try writeExactFile(
            sharedRulesMarkdown(for: selectedAgents, includeWorkspaceGuidance: includeWorkspaceGuidance),
            relativePath: ".authsia/agent-rules.md",
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )

        for group in groupedByRulePath(selectedAgents) {
            guard let agent = group.agents.first else { continue }
            try upsertMarkdownFile(
                relativePath: group.rulePath,
                prefix: markdownPrefix(for: agent),
                block: agentRuleBlock(for: group.agents, includeWorkspaceGuidance: includeWorkspaceGuidance),
                projectRoot: projectRoot,
                dryRun: dryRun,
                fileManager: fileManager,
                result: &result
            )

            for agent in group.agents {
                switch agent {
                case .claudeCode:
                    try installClaudeLocalSettings(
                        projectRoot: projectRoot,
                        dryRun: dryRun,
                        fileManager: fileManager,
                        result: &result
                    )
                case .copilot:
                    try installCopilotLocalSettings(
                        projectRoot: projectRoot,
                        dryRun: dryRun,
                        fileManager: fileManager,
                        result: &result
                    )
                case .cursor, .codex, .windsurf:
                    break
                }
            }
        }

        return result
    }

    static func renderResult(_ result: AgentRuleInstallResult) -> String {
        var lines: [String] = []
        let createdTitle = result.dryRun ? "Would create:" : "Created:"
        let updatedTitle = result.dryRun ? "Would update:" : "Updated:"
        appendSection(createdTitle, values: result.created, to: &lines)
        appendSection(updatedTitle, values: result.updated, to: &lines)
        appendSection("Unchanged:", values: result.unchanged, to: &lines)

        if !result.manualSteps.isEmpty {
            if !lines.isEmpty { lines.append("") }
            lines.append("Manual steps:")
            for step in result.manualSteps {
                lines.append("  \(step.path) \(step.reason)")
                lines.append("")
                lines.append(indent(step.block, by: "    "))
            }
        }

        if !lines.isEmpty { lines.append("") }
        lines.append("Authsia agent rules are ready.")
        lines.append("Restart or reload your agent so it picks up the new project rules.")
        return lines.joined(separator: "\n")
    }

    static func uninstall(
        projectRoot: URL,
        agents: [AgentTool],
        dryRun: Bool = false,
        fileManager: FileManager = .default
    ) throws -> AgentRuleRemovalResult {
        var result = AgentRuleRemovalResult(dryRun: dryRun)
        let selectedAgents = unique(agents)
        guard !selectedAgents.isEmpty else { return result }

        try removeGeneratedSharedRulesFile(
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )

        var processedRulePaths = Set<String>()
        for agent in selectedAgents {
            if processedRulePaths.insert(agent.rulePath).inserted {
                try removeManagedMarkdownBlock(
                    relativePath: agent.rulePath,
                    removablePrefix: markdownPrefix(for: agent),
                    projectRoot: projectRoot,
                    dryRun: dryRun,
                    fileManager: fileManager,
                    result: &result
                )
            }

            if agent == .claudeCode {
                try removeClaudeLocalSettings(
                    projectRoot: projectRoot,
                    dryRun: dryRun,
                    fileManager: fileManager,
                    result: &result
                )
            }
            if agent == .copilot {
                try removeGeneratedFile(
                    relativePath: ".github/copilot/settings.local.json",
                    expectedContent: copilotSettingsJSON,
                    projectRoot: projectRoot,
                    dryRun: dryRun,
                    fileManager: fileManager,
                    result: &result
                )
            }
        }

        return result
    }

    static func renderRemovalResult(_ result: AgentRuleRemovalResult) -> String {
        var lines: [String] = []
        let removedTitle = result.dryRun ? "Would remove:" : "Removed:"
        let updatedTitle = result.dryRun ? "Would update:" : "Updated:"
        appendSection(removedTitle, values: result.removed, to: &lines)
        appendSection(updatedTitle, values: result.updated, to: &lines)
        appendSection("Unchanged:", values: result.unchanged, to: &lines)

        if !result.manualSteps.isEmpty {
            if !lines.isEmpty { lines.append("") }
            lines.append("Manual steps:")
            for step in result.manualSteps {
                lines.append("  \(step.path) \(step.reason)")
            }
        }

        if lines.isEmpty {
            lines.append("No Authsia agent rule artifacts found.")
        }
        return lines.joined(separator: "\n")
    }

    static func isInstalled(
        projectRoot: URL,
        agent: AgentTool,
        fileManager: FileManager = .default
    ) -> Bool {
        let sharedRulesURL = projectRoot.appendingPathComponent(".authsia/agent-rules.md")
        let toolRulesURL = projectRoot.appendingPathComponent(agent.rulePath)
        guard fileManager.fileExists(atPath: sharedRulesURL.path),
              fileManager.fileExists(atPath: toolRulesURL.path),
              let sharedRules = try? String(contentsOf: sharedRulesURL, encoding: .utf8),
              let toolRules = try? String(contentsOf: toolRulesURL, encoding: .utf8) else {
            return false
        }
        guard generatedSharedRules(sharedRules, contains: agent),
              let range = managedBlockRange(in: toolRules) else {
            return false
        }
        return toolRules[range].contains("AUTHSIA_AGENT_PLATFORM=\(agent.platformName)")
    }

    // MARK: - File Installation

    private static func installClaudeLocalSettings(
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleInstallResult
    ) throws {
        let path = ".claude/settings.local.json"
        let url = projectRoot.appendingPathComponent(path)
        if fileManager.fileExists(atPath: url.path) {
            let existing = try String(contentsOf: url, encoding: .utf8)
            guard let merged = mergedClaudeSettingsJSON(existing) else {
                result.manualSteps.append(
                    AgentRuleManualStep(
                        path: path,
                        reason: "already exists but could not be parsed or safely merged. " +
                            "Add this sandbox command-exclusion and command-history hook block manually.",
                        block: claudeSettingsManualBlock
                    )
                )
                return
            }
            try writeFile(
                merged,
                existing: existing,
                relativePath: path,
                projectRoot: projectRoot,
                dryRun: dryRun,
                fileManager: fileManager,
                result: &result
            )
            return
        }

        try writeExactFile(
            claudeSettingsJSON,
            relativePath: path,
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )
    }

    private static func mergedClaudeSettingsJSON(_ existing: String) -> String? {
        guard var settings = jsonObject(from: existing),
              let generated = jsonObject(from: claudeSettingsJSON) else {
            return nil
        }
        guard !jsonObjectsAreEqual(settings, generated) else { return existing }
        guard mergeClaudeHooks(from: generated, into: &settings),
              mergeClaudeSandbox(from: generated, into: &settings) else {
            return nil
        }
        guard JSONSerialization.isValidJSONObject(settings),
              let data = try? JSONSerialization.data(
                withJSONObject: settings,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let output = String(data: data, encoding: .utf8) else {
            return nil
        }
        return output.hasSuffix("\n") ? output : "\(output)\n"
    }

    private static func jsonObject(from value: String) -> [String: Any]? {
        guard let data = value.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return object
    }

    /// Merges the generated hook block into `settings`. Returns `false` if the existing file has a
    /// value of an unexpected shape where we would need to write (e.g. `hooks` or a hook event is not
    /// an object/array), so the caller can fall back to the manual block instead of clobbering it.
    private static func mergeClaudeHooks(from generated: [String: Any], into settings: inout [String: Any]) -> Bool {
        guard let generatedHooks = generated["hooks"] as? [String: Any] else { return true }
        guard var hooks = existingObject(settings["hooks"]) else { return false }
        for (eventName, generatedValue) in generatedHooks {
            guard let generatedEntries = generatedValue as? [[String: Any]] else {
                hooks[eventName] = generatedValue
                continue
            }
            guard var existingEntries = existingArray(hooks[eventName]) else { return false }
            for generatedEntry in generatedEntries {
                guard mergeClaudeHookEntry(generatedEntry, into: &existingEntries) else { return false }
            }
            hooks[eventName] = existingEntries
        }
        settings["hooks"] = hooks
        return true
    }

    private static func mergeClaudeHookEntry(
        _ generatedEntry: [String: Any],
        into entries: inout [[String: Any]]
    ) -> Bool {
        guard let matcher = generatedEntry["matcher"] as? String else {
            if !entries.contains(where: { jsonObjectsAreEqual($0, generatedEntry) }) {
                entries.append(generatedEntry)
            }
            return true
        }

        guard let generatedHooks = generatedEntry["hooks"] as? [[String: Any]] else { return false }

        let matchingIndices = entries.indices.filter { entries[$0]["matcher"] as? String == matcher }
        guard let targetIndex = matchingIndices.first else {
            entries.append(generatedEntry)
            return true
        }

        let existingHookGroups = matchingIndices.compactMap { existingArray(entries[$0]["hooks"]) }
        guard existingHookGroups.count == matchingIndices.count,
              var targetHooks = existingHookGroups.first else {
            return false
        }

        var didAppend = false
        for generatedHook in generatedHooks {
            let alreadyExists = targetHooks.contains { jsonObjectsAreEqual($0, generatedHook) } ||
                existingHookGroups.dropFirst().contains { hooks in
                    hooks.contains { jsonObjectsAreEqual($0, generatedHook) }
                }
            guard !alreadyExists else { continue }
            targetHooks.append(generatedHook)
            didAppend = true
        }
        if didAppend {
            var targetEntry = entries[targetIndex]
            targetEntry["hooks"] = targetHooks
            entries[targetIndex] = targetEntry
        }
        return true
    }

    /// Merges the generated sandbox command exclusions into `settings` and removes obsolete Authsia
    /// network exceptions. Returns `false` if an existing value has an unexpected shape, so the caller can
    /// fall back to the manual block instead of clobbering them.
    private static func mergeClaudeSandbox(from generated: [String: Any], into settings: inout [String: Any]) -> Bool {
        guard let generatedSandbox = generated["sandbox"] as? [String: Any] else { return true }
        guard var sandbox = existingObject(settings["sandbox"]) else { return false }
        if let generatedValues = generatedSandbox["excludedCommands"] as? [String] {
            guard let existingValues = existingStringArray(sandbox["excludedCommands"]) else { return false }
            sandbox["excludedCommands"] = appendMissingValues(generatedValues, to: existingValues)
        }
        var didRemoveLegacyPermission = false
        guard removeLegacyClaudeNetworkPermissions(
            from: &sandbox,
            didRemove: &didRemoveLegacyPermission
        ) else { return false }
        settings["sandbox"] = sandbox
        return true
    }

    private static func removeLegacyClaudeNetworkPermissions(
        from sandbox: inout [String: Any],
        didRemove: inout Bool
    ) -> Bool {
        guard let networkValue = sandbox["network"], !(networkValue is NSNull) else { return true }
        guard var network = networkValue as? [String: Any] else { return false }
        guard removeClaudeSandboxNetworkValues(
            legacyClaudeUnixSocketValues,
            forKey: "allowUnixSockets",
            from: &network,
            didRemove: &didRemove
        ), removeClaudeSandboxNetworkValues(
            legacyClaudeMachLookupValues,
            forKey: "allowMachLookup",
            from: &network,
            didRemove: &didRemove
        ) else {
            return false
        }
        if network.isEmpty {
            sandbox.removeValue(forKey: "network")
        } else {
            sandbox["network"] = network
        }
        return true
    }

    /// Returns the value as a JSON object, an empty object if absent, or `nil` if present with a
    /// non-object shape (signals the caller to fall back rather than overwrite user content).
    private static func existingObject(_ value: Any?) -> [String: Any]? {
        guard let value, !(value is NSNull) else { return [:] }
        return value as? [String: Any]
    }

    /// Returns the value as an array of JSON objects, an empty array if absent, or `nil` if present
    /// with an incompatible shape.
    private static func existingArray(_ value: Any?) -> [[String: Any]]? {
        guard let value, !(value is NSNull) else { return [] }
        return value as? [[String: Any]]
    }

    /// Returns the value as a string array, an empty array if absent, or `nil` if present with an
    /// incompatible shape.
    private static func existingStringArray(_ value: Any?) -> [String]? {
        guard let value, !(value is NSNull) else { return [] }
        return value as? [String]
    }

    private static func appendMissingValues(_ values: [String], to existing: [String]) -> [String] {
        var merged = existing
        for value in values where !merged.contains(value) {
            merged.append(value)
        }
        return merged
    }

    private static func jsonObjectsAreEqual(_ lhs: [String: Any], _ rhs: [String: Any]) -> Bool {
        guard JSONSerialization.isValidJSONObject(lhs),
              JSONSerialization.isValidJSONObject(rhs),
              let lhsData = try? JSONSerialization.data(withJSONObject: lhs, options: [.sortedKeys]),
              let rhsData = try? JSONSerialization.data(withJSONObject: rhs, options: [.sortedKeys]) else {
            return false
        }
        return lhsData == rhsData
    }

    private static func installCopilotLocalSettings(
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleInstallResult
    ) throws {
        let path = ".github/copilot/settings.local.json"
        let url = projectRoot.appendingPathComponent(path)
        if fileManager.fileExists(atPath: url.path) {
            result.manualSteps.append(
                AgentRuleManualStep(
                    path: path,
                    reason: "already exists. Add this command-history hook block manually.",
                    block: copilotSettingsManualBlock
                )
            )
            return
        }

        try writeExactFile(
            copilotSettingsJSON,
            relativePath: path,
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )
    }

    private static func upsertMarkdownFile(
        relativePath: String,
        prefix: String?,
        block: String,
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleInstallResult
    ) throws {
        let url = projectRoot.appendingPathComponent(relativePath)
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        let updated = upsertManagedBlock(in: existing, prefix: prefix, block: block)
        try writeFile(
            updated,
            existing: fileManager.fileExists(atPath: url.path) ? existing : nil,
            relativePath: relativePath,
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )
    }

    private static func writeExactFile(
        _ content: String,
        relativePath: String,
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleInstallResult
    ) throws {
        let url = projectRoot.appendingPathComponent(relativePath)
        let existing = try? String(contentsOf: url, encoding: .utf8)
        try writeFile(
            content,
            existing: existing,
            relativePath: relativePath,
            projectRoot: projectRoot,
            dryRun: dryRun,
            fileManager: fileManager,
            result: &result
        )
    }

    private static func writeFile(
        _ content: String,
        existing: String?,
        relativePath: String,
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleInstallResult
    ) throws {
        if let existing {
            guard existing != content else {
                result.unchanged.append(relativePath)
                return
            }
            if !dryRun {
                let url = projectRoot.appendingPathComponent(relativePath)
                try content.write(to: url, atomically: true, encoding: .utf8)
            }
            result.updated.append(relativePath)
            return
        }

        if !dryRun {
            let url = projectRoot.appendingPathComponent(relativePath)
            try fileManager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try content.write(to: url, atomically: true, encoding: .utf8)
        }
        result.created.append(relativePath)
    }

    // MARK: - File Removal

    private static func removeClaudeLocalSettings(
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleRemovalResult
    ) throws {
        let relativePath = ".claude/settings.local.json"
        let url = projectRoot.appendingPathComponent(relativePath)
        guard fileManager.fileExists(atPath: url.path) else { return }
        let existing = try String(contentsOf: url, encoding: .utf8)
        if existing == claudeSettingsJSON {
            if !dryRun {
                try fileManager.removeItem(at: url)
            }
            result.removed.append(relativePath)
            return
        }
        if let generatedObject = jsonObject(from: claudeSettingsJSON) {
            let existingObject = jsonObject(from: existing)
            let migratedObject = mergedClaudeSettingsJSON(existing).flatMap(jsonObject(from:))
            if existingObject.map({ jsonObjectsAreEqual($0, generatedObject) }) == true ||
                migratedObject.map({ jsonObjectsAreEqual($0, generatedObject) }) == true {
                if !dryRun {
                    try fileManager.removeItem(at: url)
                }
                result.removed.append(relativePath)
                return
            }
        }

        guard let updated = removingClaudeSettingsJSON(existing) else {
            result.manualSteps.append(AgentRuleManualStep(
                path: relativePath,
                reason: "has a structure that cannot be safely updated. Remove Authsia hooks and " +
                    "sandbox command exclusions or legacy network permissions manually.",
                block: ""
            ))
            return
        }
        guard updated != existing else {
            result.unchanged.append(relativePath)
            return
        }
        if !dryRun {
            try updated.write(to: url, atomically: true, encoding: .utf8)
        }
        result.updated.append(relativePath)
    }

    private static func removingClaudeSettingsJSON(_ existing: String) -> String? {
        guard var settings = jsonObject(from: existing),
              let generated = jsonObject(from: claudeSettingsJSON) else {
            return nil
        }
        var didRemove = false
        guard removeClaudeHooks(from: generated, in: &settings, didRemove: &didRemove),
              removeClaudeSandbox(from: generated, in: &settings, didRemove: &didRemove) else {
            return nil
        }
        guard didRemove else { return existing }
        guard JSONSerialization.isValidJSONObject(settings),
              let data = try? JSONSerialization.data(
                withJSONObject: settings,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let output = String(data: data, encoding: .utf8) else {
            return nil
        }
        return output.hasSuffix("\n") ? output : "\(output)\n"
    }

    private static func removeClaudeHooks(
        from generated: [String: Any],
        in settings: inout [String: Any],
        didRemove: inout Bool
    ) -> Bool {
        guard let generatedHooksValue = generated["hooks"], !(generatedHooksValue is NSNull) else {
            return true
        }
        guard let generatedHooks = generatedHooksValue as? [String: Any] else { return false }
        guard let hooksValue = settings["hooks"], !(hooksValue is NSNull) else { return true }
        guard var hooks = hooksValue as? [String: Any] else { return false }

        for (eventName, generatedValue) in generatedHooks {
            guard let generatedEntries = generatedValue as? [[String: Any]] else { return false }
            guard let eventValue = hooks[eventName], !(eventValue is NSNull) else { continue }
            guard var entries = eventValue as? [[String: Any]] else { return false }

            for generatedEntry in generatedEntries {
                let entryCount = entries.count
                entries.removeAll { jsonObjectsAreEqual($0, generatedEntry) }
                if entries.count != entryCount {
                    didRemove = true
                }
                guard let matcher = generatedEntry["matcher"] as? String else { continue }
                guard let generatedEntryHooks = generatedEntry["hooks"] as? [[String: Any]] else {
                    return false
                }
                for entryIndex in entries.indices where entries[entryIndex]["matcher"] as? String == matcher {
                    var entry = entries[entryIndex]
                    guard let entryHooksValue = entry["hooks"], !(entryHooksValue is NSNull) else { continue }
                    guard let entryHooks = entryHooksValue as? [[String: Any]] else { return false }
                    let filteredHooks = entryHooks.filter { existingHook in
                        !generatedEntryHooks.contains(where: { generatedHook in
                            jsonObjectsAreEqual(existingHook, generatedHook)
                        })
                    }
                    if filteredHooks.count != entryHooks.count {
                        entry["hooks"] = filteredHooks
                        entries[entryIndex] = entry
                        didRemove = true
                    }
                }
            }
            hooks[eventName] = entries
        }
        settings["hooks"] = hooks
        return true
    }

    private static func removeClaudeSandbox(
        from generated: [String: Any],
        in settings: inout [String: Any],
        didRemove: inout Bool
    ) -> Bool {
        guard let generatedSandboxValue = generated["sandbox"], !(generatedSandboxValue is NSNull) else {
            return true
        }
        guard let generatedSandbox = generatedSandboxValue as? [String: Any] else { return false }
        guard let sandboxValue = settings["sandbox"], !(sandboxValue is NSNull) else { return true }
        guard var sandbox = sandboxValue as? [String: Any] else { return false }
        if let generatedExcludedCommands = generatedSandbox["excludedCommands"] as? [String] {
            guard removeClaudeSandboxNetworkValues(
                generatedExcludedCommands,
                forKey: "excludedCommands",
                from: &sandbox,
                didRemove: &didRemove
            ) else { return false }
        }
        guard removeLegacyClaudeNetworkPermissions(
            from: &sandbox,
            didRemove: &didRemove
        ) else { return false }
        if sandbox.isEmpty {
            settings.removeValue(forKey: "sandbox")
        } else {
            settings["sandbox"] = sandbox
        }
        return true
    }

    private static func removeClaudeSandboxNetworkValues(
        _ generatedValues: [String],
        forKey key: String,
        from network: inout [String: Any],
        didRemove: inout Bool
    ) -> Bool {
        guard let existingValue = network[key], !(existingValue is NSNull) else { return true }
        guard let existingValues = existingValue as? [String] else { return false }
        let filteredValues = existingValues.filter { !generatedValues.contains($0) }
        guard filteredValues.count != existingValues.count else { return true }
        if filteredValues.isEmpty {
            network.removeValue(forKey: key)
        } else {
            network[key] = filteredValues
        }
        didRemove = true
        return true
    }

    private static func removeGeneratedSharedRulesFile(
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleRemovalResult
    ) throws {
        let relativePath = ".authsia/agent-rules.md"
        let url = projectRoot.appendingPathComponent(relativePath)
        guard fileManager.fileExists(atPath: url.path) else { return }
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        guard isGeneratedSharedRulesMarkdown(existing) else {
            result.manualSteps.append(AgentRuleManualStep(
                path: relativePath,
                reason: "contains local edits. Remove Authsia content manually.",
                block: ""
            ))
            return
        }
        if !dryRun {
            try fileManager.removeItem(at: url)
        }
        result.removed.append(relativePath)
    }

    private static func removeGeneratedFile(
        relativePath: String,
        expectedContent: String,
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleRemovalResult
    ) throws {
        let url = projectRoot.appendingPathComponent(relativePath)
        guard fileManager.fileExists(atPath: url.path) else { return }
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        guard existing == expectedContent else {
            result.manualSteps.append(AgentRuleManualStep(
                path: relativePath,
                reason: "contains local edits. Remove Authsia content manually.",
                block: ""
            ))
            return
        }
        if !dryRun {
            try fileManager.removeItem(at: url)
        }
        result.removed.append(relativePath)
    }

    private static func removeManagedMarkdownBlock(
        relativePath: String,
        removablePrefix: String?,
        projectRoot: URL,
        dryRun: Bool,
        fileManager: FileManager,
        result: inout AgentRuleRemovalResult
    ) throws {
        let url = projectRoot.appendingPathComponent(relativePath)
        guard fileManager.fileExists(atPath: url.path) else { return }
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        guard let range = managedBlockRange(in: existing) else {
            result.unchanged.append(relativePath)
            return
        }

        var base = existing
        base.removeSubrange(range)
        let cleaned = base.trimmingCharacters(in: .newlines)
        let removablePrefix = removablePrefix?.trimmingCharacters(in: .newlines)
        let shouldDelete = cleaned.isEmpty || (removablePrefix != nil && cleaned == removablePrefix)
        if shouldDelete {
            if !dryRun {
                try fileManager.removeItem(at: url)
            }
            result.removed.append(relativePath)
        } else {
            if !dryRun {
                try "\(cleaned)\n".write(to: url, atomically: true, encoding: .utf8)
            }
            result.updated.append(relativePath)
        }
    }

    private static func upsertManagedBlock(in content: String, prefix: String?, block: String) -> String {
        var base = content
        if let range = managedBlockRange(in: base) {
            base.removeSubrange(range)
        }

        let managedBlock = """
        \(managedStartMarker)
        \(block)
        \(managedEndMarker)
        """

        let trimmedBase = base.trimmingCharacters(in: .newlines)
        if trimmedBase.isEmpty {
            if let prefix, !prefix.isEmpty {
                return "\(prefix.trimmingCharacters(in: .newlines))\n\n\(managedBlock)\n"
            }
            return "\(managedBlock)\n"
        }
        return "\(trimmedBase)\n\n\(managedBlock)\n"
    }

    private static func managedBlockRange(in content: String) -> Range<String.Index>? {
        guard let startRange = content.range(of: managedStartMarker),
              let endRange = content.range(of: managedEndMarker),
              startRange.lowerBound <= endRange.lowerBound else {
            return nil
        }
        var upperBound = endRange.upperBound
        if upperBound < content.endIndex, content[upperBound] == "\n" {
            upperBound = content.index(after: upperBound)
        }
        return startRange.lowerBound..<upperBound
    }

    // MARK: - Content

    private static func sharedRulesMarkdown(
        for agents: [AgentTool],
        includeWorkspaceGuidance: Bool = false,
        includeOutsideSandboxRule: Bool = true,
        includeCommandHistoryGuidance: Bool = true,
        includeCopilotCommandHistoryGuidance: Bool = true
    ) -> String {
        """
    # Authsia Agent Rules

    \(agentRuleBlock(
        for: agents,
        includeWorkspaceGuidance: includeWorkspaceGuidance,
        includeOutsideSandboxRule: includeOutsideSandboxRule,
        includeCommandHistoryGuidance: includeCommandHistoryGuidance,
        includeCopilotCommandHistoryGuidance: includeCopilotCommandHistoryGuidance
    ))
    """
    }

    private static func agentRuleBlock(
        for agents: [AgentTool],
        includeWorkspaceGuidance: Bool = false,
        includeOutsideSandboxRule: Bool = true,
        includeCommandHistoryGuidance: Bool = true,
        includeCopilotCommandHistoryGuidance: Bool = true
    ) -> String {
        let selectedAgents = unique(agents)
        let platformLines = selectedAgents
            .map { "  `env AUTHSIA_AGENT_PLATFORM=\($0.platformName) AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`" }
            .joined(separator: "\n")
        let markerIntro = selectedAgents.count == 1
            ? "- When \(selectedAgents[0].title) runs Authsia, every Authsia terminal command must start with:"
            : "- When a selected agent runs Authsia, use the matching platform marker:"
        let workspaceGuidance = workspaceRuleSection(includeWorkspaceGuidance: includeWorkspaceGuidance)
        let sandboxGuidance = sandboxRuleSection(includeOutsideSandboxRule: includeOutsideSandboxRule)
        let commandHistoryGuidance = commandHistoryRuleSection(
            agents: selectedAgents,
            includeCommandHistoryGuidance: includeCommandHistoryGuidance,
            includeCopilotCommandHistoryGuidance: includeCopilotCommandHistoryGuidance
        )
        return """
    ## Authsia Secret Handling

    - Never ask the user for plaintext secrets.
    - Never write resolved secret values to source files, logs, issues, chat, or generated docs.
    - Use `authsia list ...` only for safe metadata discovery, and still include the Authsia agent marker.
    - Use `authsia://` references when a file or template needs a secret placeholder.
    - Use `authsia exec ... -- <command>` when a command needs real secret values.
    - Never run bare `authsia get`, `authsia read`, `authsia load`, `authsia code`, `authsia inject`, or any unprefixed `authsia ...` command from an agent.
    - Unprefixed Authsia commands are treated as direct human CLI and will not be attributed to the agent.
    \(markerIntro)
    \(platformLines)
    - If access is denied, ask the user to approve Authsia access instead of requesting the secret.
    \(workspaceGuidance)

    \(sandboxGuidance)
    \(commandHistoryGuidance)
    """
    }

    private static func sandboxRuleSection(includeOutsideSandboxRule: Bool) -> String {
        if includeOutsideSandboxRule {
            return """
    ## Authsia Sandbox Handling

    - Always run every `authsia ...` CLI command outside the sandbox.
    - If the agent session is sandboxed, request permission to run Authsia CLI commands outside the sandbox before trying them.
    - Treat missing `authsia`, missing `/Applications/Authsia.app`, missing `~/.authsia/agent.sock`, authentication failures, or bridge communication failures inside a sandbox as sandbox/runtime-boundary issues first.
    """
        }
        return """
    ## Authsia Sandbox Handling

    - If sandboxed, request access to `Authsia.Bridge`, `Authsia.SSHAgent`, and `~/.authsia/agent.sock`.
    - If sandbox access is unavailable, request permission to run Authsia-backed commands outside the sandbox.
    - Treat missing `authsia`, missing `/Applications/Authsia.app`, missing `~/.authsia/agent.sock`, or bridge communication failures inside a sandbox as sandbox/runtime-boundary issues first.
    """
    }

    private static func workspaceRuleSection(includeWorkspaceGuidance: Bool) -> String {
        guard includeWorkspaceGuidance else { return "" }
        return """

    ## Authsia Workspace Handling

    - If `.authsia/workspace.json` exists, treat this repository as an Authsia workspace.
    - Run `authsia workspace status` before changing env files or running commands that need workspace secrets.
    - Keep the selected Authsia agent marker on workspace commands too; the command after the marker is `authsia workspace ...`.
    - Use `authsia workspace run -- <command>` when a command needs workspace secrets, so Authsia resolves `authsia://` refs only for the child process.
    \(agentShimWorkspaceGuidanceLine)
    - Use `authsia workspace run --shell -- '<command>'` for shell features such as `$VAR`, `${VAR}`, pipes, redirects, or compound commands.
    - Do not replace `authsia://` refs with plaintext values; if a ref is missing, ask the user to restore the item or run `authsia workspace update`.
    """
    }

    private static func commandHistoryRuleSection(
        agents: [AgentTool],
        includeCommandHistoryGuidance: Bool,
        includeCopilotCommandHistoryGuidance: Bool
    ) -> String {
        guard includeCommandHistoryGuidance else { return "" }
        var lines = [
            "",
            "## Authsia Command History",
            "",
            "- Authsia records supported agent command history as redacted metadata only; never include command output, stdin, environment values, or plaintext secrets.",
        ]
        if agents.contains(.claudeCode) {
            lines.append("- Claude Code command history is captured through the generated local Bash hooks when `.claude/settings.local.json` can be installed.")
        }
        if agents.contains(.codex) {
            lines.append("- Authsia records Codex command history from explicit Authsia markers and macOS process monitoring fallback.")
        }
        if agents.contains(.copilot), includeCopilotCommandHistoryGuidance {
            lines.append("- GitHub Copilot command history is captured through the generated Copilot CLI `PreToolUse` hook when `.github/copilot/settings.local.json` can be installed; VS Code Copilot commands use macOS process monitoring fallback.")
        }
        return lines.joined(separator: "\n")
    }

    private static let legacySharedRulesMarkdown = """
    # Authsia Agent Rules

    ## Authsia Secret Handling

    - Never ask the user for plaintext secrets.
    - Never write resolved secret values to source files, logs, issues, chat, or generated docs.
    - Use `authsia list ...` only for safe metadata discovery, and still include the Authsia agent marker.
    - Use `authsia://` references when a file or template needs a secret placeholder.
    - Use `authsia exec ... -- <command>` when a command needs real secret values.
    - Never run bare `authsia get`, `authsia read`, `authsia load`, `authsia code`, `authsia inject`, or any unprefixed `authsia ...` command from an agent.
    - Unprefixed Authsia commands are treated as direct human CLI and will not be attributed to the agent.
    - When your agent runs Authsia, every Authsia terminal command must start with:
      `env AUTHSIA_AGENT_PLATFORM=<claude-code|codex|cursor|windsurf|copilot> AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`
    - Every GitHub Copilot Authsia terminal command must start with:
      `env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`
    - If access is denied, ask the user to approve Authsia access instead of requesting the secret.

    ## Authsia Sandbox Handling

    - If sandboxed, request access to `Authsia.Bridge`, `Authsia.SSHAgent`, and `~/.authsia/agent.sock`.
    - If sandbox access is unavailable, request permission to run Authsia-backed commands outside the sandbox.
    - Treat missing `authsia`, missing `/Applications/Authsia.app`, missing `~/.authsia/agent.sock`, or bridge communication failures inside a sandbox as sandbox/runtime-boundary issues first.
    """

    private static let claudeSettingsJSON = """
    {
      "$schema": "https://json.schemastore.org/claude-code-settings.json",
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Write",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Edit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "MultiEdit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "LS",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Glob",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Grep",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          }
        ],
        "PostToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Write",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Edit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "MultiEdit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "LS",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Glob",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Grep",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          }
        ]
      },
      "sandbox": {
        "excludedCommands": [
          "authsia",
          "authsia *"
        ]
      }
    }
    """

    private static let claudeSettingsManualBlock = """
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Write",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Edit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "MultiEdit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "LS",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Glob",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Grep",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          }
        ],
        "PostToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Write",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Edit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "MultiEdit",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "LS",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Glob",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          },
          {
            "matcher": "Grep",
            "hooks": [
              {
                "type": "command",
                "command": "authsia agent record-command --platform claude-code --source hook"
              }
            ]
          }
        ]
      },
      "sandbox": {
        "excludedCommands": [
          "authsia",
          "authsia *"
        ]
      }
    }
    """

    private static let copilotSettingsJSON = """
    {
      "version": 1,
      "hooks": {
        "PreToolUse": [
          {
            "type": "command",
            "matcher": "Bash",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Read",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Write",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Edit",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "MultiEdit",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "LS",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Glob",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Grep",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          }
        ]
      }
    }
    """

    private static let copilotSettingsManualBlock = """
    {
      "version": 1,
      "hooks": {
        "PreToolUse": [
          {
            "type": "command",
            "matcher": "Bash",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Read",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Write",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Edit",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "MultiEdit",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "LS",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Glob",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          },
          {
            "type": "command",
            "matcher": "Grep",
            "command": "authsia agent record-command --platform copilot --source hook || true",
            "timeoutSec": 5
          }
        ]
      }
    }
    """

    private static func markdownPrefix(for agent: AgentTool) -> String? {
        switch agent {
        case .cursor:
            return """
            ---
            description: Use Authsia safely for secrets and agent workflows
            alwaysApply: true
            ---
            """
        case .windsurf:
            return """
            ---
            trigger: always_on
            ---
            """
        case .claudeCode, .codex, .copilot:
            return nil
        }
    }

    private static func groupedByRulePath(_ agents: [AgentTool]) -> [(rulePath: String, agents: [AgentTool])] {
        var groups: [(rulePath: String, agents: [AgentTool])] = []
        for agent in agents {
            if let index = groups.firstIndex(where: { $0.rulePath == agent.rulePath }) {
                groups[index].agents.append(agent)
            } else {
                groups.append((agent.rulePath, [agent]))
            }
        }
        return groups
    }

    private static func isGeneratedSharedRulesMarkdown(_ content: String) -> Bool {
        if content == legacySharedRulesMarkdown {
            return true
        }
        let agents = generatedAgents(in: content)
        return !agents.isEmpty && generatedSharedRulesVariants(for: agents).contains { variant in
            sharedRulesMarkdown(content, matchesGeneratedVariant: variant)
        }
    }

    private static func generatedAgents(in content: String) -> [AgentTool] {
        content.split(separator: "\n").compactMap { line in
            let trimmedLine = line.trimmingCharacters(in: .whitespaces)
            return AgentTool.allCases.first { agent in
                trimmedLine == "`env AUTHSIA_AGENT_PLATFORM=\(agent.platformName) " +
                    "AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`"
            }
        }
    }

    private static func sharedRulesMarkdown(_ content: String, matchesGeneratedVariant variant: String) -> Bool {
        content == variant
            || content == variant.replacingOccurrences(of: "\n\(agentShimWorkspaceGuidanceLine)", with: "")
    }

    private static func generatedSharedRules(_ content: String, contains agent: AgentTool) -> Bool {
        let agents = generatedAgents(in: content)
        return agents.contains(agent) && generatedSharedRulesVariants(for: agents).contains { variant in
            sharedRulesMarkdown(content, matchesGeneratedVariant: variant)
        }
    }

    private static func generatedSharedRulesVariants(for agents: [AgentTool]) -> [String] {
        var variants = [
            sharedRulesMarkdown(for: agents),
            sharedRulesMarkdown(for: agents, includeWorkspaceGuidance: true),
            sharedRulesMarkdown(for: agents, includeOutsideSandboxRule: false),
            sharedRulesMarkdown(
                for: agents,
                includeWorkspaceGuidance: true,
                includeOutsideSandboxRule: false
            ),
            sharedRulesMarkdown(for: agents, includeCommandHistoryGuidance: false),
            sharedRulesMarkdown(
                for: agents,
                includeWorkspaceGuidance: true,
                includeCommandHistoryGuidance: false
            ),
            sharedRulesMarkdown(
                for: agents,
                includeOutsideSandboxRule: false,
                includeCommandHistoryGuidance: false
            ),
            sharedRulesMarkdown(
                for: agents,
                includeWorkspaceGuidance: true,
                includeOutsideSandboxRule: false,
                includeCommandHistoryGuidance: false
            ),
        ]
        if agents.contains(.copilot) {
            variants.append(contentsOf: [
                sharedRulesMarkdown(for: agents, includeCopilotCommandHistoryGuidance: false),
                sharedRulesMarkdown(
                    for: agents,
                    includeWorkspaceGuidance: true,
                    includeCopilotCommandHistoryGuidance: false
                ),
                sharedRulesMarkdown(
                    for: agents,
                    includeOutsideSandboxRule: false,
                    includeCopilotCommandHistoryGuidance: false
                ),
                sharedRulesMarkdown(
                    for: agents,
                    includeWorkspaceGuidance: true,
                    includeOutsideSandboxRule: false,
                    includeCopilotCommandHistoryGuidance: false
                ),
            ])
        }
        return variants
    }

    // MARK: - Utilities

    private static func unique(_ agents: [AgentTool]) -> [AgentTool] {
        var seen: [AgentTool] = []
        for agent in agents where !seen.contains(agent) {
            seen.append(agent)
        }
        return seen
    }

    private static func appendSection(_ title: String, values: [String], to lines: inout [String]) {
        guard !values.isEmpty else { return }
        if !lines.isEmpty { lines.append("") }
        lines.append(title)
        lines.append(contentsOf: values.map { "  \($0)" })
    }

    private static func indent(_ text: String, by prefix: String) -> String {
        text.split(separator: "\n", omittingEmptySubsequences: false)
            .map { "\(prefix)\($0)" }
            .joined(separator: "\n")
    }
}
