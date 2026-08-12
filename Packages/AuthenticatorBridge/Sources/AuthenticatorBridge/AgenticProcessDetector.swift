import Foundation
#if os(macOS)
import Darwin
#endif

public struct AgenticProcessReference: Equatable, Sendable {
    public let processName: String
    public let bundleIdentifier: String?
    public let arguments: [String]

    public init(processName: String, bundleIdentifier: String?, arguments: [String] = []) {
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.arguments = arguments
    }
}

public struct AgenticParentProcessContext: Equatable {
    public let parent: ParentProcessInfo?
    public let host: ParentProcessInfo?

    public init(parent: ParentProcessInfo?, host: ParentProcessInfo?) {
        self.parent = parent
        self.host = host
    }
}

public enum AgenticProcessDetector {
    private static let knownProcessNames: Set<String> = [
        "claude",
        "claude-code",
        "codex",
        "cursor-agent",
        "github-copilot",
        "windsurf-agent",
    ]

    private static let automationSuspectProcessNames: Set<String> = [
        "appcode",
        "clion",
        "code-helper",
        "cursor",
        "cursor-helper",
        "fleet",
        "goland",
        "idea",
        "intellij-idea",
        "jetbrains-client",
        "phpstorm",
        "pycharm",
        "rider",
        "rubymine",
        "trae",
        "trae-helper",
        "visual-studio-code",
        "webstorm",
        "windsurf",
        "windsurf-helper",
        "devin",
        "devin-helper",
        "devin-desktop",
        "zed",
        "zed-helper",
    ]

    private static let automationSuspectBundleFragments: [String] = [
        "ai.windsurf",
        "com.cognition.devin",
        "com.cursor",
        "com.exafunction.windsurf",
        "com.jetbrains.",
        "com.microsoft.vscode",
        "com.todesktop.230313mzl4w4u92",
        "dev.zed.zed",
    ]

    private static let shellProcessNames: Set<String> = [
        "zsh", "bash", "sh", "fish", "dash", "tcsh", "csh", "ksh", "login",
    ]

    public static func containsAgenticProcess(_ ancestry: [AgenticProcessReference]) -> Bool {
        ancestry.contains {
            isAgenticProcess(
                processName: $0.processName,
                bundleIdentifier: $0.bundleIdentifier,
                arguments: $0.arguments
            )
        }
    }

    public static func containsAutomationSuspectProcess(_ ancestry: [AgenticProcessReference]) -> Bool {
        ancestry.contains {
            isAutomationSuspectProcess(
                processName: $0.processName,
                bundleIdentifier: $0.bundleIdentifier,
                arguments: $0.arguments
            )
        }
    }

    public static func parentProcessContext(from ancestry: [ParentProcessInfo]) -> AgenticParentProcessContext {
        var parent: ParentProcessInfo?

        for info in ancestry {
            if isShellProcess(info.processName) {
                continue
            }

            if parent == nil {
                parent = info
                continue
            }

            if isAgenticProcess(processName: info.processName, bundleIdentifier: info.bundleIdentifier)
                || isAutomationSuspectProcess(processName: info.processName, bundleIdentifier: info.bundleIdentifier) {
                return AgenticParentProcessContext(parent: parent, host: info)
            }
        }

        return AgenticParentProcessContext(parent: parent, host: nil)
    }

    public static func isAgenticProcess(
        processName: String?,
        bundleIdentifier: String?,
        arguments: [String] = []
    ) -> Bool {
        agentPlatform(processName: processName, bundleIdentifier: bundleIdentifier, arguments: arguments) != nil
    }

    public static func agentPlatform(
        processName: String?,
        bundleIdentifier: String?,
        arguments: [String] = []
    ) -> String? {
        if let normalizedName = normalizeProcessName(processName),
           let platform = platformName(forKnownAgentName: normalizedName) {
            return platform
        }

        if isGitHubCopilotHost(processName: processName, bundleIdentifier: bundleIdentifier, arguments: arguments) {
            return "copilot"
        }

        if let platform = agentPlatformReferencedByArguments(arguments) {
            return platform
        }

        guard let normalizedBundle = normalize(bundleIdentifier) else { return nil }
        if normalizedBundle.contains("com.anthropic.claude") {
            return "claude-code"
        }
        if normalizedBundle.contains("codex") {
            return "codex"
        }
        return nil
    }

    public static func isAutomationSuspectProcess(
        processName: String?,
        bundleIdentifier: String?,
        arguments: [String] = []
    ) -> Bool {
        if let normalizedName = normalizeProcessName(processName),
           automationSuspectProcessNames.contains(normalizedName) {
            return true
        }

        if argumentsReferenceAutomationSuspectHost(arguments) {
            return true
        }

        if arguments.contains(where: isExtensionHostArgument),
           normalizeProcessName(processName) == "electron" {
            return true
        }

        guard let normalizedBundle = normalize(bundleIdentifier) else { return false }
        return automationSuspectBundleFragments.contains { normalizedBundle.contains($0) }
    }

    /// Platform label for a process that *hosts* automation without being a known agent
    /// binary — IDEs and their Electron extension hosts. Shells are excluded: a shell is
    /// the vehicle automation runs through, never the host, and its lifetime is too short
    /// to anchor anything to.
    public static func automationSuspectPlatform(
        processName: String?,
        bundleIdentifier: String?,
        arguments: [String] = []
    ) -> String? {
        guard !isShellProcess(processName) else { return nil }
        guard isAutomationSuspectProcess(
            processName: processName,
            bundleIdentifier: bundleIdentifier,
            arguments: arguments
        ) else { return nil }
        return normalizeProcessName(processName)
    }

    public static func currentProcessAncestry(maxHops: Int = 8) -> [AgenticProcessReference] {
        #if os(macOS)
        processAncestry(startingAt: getpid(), maxHops: maxHops)
        #else
        []
        #endif
    }

    public static func processAncestry(startingAt pid: Int32, maxHops: Int = 8) -> [AgenticProcessReference] {
        #if os(macOS)
        var ancestry: [AgenticProcessReference] = []
        var current: Int32? = pid
        var seen = Set<Int32>()
        var hops = 0

        while let pid = current, pid > 1, hops < maxHops, !seen.contains(pid) {
            let arguments = processArguments(for: pid)
            ancestry.append(AgenticProcessReference(
                processName: processName(for: pid, arguments: arguments) ?? "unknown",
                bundleIdentifier: nil,
                arguments: arguments
            ))
            seen.insert(pid)
            current = TerminalSessionScope.parentProcessIdentifier(pid: pid)
            hops += 1
        }
        return ancestry
        #else
        return []
        #endif
    }

    private static func normalize(_ value: String?) -> String? {
        guard let value else { return nil }
        let normalized = value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "_", with: "-")
            .replacingOccurrences(of: " ", with: "-")
        return normalized.isEmpty ? nil : normalized
    }

    private static func normalizeProcessName(_ value: String?) -> String? {
        guard let normalized = normalize(value) else { return nil }
        let base = droppingRoleQualifier(normalized)
        guard base.hasSuffix(".exe") else { return base }
        return String(base.dropLast(".exe".count))
    }

    /// Electron names its child processes `X Helper (Plugin)`, `X Helper (Renderer)`,
    /// `X Helper (GPU)`. The parenthesized qualifier is the process role, not the
    /// application, so it must not defeat a name lookup: the suspect list holds the base
    /// name (`code-helper`), and `(Plugin)` is precisely the IDE extension host that
    /// spawns the automation worth classifying.
    private static func droppingRoleQualifier(_ normalizedValue: String) -> String {
        guard normalizedValue.hasSuffix(")"),
              let qualifier = normalizedValue.range(of: "-(", options: .backwards) else {
            return normalizedValue
        }
        let base = String(normalizedValue[normalizedValue.startIndex..<qualifier.lowerBound])
        return base.isEmpty ? normalizedValue : base
    }

    private static func isShellProcess(_ processName: String?) -> Bool {
        guard let normalizedName = normalizeProcessName(processName) else { return false }
        return shellProcessNames.contains(normalizedName)
    }

    /// Agent and IDE names double as ordinary words (`fleet`, `idea`, `rider`, `zed`) and
    /// as repository names (`claude`, `codex`), so an *operand* naming one proves nothing:
    /// `grep codex notes.txt` is not an agent, and a URL containing `cursor` is a request
    /// target, not the requester. Only a real filesystem path identifies a process there.
    private static func hostMatchingPathComponents(_ value: String) -> [String]? {
        guard value.contains("/"), !value.contains("://") else { return nil }
        let components = (value as NSString).pathComponents
        return components.isEmpty ? nil : components
    }

    /// argv[0] is the invoked command name and identifies the process even as a bare word:
    /// `codex` on PATH is a symlink to `codex-aarch64-apple-darwin`, which `proc_pidpath`
    /// resolves, so the process name never matches and argv[0] is the only remaining
    /// signal. Every later argument is an operand and must look like a path to count.
    private static func identityComponents(in arguments: [String]) -> [String] {
        arguments.enumerated().flatMap { index, value -> [String] in
            if let components = hostMatchingPathComponents(value) {
                return components
            }
            return index == 0 ? [value] : []
        }
    }

    private static func agentPlatformReferencedByArguments(_ arguments: [String]) -> String? {
        identityComponents(in: arguments).compactMap { component -> String? in
            guard let normalized = normalize(component) else { return nil }
            let withoutAppSuffix = normalized.hasSuffix(".app")
                ? String(normalized.dropLast(".app".count))
                : normalized
            // Only strip executable wrappers (.exe). Do not use generic
            // deletingPathExtension — that misattributes docs like CLAUDE.md.
            let withoutExeSuffix = withoutAppSuffix.hasSuffix(".exe")
                ? String(withoutAppSuffix.dropLast(".exe".count))
                : withoutAppSuffix
            return platformName(forKnownAgentName: withoutAppSuffix)
                ?? platformName(forKnownAgentName: withoutExeSuffix)
        }.first
    }

    private static func platformName(forKnownAgentName normalizedName: String) -> String? {
        guard knownProcessNames.contains(normalizedName) else { return nil }
        switch normalizedName {
        case "claude", "claude-code":
            return "claude-code"
        case "github-copilot":
            return "copilot"
        case "cursor-agent":
            return "cursor"
        case "windsurf-agent":
            return "devin"
        default:
            return normalizedName
        }
    }

    private static func isGitHubCopilotHost(
        processName: String?,
        bundleIdentifier: String?,
        arguments: [String]
    ) -> Bool {
        guard arguments.contains(where: argumentReferencesGitHubCopilotExtension) else {
            return false
        }
        if let normalizedName = normalizeProcessName(processName),
           automationSuspectProcessNames.contains(normalizedName) || normalizedName == "electron" {
            return true
        }
        if let normalizedBundle = normalize(bundleIdentifier),
           normalizedBundle.contains("com.microsoft.vscode") {
            return true
        }
        return arguments.contains(where: isExtensionHostArgument)
    }

    private static func argumentReferencesGitHubCopilotExtension(_ value: String) -> Bool {
        guard let normalized = normalize(value) else { return false }
        return normalized.contains("github.copilot") || normalized.contains("github-copilot")
    }

    private static func argumentsReferenceAutomationSuspectHost(_ arguments: [String]) -> Bool {
        identityComponents(in: arguments).contains { component in
            guard let normalized = normalize(component) else { return false }
            let withoutAppSuffix = normalized.hasSuffix(".app")
                ? String(normalized.dropLast(".app".count))
                : normalized
            let withoutExtension = (withoutAppSuffix as NSString).deletingPathExtension
            return automationSuspectProcessNames.contains(withoutAppSuffix)
                || automationSuspectProcessNames.contains(withoutExtension)
        }
    }

    private static func isExtensionHostArgument(_ value: String) -> Bool {
        normalize(value)?.contains("extensionhost") == true
    }

    #if os(macOS)
    private static let runtimeNames: Set<String> = ["node", "python", "python3", "ruby", "java", "bun", "deno"]

    private static func processName(for pid: pid_t, arguments: [String]) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard length > 0 else { return nil }
        let fullPath = pathBuffer
            .prefix(Int(length))
            .prefix { $0 != 0 }
            .map { UInt8(bitPattern: $0) }
        let baseName = (String(decoding: fullPath, as: UTF8.self) as NSString).lastPathComponent

        if runtimeNames.contains(baseName), let applicationName = applicationName(from: arguments) {
            return applicationName
        }
        return baseName
    }

    private static func applicationName(from arguments: [String]) -> String? {
        guard let argv0 = arguments.first else { return nil }
        let argv0Name = (argv0 as NSString).lastPathComponent
        if !runtimeNames.contains(argv0Name) {
            return argv0Name
        }
        // The token after the runtime is only the app name when it's a script
        // path, not an interpreter flag (e.g. `node --liftoff-only app.js`).
        // For a flag, keep the runtime basename so it shows as `node`, not the flag.
        guard let argv1 = arguments.dropFirst().first, !argv1.hasPrefix("-") else { return nil }
        return (argv1 as NSString).lastPathComponent
    }

    private static func processArguments(for pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else {
            return []
        }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        guard argc > 0 else { return [] }

        var offset = MemoryLayout<Int32>.size
        while offset < size && buffer[offset] != 0 { offset += 1 }
        while offset < size && buffer[offset] == 0 { offset += 1 }
        guard offset < size else { return [] }

        var arguments: [String] = []
        for _ in 0..<argc {
            guard offset < size else { break }
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            if start < offset,
               let argument = String(bytes: buffer[start..<offset], encoding: .utf8) {
                arguments.append(argument)
            }
            while offset < size && buffer[offset] == 0 { offset += 1 }
        }
        return arguments
    }
    #endif
}
