import Foundation

struct WorkspaceGuardedTerminalPlan: Equatable {
    let workspaceRoot: URL
    let shimDirectory: URL
    let tools: [String]
    let aliasTools: [String]
    let unsetEnvironmentNames: [String]
    let environment: [String: String]
    let originalSearchPaths: [String]

    init(
        workspaceRoot: URL,
        shimDirectory: URL,
        tools: [String],
        aliasTools: [String] = [],
        unsetEnvironmentNames: [String] = [],
        environment: [String: String],
        originalSearchPaths: [String]
    ) {
        self.workspaceRoot = workspaceRoot
        self.shimDirectory = shimDirectory
        self.tools = tools
        self.aliasTools = aliasTools
        self.unsetEnvironmentNames = unsetEnvironmentNames
        self.environment = environment
        self.originalSearchPaths = originalSearchPaths
    }
}

struct WorkspaceGuardedTerminalInstallResult: Equatable {
    let shimDirectory: URL
    let installedTools: [String]
    let skippedTools: [String]
}

enum WorkspaceGuardedTerminal {
    // Agent harnesses, language servers, MCP servers, and plugin hooks spawn
    // launchers recursively during startup. Shimming those routes startup work
    // through `workspace run` and eagerly resolves workspace secrets at agent
    // launch. Commands that genuinely need secrets can run via explicit
    // `authsia workspace run -- <tool> ...` or opt in with `--tool <name>`.
    static let defaultTools = [
        "npm", "pnpm", "yarn",
        "python", "python3", "pip", "pip3", "poetry", "uv",
        "docker", "docker-compose", "kubectl", "helm", "kustomize", "skaffold", "tilt",
        "aws", "gcloud", "az", "doctl", "flyctl",
        "terraform", "tofu", "terragrunt", "pulumi", "cdk", "sam", "serverless", "sls",
        "ansible", "ansible-playbook", "packer",
        "swift", "go", "cargo", "make", "just", "task", "mvn", "gradle",
    ]

    static let blockedDefaultTools = [
        "curl", "echo", "env", "printenv", "cat", "osascript", "sh", "bash", "zsh",
        "vault", "op",
    ]

    /// Set to "1" in the environment of every tool invocation that reaches
    /// `workspace run` through a guarded-terminal shim or shell wrapper, so the
    /// run command can tell implicit shim traffic from explicit CLI calls.
    static let shimInvocationEnvironmentName = "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"

    static let shellExpansionWarning =
        "Guarded terminal does not make shell-expanded secrets safe. " +
        "Commands like `curl $API_KEY` or `curl ${API_KEY}` expand before Authsia can mediate them. " +
        "Use `authsia workspace run --shell -- 'curl \"$API_KEY\"'` for that case."

    static func plan(
        workspaceRoot: URL,
        tools: [String],
        aliasTools: [String] = [],
        unsetEnvironmentNames: [String] = [],
        baseTemporaryDirectory: URL = FileManager.default.temporaryDirectory,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> WorkspaceGuardedTerminalPlan {
        let sessionName = "authsia-guard-\(UUID().uuidString)"
        let shimDirectory = baseTemporaryDirectory.appendingPathComponent(sessionName, isDirectory: true)
        let searchPaths = searchPaths(from: environment["PATH"])
        let resolvedTools = uniqueTools(tools)
        let aliasesToClear = uniqueTools(resolvedTools + aliasTools).filter { resolvedTools.contains($0) }
        return WorkspaceGuardedTerminalPlan(
            workspaceRoot: workspaceRoot,
            shimDirectory: shimDirectory,
            tools: resolvedTools,
            aliasTools: aliasesToClear,
            unsetEnvironmentNames: environmentNamesToUnset(from: unsetEnvironmentNames),
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDirectory.path,
                "AUTHSIA_WORKSPACE_ROOT": workspaceRoot.path,
                "PATH": "\(shimDirectory.path):$PATH",
            ],
            originalSearchPaths: searchPaths
        )
    }

    static func install(
        _ plan: WorkspaceGuardedTerminalPlan,
        authsiaExecutablePath: String,
        fileManager: FileManager = .default
    ) throws -> WorkspaceGuardedTerminalInstallResult {
        try fileManager.createDirectory(at: plan.shimDirectory, withIntermediateDirectories: true)
        var installedTools: [String] = []
        var skippedTools: [String] = []

        for tool in plan.tools {
            guard let toolPath = resolveToolPath(
                tool,
                searchPaths: plan.originalSearchPaths,
                fileManager: fileManager
            ) else {
                skippedTools.append(tool)
                continue
            }

            let shimURL = plan.shimDirectory.appendingPathComponent(tool)
            let script = shimScript(
                authsiaExecutablePath: authsiaExecutablePath,
                toolPath: toolPath
            )
            try script.write(to: shimURL, atomically: true, encoding: .utf8)
            try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: shimURL.path)
            installedTools.append(tool)
        }

        return WorkspaceGuardedTerminalInstallResult(
            shimDirectory: plan.shimDirectory,
            installedTools: installedTools,
            skippedTools: skippedTools
        )
    }

    /// Best-effort removal of stale guarded-terminal shim directories left by prior
    /// sessions. Every guarded shell mints a new `authsia-guard-<uuid>` dir and nothing
    /// tears it down on shell exit, so they pile up in the temp dir until the OS sweeps
    /// it (only after a reboot, on infrequently-restarted machines). On each new guard
    /// setup we prune siblings older than `age`, skipping the directory we just created.
    /// The age threshold is a proxy for "belongs to a dead shell" — a dir touched within
    /// the last 8 hours likely backs another live shell (a workday-length session), so we
    /// leave it.
    @discardableResult
    static func cleanupStaleShimDirectories(
        in baseTemporaryDirectory: URL = FileManager.default.temporaryDirectory,
        keeping currentShimDirectory: URL? = nil,
        olderThan age: TimeInterval = 28_800,
        now: Date = Date(),
        fileManager: FileManager = .default
    ) -> [URL] {
        let currentPath = currentShimDirectory?.standardizedFileURL.path
        guard let entries = try? fileManager.contentsOfDirectory(
            at: baseTemporaryDirectory,
            includingPropertiesForKeys: [.isDirectoryKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        var removed: [URL] = []
        for entry in entries {
            guard entry.lastPathComponent.hasPrefix("authsia-guard-") else { continue }
            if entry.standardizedFileURL.path == currentPath { continue }

            let values = try? entry.resourceValues(forKeys: [.isDirectoryKey, .contentModificationDateKey])
            guard values?.isDirectory == true else { continue }
            guard let modified = values?.contentModificationDate,
                  now.timeIntervalSince(modified) > age else { continue }

            do {
                try fileManager.removeItem(at: entry)
                removed.append(entry)
            } catch {
                // Best-effort: a dir we can't remove (permissions, race with another
                // session deleting it) is skipped silently. Cleanup must never break guard setup.
            }
        }
        return removed.sorted { $0.path < $1.path }
    }

    static func resolveToolPath(
        _ tool: String,
        searchPaths: [String],
        fileManager: FileManager = .default
    ) -> String? {
        for directory in searchPaths {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(tool).path
            guard fileManager.isExecutableFile(atPath: candidate) else { continue }
            return candidate
        }
        return nil
    }

    static func shimScript(
        authsiaExecutablePath: String,
        toolPath: String
    ) -> String {
        """
        #!/bin/sh
        export \(shimInvocationEnvironmentName)=1
        exec \(shellQuoted(authsiaExecutablePath)) workspace run -- \(shellQuoted(toolPath)) "$@"
        """
    }

    static func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    static func shellWrapperExports(authsiaExecutablePath: String = "authsia", aliasTools: [String] = []) -> String {
        let aliasesToClear = uniqueTools(aliasTools + ["python", "python3", "pip", "pip3"])
            .map { "unalias \(shellQuoted($0)) 2>/dev/null || true" }
            .joined(separator: "\n")
        return """
        _authsia_guard_path_without_shim() {
            printf '%s' "$PATH" | awk -v shim="$AUTHSIA_WORKSPACE_GUARD_SHIM_DIR" '
                BEGIN { RS = ":"; ORS = "" }
                $0 != shim { printf "%s%s", sep, $0; sep = ":" }
            '
        }

        _authsia_guard_run() {
            _authsia_guard_tool="$1"
            shift
            _authsia_guard_saved_path="$PATH"
            if [ -n "${AUTHSIA_WORKSPACE_GUARD_SHIM_DIR:-}" ]; then
                PATH="$(_authsia_guard_path_without_shim)"
            fi
            _authsia_guard_resolved="$(command -v "$_authsia_guard_tool")"
            _authsia_guard_ec=$?
            PATH="$_authsia_guard_saved_path"
            if [ "$_authsia_guard_ec" -ne 0 ] || [ -z "$_authsia_guard_resolved" ]; then
                printf '%s\\n' "Authsia guarded terminal could not find $_authsia_guard_tool" >&2
                return 127
            fi
            \(shimInvocationEnvironmentName)=1 command \(shellQuoted(authsiaExecutablePath)) workspace run -- "$_authsia_guard_resolved" "$@"
        }
        \(aliasesToClear)
        function python { _authsia_guard_run python "$@"; }
        function python3 { _authsia_guard_run python3 "$@"; }
        function pip { _authsia_guard_run pip "$@"; }
        function pip3 { _authsia_guard_run pip3 "$@"; }
        """
    }

    static func unsetEnvironmentExports(_ names: [String]) -> String {
        environmentNamesToUnset(from: names)
            .map { name in
                "case \"${\(name)-}\" in authsia://*) ;; *) unset \(name) 2>/dev/null || true ;; esac"
            }
            .joined(separator: "\n")
    }

    /// Requested tool names that will not be shimmed because they are blocked,
    /// in first-requested order and de-duplicated. Lets callers tell the user why
    /// an explicit `--tool` request was dropped.
    static func blockedTools(in tools: [String]) -> [String] {
        let blocked = Set(blockedDefaultTools)
        var seen = Set<String>()
        return tools.compactMap { raw in
            let tool = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard blocked.contains(tool), seen.insert(tool).inserted else { return nil }
            return tool
        }
    }

    static func shimmableTools(from tools: [String]) -> [String] {
        uniqueTools(tools)
    }

    static func environmentNamesToUnset(from names: [String]) -> [String] {
        var seen = Set<String>()
        return names.compactMap { raw in
            let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard WorkspaceConfigStore.isValidEnvironmentName(name),
                  !protectedEnvironmentNames.contains(name),
                  seen.insert(name).inserted else {
                return nil
            }
            return name
        }
    }

    private static func uniqueTools(_ tools: [String]) -> [String] {
        // Blocked names (shells, secret-printing tools, third-party secret managers)
        // are never shimmed — even when explicitly requested via `--tool`. A name-based
        // shim either gives a false sense of safety (shell expansion happens before the
        // shim sees args) or routes secret output outside Authsia's masking boundary.
        let blocked = Set(blockedDefaultTools)
        var seen = Set<String>()
        return tools.compactMap { raw in
            let tool = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !tool.isEmpty, !blocked.contains(tool), seen.insert(tool).inserted else { return nil }
            return tool
        }
    }

    private static let protectedEnvironmentNames: Set<String> = [
        "PATH",
        "AUTHSIA_WORKSPACE_GUARD",
        "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR",
        "AUTHSIA_WORKSPACE_ROOT",
        "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH",
    ]

    private static func searchPaths(from path: String?) -> [String] {
        (path ?? "")
            .split(separator: ":")
            .map(String.init)
            .filter { !$0.isEmpty }
    }
}
