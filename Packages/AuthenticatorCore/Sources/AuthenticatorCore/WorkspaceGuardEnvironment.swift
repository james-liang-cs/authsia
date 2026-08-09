import Foundation

public enum WorkspaceGuardEnvironment {
    public static let shimInvocationEnvironmentName = "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"
    public static let shimDirectoryPrefix = "authsia-guard-"
    public static let guardEnvironmentNames = [
        "AUTHSIA_WORKSPACE_GUARD",
        "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR",
        "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH",
        shimInvocationEnvironmentName,
    ]

    public static func isGuarded(environment: [String: String]) -> Bool {
        if guardEnvironmentNames.contains(where: { !(environment[$0] ?? "").isEmpty }) {
            return true
        }
        return searchPaths(from: environment["PATH"]).contains(where: isShimDirectory)
    }

    public static func unguardedEnvironment(_ environment: [String: String]) -> [String: String] {
        guard isGuarded(environment: environment) else { return environment }
        var unguarded = environment
        for name in guardEnvironmentNames {
            unguarded.removeValue(forKey: name)
        }
        if let path = unguardedSearchPath(environment: environment) {
            unguarded["PATH"] = path
        }
        return unguarded
    }

    public static func unguardedSearchPath(environment: [String: String]) -> String? {
        let recordedShimDirectory = environment["AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"]
        let savedPath = environment["AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"]
        guard let candidate = (savedPath?.isEmpty == false) ? savedPath : environment["PATH"] else {
            return nil
        }
        let unguarded = candidate.split(separator: ":", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { $0 != recordedShimDirectory && !isShimDirectory($0) }
            .joined(separator: ":")
        return unguarded == environment["PATH"] ? nil : unguarded
    }

    public static func isShimDirectory(_ path: String) -> Bool {
        URL(fileURLWithPath: path).lastPathComponent.hasPrefix(shimDirectoryPrefix)
    }

    /// Builds a subshell command that keeps the parent guarded while the child receives
    /// the saved pre-guard PATH with every stale guard shim removed.
    public static func unguardedChildShellCommand(
        agentPlatform: String,
        command: String
    ) -> String {
        "(\(unguardedShellStatements(agentPlatform: agentPlatform, command: command).joined(separator: "; ")))"
    }

    public static func unguardedExecShellScript(command: String) -> String {
        "#!/bin/sh\n" + unguardedShellStatements(agentPlatform: nil, command: command).joined(separator: "\n")
    }

    private static func unguardedShellStatements(
        agentPlatform: String?,
        command: String
    ) -> [String] {
        let awkProgram = #"BEGIN { RS = ":"; ORS = "" } { entry = $0; sub(/.*\//, "", entry) } entry !~ /^authsia-guard-/ { printf "%s%s", sep, $0; sep = ":" }"#
        let unsetArguments = guardEnvironmentNames.map { "-u \($0)" }.joined(separator: " ")
        let agentEnvironment = agentPlatform.map {
            " AUTHSIA_AGENT_PLATFORM=\($0) AUTHSIA_AGENT_INVOKES_AUTHSIA=1"
        } ?? ""
        return [
            #"_authsia_path="${AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH:-$PATH}""#,
            #"_authsia_clean_path="$(printf '%s' "$_authsia_path" | /usr/bin/awk '"# + awkProgram + #"')" && _authsia_path="$_authsia_clean_path""#,
            "exec /usr/bin/env \(unsetArguments) PATH=\"$_authsia_path\"\(agentEnvironment) \(command)",
        ]
    }

    private static func searchPaths(from path: String?) -> [String] {
        (path ?? "")
            .split(separator: ":")
            .map(String.init)
            .filter { !$0.isEmpty }
    }
}
