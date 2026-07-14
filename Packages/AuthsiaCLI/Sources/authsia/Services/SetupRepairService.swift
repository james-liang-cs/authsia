import Foundation

struct SetupStatus: Equatable {
    let cliInstalled: Bool
    let shellIntegrationInstalled: Bool
    let bridgeReachable: Bool
    let sshAgentSocketExists: Bool
    let doctorIssueCount: Int
}

enum SetupStatusRenderer {
    static func render(_ status: SetupStatus) -> String {
        let rows: [(String, Bool)] = [
            ("Install CLI", status.cliInstalled),
            ("Install shell integration", status.shellIntegrationInstalled),
            ("Register bridge", status.bridgeReachable),
            ("Enable SSH agent", status.sshAgentSocketExists),
            ("Run doctor", status.doctorIssueCount == 0),
        ]

        var lines = ["Authsia setup status:"]
        lines += rows.map { title, ok in
            "  \(ok ? "OK" : "Needs attention")  \(title)"
        }
        return lines.joined(separator: "\n")
    }
}

struct SetupRepairResult: Equatable {
    var updatedFiles: [String] = []
    var removedFiles: [String] = []
}

enum SetupRepairService {
    enum Shell: CaseIterable {
        case zsh
        case bash

        var fileName: String {
            switch self {
            case .zsh: return ".zshrc"
            case .bash: return ".bashrc"
            }
        }

        var commandName: String {
            switch self {
            case .zsh: return "zsh"
            case .bash: return "bash"
            }
        }
    }

    static let shellIntegrationStartMarker = "# >>> Authsia shell integration >>>"
    static let shellIntegrationEndMarker = "# <<< Authsia shell integration <<<"

    static func repairShellIntegration(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        shells: [Shell] = Shell.allCases
    ) throws -> SetupRepairResult {
        var result = SetupRepairResult()
        for shell in shells {
            let url = homeDirectory.appendingPathComponent(shell.fileName)
            let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            let cleaned = removeLegacyShellEvalLines(in: existing, shellName: shell.commandName)
            let updated = upsertShellIntegrationBlock(in: cleaned, shellName: shell.commandName)
            guard updated != existing else { continue }
            try updated.write(to: url, atomically: true, encoding: .utf8)
            result.updatedFiles.append(shell.fileName)
        }
        return result
    }

    static func uninstallClean(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        shells: [Shell] = Shell.allCases
    ) throws -> SetupRepairResult {
        var result = SetupRepairResult()
        for shell in shells {
            let url = homeDirectory.appendingPathComponent(shell.fileName)
            guard let existing = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let cleaned = removeLegacyShellEvalLines(in: existing, shellName: shell.commandName)
            let updated = removeManagedShellIntegrationBlock(in: cleaned)
            guard updated != existing else { continue }
            try updated.write(to: url, atomically: true, encoding: .utf8)
            result.updatedFiles.append(shell.fileName)
        }
        try removeManagedUserSymlink(homeDirectory: homeDirectory, result: &result)
        return result
    }

    static func hasManagedShellIntegration(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) -> Bool {
        Shell.allCases.contains { shell in
            let url = homeDirectory.appendingPathComponent(shell.fileName)
            guard let content = try? String(contentsOf: url, encoding: .utf8) else { return false }
            return content.contains(shellIntegrationStartMarker) && content.contains(shellIntegrationEndMarker)
        }
    }

    static func upsertShellIntegrationBlock(in content: String, shellName: String) -> String {
        let block = """
        \(shellIntegrationStartMarker)
        if command -v authsia >/dev/null 2>&1; then
            eval "$(authsia init \(shellName))"
            eval "$(authsia completion \(shellName))"
        fi
        \(shellIntegrationEndMarker)
        """

        var base = content
        if let range = managedShellIntegrationRange(in: base) {
            base.removeSubrange(range)
        }

        let trimmedBase = base.trimmingCharacters(in: .newlines)
        if trimmedBase.isEmpty {
            return "\(block)\n"
        }
        return "\(trimmedBase)\n\n\(block)\n"
    }

    static func removeManagedShellIntegrationBlock(in content: String) -> String {
        var base = content
        if let range = managedShellIntegrationRange(in: base) {
            base.removeSubrange(range)
        }

        let trimmed = base.trimmingCharacters(in: .newlines)
        guard !trimmed.isEmpty else { return "" }
        return "\(trimmed)\n"
    }

    private static func removeLegacyShellEvalLines(in content: String, shellName: String) -> String {
        let lines = content.components(separatedBy: .newlines).filter { line in
            let normalized = line.trimmingCharacters(in: .whitespaces)
            guard !normalized.isEmpty else { return true }
            if normalized.contains("authsia init \(shellName)") && normalized.contains("eval") {
                return false
            }
            if normalized.contains("authsia completion \(shellName)") && normalized.contains("eval") {
                return false
            }
            return true
        }
        return lines.joined(separator: "\n")
    }

    private static func managedShellIntegrationRange(in content: String) -> Range<String.Index>? {
        guard let start = content.range(of: shellIntegrationStartMarker),
              let end = content.range(of: shellIntegrationEndMarker),
              start.lowerBound <= end.lowerBound else {
            return nil
        }
        var upperBound = end.upperBound
        if upperBound < content.endIndex, content[upperBound] == "\n" {
            upperBound = content.index(after: upperBound)
        }
        return start.lowerBound..<upperBound
    }

    private static func removeManagedUserSymlink(homeDirectory: URL, result: inout SetupRepairResult) throws {
        let relativePath = ".local/bin/authsia"
        let url = homeDirectory.appendingPathComponent(relativePath)
        guard let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: url.path),
              destination.contains("Authsia.app/Contents/Helpers/authsia") else {
            return
        }

        try FileManager.default.removeItem(at: url)
        result.removedFiles.append(relativePath)
    }
}
