import Foundation

actor ShellConfigService {
    private static let shellIntegrationStartMarker = "# >>> Authsia shell integration >>>"
    private static let shellIntegrationEndMarker = "# <<< Authsia shell integration <<<"
    
    struct ConfigChange {
        let filePath: String
        let originalLine: String
        let replacementLine: String
        let lineNumber: Int
        let secret: DetectedSecret
    }
    
    struct DiffResult {
        let filePath: String
        let changes: [ConfigChange]
        let additions: Int
        let deletions: Int
        let shellIntegrationBlock: String?
    }
    
    func generateDiff(for secrets: [DetectedSecret], folderPath: String? = nil) async -> [DiffResult] {
        let grouped = Dictionary(grouping: secrets) { $0.filePath }
        
        return grouped.map { filePath, secrets in
            let existingContent = try? String(contentsOfFile: filePath, encoding: .utf8)
            let shellIntegrationBlock = integrationDiffBlock(
                existingContent: existingContent,
                filePath: filePath,
                secrets: secrets
            )
            let changes = secrets.map { secret in
                ConfigChange(
                    filePath: filePath,
                    originalLine: secret.originalLine,
                    replacementLine: replacementLine(for: secret, folderPath: folderPath),
                    lineNumber: secret.lineNumber,
                    secret: secret
                )
            }
            
            return DiffResult(
                filePath: filePath,
                changes: changes,
                additions: changes.count * 2 + blockLineCount(shellIntegrationBlock),
                deletions: changes.count,
                shellIntegrationBlock: shellIntegrationBlock
            )
        }
    }
    
    func displayDiff(_ diffResults: [DiffResult]) {
        print("")
        print("📋 CHANGES TO BE APPLIED:")
        print("═══════════════════════════════════════════════════════════════")
        
        for result in diffResults {
            guard let firstChange = result.changes.first else { continue }
            print("")
            print("--- \(result.filePath)")
            print("+++ \(result.filePath)")
            print("@@ -\(firstChange.lineNumber),\(result.changes.count) +\(firstChange.lineNumber),\(result.changes.count * 2) @@")

            if let shellIntegrationBlock = result.shellIntegrationBlock {
                for line in shellIntegrationBlock.components(separatedBy: .newlines) where !line.isEmpty {
                    print("+\(line)")
                }
            }
            
            for change in result.changes {
                print("-\(change.secret.redactedOriginalLine)")
                print("+# Migrated to Authsia - Original: \(change.secret.key)")
                print("+\(change.replacementLine)")
            }
        }
        
        print("")
        print("═══════════════════════════════════════════════════════════════")
    }
    
    func applyChanges(
        _ secrets: [DetectedSecret],
        folderPath: String? = nil,
        dryRun: Bool = false
    ) async throws -> [String] {
        let grouped = Dictionary(grouping: secrets) { $0.filePath }
        
        var modifiedFiles: [String] = []
        
        for (filePath, fileSecrets) in grouped {
            guard FileManager.default.isReadableFile(atPath: filePath) else {
                throw ShellConfigError.fileNotReadable(filePath)
            }
            
            do {
                let content = try String(contentsOfFile: filePath, encoding: .utf8)
                var lines = content.components(separatedBy: .newlines)
                
                let sortedSecrets = fileSecrets.sorted { $0.lineNumber > $1.lineNumber }
                
                for secret in sortedSecrets {
                    let index = secret.lineNumber - 1
                    guard index >= 0 && index < lines.count else { continue }
                    guard lines[index] == secret.originalLine else {
                        throw ShellConfigError.staleLine(filePath, secret.lineNumber)
                    }
                    
                    if !dryRun {
                        lines[index] = "# Migrated to Authsia - Original: \(secret.key)"
                        lines.insert(replacementLine(for: secret, folderPath: folderPath), at: index + 1)
                    }
                }
                
                if !dryRun {
                    var newContent = lines.joined(separator: "\n")
                    if fileSecrets.contains(where: \.isShellConfig) {
                        newContent = upsertShellIntegrationBlock(in: newContent, filePath: filePath)
                    }
                    try AtomicFileWriter.writeString(newContent, toFile: filePath)
                    modifiedFiles.append(filePath)
                }
            } catch {
                throw ShellConfigError.modifyFailed(filePath, error.localizedDescription)
            }
        }
        
        return modifiedFiles
    }

    enum ShellIntegrationOutcome: Equatable {
        case added(String)
        case alreadyPresent
        case unsupported
    }

    /// Ensures the managed `authsia init` block exists in the user's shell startup file.
    /// SSH key adoption needs this so the Authsia agent socket is exported into new shells;
    /// without it adopted keys are stored but unusable until the user wires up the shell.
    func ensureShellIntegration(
        shellPath: String? = ProcessInfo.processInfo.environment["SHELL"],
        homeDirectory: String = NSHomeDirectory()
    ) -> ShellIntegrationOutcome {
        guard let rcPath = shellRCPath(shellPath: shellPath, home: homeDirectory),
              let shellName = shellName(for: rcPath) else {
            return .unsupported
        }

        let existing = (try? String(contentsOfFile: rcPath, encoding: .utf8)) ?? ""
        if hasShellIntegration(existing, shellName: shellName) {
            return .alreadyPresent
        }

        let updated = upsertShellIntegrationBlock(in: existing, filePath: rcPath)
        guard (try? AtomicFileWriter.writeString(updated, toFile: rcPath)) != nil else {
            return .unsupported
        }
        return .added(rcPath)
    }

    private func shellRCPath(shellPath: String?, home: String) -> String? {
        let shell = (shellPath as NSString?)?.lastPathComponent ?? ""
        let fileName: String
        switch shell {
        case "zsh":
            fileName = ".zshrc"
        case "bash":
            fileName = ".bashrc"
        default:
            return nil
        }
        return (home as NSString).appendingPathComponent(fileName)
    }

    private func hasShellIntegration(_ content: String, shellName: String) -> Bool {
        if content.contains(Self.shellIntegrationStartMarker) {
            return true
        }
        return content.components(separatedBy: .newlines).contains { line in
            let normalized = line.trimmingCharacters(in: .whitespaces)
            return normalized.contains("authsia init \(shellName)") && normalized.contains("eval")
        }
    }

    private func replacementLine(for secret: DetectedSecret, folderPath: String?) -> String {
        if secret.isShellConfig {
            return secret.shellReplacementLine(folderPath: folderPath)
        }
        return "\(secret.key)=$(\(secret.cliGetCommand))"
    }

    private func integrationDiffBlock(
        existingContent: String?,
        filePath: String,
        secrets: [DetectedSecret]
    ) -> String? {
        guard secrets.contains(where: \.isShellConfig),
              let existingContent else {
            return nil
        }

        let updatedContent = upsertShellIntegrationBlock(in: existingContent, filePath: filePath)
        guard updatedContent != existingContent else {
            return nil
        }
        return managedShellIntegrationBlock(filePath: filePath)
    }

    private func upsertShellIntegrationBlock(in content: String, filePath: String) -> String {
        guard let block = managedShellIntegrationBlock(filePath: filePath),
              let shellName = shellName(for: filePath) else {
            return content
        }

        let withoutLegacyEval = removeLegacyInitEvalLines(in: content, shellName: shellName)
        let withoutManagedBlock = removeManagedShellIntegrationBlock(in: withoutLegacyEval)
        let trimmed = withoutManagedBlock.trimmingCharacters(in: .newlines)
        guard !trimmed.isEmpty else {
            return "\(block)\n"
        }
        return "\(block)\n\n\(trimmed)\n"
    }

    private func managedShellIntegrationBlock(filePath: String) -> String? {
        guard let shellName = shellName(for: filePath) else {
            return nil
        }

        return """
        \(Self.shellIntegrationStartMarker)
        if command -v authsia >/dev/null 2>&1; then
            eval "$(authsia init \(shellName))"
        fi
        \(Self.shellIntegrationEndMarker)
        """
    }

    private func shellName(for filePath: String) -> String? {
        let fileName = (filePath as NSString).lastPathComponent
        switch fileName {
        case ".zshrc", ".zprofile":
            return "zsh"
        case ".bashrc", ".bash_profile", ".profile":
            return "bash"
        default:
            return nil
        }
    }

    private func removeLegacyInitEvalLines(in content: String, shellName: String) -> String {
        let lines = content.components(separatedBy: .newlines).filter { line in
            let normalized = line.trimmingCharacters(in: .whitespaces)
            guard !normalized.isEmpty else {
                return true
            }
            if normalized.contains("authsia init \(shellName)") && normalized.contains("eval") {
                return false
            }
            return true
        }
        return lines.joined(separator: "\n")
    }

    private func removeManagedShellIntegrationBlock(in content: String) -> String {
        var base = content
        if let range = managedShellIntegrationRange(in: base) {
            base.removeSubrange(range)
        }
        let trimmed = base.trimmingCharacters(in: .newlines)
        guard !trimmed.isEmpty else {
            return ""
        }
        return "\(trimmed)\n"
    }

    private func managedShellIntegrationRange(in content: String) -> Range<String.Index>? {
        guard let startRange = content.range(of: Self.shellIntegrationStartMarker),
              let endRange = content.range(of: Self.shellIntegrationEndMarker),
              startRange.lowerBound <= endRange.lowerBound else {
            return nil
        }

        var upperBound = endRange.upperBound
        if upperBound < content.endIndex, content[upperBound] == "\n" {
            upperBound = content.index(after: upperBound)
        }
        return startRange.lowerBound..<upperBound
    }

    private func blockLineCount(_ block: String?) -> Int {
        guard let block else { return 0 }
        return block.components(separatedBy: .newlines).filter { !$0.isEmpty }.count
    }
    
    enum ShellConfigError: LocalizedError {
        case fileNotReadable(String)
        case staleLine(String, Int)
        case modifyFailed(String, String)
        
        var errorDescription: String? {
            switch self {
            case .fileNotReadable(let path):
                return "Cannot read file: \(path)"
            case .staleLine(let path, let lineNumber):
                return "Refusing to rewrite \(path): line \(lineNumber) changed after scan."
            case .modifyFailed(let path, let reason):
                return "Failed to modify \(path): \(reason)"
            }
        }
    }
}
