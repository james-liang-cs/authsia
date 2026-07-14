import Foundation

enum SSHConfigWriter {
    struct HostEntry: Equatable {
        let host: String
        let hostname: String
        let user: String?
        let keyName: String
    }

    static func upsertHostEntry(
        host: String,
        keyName: String,
        configPath: String
    ) throws {
        try upsertHostEntry(
            entry: HostEntry(host: host, hostname: host, user: nil, keyName: keyName),
            configPath: configPath
        )
    }

    static func upsertHostEntry(
        entry: HostEntry,
        configPath: String
    ) throws {
        let url = URL(fileURLWithPath: configPath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)

        let block = render(entry: entry)

        let existing = (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? ""
        let updated = upsert(host: entry.host, block: block, into: existing)
        try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
    }

    private static func render(entry: HostEntry) -> String {
        var lines = [
            "Host \(entry.host)",
            "    HostName \(entry.hostname)"
        ]

        if let user = entry.user?.trimmingCharacters(in: .whitespacesAndNewlines), !user.isEmpty {
            lines.append("    User \(user)")
        }

        lines.append("    IdentityAgent $SSH_AUTH_SOCK")
        lines.append("    IdentitiesOnly yes")
        lines.append("    # Key managed by Authsia — served by built-in Authsia agent")
        return lines.joined(separator: "\n")
    }

    private static func upsert(host: String, block: String, into content: String) -> String {
        let normalizedBlock = block.hasSuffix("\n") ? block : block + "\n"
        let lines = content.isEmpty ? [] : content.components(separatedBy: .newlines)
        var output: [String] = []
        var index = 0
        var replaced = false

        while index < lines.count {
            let line = lines[index]
            if line == "Host \(host)" {
                if !replaced {
                    output.append(contentsOf: normalizedBlock.trimmingCharacters(in: .newlines).components(separatedBy: .newlines))
                    replaced = true
                }
                index += 1
                while index < lines.count, !lines[index].hasPrefix("Host ") {
                    index += 1
                }
                continue
            }

            output.append(line)
            index += 1
        }

        if !replaced {
            if !output.isEmpty, !output.last!.isEmpty {
                output.append("")
            }
            output.append(contentsOf: normalizedBlock.trimmingCharacters(in: .newlines).components(separatedBy: .newlines))
        }

        return output.joined(separator: "\n").trimmingCharacters(in: .newlines) + "\n"
    }
}
