import ArgumentParser
import AuthenticatorBridge
import Foundation

protocol ShellCompletionListClient {
    func listForShellCompletion() throws -> BridgeListPayload?
}

extension AuthsiaBridgeClient: ShellCompletionListClient {}

enum ShellCompletionMetadata {
    enum ItemKind: String, Hashable, CaseIterable {
        case password
        case apiKey = "api-key"
        case cert
        case note
        case ssh
        case otp
    }

    private struct Item {
        let name: String
        let kind: ItemKind
        let folderPath: String?

        var description: String {
            guard let folderPath, !folderPath.isEmpty else {
                return kind.rawValue
            }
            return "\(kind.rawValue) folder: \(folderPath)"
        }

        var plainRow: String {
            guard let folderPath, !folderPath.isEmpty else {
                return "\(name)\t\(kind.rawValue)"
            }
            return "\(name)\t\(kind.rawValue)\tfolder: \(folderPath)"
        }
    }

    static func completeItems(arguments: [String], wordIndex: Int, currentWord: String) -> [String] {
        completeItems(
            arguments: arguments,
            wordIndex: wordIndex,
            currentWord: currentWord,
            client: AuthsiaBridgeClient.shared
        )
    }

    static func completeItems(
        arguments: [String],
        wordIndex: Int,
        currentWord: String,
        client: ShellCompletionListClient,
        shell: CompletionShell? = CompletionShell.requesting
    ) -> [String] {
        guard let payload = try? client.listForShellCompletion() else { return [] }

        return completions(
            from: payload,
            allowedKinds: inferredAllowedKinds(from: arguments),
            folderPath: folderFilter(from: arguments),
            currentWord: currentWord,
            shell: shell
        )
    }

    static func completeFolders(arguments: [String], wordIndex: Int, currentWord: String) -> [String] {
        completeFolders(
            arguments: arguments,
            wordIndex: wordIndex,
            currentWord: currentWord,
            client: AuthsiaBridgeClient.shared
        )
    }

    static func completeFolders(
        arguments: [String],
        wordIndex: Int,
        currentWord: String,
        client: ShellCompletionListClient,
        shell: CompletionShell? = CompletionShell.requesting
    ) -> [String] {
        guard let payload = try? client.listForShellCompletion() else { return [] }

        return folderCompletions(
            from: payload,
            allowedKinds: inferredAllowedKinds(from: arguments),
            currentWord: currentWord,
            shell: shell
        )
    }

    static func completeGetFields(arguments: [String], wordIndex: Int, currentWord: String) -> [String] {
        fieldCompletions(arguments: ["get"] + arguments, currentWord: currentWord)
    }

    static func completeLoadFields(arguments: [String], wordIndex: Int, currentWord: String) -> [String] {
        fieldCompletions(arguments: ["load"] + arguments, currentWord: currentWord)
    }

    static func completeExecFields(arguments: [String], wordIndex: Int, currentWord: String) -> [String] {
        fieldCompletions(arguments: ["exec"] + arguments, currentWord: currentWord)
    }

    static func fieldCompletions(arguments: [String], currentWord: String) -> [String] {
        guard let kind = explicitKind(in: arguments) else { return [] }

        return fields(for: kind, command: fieldCompletionCommand(in: arguments))
            .filter { matchesCurrentWord($0, currentWord: currentWord) }
    }

    static func plainRows(
        from payload: BridgeListPayload,
        allowedKinds: Set<ItemKind>?,
        folderPath: String? = nil,
        currentWord: String
    ) -> [String] {
        matchingItems(
            from: payload,
            allowedKinds: allowedKinds,
            folderPath: folderPath,
            currentWord: currentWord
        )
            .map(\.plainRow)
    }

    static func completions(
        from payload: BridgeListPayload,
        allowedKinds: Set<ItemKind>?,
        folderPath: String? = nil,
        currentWord: String,
        shell: CompletionShell?
    ) -> [String] {
        let items = matchingItems(
            from: payload,
            allowedKinds: allowedKinds,
            folderPath: folderPath,
            currentWord: currentWord
        )
        switch shell {
        case .some(.zsh):
            return unique(items.map { zshEscape($0.name) })
        case .some(.fish):
            return items.map { "\($0.name)\t\($0.description)" }
        case .some(.bash):
            return unique(items.map(\.name))
        default:
            return items.map(\.plainRow)
        }
    }

    static func folderCompletions(
        from payload: BridgeListPayload,
        allowedKinds: Set<ItemKind>?,
        currentWord: String,
        shell: CompletionShell?
    ) -> [String] {
        let folders = unique(items(from: payload)
            .filter { allowedKinds?.contains($0.kind) ?? true }
            .compactMap { normalizeFolderPath($0.folderPath) }
            .flatMap(folderPrefixes)
            .filter { matchesCurrentWord($0, currentWord: currentWord) })

        switch shell {
        case .some(.zsh):
            return folders.map(zshEscape)
        case .some(.fish):
            return folders.map { "\($0)\tfolder" }
        default:
            return folders
        }
    }

    static func folderFilter(from arguments: [String]) -> String? {
        for argument in arguments {
            if argument.hasPrefix("--folder=") {
                return normalizeFolderPath(String(argument.dropFirst("--folder=".count)))
            }
        }

        for (index, argument) in arguments.enumerated() where argument == "--folder" || argument == "-f" {
            let nextIndex = arguments.index(after: index)
            guard arguments.indices.contains(nextIndex) else { continue }
            let value = arguments[nextIndex]
            guard !value.isEmpty, !value.hasPrefix("-") else { continue }
            return normalizeFolderPath(value)
        }

        return nil
    }

    private static func fieldCompletionCommand(in arguments: [String]) -> String {
        if arguments.contains("load") {
            return "load"
        }
        if arguments.contains("exec") {
            return "exec"
        }
        return "get"
    }

    private static func fields(for kind: ItemKind, command: String) -> [String] {
        switch command {
        case "load", "exec":
            return loadFields(for: kind)
        default:
            return getFields(for: kind)
        }
    }

    private static func getFields(for kind: ItemKind) -> [String] {
        switch kind {
        case .password:
            return ["username", "password", "all"]
        case .apiKey:
            return ["key", "all"]
        case .cert:
            return ["certificate", "privateKey", "all"]
        case .note:
            return ["content", "all"]
        case .ssh:
            return ["publicKey", "privateKey", "comment", "fingerprint", "keyType", "approvalPolicy", "boundHosts", "all"]
        case .otp:
            return []
        }
    }

    private static func loadFields(for kind: ItemKind) -> [String] {
        switch kind {
        case .password:
            return ["username", "password"]
        case .apiKey:
            return ["key"]
        case .cert:
            return ["certificate", "privateKey"]
        case .note:
            return ["content"]
        case .ssh, .otp:
            return []
        }
    }

    private static func matchingItems(
        from payload: BridgeListPayload,
        allowedKinds: Set<ItemKind>?,
        folderPath: String?,
        currentWord: String
    ) -> [Item] {
        let normalizedFolderPath = normalizeFolderPath(folderPath)
        return items(from: payload)
            .filter { !$0.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .filter { allowedKinds?.contains($0.kind) ?? true }
            .filter { item in
                guard let normalizedFolderPath else { return true }
                return normalizeFolderPath(item.folderPath) == normalizedFolderPath
            }
            .filter { matchesCurrentWord($0.name, currentWord: currentWord) }
    }

    private static func items(from payload: BridgeListPayload) -> [Item] {
        let passwords = payload.passwords
            .filter(\.isCliEnabled)
            .map { Item(name: $0.name, kind: .password, folderPath: $0.folderPath) }
        let apiKeys = payload.apiKeys
            .filter(\.isCliEnabled)
            .map { Item(name: $0.name, kind: .apiKey, folderPath: $0.folderPath) }
        let certificates = payload.certificates
            .filter(\.isCliEnabled)
            .map { Item(name: $0.name, kind: .cert, folderPath: $0.folderPath) }
        let notes = payload.notes
            .filter(\.isCliEnabled)
            .map { Item(name: $0.title, kind: .note, folderPath: $0.folderPath) }
        let sshKeys = payload.sshKeys
            .filter(\.isCliEnabled)
            .map { Item(name: $0.name, kind: .ssh, folderPath: $0.folderPath) }
        let accounts = payload.accounts
            .filter(\.isCliEnabled)
            .map { Item(name: $0.issuer, kind: .otp, folderPath: nil) }

        return passwords + apiKeys + certificates + notes + sshKeys + accounts
    }

    private static func matchesCurrentWord(_ name: String, currentWord: String) -> Bool {
        guard !currentWord.isEmpty else { return true }
        return name.range(of: currentWord, options: [.caseInsensitive, .diacriticInsensitive]) != nil
    }

    private static func inferredAllowedKinds(from arguments: [String]) -> Set<ItemKind>? {
        if let explicitKind = explicitKind(in: arguments) {
            return [explicitKind]
        }

        if arguments.contains("exec") {
            return [.password, .apiKey, .cert, .note]
        }
        if arguments.contains("load") {
            return [.password, .apiKey, .cert, .note, .ssh]
        }
        return nil
    }

    private static func explicitKind(in arguments: [String]) -> ItemKind? {
        for argument in arguments {
            if let kind = ItemKind(rawValue: argument) {
                return kind
            }
            if let pluralKind = pluralItemKind(argument) {
                return pluralKind
            }
        }

        for (index, argument) in arguments.enumerated() where argument == "--type" || argument == "-t" {
            let nextIndex = arguments.index(after: index)
            guard arguments.indices.contains(nextIndex) else { continue }
            if let kind = ItemKind(rawValue: arguments[nextIndex]) {
                return kind
            }
            if let pluralKind = pluralItemKind(arguments[nextIndex]) {
                return pluralKind
            }
        }

        return nil
    }

    private static func pluralItemKind(_ value: String) -> ItemKind? {
        switch value {
        case "passwords":
            return .password
        case "api-keys":
            return .apiKey
        case "certs":
            return .cert
        case "notes":
            return .note
        default:
            return nil
        }
    }

    private static func zshEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: ":", with: "\\:")
    }

    /// Expands a normalized folder path into every ancestor prefix so that
    /// intermediate folders are suggested, not only the leaf folders that
    /// directly contain an item. "Team/StackOps/dev" -> ["Team", "Team/StackOps", "Team/StackOps/dev"].
    private static func folderPrefixes(_ path: String) -> [String] {
        let segments = path.split(separator: "/").map(String.init)
        guard !segments.isEmpty else { return [] }
        return (1...segments.count).map { segments.prefix($0).joined(separator: "/") }
    }

    private static func normalizeFolderPath(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let normalized = folderPath
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return normalized.isEmpty ? nil : normalized
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
