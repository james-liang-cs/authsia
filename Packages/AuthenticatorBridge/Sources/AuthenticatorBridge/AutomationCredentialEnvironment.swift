import Foundation

public enum AutomationCredentialEnvironment {
    public static let generalCredentialKey = "AUTHSIA_ACCESS_CREDENTIAL"
    public static let sshCredentialKey = "AUTHSIA_SSH_ACCESS_CREDENTIAL"
}

public enum AutomationCredentialScope {
    public enum Normalized: Equatable, Sendable {
        case global
        case folder(String)
        case folders([String])
    }

    private static let multiFolderStoragePrefix = "folders:v1:"

    public static func normalizeForCreation(_ scope: String?) -> Normalized? {
        guard let scope else { return .global }
        let trimmed = scope.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let normalized = normalizeFolderPath(trimmed) else {
            return nil
        }
        return .folder(normalized)
    }

    public static func normalizeForCreation(folderPaths: [String]) -> Normalized? {
        makeNormalizedScope(for: folderPaths)
    }

    public static func normalizeStored(_ scope: String?) -> Normalized? {
        guard let scope else { return .global }
        let trimmed = scope.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix(multiFolderStoragePrefix) {
            if let decoded = decodeMultiFolderScope(trimmed) {
                return decoded
            }
        }
        guard let normalized = normalizeFolderPath(trimmed) else { return nil }
        return .folder(normalized)
    }

    public static func storageValue(_ normalizedScope: Normalized) -> String? {
        switch normalizedScope {
        case .global:
            return nil
        case .folder(let scope):
            return scope
        case .folders(let scopes):
            guard let normalized = makeNormalizedScope(for: scopes) else { return nil }
            switch normalized {
            case .global:
                return nil
            case .folder(let scope):
                return scope
            case .folders(let paths):
                let data = (try? JSONEncoder().encode(paths)) ?? Data()
                return multiFolderStoragePrefix + data.base64EncodedString()
            }
        }
    }

    public static func isGlobal(_ normalizedScope: Normalized) -> Bool {
        if case .global = normalizedScope { return true }
        return false
    }

    public static func contains(itemFolderPath: String?, normalizedScope: Normalized) -> Bool {
        switch normalizedScope {
        case .global:
            return true
        case .folder(let scope):
            return folderMatches(itemFolderPath: itemFolderPath, filterFolderPath: scope)
        case .folders(let scopes):
            return scopes.contains {
                folderMatches(itemFolderPath: itemFolderPath, filterFolderPath: $0)
            }
        }
    }

    public static func displayName(_ scope: String?) -> String {
        guard let normalized = normalizeStored(scope) else { return scope ?? "all" }
        return displayName(normalized)
    }

    public static func displayName(_ normalizedScope: Normalized) -> String {
        switch normalizedScope {
        case .global:
            return "all"
        case .folder(let scope):
            return scope
        case .folders(let scopes):
            return scopes.joined(separator: ", ")
        }
    }

    private static func makeNormalizedScope(for folderPaths: [String]) -> Normalized? {
        let paths = normalizeFolderPaths(folderPaths)
        guard !paths.isEmpty else { return nil }
        if paths.count == 1, let path = paths.first {
            return .folder(path)
        }
        return .folders(paths)
    }

    private static func normalizeFolderPaths(_ folderPaths: [String]) -> [String] {
        var normalized: [String] = []
        for folderPath in folderPaths {
            guard let path = normalizeFolderPath(folderPath), !normalized.contains(path) else {
                continue
            }
            normalized.append(path)
        }
        return normalized
    }

    private static func decodeMultiFolderScope(_ storedScope: String) -> Normalized? {
        let encoded = String(storedScope.dropFirst(multiFolderStoragePrefix.count))
        guard let data = Data(base64Encoded: encoded),
              let paths = try? JSONDecoder().decode([String].self, from: data) else {
            return nil
        }
        return makeNormalizedScope(for: paths)
    }
}
