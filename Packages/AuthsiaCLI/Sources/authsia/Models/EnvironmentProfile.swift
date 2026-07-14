import Foundation

enum EnvironmentProfileScope: Codable, Equatable {
    case all
    case folders([String])

    var folderPaths: [String] {
        switch self {
        case .all:
            return []
        case .folders(let paths):
            return paths
        }
    }

    var displayName: String {
        switch self {
        case .all:
            return "all"
        case .folders(let paths):
            return paths.joined(separator: ", ")
        }
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case folderPaths
    }

    private enum Kind: String, Codable {
        case all
        case folders
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(Kind.self, forKey: .kind)
        switch kind {
        case .all:
            self = .all
        case .folders:
            let paths = try container.decode([String].self, forKey: .folderPaths)
            guard !paths.isEmpty else {
                throw DecodingError.dataCorruptedError(
                    forKey: .folderPaths,
                    in: container,
                    debugDescription: "Folder scope must include at least one folder."
                )
            }
            self = .folders(paths)
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .all:
            try container.encode(Kind.all, forKey: .kind)
        case .folders(let paths):
            try container.encode(Kind.folders, forKey: .kind)
            try container.encode(paths, forKey: .folderPaths)
        }
    }
}

struct EnvironmentProfile: Codable, Equatable, Identifiable {
    var id: String { name }

    let name: String
    let scope: EnvironmentProfileScope
    let defaultMachineId: String?

    var folderPath: String {
        folderPaths.first ?? "all"
    }

    var folderPaths: [String] {
        scope.folderPaths
    }

    var scopeDisplayName: String {
        scope.displayName
    }

    init(name: String, folderPath: String, defaultMachineId: String?) {
        self.init(name: name, scope: .folders([folderPath]), defaultMachineId: defaultMachineId)
    }

    init(name: String, scope: EnvironmentProfileScope, defaultMachineId: String?) {
        self.name = name
        self.scope = scope
        self.defaultMachineId = defaultMachineId
    }

    private enum CodingKeys: String, CodingKey {
        case name
        case scope
        case folderPath
        case folderPaths
        case defaultMachineId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        defaultMachineId = try container.decodeIfPresent(String.self, forKey: .defaultMachineId)

        if let decodedScope = try container.decodeIfPresent(EnvironmentProfileScope.self, forKey: .scope) {
            scope = decodedScope
        } else if let paths = try container.decodeIfPresent([String].self, forKey: .folderPaths) {
            guard !paths.isEmpty else {
                throw DecodingError.dataCorruptedError(
                    forKey: .folderPaths,
                    in: container,
                    debugDescription: "Folder scope must include at least one folder."
                )
            }
            scope = .folders(paths)
        } else {
            let path = try container.decode(String.self, forKey: .folderPath)
            scope = .folders([path])
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(scope, forKey: .scope)
        try container.encodeIfPresent(defaultMachineId, forKey: .defaultMachineId)

        if case .folders(let paths) = scope {
            try container.encode(paths, forKey: .folderPaths)
            if paths.count == 1 {
                try container.encode(paths[0], forKey: .folderPath)
            }
        }
    }
}
