#if os(macOS)
import CryptoKit
import Foundation

public struct MCPServerDefinition: Sendable {
    public let identity: MCPServerIdentity
    public let upstream: MCPUpstreamConfig
    public let revision: String
    public var serverID: String { MCPWorkspaceStore.serverID(identity) }
}

public struct MCPHeaderReference: Equatable, Sendable {
    public let type: String
    public let item: String
    public let field: String
    public let folder: String?
    public init(_ raw: String) throws {
        guard let url = URLComponents(string: raw), url.scheme == "authsia",
              let type = url.host, ["api-key", "password", "note", "cert"].contains(type),
              url.user == nil, url.password == nil, url.port == nil, url.fragment == nil,
              (url.queryItems ?? []).allSatisfy({ $0.name == "folder" }),
              (url.queryItems ?? []).count <= 1 else { throw MCPManagementError.invalidRequest }
        let parts = url.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false)
        guard (2...3).contains(parts.count), parts.first == "",
              let item = String(parts[1]).removingPercentEncoding, !item.isEmpty,
              !item.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw MCPManagementError.invalidRequest
        }
        let field = parts.count == 3 ? String(parts[2]) : (type == "api-key" ? "key" : type == "password" ? "password" : type == "cert" ? "certificate" : "content")
        let fields = type == "password" ? ["password", "username"] : type == "api-key" ? ["key"] : type == "cert" ? ["certificate", "privateKey"] : ["content"]
        guard fields.contains(field) else { throw MCPManagementError.invalidRequest }
        self.type = type; self.item = item; self.field = field
        self.folder = url.queryItems?.first?.value
    }
}

public enum MCPWorkspaceStore {
    public static let maximumBytes = 1_048_576
    public static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    public static func serverID(_ identity: MCPServerIdentity) -> String {
        String(digest(Data((identity.workspacePath + "\u{0}" + identity.upstreamName).utf8)).prefix(32))
    }
    public static func configurationURL(_ root: URL) throws -> URL {
        let canonical = root.resolvingSymlinksInPath().standardizedFileURL
        let file = canonical.appendingPathComponent(".authsia/workspace.json")
        guard file.resolvingSymlinksInPath().path.hasPrefix(canonical.path + "/") else {
            throw MCPManagementError.invalidRequest
        }
        return file
    }
    public static func readBytes(_ file: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= maximumBytes else {
            throw MCPManagementError.invalidRequest
        }
        let data = try Data(contentsOf: file)
        guard data.count <= maximumBytes else { throw MCPManagementError.invalidRequest }
        return data
    }
    public static func read(_ root: URL) throws -> [MCPServerDefinition] {
        let file = try configurationURL(root)
        return try decode(readBytes(file), root: root.resolvingSymlinksInPath().standardizedFileURL)
    }
    public static func definition(_ identity: MCPServerIdentity) throws -> MCPServerDefinition {
        guard let result = try read(URL(fileURLWithPath: identity.workspacePath)).first(where: { $0.identity == identity }) else {
            throw MCPManagementError.notFound
        }
        return result
    }
    public static func decode(_ data: Data, root: URL) throws -> [MCPServerDefinition] {
        struct Envelope: Decodable {
            struct Workspace: Decodable { let name: String; let authsiaFolder: String }
            let schemaVersion: Int; let workspace: Workspace; let mcpUpstreams: [MCPUpstreamConfig]?
        }
        guard data.count <= maximumBytes,
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              (1...3).contains(envelope.schemaVersion), !envelope.workspace.name.isEmpty,
              !envelope.workspace.authsiaFolder.isEmpty else { throw MCPManagementError.invalidRequest }
        var names = Set<String>()
        let upstreams = envelope.mcpUpstreams ?? []
        try MCPUpstreamValidator.validateCatalogBounds(upstreams)
        return try upstreams.map { upstream in
            guard MCPUpstreamValidator.isValidName(upstream.name), names.insert(upstream.name).inserted else {
                throw MCPManagementError.invalidRequest
            }
            try MCPUpstreamValidator.validate(upstream) { raw in
                guard raw.lowercased().hasPrefix("authsia://") else { return .notReference }
                return (try? MCPHeaderReference(raw)) != nil ? .permitted : .invalidOrUnsupported
            }
            guard Set(upstream.catalog.map(\.name)).count == upstream.catalog.count else { throw MCPManagementError.invalidRequest }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            return MCPServerDefinition(identity: MCPServerIdentity(workspaceRoot: root, upstreamName: upstream.name),
                                       upstream: upstream, revision: digest(try encoder.encode(upstream)))
        }
    }
}
#endif
