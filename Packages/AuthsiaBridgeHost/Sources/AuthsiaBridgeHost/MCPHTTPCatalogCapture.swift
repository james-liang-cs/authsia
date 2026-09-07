#if os(macOS)
import AuthenticatorBridge
import Foundation

/// Portal-originated localhost catalog capture. Initialization and tools/list
/// only; never tools/call. Secrets stay in the in-memory lease.
public enum MCPHTTPCatalogCapture {
    private static let toolLimit = 256
    private static let pageLimit = 8

    public static func run(
        endpoint: String,
        headers: [String: String],
        secrets: [String] = [],
        validate: (@Sendable () async throws -> Void)? = nil
    ) async throws -> [MCPUpstreamToolDescriptor] {
        let url = try MCPLocalHTTPEndpointValidator.validate(endpoint)
        let connection = MCPHTTPUpstreamConnection()
        defer { connection.close() }
        let version = "2025-06-18"
        let initialize = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0", "id": "authsia-catalog-init", "method": "initialize",
            "params": ["protocolVersion": version, "capabilities": [:], "clientInfo": ["name": "authsia-catalog", "version": "1.0"]],
        ])
        let (initBytes, initResponse) = try await connection.request(
            endpoint: url, method: "POST", body: initialize, version: version, sessionID: nil, headers: headers)
        let initData = try await MCPHTTPUpstreamConnection.collect(initBytes, response: initResponse)
        guard initResponse.statusCode == 200,
              let initObject = try JSONSerialization.jsonObject(with: initData) as? [String: Any],
              initObject["error"] == nil else { throw MCPManagementError.catalogStartupFailed }
        let sessionID = initResponse.value(forHTTPHeaderField: "MCP-Session-Id")
        let initialized = Data(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.utf8)
        let (note, noteStatus) = try await connection.request(
            endpoint: url, method: "POST", body: initialized, version: version, sessionID: sessionID, headers: headers)
        note.task.cancel()
        guard (200...299).contains(noteStatus.statusCode) else { throw MCPManagementError.catalogStartupFailed }
        var cursor: String?
        var descriptors: [MCPUpstreamToolDescriptor] = []
        for page in 1...pageLimit {
            try await validate?()
            var params: [String: Any] = [:]
            if let cursor { params["cursor"] = cursor }
            let list = try JSONSerialization.data(withJSONObject: [
                "jsonrpc": "2.0", "id": "authsia-catalog-list-\(page)", "method": "tools/list", "params": params,
            ])
            let (listBytes, listResponse) = try await connection.request(
                endpoint: url, method: "POST", body: list, version: version, sessionID: sessionID, headers: headers)
            let listData = try MCPHTTPMessageMasker(secrets: secrets).mask(
                try await MCPHTTPUpstreamConnection.collect(listBytes, response: listResponse))
            guard listResponse.statusCode == 200,
                  let object = try JSONSerialization.jsonObject(with: listData) as? [String: Any],
                  object["error"] == nil,
                  let result = object["result"] as? [String: Any],
                  let tools = result["tools"] as? [[String: Any]] else { throw MCPManagementError.catalogEmpty }
            let pageDescriptors = toolDescriptors(from: tools)
            if pageDescriptors.isEmpty && cursor == nil { throw MCPManagementError.catalogEmpty }
            descriptors.append(contentsOf: pageDescriptors)
            if descriptors.count > toolLimit { throw MCPManagementError.catalogIncomplete }
            let next = (result["nextCursor"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            if next == nil { break }
            if page == pageLimit { throw MCPManagementError.catalogIncomplete }
            cursor = next
        }
        guard !descriptors.isEmpty else { throw MCPManagementError.catalogEmpty }
        return descriptors
    }

    private static func toolDescriptors(from tools: [[String: Any]]) -> [MCPUpstreamToolDescriptor] {
        tools.compactMap { tool in
            guard let name = tool["name"] as? String, !name.isEmpty, name.utf8.count <= 128 else { return nil }
            let description = tool["description"] as? String ?? ""
            let schema = (tool["inputSchema"] as? [String: Any]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }
                .flatMap { try? JSONDecoder().decode(MCPJSONValue.self, from: $0) }
            return MCPUpstreamToolDescriptor(name: name, description: description, inputSchema: schema ?? .object(["type": .string("object")]))
        }
    }
}
#endif
