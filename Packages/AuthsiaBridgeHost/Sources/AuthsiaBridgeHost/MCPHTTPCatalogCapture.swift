#if os(macOS)
import AuthenticatorBridge
import Foundation

/// Portal-originated localhost catalog capture. Initialization and tools/list
/// only; never tools/call. Secrets stay in the in-memory lease.
public enum MCPHTTPCatalogCapture {
    public static func run(endpoint: String, headers: [String: String], secrets: [String] = []) async throws -> [MCPUpstreamToolDescriptor] {
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
        let list = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0", "id": "authsia-catalog-list", "method": "tools/list", "params": [:],
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
        let descriptors: [MCPUpstreamToolDescriptor] = tools.prefix(256).compactMap { tool in
            guard let name = tool["name"] as? String, !name.isEmpty, name.utf8.count <= 128 else { return nil }
            let description = tool["description"] as? String ?? ""
            let schema = (tool["inputSchema"] as? [String: Any]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }
                .flatMap { try? JSONDecoder().decode(MCPJSONValue.self, from: $0) }
            return MCPUpstreamToolDescriptor(name: name, description: description, inputSchema: schema ?? .object(["type": .string("object")]))
        }
        guard !descriptors.isEmpty else { throw MCPManagementError.catalogEmpty }
        return descriptors
    }
}
#endif
