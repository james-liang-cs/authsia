#if os(macOS)
import Foundation
import AuthenticatorBridge

/// Bounds bytes before decoding, then masks decoded JSON strings. SSE data is
/// decoded only after a complete event so secrets split across chunks are masked.
struct MCPHTTPMessageMasker: Sendable {
    let secrets: [String]
    func mask(_ data: Data) throws -> Data {
        guard data.count <= 4 * 1_024 * 1_024 else { throw MCPManagementError.busy }
        let json = try JSONSerialization.jsonObject(with: data)
        return try JSONSerialization.data(withJSONObject: value(json), options: [.fragmentsAllowed])
    }
    private func string(_ text: String) -> String {
        secrets.filter { !$0.isEmpty }.sorted { $0.count > $1.count }.reduce(text) {
            $0.replacingOccurrences(of: $1, with: "<concealed by authsia>")
        }
    }
    private func value(_ object: Any) -> Any {
        switch object {
        case let text as String: return string(text)
        case let array as [Any]: return array.map(value)
        case let dictionary as [String: Any]:
            var output: [String: Any] = [:]
            for (key, nested) in dictionary { output[string(key)] = value(nested) }
            return output
        default: return object
        }
    }
}

enum MCPHTTPProtocol {
    static let versions = ["2025-11-25", "2025-06-18", "2025-03-26"]
}

struct MCPHTTPSSEDecoder {
    var line = Data()
    var lines: [String] = []
    var eventBytes = 0
    private var previousWasCR = false
    private var firstLine = true
    mutating func append(_ byte: UInt8) throws -> Data? {
        eventBytes += 1
        guard eventBytes <= 4 * 1_024 * 1_024 else { throw MCPManagementError.busy }
        if previousWasCR {
            previousWasCR = false
            if byte == 10 { return nil }
        }
        guard byte == 10 || byte == 13 else { line.append(byte); return nil }
        previousWasCR = byte == 13
        if firstLine {
            firstLine = false
            if line.starts(with: [0xef, 0xbb, 0xbf]) { line.removeFirst(3) }
        }
        guard String(data: line, encoding: .utf8) != nil else { throw MCPManagementError.invalidRequest }
        let text = String(decoding: line, as: UTF8.self)
        line.removeAll(keepingCapacity: true)
        if !text.isEmpty { lines.append(text); return nil }
        defer { lines.removeAll(keepingCapacity: true); eventBytes = 0 }
        let fields = lines.filter { $0.hasPrefix("data:") }.map { value -> String in
            let field = String(value.dropFirst(5)); return field.first == " " ? String(field.dropFirst()) : field
        }
        if fields.isEmpty { return Data() }
        return Data(fields.joined(separator: "\n").utf8)
    }
}

final class MCPLoopbackSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class MCPHTTPUpstreamConnection: @unchecked Sendable {
    private let session: URLSession
    init() {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]; config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil; config.urlCache = nil
        config.timeoutIntervalForRequest = 120; config.timeoutIntervalForResource = 120
        session = URLSession(configuration: config, delegate: MCPLoopbackSessionDelegate(), delegateQueue: nil)
    }
    func close() { session.invalidateAndCancel() }
    func request(endpoint: URL, method: String, body: Data?, version: String, sessionID: String?,
                 headers: [String: String]) async throws -> (URLSession.AsyncBytes, HTTPURLResponse) {
        // Canonical literal peer: no DNS or redirects can escape loopback.
        let url = try MCPLocalHTTPEndpointValidator.validate(endpoint.absoluteString)
        var request = URLRequest(url: url)
        request.httpMethod = method; request.httpBody = body
        request.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(version, forHTTPHeaderField: "MCP-Protocol-Version")
        if let sessionID { request.setValue(sessionID, forHTTPHeaderField: "MCP-Session-Id") }
        for (name,value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        let (bytes,response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse, !(300...399).contains(response.statusCode) else {
            bytes.task.cancel(); throw MCPManagementError.unavailable
        }
        return (bytes,response)
    }
    static func collect(_ bytes: URLSession.AsyncBytes, response: HTTPURLResponse) async throws -> Data {
        var data = Data(), decoder = MCPHTTPSSEDecoder()
        let isSSE = response.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("text/event-stream") == true
        for try await byte in bytes {
            if isSSE {
                if let message = try decoder.append(byte), !message.isEmpty {
                    let object = try JSONSerialization.jsonObject(with: message) as? [String: Any]
                    if object?["result"] != nil || object?["error"] != nil { bytes.task.cancel(); return message }
                    if object?["id"] != nil { throw MCPManagementError.unsupported }
                }
            } else {
                guard data.count < 4 * 1_024 * 1_024 else { bytes.task.cancel(); throw MCPManagementError.busy }
                data.append(byte)
            }
        }
        return data
    }
}
#endif
