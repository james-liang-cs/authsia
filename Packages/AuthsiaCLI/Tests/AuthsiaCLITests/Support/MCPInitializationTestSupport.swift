import Foundation
import MCP
import Testing

func assertCodexIDEInitialization(_ transport: InMemoryTransport) async throws {
    try await transport.connect()
    let responses = await transport.receive()
    // The IDE chat startup differs from Codex's global MCP status discovery.
    let request = #"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"experimental":{"codex/auth-change":{}},"extensions":{"openai/elicitation":{"form":{}},"openai/form":{}},"elicitation":{"form":{},"url":{}}},"clientInfo":{"name":"codex-mcp-client","title":"Codex","version":"0.154.0-alpha.6.1"}}}"#
    try await transport.send(Data(request.utf8))
    var iterator = responses.makeAsyncIterator()
    let data = try #require(await iterator.next())
    let reply = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(reply["error"] == nil)
    #expect((reply["result"] as? [String: Any])?["protocolVersion"] as? String == "2025-06-18")
    await transport.disconnect()
}
