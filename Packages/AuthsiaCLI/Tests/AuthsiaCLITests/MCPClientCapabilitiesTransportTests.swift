import Foundation
import Testing
@testable import authsia

struct MCPClientCapabilitiesTransportTests {
    @Test("normalization preserves tool arguments, malformed requests, and ordinary initialization")
    func passThrough() {
        for json in [
            #"{"method":"tools/call","params":{"name":"read","capabilities":{"experimental":{"opaque":{}}}}}"#,
            #"{"method":"initialize","params":{"capabilities":{"experimental":42}}}"#,
            #"{"method":"initialize","params":{"capabilities":{"roots":{"listChanged":true}}}}"#,
            "malformed",
        ] {
            let data = Data(json.utf8)
            #expect(MCPClientCapabilitiesTransport.normalizedInitialization(data) == data)
        }
    }

    @Test("normalization ignores only unsupported experimental capability data")
    func preservesSupportedCapabilities() throws {
        let original = Data(#"{"jsonrpc":"2.0","id":"probe","method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"Codex","version":"1"},"capabilities":{"experimental":{"opaque":{}},"roots":{"listChanged":true},"extensions":{"unknown":{}}}}}"#.utf8)
        var expected = try JSONSerialization.jsonObject(with: original) as! [String: Any]
        var params = expected["params"] as! [String: Any]
        var capabilities = params["capabilities"] as! [String: Any]
        capabilities.removeValue(forKey: "experimental")
        params["capabilities"] = capabilities
        expected["params"] = params
        let actual = try JSONSerialization.jsonObject(with: MCPClientCapabilitiesTransport.normalizedInitialization(original)) as! NSDictionary
        #expect(actual == expected as NSDictionary)
    }
}
