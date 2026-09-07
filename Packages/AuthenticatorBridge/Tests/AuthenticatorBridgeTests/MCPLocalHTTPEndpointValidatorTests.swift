import XCTest
@testable import AuthenticatorBridge

final class MCPLocalHTTPEndpointValidatorTests: XCTestCase {
    func testAcceptsOnlyExplicitLoopbackHTTPPorts() throws {
        XCTAssertEqual(
            try MCPLocalHTTPEndpointValidator.validate("http://127.0.0.1:9000/mcp").absoluteString,
            "http://127.0.0.1:9000/mcp"
        )
        XCTAssertEqual(
            try MCPLocalHTTPEndpointValidator.validate("http://localhost:9000/mcp").host,
            "127.0.0.1"
        )
        XCTAssertEqual(
            try MCPLocalHTTPEndpointValidator.validate("http://[::1]:9000/mcp").host,
            "::1"
        )
    }

    func testRejectsRemoteHTTPSCredentialsQueriesAndManagerPorts() {
        let rejected = [
            "https://127.0.0.1:9000/mcp",
            "http://example.com:9000/mcp",
            "http://127.0.0.1/mcp",
            "http://user:pass@127.0.0.1:9000/mcp",
            "http://127.0.0.1:9000/mcp?token=synthetic",
            "http://127.0.0.1:9000/mcp#fragment",
            "http://127.0.0.1:8787/mcp",
            "http://127.0.0.1:8788/mcp",
        ]
        for value in rejected {
            XCTAssertThrowsError(try MCPLocalHTTPEndpointValidator.validate(value), value)
        }
    }

    func testHTTPDeclarationRequiresValidReferenceOnlyCredentialHeaders() throws {
        let upstream = MCPUpstreamConfig(
            name: "internal",
            transport: .streamableHTTP,
            url: "http://127.0.0.1:9000/mcp",
            tools: MCPUpstreamToolPolicy(allow: ["read"]),
            credentialHeaders: [
                MCPUpstreamCredentialHeader(
                    headerName: "X-API-Key",
                    reference: "authsia://api-key/Internal/key",
                    format: .raw
                ),
            ]
        )
        try MCPUpstreamValidator.validate(upstream) { value in
            value.hasPrefix("authsia://") ? .permitted : .notReference
        }

        var forbidden = upstream
        forbidden.credentialHeaders[0].headerName = "MCP-Session-Id"
        XCTAssertThrowsError(
            try MCPUpstreamValidator.validate(forbidden) { _ in .permitted }
        )
    }
}
