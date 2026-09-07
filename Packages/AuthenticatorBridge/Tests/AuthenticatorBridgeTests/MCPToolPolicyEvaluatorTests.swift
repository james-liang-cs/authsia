import XCTest
@testable import AuthenticatorBridge

final class MCPToolPolicyEvaluatorTests: XCTestCase {
    func testDecisionUsesDenyThenApproveThenAllowPrecedence() {
        let policy = MCPUpstreamToolPolicy(
            allow: ["read", "shared", "blocked"],
            approve: ["write", "shared", "blocked"],
            deny: ["blocked"]
        )

        XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "read", policy: policy), .allow)
        XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "write", policy: policy), .approve)
        XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "shared", policy: policy), .approve)
        XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "blocked", policy: policy), .deny)
        XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "unknown", policy: policy), .unlisted)
    }

    func testAdvertisedNamesPreserveOrderDeduplicateAndOmitDenied() {
        let policy = MCPUpstreamToolPolicy(
            allow: ["read", "shared", "read", "blocked"],
            approve: ["write", "shared", "blocked"],
            deny: ["blocked"]
        )

        XCTAssertEqual(
            MCPToolPolicyEvaluator.advertisedToolNames(in: policy),
            ["read", "shared", "write"]
        )
    }

    func testExistingWorkspaceJSONDefaultsRemainCompatible() throws {
        let data = Data(#"{"name":"filesystem","command":"npx"}"#.utf8)
        let decoded = try JSONDecoder().decode(MCPUpstreamConfig.self, from: data)

        XCTAssertEqual(decoded.transport, .stdio)
        XCTAssertEqual(decoded.args, [])
        XCTAssertEqual(decoded.env, [:])
        XCTAssertEqual(decoded.tools, MCPUpstreamToolPolicy())
        XCTAssertEqual(decoded.catalog, [])
    }
}
