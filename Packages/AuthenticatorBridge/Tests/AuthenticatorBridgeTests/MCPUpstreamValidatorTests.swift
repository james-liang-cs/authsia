import XCTest
@testable import AuthenticatorBridge

final class MCPUpstreamValidatorTests: XCTestCase {
    func testValidatesExistingStdioDeclaration() throws {
        try MCPUpstreamValidator.validate(
            MCPUpstreamConfig(
                name: "filesystem",
                command: "npx",
                args: ["-y", "fixture-server"],
                tools: MCPUpstreamToolPolicy(allow: ["read_file"])
            )
        )
    }

    func testRejectsSecretNamedLiteralEnvironmentValue() {
        XCTAssertThrowsError(
            try MCPUpstreamValidator.validate(
                MCPUpstreamConfig(
                    name: "github",
                    command: "npx",
                    env: ["GITHUB_TOKEN": "synthetic-plaintext"]
                )
            )
        ) { error in
            XCTAssertEqual(error as? MCPUpstreamValidationError, .invalidEnvironment("GITHUB_TOKEN"))
        }
    }

    func testRejectsDuplicateToolAcrossPolicyBuckets() {
        XCTAssertThrowsError(
            try MCPUpstreamValidator.validate(
                MCPUpstreamConfig(
                    name: "github",
                    command: "npx",
                    tools: MCPUpstreamToolPolicy(allow: ["shared"], approve: ["shared"])
                )
            )
        ) { error in
            XCTAssertEqual(error as? MCPUpstreamValidationError, .invalidTools("shared"))
        }
    }
}
