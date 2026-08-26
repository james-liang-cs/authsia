import Foundation
import MCP
import Testing
@testable import authsia

@Suite("MCP proxy JSON masking")
struct MCPProxyMaskingTests {
    @Test("outbound arguments mask string values without rewriting keys or structure")
    func masksOutboundArgumentsOnlyInStringValues() throws {
        let masker = MCPProxyJSONMasker(secrets: ["abc", "abcd", "synthetic-token"])
        let parameters = CallTool.Parameters(
            name: "jira_create_issue",
            arguments: [
                "synthetic-token": .string("prefix synthetic-token suffix"),
                "short": .string("abc"),
                "four": .string("abcd"),
                "nested": .array([
                    .int(7),
                    .bool(true),
                    .null,
                    .object(["token": .string("synthetic-token")]),
                ]),
            ]
        )

        let masked: CallTool.Parameters = try masker.mask(parameters)

        #expect(masked.name == "jira_create_issue")
        #expect(masked.arguments?["synthetic-token"] == .string("prefix <concealed by authsia> suffix"))
        #expect(masked.arguments?["short"] == .string("abc"))
        #expect(masked.arguments?["four"] == .string("<concealed by authsia>"))
        #expect(masked.arguments?["nested"] == .array([
            .int(7),
            .bool(true),
            .null,
            .object(["token": .string("<concealed by authsia>")]),
        ]))
    }

    @Test("inbound content and structured content use exact-secret masking")
    func masksInboundResultWithoutDerivedEncodings() throws {
        let masker = MCPProxyJSONMasker(secrets: ["hunter2"])
        let result = CallTool.Result(
            content: [
                .text(
                    text: "token=hunter2 encoded=aHVudGVyMg==",
                    annotations: nil,
                    _meta: nil
                ),
            ],
            structuredContent: .object([
                "token": .string("hunter2"),
                "encoded": .string("aHVudGVyMg=="),
            ]),
            isError: false
        )

        let masked: CallTool.Result = try masker.mask(result)

        #expect(masked.content == [
            .text(
                text: "token=<concealed by authsia> encoded=aHVudGVyMg==",
                annotations: nil,
                _meta: nil
            ),
        ])
        #expect(masked.structuredContent == .object([
            "token": .string("<concealed by authsia>"),
            "encoded": .string("aHVudGVyMg=="),
        ]))
        #expect(masked.isError == false)
    }

    @Test("invalid JSON is rejected instead of byte-patched")
    func rejectsInvalidJSON() {
        let masker = MCPProxyJSONMasker(secrets: ["synthetic-token"])

        #expect(throws: (any Error).self) {
            try masker.maskJSONData(Data("not json synthetic-token".utf8))
        }
    }

    @Test("proxy masks arguments before forwarding and results before returning")
    func proxyMasksBothDirections() async throws {
        let secret = "synthetic-token"
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))

        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "AUTHSIA_TEST_ECHO_ARGUMENTS": "1",
                "AUTHSIA_TEST_RESULT_SECRET": secret,
                "JIRA_API_TOKEN": secret,
            ],
            secrets: [secret]
        )
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP masking test")
        let request: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_create_issue",
            arguments: ["token": .string(secret)]
        )

        let result = try await request.value
        let text: String
        switch try #require(result.content.first) {
        case .text(let value, _, _):
            text = value
        default:
            Issue.record("Expected a text result from the fixture upstream")
            return
        }

        #expect(!text.contains(secret))
        #expect(text.contains(#"request={"token":"<concealed by authsia>"}"#))
        #expect(text.contains("result=<concealed by authsia>"))

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }
}
