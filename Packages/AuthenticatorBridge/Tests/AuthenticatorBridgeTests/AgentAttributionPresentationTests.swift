import XCTest
@testable import AuthenticatorBridge

final class AgentAttributionPresentationTests: XCTestCase {
    func testUnknownMCPAndIDOnlyCallerDoNotClaimMainThread() {
        let context = AgentRuntimeContext(platform: "claude-code", agentType: "authsia-mcp")
        XCTAssertEqual(AgentAttributionPresentation.caption(for: context),
                       "Claude Code · sub-agent unknown (reported by hook)")
        let caller = AgentRuntimeContext(platform: "claude-code", agentID: "agent-1")
        XCTAssertEqual(AgentAttributionPresentation.usedByLabels(creator: context, contexts: [caller]), ["agent-1"])
    }

    func testSameTypeSubagentsRemainDistinct() {
        let first = AgentRuntimeContext(platform: "claude-code", agentID: "agent-1", agentType: "general-purpose")
        let second = AgentRuntimeContext(platform: "claude-code", agentID: "agent-2", agentType: "general-purpose")
        XCTAssertEqual(AgentAttributionPresentation.usedByLabels(creator: first, contexts: [first, second]),
                       ["general-purpose (agent-1)", "general-purpose (agent-2)"])
    }

    func testCaptionMarksHookTrustAndPromptUsesMiddleDot() {
        let context = AgentRuntimeContext(platform: "claude-code", agentType: "Explore")

        XCTAssertEqual(
            AgentAttributionPresentation.caption(for: context),
            "Claude Code / Explore (reported by hook)"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.promptValue(for: context),
            "Claude Code · Explore (reported by hook)"
        )
        XCTAssertNil(AgentAttributionPresentation.caption(for: nil))
        XCTAssertNil(AgentAttributionPresentation.promptValue(for: nil))
    }

    func testUnmappedPlatformKeepsItsOwnCasing() {
        XCTAssertEqual(
            AgentAttributionPresentation.platformDisplayName("Visual Studio Code"),
            "Visual Studio Code"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.platformDisplayName("Cursor Helper (Plugin)"),
            "Cursor Helper (Plugin)"
        )
        XCTAssertEqual(AgentAttributionPresentation.platformDisplayName("CLAUDE-CODE"), "Claude Code")
        XCTAssertNil(AgentAttributionPresentation.platformDisplayName(nil))
    }

    func testAmbiguousContextHidesSubAgentGuess() {
        let context = AgentRuntimeContext(platform: "codex", attributionConfidence: .ambiguous)

        XCTAssertEqual(
            AgentAttributionPresentation.caption(for: context),
            "Codex · sub-agent unknown (reported by hook)"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.promptValue(for: context),
            "Codex · sub-agent unknown (reported by hook)"
        )
    }

    func testCommandToolTextUsesDisplayNameAndAgentType() {
        XCTAssertEqual(
            AgentAttributionPresentation.commandToolText(
                platform: "codex",
                agentType: "reviewer",
                fallback: "zsh"
            ),
            "Codex · reviewer"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.commandToolText(
                platform: "claude-code",
                agentType: nil,
                fallback: "zsh"
            ),
            "Claude Code"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.commandToolText(
                platform: nil,
                agentType: "Explore",
                fallback: "zsh"
            ),
            "zsh"
        )
    }

    func testUsedByOmitsCreatorOnlySet() {
        let creator = AgentRuntimeContext(platform: "claude-code")
        XCTAssertEqual(
            AgentAttributionPresentation.usedByLabels(creator: creator, contexts: [creator]),
            []
        )

        let labels = AgentAttributionPresentation.usedByLabels(
            creator: creator,
            contexts: [
                AgentRuntimeContext(platform: "claude-code", agentType: "Explore"),
                AgentRuntimeContext(platform: "claude-code", agentType: "Plan"),
                creator,
            ]
        )
        XCTAssertEqual(labels, ["Explore", "Plan", "sub-agent unknown"])
        XCTAssertEqual(
            AgentAttributionPresentation.usedByCaption(labels: labels),
            "Used by: Explore, Plan, sub-agent unknown"
        )
    }

    func testSessionHeaderAndPlatformGlyphs() {
        XCTAssertEqual(
            AgentAttributionPresentation.sessionGroupHeader(
                platform: "claude-code",
                sessionID: "session-abcdef",
                grantCount: 3,
                subAgentCount: 2
            ),
            "Claude Code · session sess…ef · 3 grants · 2 sub-agents"
        )
        XCTAssertEqual(AgentAttributionPresentation.platformSymbolName("codex"), "terminal.fill")
        XCTAssertEqual(AgentAttributionPresentation.platformSymbolName("mystery"), "app.dashed")
        XCTAssertEqual(AgentAttributionPresentation.platformMonogram("claude-code"), "C")
        XCTAssertEqual(
            AgentAttributionPresentation.platformMonogram(nil, processName: "node"),
            "N"
        )
        XCTAssertEqual(
            AgentAttributionPresentation.topAgentLabel(platform: "claude-code", agentType: "Explore"),
            "Claude Code / Explore"
        )
    }

    func testLegacyContextDecodesWithoutAttributionConfidence() throws {
        let data = Data(#"{"platform":"codex","agentType":"reviewer"}"#.utf8)
        let decoded = try JSONDecoder().decode(AgentRuntimeContext.self, from: data)
        XCTAssertEqual(decoded.platform, "codex")
        XCTAssertEqual(decoded.agentType, "reviewer")
        XCTAssertEqual(decoded.attributionConfidence, .high)
    }

    func testDefaultAttributionConfidenceIsOmittedFromEncoding() throws {
        let encoded = try JSONEncoder().encode(AgentRuntimeContext(platform: "codex", agentType: "reviewer"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(object["platform"] as? String, "codex")
        XCTAssertNil(object["attributionConfidence"])

        let ambiguous = try JSONEncoder().encode(
            AgentRuntimeContext(platform: "codex", attributionConfidence: .ambiguous)
        )
        let ambiguousObject = try XCTUnwrap(JSONSerialization.jsonObject(with: ambiguous) as? [String: Any])
        XCTAssertEqual(ambiguousObject["attributionConfidence"] as? String, "ambiguous")
    }
}
