import XCTest
@testable import AuthenticatorBridge

final class AgentAttributionPresentationTests: XCTestCase {
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
        XCTAssertEqual(labels, ["Explore", "Plan", "main thread"])
        XCTAssertEqual(
            AgentAttributionPresentation.usedByCaption(labels: labels),
            "Used by: Explore, Plan, main thread"
        )
    }

    func testLegacyContextDecodesWithoutAttributionConfidence() throws {
        let data = Data(#"{"platform":"codex","agentType":"reviewer"}"#.utf8)
        let decoded = try JSONDecoder().decode(AgentRuntimeContext.self, from: data)
        XCTAssertEqual(decoded.platform, "codex")
        XCTAssertEqual(decoded.agentType, "reviewer")
        XCTAssertEqual(decoded.attributionConfidence, .high)
    }
}
