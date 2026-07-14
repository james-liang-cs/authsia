import Testing
@testable import authsia

@Suite("Match helper")
struct MatchHelperTests {
    private struct Item {
        let id: String
        let name: String
    }

    @Test("exact case match wins before case insensitive ambiguity")
    func exactCaseMatchWinsBeforeCaseInsensitiveAmbiguity() throws {
        let items = [
            Item(id: "lower", name: "password"),
            Item(id: "upper", name: "PASSWORD"),
        ]

        let match = try MatchHelper.findSingle(
            query: "PASSWORD",
            items: items,
            kind: "password item",
            id: { $0.id },
            searchable: { [$0.name] },
            display: { CLIError.MatchDescriptor(name: $0.name, id: $0.id) }
        )

        #expect(match.id == "upper")
    }

    @Test("same case duplicate names remain ambiguous")
    func sameCaseDuplicateNamesRemainAmbiguous() throws {
        let items = [
            Item(id: "one", name: "Shared"),
            Item(id: "two", name: "Shared"),
        ]

        do {
            _ = try MatchHelper.findSingle(
                query: "Shared",
                items: items,
                kind: "password item",
                id: { $0.id },
                searchable: { [$0.name] },
                display: { CLIError.MatchDescriptor(name: $0.name, id: $0.id) }
            )
            Issue.record("Expected same-case duplicates to remain ambiguous.")
        } catch CLIError.multipleMatches(let kind, let query, let matches) {
            #expect(kind == "password item")
            #expect(query == "Shared")
            #expect(matches.map(\.id) == ["one", "two"])
        }
    }
}
