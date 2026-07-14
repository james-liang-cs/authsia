import Foundation
import Testing
@testable import authsia

@Suite("CheckboxTUI pagination")
struct CheckboxTUIPaginationTests {

    @Test("default page size is 50")
    func defaultPageSizeIs50() {
        #expect(CheckboxTUI.defaultPageSize == 50)
    }

    @Test("current page selection only changes visible page")
    func currentPageSelectionOnlyChangesVisiblePage() {
        var state = CheckboxTUI.SelectionState(secrets: Self.makeSecrets(count: 7), pageSize: 3)

        #expect(state.pageCount == 3)
        #expect(state.currentPage == 0)
        #expect(state.visibleItems.map(\.secret.key) == ["KEY_0", "KEY_1", "KEY_2"])

        state.toggleCurrentPageSelection()
        #expect(state.selectedSecrets.map(\.key) == ["KEY_0", "KEY_1", "KEY_2"])

        state.nextPage()
        #expect(state.currentPage == 1)
        #expect(state.visibleItems.map(\.secret.key) == ["KEY_3", "KEY_4", "KEY_5"])

        state.toggleCurrentPageSelection()
        #expect(state.selectedSecrets.map(\.key) == ["KEY_0", "KEY_1", "KEY_2", "KEY_3", "KEY_4", "KEY_5"])
    }

    @Test("all pages selection toggles every item")
    func allPagesSelectionTogglesEveryItem() {
        var state = CheckboxTUI.SelectionState(secrets: Self.makeSecrets(count: 5), pageSize: 2)

        state.toggleCurrentPageSelection()
        #expect(state.selectedSecrets.count == 2)

        state.toggleAllPagesSelection()
        #expect(state.selectedSecrets.count == 5)

        state.toggleAllPagesSelection()
        #expect(state.selectedSecrets.isEmpty)
    }

    @Test("scrape uses selected secrets returned from a later page")
    func scrapeUsesSelectedSecretsReturnedFromLaterPage() throws {
        let secrets = Self.makeSecrets(count: 8)
        var state = CheckboxTUI.SelectionState(secrets: secrets, pageSize: 3)
        state.nextPage()
        state.toggleCurrentPageSelection()
        let pageSelection = state.selectedSecrets

        var scrape = Scrape()
        scrape.yes = false
        scrape.replaceAll = false
        let selected = try scrape.selectedSecretsForMigration(
            from: secrets,
            isInteractiveSession: true,
            selector: { _ in pageSelection }
        )

        #expect(selected.map(\.key) == ["KEY_3", "KEY_4", "KEY_5"])
    }

    private static func makeSecrets(count: Int) -> [DetectedSecret] {
        (0..<count).map { index in
            DetectedSecret(
                filePath: "/tmp/.env",
                lineNumber: index + 1,
                originalLine: "KEY_\(index)=AUTHSIA_FIXTURE_SECRET_1234567890abcdef",
                key: "KEY_\(index)",
                value: "AUTHSIA_FIXTURE_SECRET_1234567890abcdef",
                rawContent: nil,
                confidence: .high,
                type: .apiKey,
                entropy: 4.9,
                description: "api key",
                sshMetadata: nil
            )
        }
    }
}
