import XCTest
@testable import AuthenticatorBridge

final class AutomationCredentialScopeTests: XCTestCase {
    func testMultiFolderScopeRoundTripsThroughStorage() throws {
        let normalized = try XCTUnwrap(
            AutomationCredentialScope.normalizeForCreation(
                folderPaths: [" Team / API ", "Team/Web", "Team/API"]
            )
        )

        XCTAssertEqual(normalized, .folders(["Team/API", "Team/Web"]))

        let stored = AutomationCredentialScope.storageValue(normalized)
        let reloaded = try XCTUnwrap(AutomationCredentialScope.normalizeStored(stored))

        XCTAssertEqual(reloaded, .folders(["Team/API", "Team/Web"]))
        XCTAssertEqual(AutomationCredentialScope.displayName(stored), "Team/API, Team/Web")
        XCTAssertTrue(AutomationCredentialScope.contains(itemFolderPath: "Team/Web/App", normalizedScope: reloaded))
        XCTAssertFalse(AutomationCredentialScope.contains(itemFolderPath: "Team/Other", normalizedScope: reloaded))
    }

    func testPrefixedPlainFolderScopeStaysPlainFolderWhenEncodingIsInvalid() throws {
        let reloaded = try XCTUnwrap(AutomationCredentialScope.normalizeStored("folders:v1:Legacy"))

        XCTAssertEqual(reloaded, .folder("folders:v1:Legacy"))
        XCTAssertTrue(AutomationCredentialScope.contains(itemFolderPath: "folders:v1:Legacy/App", normalizedScope: reloaded))
    }
}
