import Foundation
import Testing
@testable import authsia

@Suite("CheckboxTUI file path truncation")
struct CheckboxTUITruncationTests {

    @Test("short path fits within limit unchanged")
    func shortPathUnchanged() {
        #expect(CheckboxTUI.smartTruncatePath("~/.zshrc", maxLength: 14) == "~/.zshrc")
    }

    @Test("long path shows parent/filename within length")
    func longPathShowsParentAndFilename() {
        let result = CheckboxTUI.smartTruncatePath(
            "/Users/example/Projects/myapp/.env.production", maxLength: 16
        )
        #expect(result.count <= 16)
        // Should show meaningful segment — parent or filename
        #expect(result.contains("myapp") || result.hasSuffix(".env.production"))
    }

    @Test("truncation respects maxLength")
    func truncationRespectsMaxLength() {
        let path = "/very/deeply/nested/directory/structure/file.env"
        let result = CheckboxTUI.smartTruncatePath(path, maxLength: 14)
        #expect(result.count <= 14)
    }

    @Test("home directory path uses tilde")
    func homePath() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let result = CheckboxTUI.smartTruncatePath("\(home)/.zshrc", maxLength: 14)
        #expect(result == "~/.zshrc")
    }
}
