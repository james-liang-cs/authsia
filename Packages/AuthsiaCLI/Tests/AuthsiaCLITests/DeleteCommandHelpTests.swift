import Testing
@testable import authsia

@Suite("Delete command help")
struct DeleteCommandHelpTests {
    @Test("help shows password delete by ID example")
    func helpShowsPasswordDeleteByIDExample() {
        let rootHelp = Delete.helpMessage(columns: 160)
        let passwordHelp = DeletePassword.helpMessage(columns: 160)
        let folderHelp = DeleteFolder.helpMessage(columns: 160)

        #expect(rootHelp.contains("authsia delete password 11111111-1111-1111-1111-111111111111 --force"))
        #expect(rootHelp.contains("authsia delete folder Workspaces/demo --force"))
        #expect(passwordHelp.contains("authsia delete password 11111111-1111-1111-1111-111111111111 --force"))
        #expect(rootHelp.contains("folder     Delete a vault folder"))
        #expect(!rootHelp.contains("folder     Delete a password vault folder"))
        #expect(folderHelp.contains("Deletes a vault folder and any vault items under it."))
        #expect(!folderHelp.contains("Deletes a password vault folder"))
        #expect(folderHelp.contains("authsia delete folder Workspaces/demo --force"))
    }
}
