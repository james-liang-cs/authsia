import Testing
import ArgumentParser
@testable import authsia

@Suite("Load command help")
struct LoadCommandHelpTests {
    @Test("help covers item, folder, nested folder, and env scopes")
    func helpCoversSupportedScopes() {
        let help = Load.helpMessage(columns: 160)

        #expect(help.contains("authsia load password DB_PASSWORD"))
        #expect(help.contains("authsia load password DB_PASSWORD --folder Team/API"))
        #expect(help.contains("authsia load api-key API_KEY --silent"))
        #expect(help.contains("authsia load password --folder Team/API"))
        #expect(help.contains("authsia load password --folder Team/API/Prod"))
        #expect(help.contains("authsia load password --env Production"))
        #expect(help.contains("including nested folders"))
    }
}
