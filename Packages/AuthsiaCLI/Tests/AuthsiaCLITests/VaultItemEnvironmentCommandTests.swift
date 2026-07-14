import ArgumentParser
import Testing
@testable import authsia

@Suite("Vault item environment commands")
struct VaultItemEnvironmentCommandTests {
    @Test("add accepts repeatable environment tags")
    func addAcceptsRepeatableEnvironmentTags() throws {
        let command = try AddAPIKey.parse([
            "--name", "DATABASE_URL",
            "--key", "-",
            "--environment", "Development",
            "--environment", "Production",
        ])

        #expect(command.environment == ["Development", "Production"])
    }

    @Test("edit accepts environment mutation flags")
    func editAcceptsEnvironmentMutationFlags() throws {
        let command = try EditAPIKey.parse([
            "DATABASE_URL",
            "--environment", "Production",
            "--add-environment", "Staging",
            "--remove-environment", "Development",
        ])

        #expect(command.environment == "Production")
        #expect(command.addEnvironment == ["Staging"])
        #expect(command.removeEnvironment == ["Development"])
        #expect(!command.clearEnvironments)
    }

    @Test("get and delete accept environment disambiguators")
    func getAndDeleteAcceptEnvironmentDisambiguators() throws {
        let get = try Get.parse(["api-key", "DATABASE_URL", "--environment", "Production"])
        let delete = try DeleteAPIKey.parse(["DATABASE_URL", "--environment", "Production", "--force"])

        #expect(get.environment == "Production")
        #expect(delete.environment == "Production")
    }

    @Test("list environment filter keeps default-environment items eligible")
    func listEnvironmentFilterKeepsDefaultEnvironmentItemsEligible() {
        #expect(List.environmentMatches("Production", itemEnvironments: []))
        #expect(List.environmentMatches("Production", itemEnvironments: ["Production"]))
        #expect(!List.environmentMatches("Production", itemEnvironments: ["Development"]))
    }
}
