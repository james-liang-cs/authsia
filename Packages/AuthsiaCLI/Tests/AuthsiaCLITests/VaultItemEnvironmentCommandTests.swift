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

    @Test("edit keeps All and named tags mutually exclusive, matching the app")
    func editKeepsAllAndNamedTagsMutuallyExclusive() throws {
        // The app enforces this through VaultEnvironmentTags.applying. A plain
        // merge here would store All beside a named tag, a state the app
        // collapses on its next edit and the resolver scores differently.
        #expect(
            try environmentReplacement(existing: ["Production"], add: ["All"], remove: [], clear: false)
                == ["All"]
        )
        #expect(
            try environmentReplacement(existing: ["All"], add: ["Production"], remove: [], clear: false)
                == ["Production"]
        )
        #expect(
            try environmentReplacement(existing: ["Production"], add: ["Staging"], remove: [], clear: false)
                == ["Production", "Staging"]
        )
        #expect(
            try environmentReplacement(
                existing: ["Production", "Staging"],
                add: [],
                remove: ["staging"],
                clear: false
            ) == ["Production"]
        )
        #expect(
            try environmentReplacement(existing: ["Production"], add: [], remove: [], clear: true) == []
        )
        #expect(
            try environmentReplacement(existing: ["Production"], add: [], remove: [], clear: false) == nil
        )
    }

    @Test("get and delete accept environment disambiguators")
    func getAndDeleteAcceptEnvironmentDisambiguators() throws {
        let get = try Get.parse(["api-key", "DATABASE_URL", "--environment", "Production"])
        let delete = try DeleteAPIKey.parse(["DATABASE_URL", "--environment", "Production", "--force"])

        #expect(get.environment == "Production")
        #expect(delete.environment == "Production")
    }

    @Test("list environment filter requires the selected tag")
    func listEnvironmentFilterRequiresSelectedTag() {
        #expect(!List.environmentMatches("Production", itemEnvironments: []))
        #expect(List.environmentMatches("Production", itemEnvironments: ["Production"]))
        #expect(List.environmentMatches("Production", itemEnvironments: ["All"]))
        #expect(!List.environmentMatches("Production", itemEnvironments: ["Development"]))
    }
}
