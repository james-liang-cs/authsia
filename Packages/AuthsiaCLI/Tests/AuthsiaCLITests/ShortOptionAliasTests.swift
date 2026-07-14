import ArgumentParser
import Testing
@testable import authsia

@Suite("Short option aliases")
struct ShortOptionAliasTests {
    @Test("folder alias parses for folder-scoped commands")
    func folderAliasParsesForFolderScopedCommands() throws {
        #expect(try AddAPIKey.parse(["--name", "Stripe", "--key", "-", "-f", "Team/API"]).folder == "Team/API")
        #expect(try AddPassword.parse(["--name", "GitHub", "--username", "dev", "-f", "Team/API"]).folder == "Team/API")
        #expect(try AddCertificate.parse(["--name", "TLS", "--cert-file", "cert.pem", "-f", "PKI"]).folder == "PKI")
        #expect(try AddNote.parse(["--title", "Runbook", "-f", "Ops"]).folder == "Ops")
        #expect(try AddSSH.parse(["--name", "deploy", "--private-key", "id_ed25519", "-f", "Infra/SSH"]).folder == "Infra/SSH")

        #expect(try EditAPIKey.parse(["Stripe", "-f", "Team/API"]).folder == "Team/API")
        #expect(try EditPassword.parse(["GitHub", "-f", "Team/API"]).folder == "Team/API")
        #expect(try EditCertificate.parse(["TLS", "-f", "PKI"]).folder == "PKI")
        #expect(try EditNote.parse(["Runbook", "-f", "Ops"]).folder == "Ops")
        #expect(try EditSSH.parse(["deploy", "-f", "Infra/SSH"]).folder == "Infra/SSH")

        #expect(try List.parse(["api-keys", "-f", "Team/API"]).folder == "Team/API")
        #expect(try List.parse(["passwords", "-f", "Team/API"]).folder == "Team/API")
        #expect(try Get.parse(["api-key", "Stripe", "-f", "Team/API"]).folder == "Team/API")
        #expect(try Get.parse(["password", "GitHub", "-f", "Team/API"]).folder == "Team/API")
        #expect(try Load.parse(["password", "-f", "Team/API"]).folder == "Team/API")
        #expect(try Exec.parse(["password", "-f", "Team/API", "--", "env"]).folder == "Team/API")
        #expect(try Scrape.parse(["-f", "Team/API", "--dry-run"]).folder == "Team/API")
        #expect(try SSH.Adopt.parse(["-f", "Infra/SSH", "--dry-run"]).folder == "Infra/SSH")
        #expect(try Env.Add.parse(["--name", "prod", "-f", "Team/API", "-f", "Team/Web"]).folder == [
            "Team/API",
            "Team/Web",
        ])
    }

    @Test("type alias parses for type-filtered commands")
    func typeAliasParsesForTypeFilteredCommands() throws {
        let scrape = try Scrape.parse(["-t", "password", "json", "--dry-run"])
        #expect(scrape.type == [.password, .json])

        let exec = try Exec.parse(["-t", "password", "--query", "GitHub", "--", "env"])
        #expect(exec.resolvedType == .password)

        let sshGenerate = try SSH.Generate.parse(["--name", "deploy", "-t", "rsa"])
        #expect(sshGenerate.type == "rsa")

        let auditList = try Audit.List.parse(["-t", "getPassword", "-t", "getOTP"])
        #expect(auditList.type == ["getPassword", "getOTP"])
    }

    @Test("yes alias parses for non-interactive commands")
    func yesAliasParsesForNonInteractiveCommands() throws {
        #expect(try Scrape.parse(["-y", "--dry-run"]).yes)
        #expect(try SSH.Adopt.parse(["-y", "--dry-run"]).yes)
    }
}
