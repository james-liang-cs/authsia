import Testing
import Foundation
import ArgumentParser
@testable import authsia

@Suite("InjectCommand")
struct InjectCommandTests {

    // Test 1: template with no authsia:// refs passes through unchanged
    @Test("passthrough when no refs found")
    func noRefsPassthrough() throws {
        let content = "DB_HOST=localhost\nDB_PORT=5432\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [:]))
        #expect(result == content)
    }

    // Test 2: single URI replaced
    @Test("single URI is replaced with resolved value")
    func singleURIReplaced() throws {
        let content = "API_KEY=authsia://password/GitHub/password\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/GitHub/password": "secret-value",
        ]))
        #expect(result == "API_KEY=secret-value\n")
        #expect(!result.contains("authsia://"))
    }

    // Test 3: same URI used multiple times — all replaced
    @Test("duplicate URI occurrences all replaced")
    func duplicateURIsAllReplaced() throws {
        let content = "A=authsia://password/K/password\nB=authsia://password/K/password\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/K/password": "val",
        ]))
        #expect(result == "A=val\nB=val\n")
    }

    // Test 4: multiple different URIs replaced
    @Test("multiple different URIs replaced")
    func multipleURIsReplaced() throws {
        let content = "A=authsia://password/A/password\nB=authsia://cert/B/certificate\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/A/password": "pass-val",
            "authsia://cert/B/certificate": "cert-val",
        ]))
        #expect(result.contains("A=pass-val"))
        #expect(result.contains("B=cert-val"))
    }

    // Test 5: resolution failure throws
    @Test("resolution failure throws error")
    func resolutionFailureThrows() throws {
        let content = "KEY=authsia://password/Missing/password\n"
        #expect(throws: (any Error).self) {
            try Inject.processTemplate(content, resolver: StubResolver(values: [:], failOnMissing: true))
        }
    }

    // Test 6: URIs in YAML-style content (values, quoted)
    @Test("URI embedded in YAML value is resolved")
    func uriInYAML() throws {
        let content = "database:\n  password: authsia://password/DB/password\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/DB/password": "db-secret",
        ]))
        #expect(result.contains("password: db-secret"))
    }

    // Test 7: multiple failing URIs — all errors collected before throwing
    @Test("all resolution errors collected before failing")
    func multipleErrorsCollected() throws {
        let content = """
            A=authsia://password/Missing1/password
            B=authsia://password/Missing2/password
            """
        #expect(throws: (any Error).self) {
            try Inject.processTemplate(content, resolver: StubResolver(values: [:], failOnMissing: true))
        }
    }

    // Test 8: content with no-ref text interspersed
    @Test("non-reference text is preserved verbatim")
    func nonRefTextPreserved() throws {
        let content = "# Generated config\nPORT=8080\nSECRET=authsia://password/App/password\nHOST=localhost\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/App/password": "my-secret",
        ]))
        #expect(result == "# Generated config\nPORT=8080\nSECRET=my-secret\nHOST=localhost\n")
    }

    // Test 9: URI stops at whitespace
    @Test("URI stops at whitespace boundary")
    func uriStopsAtWhitespace() throws {
        let content = "value: authsia://password/X/password and more text\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/X/password": "resolved",
        ]))
        #expect(result == "value: resolved and more text\n")
    }

    // Test 10: URI stops at double-quote (JSON context)
    @Test("URI stops at double-quote in JSON context")
    func uriStopsAtDoubleQuote() throws {
        let content = #"{"key": "authsia://password/X/password"}"#
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/X/password": "resolved",
        ]))
        #expect(result == #"{"key": "resolved"}"#)
    }

    // Test 11: resolved value containing authsia:// does not cause cascading substitution
    @Test("resolved value with authsia:// URI does not cascade")
    func noCascadingSubstitution() throws {
        let content = "A=authsia://password/First/password\nB=authsia://password/Second/password\n"
        let result = try Inject.processTemplate(content, resolver: StubResolver(values: [
            "authsia://password/First/password": "authsia://password/Second/password",
            "authsia://password/Second/password": "real-secret",
        ]))
        // First should resolve to the literal string that looks like a URI,
        // Second should resolve to its own value — no cascading.
        #expect(result == "A=authsia://password/Second/password\nB=real-secret\n")
    }

    @Test("inject rejects when credential omits .inject")
    func injectRejectsWithoutInjectCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "inject-cap")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "exec-only",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )

        do {
            try Inject.authorizeAutomationAccess(
                environment: [AutomationAccessResolver.environmentKey: credential.id.uuidString],
                store: store,
                now: now.addingTimeInterval(60)
            )
            Issue.record("expected ValidationError")
        } catch let error as ValidationError {
            #expect(String(describing: error).contains("does not permit 'inject'"))
        } catch {
            Issue.record("expected ValidationError, got \(error)")
        }
    }
}

// MARK: - Test stub

private struct StubResolver: SecretResolverClient {
    let values: [String: String]
    var failOnMissing = false

    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String {
        let uri = "authsia://\(type.rawValue)/\(query)/\(field)"
        if let value = values[uri] { return value }
        if failOnMissing { throw SecretReferenceError.missingItem(uri) }
        return ""
    }
}
