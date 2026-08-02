import XCTest
@testable import AuthsiaNativeHostCore
import Security

final class NativeHostCoreTests: XCTestCase {
    private static let passwordID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private static let otherPasswordID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    private static let otpID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    private func encodeFixture<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    private func passwordMatch(
        id: UUID,
        name: String = "Example",
        username: String? = "user",
        website: String? = "https://example.com",
        storedHost: String? = "example.com",
        isExact: Bool = true
    ) -> CLIAutofillMatch {
        CLIAutofillMatch(
            kind: .password,
            id: id,
            name: name,
            username: username,
            website: website,
            storedHost: storedHost,
            isExact: isExact
        )
    }

    private func otpMatch(id: UUID, issuer: String = "Example", label: String = "user") -> CLIAutofillMatch {
        CLIAutofillMatch(kind: .otp, id: id, name: issuer, username: label, website: nil)
    }

    // MARK: - Native messaging

    func testNativeMessagingFrameRoundTrip() throws {
        let payload = Data("{\"type\":\"getCredentials\",\"host\":\"example.com\"}".utf8)

        let framed = NativeMessaging.encodeFrame(payload)
        let decoded = try NativeMessaging.decodeFrame(framed)

        XCTAssertEqual(decoded.payload, payload)
        XCTAssertEqual(decoded.bytesConsumed, framed.count)
    }

    // MARK: - CLI command shape

    func testCLIGetCommandsUseChromeNativeHostMarker() {
        XCTAssertEqual(
            CLICommand.getChromePasswordJSON(id: Self.passwordID).arguments,
            ["authsia", "get", "password", Self.passwordID.uuidString, "--format", "json", "--chrome-native-host"]
        )
        XCTAssertEqual(
            CLICommand.getChromeOTPJSON(id: Self.otpID).arguments,
            ["authsia", "get", "otp", Self.otpID.uuidString, "--format", "json", "--chrome-native-host"]
        )
    }

    func testAutofillMatchesCommandCarriesHostURLAndKind() {
        XCTAssertEqual(
            CLICommand.autofillMatchesJSON(host: "example.com", currentURL: nil, kind: nil).arguments,
            ["authsia", "chrome-autofill", "matches", "--host", "example.com", "--chrome-native-host"]
        )
        XCTAssertEqual(
            CLICommand.autofillMatchesJSON(
                host: "example.com",
                currentURL: "https://example.com/login",
                kind: .otp
            ).arguments,
            [
                "authsia", "chrome-autofill", "matches",
                "--host", "example.com",
                "--url", "https://example.com/login",
                "--kind", "otp",
                "--chrome-native-host",
            ]
        )
    }

    func testCLIResolutionPrefersBundledSiblingHelper() {
        let nativeHost = URL(fileURLWithPath: "/Applications/Authsia.app/Contents/Helpers/AuthsiaNativeHost")
        let candidates = CLIClient.candidatePaths(
            executableURL: nativeHost,
            homeDirectory: "/Users/test"
        )

        XCTAssertEqual(candidates.map(\.path), [
            "/Applications/Authsia.app/Contents/Helpers/authsia",
            "/usr/local/bin/authsia",
            "/opt/homebrew/bin/authsia",
            "/Users/test/.local/bin/authsia",
        ])

        var inspected: [URL] = []
        let result = CLIClient.resolveExecutablePath(
            candidatePaths: candidates,
            expectedTeamIdentifier: "TEAM123",
            isExecutable: { _ in true },
            teamIdentifierForExecutable: { url in
                inspected.append(url)
                return "TEAM123"
            }
        )

        XCTAssertEqual(result, candidates[0])
        XCTAssertEqual(inspected, [candidates[0]])
    }

    func testCLIResolutionRefusesCandidatesThatDoNotVerify() {
        let candidates = [
            URL(fileURLWithPath: "/app/authsia"),
            URL(fileURLWithPath: "/usr/local/bin/authsia"),
        ]

        let mismatched = CLIClient.resolveExecutablePath(
            candidatePaths: candidates,
            expectedTeamIdentifier: "TEAM123",
            isExecutable: { _ in true },
            teamIdentifierForExecutable: { _ in "OTHERTEAM" }
        )
        let missingHostIdentity = CLIClient.resolveExecutablePath(
            candidatePaths: candidates,
            expectedTeamIdentifier: nil,
            isExecutable: { _ in true },
            teamIdentifierForExecutable: { _ in "TEAM123" }
        )

        XCTAssertNil(mismatched)
        XCTAssertNil(missingHostIdentity)
    }

    func testCLITeamValidationRequestsSigningInformationMetadata() {
        XCTAssertEqual(
            CLIClient.signingInformationFlags,
            SecCSFlags(rawValue: kSecCSSigningInformation)
        )
    }

    // MARK: - listCredentials

    func testListCredentialsForwardsHostURLAndKindAndMapsMatches() throws {
        var issued: [CLICommand] = []
        let client = CLIClient { command in
            issued.append(command)
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([
                    self.passwordMatch(id: Self.passwordID, name: "Example Login"),
                    self.otpMatch(id: Self.otpID, issuer: "Example", label: "user@example.com"),
                ])
            default:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).listCredentials(
            forHost: "Example.com",
            currentURL: "https://example.com/login",
            kind: nil
        )

        XCTAssertEqual(
            issued,
            [.autofillMatchesJSON(host: "example.com", currentURL: "https://example.com/login", kind: nil)]
        )
        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credentials?.map(\.id), [Self.passwordID, Self.otpID])
        XCTAssertEqual(response.credentials?.map(\.kind), ["password", "otp"])
        XCTAssertEqual(response.credentials?.first?.name, "Example Login")
        XCTAssertEqual(response.credentials?.last?.username, "user@example.com")
    }

    func testListCredentialsPassesKindThrough() throws {
        var issued: [CLICommand] = []
        let client = CLIClient { command in
            issued.append(command)
            return try self.encodeFixture([self.passwordMatch(id: Self.passwordID)])
        }

        _ = try CredentialResolver(cliClient: client).listCredentials(
            forHost: "example.com",
            kind: .password
        )

        XCTAssertEqual(
            issued,
            [.autofillMatchesJSON(host: "example.com", currentURL: nil, kind: .password)]
        )
    }

    func testListCredentialsRejectsInvalidHostWithoutCallingCLI() throws {
        let client = CLIClient { command in
            XCTFail("Did not expect any CLI call for an invalid host: \(command)")
            return Data()
        }

        let response = try CredentialResolver(cliClient: client).listCredentials(forHost: "exa mple.com")

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .invalidHost)
    }

    func testListCredentialsReportsCLIFailure() throws {
        let client = CLIClient { _ in
            throw CLIClientError.nonZeroExit(status: 1, stderr: "denied")
        }

        let response = try CredentialResolver(cliClient: client).listCredentials(forHost: "example.com")

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .cliFailure)
    }

    func testListCredentialsReturnsEmptyForHostWithNoMatches() throws {
        let client = CLIClient { _ in Data("[]".utf8) }

        let response = try CredentialResolver(cliClient: client).listCredentials(forHost: "unrelated.example")

        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credentials?.count, 0)
    }

    // MARK: - getCredential

    func testGetCredentialFetchesPasswordForMatchedID() throws {
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([self.passwordMatch(id: Self.passwordID, name: "Match")])
            case .getChromePasswordJSON(let queryID):
                XCTAssertEqual(queryID, Self.passwordID)
                return try self.encodeFixture(
                    CLIGetPasswordResult(
                        id: queryID.uuidString,
                        name: "Match",
                        username: "user",
                        password: "pass",
                        website: "https://example.com"
                    )
                )
            default:
                XCTFail("Unexpected command: \(command)")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: Self.passwordID
        )

        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credential?.password, "pass")
        XCTAssertEqual(response.match?.name, "Match")
    }

    func testGetCredentialFetchesOTPForMatchedID() throws {
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([self.otpMatch(id: Self.otpID, issuer: "Acme")])
            case .getChromeOTPJSON(let queryID):
                XCTAssertEqual(queryID, Self.otpID)
                return try self.encodeFixture(
                    CLIGetOTPResult(
                        id: queryID.uuidString,
                        issuer: "Acme",
                        label: "user",
                        code: "654321",
                        remaining: 18,
                        expiresAt: Date(timeIntervalSince1970: 30),
                        isFavorite: false
                    )
                )
            default:
                XCTFail("Unexpected command: \(command)")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: Self.otpID
        )

        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credential?.otpCode, "654321")
        XCTAssertEqual(response.match?.kind, "otp")
    }

    func testGetCredentialRefusesIDOutsideTheHostMatchSet() throws {
        var fetched = false
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([self.passwordMatch(id: Self.passwordID)])
            default:
                fetched = true
                XCTFail("Did not expect a secret lookup for an unmatched ID")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: Self.otherPasswordID
        )

        XCTAssertFalse(fetched)
        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .accessDenied)
    }

    func testGetCredentialAutoSelectsSingleExactPasswordMatch() throws {
        var issued: [CLICommand] = []
        let client = CLIClient { command in
            issued.append(command)
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([
                    self.passwordMatch(
                        id: Self.otherPasswordID,
                        website: "https://example.com",
                        storedHost: "example.com",
                        isExact: false
                    ),
                    self.passwordMatch(
                        id: Self.passwordID,
                        website: "https://sub.example.com",
                        storedHost: "sub.example.com",
                        isExact: true
                    ),
                ])
            case .getChromePasswordJSON(let queryID):
                return try self.encodeFixture(
                    CLIGetPasswordResult(
                        id: queryID.uuidString,
                        name: "Example",
                        username: "user",
                        password: "pass",
                        website: "https://sub.example.com"
                    )
                )
            default:
                XCTFail("Unexpected command: \(command)")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "sub.example.com",
            credentialId: nil
        )

        // Auto-selection only ever fills a password, so it never asks for OTP.
        XCTAssertEqual(
            issued.first,
            .autofillMatchesJSON(host: "sub.example.com", currentURL: nil, kind: .password)
        )
        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.match?.id, Self.passwordID)
    }

    func testGetCredentialReportsMultipleMatchesWhenAmbiguous() throws {
        var fetched = false
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([
                    self.passwordMatch(id: Self.passwordID, name: "One"),
                    self.passwordMatch(id: Self.otherPasswordID, name: "Two"),
                ])
            default:
                fetched = true
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: nil
        )

        XCTAssertFalse(fetched)
        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .multipleMatches)
    }

    func testGetCredentialReportsNoMatchWhenNothingMatches() throws {
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return Data("[]".utf8)
            default:
                XCTFail("Did not expect a secret lookup")
                return Data()
            }
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: nil
        )

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .noMatch)
    }

    func testGetCredentialWithoutIDNeverAutoSelectsOTP() throws {
        let client = CLIClient { command in
            XCTFail("Did not expect any CLI call: \(command)")
            return Data()
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "example.com",
            credentialId: nil,
            kind: .otp
        )

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .noMatch)
    }

    func testGetCredentialRejectsInvalidHostWithoutCallingCLI() throws {
        let client = CLIClient { command in
            XCTFail("Did not expect any CLI call for an invalid host: \(command)")
            return Data()
        }

        let response = try CredentialResolver(cliClient: client).getCredential(
            forHost: "exa mple.com",
            credentialId: Self.passwordID
        )

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .invalidHost)
    }

    // MARK: - Handler

    func testHandlerRejectsUnknownRequestType() throws {
        let resolver = CredentialResolver(
            cliClient: CLIClient { command in
                XCTFail("Resolver should not be called for invalid request types: \(command)")
                return Data()
            }
        )
        let handler = NativeHostHandler(resolver: resolver)

        let request = NativeHostRequest(type: "ping", host: "example.com")
        let data = try JSONEncoder().encode(request)
        let responseData = handler.handleRequestData(data)
        let response = try JSONDecoder().decode(NativeHostResponse.self, from: responseData)

        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .invalidRequest)
    }

    func testHandlerUsesResolverAndEncodesResponse() throws {
        let client = CLIClient { command in
            switch command {
            case .autofillMatchesJSON:
                return try self.encodeFixture([
                    self.passwordMatch(id: Self.passwordID, name: "Match", website: "https://example.com/login")
                ])
            case .getChromePasswordJSON(let queryID):
                return try self.encodeFixture(
                    CLIGetPasswordResult(
                        id: queryID.uuidString,
                        name: "Match",
                        username: "user",
                        password: "pass",
                        website: "https://example.com/login"
                    )
                )
            default:
                XCTFail("Unexpected command: \(command)")
                return Data()
            }
        }
        let handler = NativeHostHandler(resolver: CredentialResolver(cliClient: client))

        let request = NativeHostRequest(type: "getCredentials", host: "example.com")
        let requestData = try JSONEncoder().encode(request)
        let responseData = handler.handleRequestData(requestData)
        let response = try JSONDecoder().decode(NativeHostResponse.self, from: responseData)

        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credential?.username, "user")
        XCTAssertEqual(response.credential?.password, "pass")
        XCTAssertEqual(response.match?.name, "Match")
    }
}
