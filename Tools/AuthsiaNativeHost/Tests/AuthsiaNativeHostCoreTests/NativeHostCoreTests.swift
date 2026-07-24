import XCTest
@testable import AuthsiaNativeHostCore

final class NativeHostCoreTests: XCTestCase {
    private func encodeFixture<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    func testNativeMessagingFrameRoundTrip() throws {
        let payload = Data("{\"type\":\"getCredentials\",\"host\":\"example.com\"}".utf8)

        let framed = NativeMessaging.encodeFrame(payload)
        let decoded = try NativeMessaging.decodeFrame(framed)

        XCTAssertEqual(decoded.payload, payload)
        XCTAssertEqual(decoded.bytesConsumed, framed.count)
    }

    func testCLIListAccountsUsesCanonicalOTPScope() {
        XCTAssertEqual(
            CLICommand.listOTPJSON.arguments,
            ["authsia", "list", "otp", "--format", "json"]
        )
    }

    func testCLIGetCommandsUseChromeNativeHostMarker() {
        let passwordID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let otpID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

        XCTAssertEqual(
            CLICommand.getChromePasswordJSON(id: passwordID).arguments,
            ["authsia", "get", "password", passwordID.uuidString, "--format", "json", "--chrome-native-host"]
        )
        XCTAssertEqual(
            CLICommand.getChromeOTPJSON(id: otpID).arguments,
            ["authsia", "get", "otp", otpID.uuidString, "--format", "json", "--chrome-native-host"]
        )
    }

    func testCLIListCommandsUseChromeNativeHostMarker() {
        XCTAssertEqual(
            CLICommand.listPasswordsJSON.arguments,
            ["authsia", "list", "passwords", "--format", "json", "--chrome-native-host"]
        )
        XCTAssertEqual(
            CLICommand.listOTPJSON.arguments,
            ["authsia", "list", "otp", "--format", "json", "--chrome-native-host"]
        )
    }

    func testCredentialResolverListsCliDisabledMatchesForChromeAutofill() throws {
        let passwordId = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let otpId = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

        let passwords: [CLIListPassword] = [
            CLIListPassword(
                id: passwordId,
                name: "Disabled Password",
                username: "disabled-user",
                website: "https://example.com/login",
                isFavorite: false,
                isCliEnabled: false
            ),
        ]
        let accounts: [CLIListAccount] = [
            CLIListAccount(
                id: otpId,
                issuer: "Example",
                label: "disabled@example.com",
                hosts: ["example.com"],
                isFavorite: false,
                isCliEnabled: false,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            ),
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getOTPJSON, .getChromePasswordJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.listCredentials(forHost: "example.com", currentURL: "https://example.com/login")

        XCTAssertEqual(response.credentials?.map(\.id), [passwordId, otpId])
        XCTAssertEqual(response.credentials?.map(\.kind), ["password", "otp"])
    }

    func testCredentialResolverFetchesCliDisabledPasswordForChromeAutofill() throws {
        let disabledId = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

        let passwords: [CLIListPassword] = [
            CLIListPassword(
                id: disabledId,
                name: "Disabled",
                username: "disabled-user",
                website: "https://example.com/login",
                isFavorite: false,
                isCliEnabled: false
            ),
        ]

        var commands: [CLICommand] = []
        let client = CLIClient { command in
            commands.append(command)
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return Data("[]".utf8)
            case .getChromePasswordJSON(let id):
                XCTAssertEqual(id, disabledId)
                let result = CLIGetPasswordResult(
                    id: id.uuidString,
                    name: "Disabled",
                    username: "disabled-user",
                    password: "s3cr3t",
                    website: "https://example.com/login"
                )
                return try JSONEncoder().encode(result)
            case .getPasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect non-password lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.getCredential(forHost: "login.example.com", credentialId: disabledId)

        XCTAssertEqual(commands, [.listPasswordsJSON, .listOTPJSON, .getChromePasswordJSON(id: disabledId)])
        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credential?.username, "disabled-user")
        XCTAssertEqual(response.credential?.password, "s3cr3t")
        XCTAssertEqual(response.match?.id, disabledId)
        XCTAssertEqual(response.match?.name, "Disabled")
    }

    func testCredentialResolverMatchesPasswordByCurrentURLPrefix() throws {
        let id = UUID(uuidString: "12121212-1212-1212-1212-121212121212")!
        let passwords = [
            CLIListPassword(
                id: id,
                name: "Path scoped",
                username: "path-user",
                website: "https://example.com/app",
                isFavorite: false,
                isCliEnabled: true
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return Data("[]".utf8)
            case .getChromePasswordJSON(let queryID):
                let result = CLIGetPasswordResult(
                    id: queryID.uuidString,
                    name: "Path scoped",
                    username: "path-user",
                    password: "s3cr3t",
                    website: "https://example.com/app"
                )
                return try JSONEncoder().encode(result)
            case .getPasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect OTP lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.getCredential(
            forHost: "example.com",
            currentURL: "https://example.com/app/login",
            credentialId: nil
        )

        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.match?.id, id)
    }

    func testCredentialResolverFetchesCliDisabledOTPForChromeAutofill() throws {
        let id = UUID(uuidString: "34343434-3434-3434-3434-343434343434")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "GitHub",
                label: "alice@example.com",
                hosts: ["https://github.com"],
                isFavorite: true,
                isCliEnabled: false,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        var commands: [CLICommand] = []
        let client = CLIClient { command in
            commands.append(command)
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getChromeOTPJSON(let queryID):
                let result = CLIGetOTPResult(
                    id: queryID.uuidString,
                    issuer: "GitHub",
                    label: "alice@example.com",
                    code: "123456",
                    remaining: 24,
                    expiresAt: Date(timeIntervalSince1970: 30),
                    isFavorite: true
                )
                return try self.encodeFixture(result)
            case .getPasswordJSON, .getOTPJSON, .getChromePasswordJSON:
                XCTFail("Did not expect non-OTP lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.getCredential(
            forHost: "github.com",
            currentURL: "https://github.com/login",
            credentialId: id
        )

        XCTAssertEqual(commands, [.listPasswordsJSON, .listOTPJSON, .getChromeOTPJSON(id: id)])
        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.credential?.otpCode, "123456")
        XCTAssertEqual(response.match?.kind, "otp")
    }

    func testCredentialResolverListsAndFetchesOTPMatches() throws {
        let id = UUID(uuidString: "34343434-3434-3434-3434-343434343434")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "GitHub",
                label: "alice@example.com",
                hosts: ["https://github.com"],
                isFavorite: true,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON:
                XCTFail("Did not expect password lookup")
                return Data()
            case .getChromeOTPJSON(let queryID):
                let result = CLIGetOTPResult(
                    id: queryID.uuidString,
                    issuer: "GitHub",
                    label: "alice@example.com",
                    code: "123456",
                    remaining: 24,
                    expiresAt: Date(timeIntervalSince1970: 30),
                    isFavorite: true
                )
                return try self.encodeFixture(result)
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(forHost: "github.com", currentURL: "https://github.com/login")

        XCTAssertEqual(listResponse.credentials?.count, 1)
        XCTAssertEqual(listResponse.credentials?.first?.kind, "otp")

        let getResponse = try resolver.getCredential(
            forHost: "github.com",
            currentURL: "https://github.com/login",
            credentialId: id
        )

        XCTAssertEqual(getResponse.ok, true)
        XCTAssertEqual(getResponse.credential?.otpCode, "123456")
        XCTAssertEqual(getResponse.match?.kind, "otp")
    }

    func testCredentialResolverDoesNotSubstringMatchOTPIssuerInHost() throws {
        let gitId = UUID(uuidString: "73737373-7373-7373-7373-737373737373")!
        let githubId = UUID(uuidString: "74747474-7474-7474-7474-747474747474")!
        let accounts = [
            CLIListAccount(
                id: gitId,
                issuer: "Git",
                label: "synthetic-user",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            ),
            CLIListAccount(
                id: githubId,
                issuer: "GitHub",
                label: "synthetic-user",
                hosts: ["https://github.com"],
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            ),
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)

        let digitalResponse = try resolver.listCredentials(forHost: "digital.com")
        XCTAssertEqual(digitalResponse.credentials?.count ?? 0, 0)

        let githubResponse = try resolver.listCredentials(forHost: "login.github.com")
        XCTAssertEqual(githubResponse.credentials?.map(\.id), [githubId])
    }

    func testCredentialResolverDoesNotSubstringMatchShortOTPIssuerInHostLabel() throws {
        let id = UUID(uuidString: "75757575-7575-7575-7575-757575757575")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "ING",
                label: "synthetic-user",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.listCredentials(forHost: "boring.com")

        XCTAssertEqual(response.credentials?.count ?? 0, 0)
    }

    func testCredentialResolverDoesNotHostMatchOTPEmailLabel() throws {
        let id = UUID(uuidString: "76767676-7676-7676-7676-767676767676")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "Acme Corp",
                label: "user@example.com",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.listCredentials(forHost: "userexample.com")

        XCTAssertEqual(response.credentials?.count ?? 0, 0)
    }

    func testCredentialResolverDoesNotAuthorizeOTPFromIssuerMatchingUnknownPublicSuffix() throws {
        let id = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "Cloud",
                label: "synthetic-user",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(forHost: "attacker.cloud")
        let getResponse = try resolver.getCredential(
            forHost: "attacker.cloud",
            credentialId: id
        )

        XCTAssertEqual(listResponse.credentials?.count ?? 0, 0)
        XCTAssertEqual(getResponse.error, .accessDenied)
    }

    func testCredentialResolverListsOTPByMetadataHost() throws {
        let id = UUID(uuidString: "67676767-6767-6767-6767-676767676767")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "Amazon Web Services",
                label: "chen_liang@example-control-plane",
                hosts: ["https://example-control-plane.signin.aws.amazon.com/console"],
                isFavorite: true,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON:
                XCTFail("Did not expect password lookup")
                return Data()
            case .getChromeOTPJSON(let queryID):
                let result = CLIGetOTPResult(
                    id: queryID.uuidString,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    code: "112233",
                    remaining: 24,
                    expiresAt: Date(timeIntervalSince1970: 30),
                    isFavorite: true
                )
                return try self.encodeFixture(result)
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth"
        )

        XCTAssertEqual(listResponse.credentials?.count, 1)
        XCTAssertEqual(listResponse.credentials?.first?.id, id)

        let getResponse = try resolver.getCredential(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth",
            credentialId: id
        )

        XCTAssertEqual(getResponse.ok, true)
        XCTAssertEqual(getResponse.credential?.otpCode, "112233")
    }

    func testCredentialResolverListsAWSOTPByMetadataHostWithoutCurrentURL() throws {
        let id = UUID(uuidString: "68686868-6868-6868-6868-686868686868")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "Amazon Web Services",
                label: "chen_liang@example-control-plane",
                hosts: ["https://example-control-plane.signin.aws.amazon.com/console"],
                isFavorite: true,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON:
                XCTFail("Did not expect password lookup")
                return Data()
            case .getChromeOTPJSON(let queryID):
                let result = CLIGetOTPResult(
                    id: queryID.uuidString,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    code: "445566",
                    remaining: 24,
                    expiresAt: Date(timeIntervalSince1970: 30),
                    isFavorite: true
                )
                return try self.encodeFixture(result)
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(forHost: "ap-southeast-1.signin.aws.amazon.com")

        XCTAssertEqual(listResponse.credentials?.count, 1)
        XCTAssertEqual(listResponse.credentials?.first?.id, id)

        let getResponse = try resolver.getCredential(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            credentialId: id
        )

        XCTAssertEqual(getResponse.ok, true)
        XCTAssertEqual(getResponse.credential?.otpCode, "445566")
    }

    func testCredentialResolverListsAWSOTPByMetadataHostOnDifferentSignInPath() throws {
        let id = UUID(uuidString: "69696969-6969-6969-6969-696969696969")!
        let accounts = [
            CLIListAccount(
                id: id,
                issuer: "Amazon Web Services",
                label: "chen_liang@example-control-plane",
                hosts: ["https://example-control-plane.signin.aws.amazon.com/console"],
                isFavorite: true,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return Data("[]".utf8)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON:
                XCTFail("Did not expect password lookup")
                return Data()
            case .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect OTP fetch")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/mfa"
        )

        XCTAssertEqual(listResponse.credentials?.count, 1)
        XCTAssertEqual(listResponse.credentials?.first?.id, id)
    }

    func testCredentialResolverSortsSpecificAWSOTPBeforeBroadAWSHosts() throws {
        let broadId = UUID(uuidString: "70707070-7070-7070-7070-707070707070")!
        let specificId = UUID(uuidString: "71717171-7171-7171-7171-717171717171")!
        let passwords = [
            CLIListPassword(
                id: UUID(uuidString: "72727272-7272-7272-7272-727272727272")!,
                name: "example-control-plane",
                username: "chen_liang",
                website: "https://example-control-plane.signin.aws.amazon.com/console",
                isFavorite: false,
                isCliEnabled: true
            )
        ]
        let accounts = [
            CLIListAccount(
                id: broadId,
                issuer: "Amazon Web Services",
                label: "root-account-mfa-device@example-control-plane",
                hosts: ["aws.amazon.com"],
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            ),
            CLIListAccount(
                id: specificId,
                issuer: "Amazon Web Services",
                label: "chen_liang@example-control-plane",
                hosts: ["https://example-control-plane.signin.aws.amazon.com/console"],
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            ),
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getOTPJSON, .getChromePasswordJSON, .getChromeOTPJSON:
                XCTFail("Did not expect secret lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/mfa"
        )

        let otpMatches = listResponse.credentials?.filter { $0.kind == "otp" } ?? []
        XCTAssertEqual(otpMatches.map(\.id), [specificId, broadId])
    }

    func testCredentialResolverListsAWSOTPUsingMatchedPasswordAlias() throws {
        let passwordId = UUID(uuidString: "45454545-4545-4545-4545-454545454545")!
        let otpId = UUID(uuidString: "56565656-5656-5656-5656-565656565656")!
        let passwords = [
            CLIListPassword(
                id: passwordId,
                name: "example-control-plane",
                username: "chen_liang",
                website: "https://example-control-plane.signin.aws.amazon.com/console",
                isFavorite: false,
                isCliEnabled: true
            )
        ]
        let accounts = [
            CLIListAccount(
                id: otpId,
                issuer: "Amazon Web Services",
                label: "chen_liang@example-control-plane",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 2)
            )
        ]

        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return try self.encodeFixture(accounts)
            case .getPasswordJSON, .getChromePasswordJSON, .getOTPJSON:
                XCTFail("Did not expect password lookup")
                return Data()
            case .getChromeOTPJSON(let queryID):
                let result = CLIGetOTPResult(
                    id: queryID.uuidString,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    code: "654321",
                    remaining: 18,
                    expiresAt: Date(timeIntervalSince1970: 30),
                    isFavorite: false
                )
                return try self.encodeFixture(result)
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let listResponse = try resolver.listCredentials(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth"
        )

        let otpMatches = listResponse.credentials?.filter { $0.kind == "otp" } ?? []
        XCTAssertEqual(otpMatches.count, 1)
        XCTAssertEqual(otpMatches.first?.id, otpId)

        let getResponse = try resolver.getCredential(
            forHost: "ap-southeast-1.signin.aws.amazon.com",
            currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth",
            credentialId: otpId
        )

        XCTAssertEqual(getResponse.ok, true)
        XCTAssertEqual(getResponse.credential?.otpCode, "654321")
    }

    func testCredentialResolverReturnsMultipleMatchesWhenAmbiguous() throws {
        let id1 = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!
        let id2 = UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!

        let passwords: [CLIListPassword] = [
            CLIListPassword(
                id: id1,
                name: "One",
                username: "one",
                website: "https://example.com",
                isFavorite: false,
                isCliEnabled: true
            ),
            CLIListPassword(
                id: id2,
                name: "Two",
                username: "two",
                website: "https://example.com/login",
                isFavorite: false,
                isCliEnabled: true
            ),
        ]

        var getWasCalled = false
        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return Data("[]".utf8)
            case .getPasswordJSON, .getChromePasswordJSON:
                getWasCalled = true
                throw NSError(domain: "test", code: 1)
            case .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect OTP lookup")
                return Data()
            }
        }

        let resolver = CredentialResolver(cliClient: client)
        let response = try resolver.getCredential(forHost: "example.com", credentialId: nil)

        XCTAssertFalse(getWasCalled)
        XCTAssertEqual(response.ok, false)
        XCTAssertEqual(response.error, .multipleMatches)
    }

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
        let id = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let passwords: [CLIListPassword] = [
            CLIListPassword(
                id: id,
                name: "Match",
                username: "user",
                website: "https://example.com/login",
                isFavorite: false,
                isCliEnabled: true
            ),
        ]
        let client = CLIClient { command in
            switch command {
            case .listPasswordsJSON:
                return try JSONEncoder().encode(passwords)
            case .listOTPJSON:
                return Data("[]".utf8)
            case .getChromePasswordJSON(let queryID):
                let result = CLIGetPasswordResult(
                    id: queryID.uuidString,
                    name: "Match",
                    username: "user",
                    password: "pass",
                    website: "https://example.com/login"
                )
                return try JSONEncoder().encode(result)
            case .getPasswordJSON, .getOTPJSON, .getChromeOTPJSON:
                XCTFail("Did not expect OTP lookup")
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
