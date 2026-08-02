import XCTest
import CryptoKit
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

@MainActor
final class XPCRequestHandlerChromeAutofillMatchesTests: XCTestCase {
    private let cliAccessEnabledKey = "cliAccessEnabled"
    private var hadCLISetting = false
    private var previousCLISetting = false

    private static let passwordID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private static let otpID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    private let chromeCaller = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: BridgeContext.chromeNativeHostProcessName,
            bundleIdentifier: nil
        )
    )

    private let terminalCaller = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "authsia",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Terminal",
            bundleIdentifier: "com.apple.Terminal",
            isPlatformBinary: true
        )
    )

    override func setUp() {
        super.setUp()
        hadCLISetting = BridgeSettings.appDefaults.object(forKey: cliAccessEnabledKey) != nil
        previousCLISetting = BridgeSettings.appDefaults.bool(forKey: cliAccessEnabledKey)
        BridgeSettings.appDefaults.set(true, forKey: cliAccessEnabledKey)
    }

    override func tearDown() {
        if hadCLISetting {
            BridgeSettings.appDefaults.set(previousCLISetting, forKey: cliAccessEnabledKey)
        } else {
            BridgeSettings.appDefaults.removeObject(forKey: cliAccessEnabledKey)
        }
        super.tearDown()
    }

    // The whole point of the request type: a site the vault has nothing for
    // must not raise an approval prompt.
    func testMatchingHostReturnsMatchesWithoutApproval() async {
        let approver = AutofillApprovalTracker()
        let handler = makeHandler(approver: approver, caller: chromeCaller)

        let payload = await matches(handler: handler, host: "github.com")

        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(payload?.matches.map(\.id), [Self.passwordID, Self.otpID])
        XCTAssertEqual(payload?.matches.map(\.kind), [.password, .otp])
    }

    func testUnmatchedHostReturnsEmptyWithoutApproval() async {
        let approver = AutofillApprovalTracker()
        let handler = makeHandler(approver: approver, caller: chromeCaller)

        let payload = await matches(handler: handler, host: "unrelated.example")

        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(payload?.matches.count, 0)
    }

    func testKindNarrowsTheReply() async {
        let handler = makeHandler(approver: AutofillApprovalTracker(), caller: chromeCaller)

        let payload = await matches(handler: handler, host: "github.com", kind: .password)

        XCTAssertEqual(payload?.matches.map(\.kind), [.password])
    }

    func testNonNativeHostCallerIsDenied() async {
        let handler = makeHandler(approver: AutofillApprovalTracker(), caller: terminalCaller)

        let response = await send(
            handler: handler,
            requestData: makeRequest(host: "github.com", requestedCommand: "list")
        )

        XCTAssertEqual(response?.error?.code, .policyDenied)
        XCTAssertNil(response?.payload)
    }

    // The hidden CLI marker alone must not open this path for a terminal caller.
    func testChromeMarkerWithoutNativeHostAncestryIsDenied() async {
        let handler = makeHandler(approver: AutofillApprovalTracker(), caller: terminalCaller)

        let response = await send(handler: handler, requestData: makeRequest(host: "github.com"))

        XCTAssertEqual(response?.error?.code, .policyDenied)
    }

    func testInvalidHostIsRejected() async {
        let handler = makeHandler(approver: AutofillApprovalTracker(), caller: chromeCaller)

        let response = await send(handler: handler, requestData: makeRequest(host: "exa mple.com"))

        XCTAssertEqual(response?.error?.code, .invalidRequest)
    }

    func testMissingBodyIsRejected() async {
        let request = BridgeRequest(
            id: UUID(),
            type: .chromeAutofillMatches,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: makeContext(requestedCommand: BridgeContext.chromeNativeHostRequestedCommand)
        )
        let handler = makeHandler(approver: AutofillApprovalTracker(), caller: chromeCaller)

        let response = await send(
            handler: handler,
            requestData: (try? BridgeCoder.encode(request)) ?? Data()
        )

        XCTAssertEqual(response?.error?.code, .invalidRequest)
    }

    func testMatchesAreAudited() async {
        let auditDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: auditDirectory) }
        let auditURL = auditDirectory.appendingPathComponent("audit.log")

        let handler = makeHandler(
            approver: AutofillApprovalTracker(),
            caller: chromeCaller,
            auditLogger: BridgeAuditLogger(
                fileURL: auditURL,
                hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0x24, count: 32)) }
            )
        )

        _ = await matches(handler: handler, host: "github.com")

        let contents = (try? String(contentsOf: auditURL, encoding: .utf8)) ?? ""
        XCTAssertTrue(contents.contains("chrome-autofill"), "Chrome autofill lookups must leave an audit trail")
        XCTAssertTrue(contents.contains("github.com"))
    }

    // MARK: - Harness

    private func makeHandler(
        approver: AutofillApprovalTracker,
        caller: CallerIdentity,
        auditLogger: BridgeAuditLogger = BridgeAuditLogger()
    ) -> XPCRequestHandler {
        XPCRequestHandler(
            accountProvider: {
                [
                    BridgeAccount(
                        id: Self.otpID,
                        issuer: "GitHub",
                        label: "user@example.com",
                        hosts: ["https://github.com"],
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(timeIntervalSince1970: 1),
                        updatedAt: Date(timeIntervalSince1970: 2)
                    )
                ]
            },
            chromeAutofillPasswordProvider: {
                [
                    ChromeAutofillPasswordMetadata(
                        id: Self.passwordID,
                        name: "GitHub",
                        username: "user@example.com",
                        website: "https://github.com"
                    )
                ]
            },
            approver: approver,
            callerIdentityProvider: { caller },
            auditLogger: auditLogger
        )
    }

    private func makeContext(requestedCommand: String?) -> BridgeContext {
        BridgeContext(
            isTTY: false,
            isPiped: true,
            isSSH: false,
            isCI: false,
            timestamp: Date(),
            requestedCommand: requestedCommand,
            sessionScope: BridgeContext.chromeNativeHostSessionScope
        )
    }

    private func makeRequest(
        host: String,
        currentURL: String? = nil,
        kind: ChromeAutofillCredentialKind? = nil,
        requestedCommand: String? = BridgeContext.chromeNativeHostRequestedCommand
    ) -> Data {
        let request = BridgeRequest(
            id: UUID(),
            type: .chromeAutofillMatches,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: makeContext(requestedCommand: requestedCommand),
            body: try? BridgeCoder.encode(
                ChromeAutofillMatchQuery(host: host, currentURL: currentURL, kind: kind)
            )
        )
        return (try? BridgeCoder.encode(request)) ?? Data()
    }

    private func send(
        handler: XPCRequestHandler,
        requestData: Data
    ) async -> BridgeResponse<ChromeAutofillMatchesPayload>? {
        let replied = XCTestExpectation(description: "chrome autofill matches reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            replied.fulfill()
        }
        await fulfillment(of: [replied], timeout: 1)
        return try? BridgeCoder.decode(
            BridgeResponse<ChromeAutofillMatchesPayload>.self,
            from: responseData ?? Data()
        )
    }

    private func matches(
        handler: XPCRequestHandler,
        host: String,
        currentURL: String? = nil,
        kind: ChromeAutofillCredentialKind? = nil
    ) async -> ChromeAutofillMatchesPayload? {
        await send(
            handler: handler,
            requestData: makeRequest(host: host, currentURL: currentURL, kind: kind)
        )?.payload
    }
}

private final class AutofillApprovalTracker: BridgeApprover {
    private(set) var callCount = 0
    private(set) var prompts: [String] = []

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        callCount += 1
        prompts.append(prompt)
        return .approved(source: .macBiometric)
    }
}
