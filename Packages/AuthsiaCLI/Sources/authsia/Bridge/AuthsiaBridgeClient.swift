import Foundation
import Darwin
import AuthenticatorBridge
import AuthenticatorCore

// MARK: - Bridge Client Error

enum BridgeClientError: LocalizedError {
    case connectionFailed
    case timeout
    case invalidResponse
    case appUnavailable
    case bridgeError(code: String, message: String, query: String?)

    var errorDescription: String? {
        switch self {
        case .connectionFailed:
            return Self.cliUnavailableMessage
        case .timeout:
            return "Request timed out. \(Self.cliAccessGuidance)"
        case .invalidResponse:
            return "Received an invalid response from Authsia."
        case .appUnavailable:
            return Self.cliUnavailableMessage
        case .bridgeError(let code, let message, let query):
            return Self.friendlyMessage(for: code, query: query, serverMessage: message)
        }
    }

    /// True only for an explicit approval denial (the user rejected the prompt, or a
    /// security policy refused). A locked vault or an unreachable bridge surfaces as
    /// `appUnavailable` / transport errors and returns false, so callers can degrade
    /// gracefully for those while treating a denial as fatal.
    static func isApprovalDenied(_ error: Error) -> Bool {
        guard case let BridgeClientError.bridgeError(code, _, _) = error else { return false }
        return code == "notAuthorized" || code == "policyDenied"
    }

    private static let cliAccessGuidance =
        "Open the Authsia app and Enable CLI Access in Settings > Security."

    private static let cliUnavailableMessage =
        "Could not reach the Authsia bridge. If you just installed Authsia, open the app once to "
        + "register CLI access — it then launches on demand, so you don't need to keep it open. "
        + "Make sure Authsia is installed in /Applications. \(cliAccessGuidance)"

    static let approvalPromptGuidance =
        "Waiting for Authsia Direct CLI approval in the app. " +
        "If nothing appears, open Authsia and enable CLI Access in Settings > Security."

    static let agentJITApprovalPromptGuidance =
        "Waiting for Authsia Agent JIT approval in the app. " +
        "Approving creates a temporary scoped grant for the detected coding agent. " +
        "If nothing appears, open Authsia and enable CLI Access in Settings > Security."

    static let accessCredentialApprovalPromptGuidance =
        "Waiting for Authsia Access Credential approval in the app. " +
        "Approving creates a scoped access credential for automation. " +
        "If nothing appears, open Authsia and enable CLI Access in Settings > Security."

    private static func friendlyMessage(for code: String, query: String?, serverMessage: String?) -> String {
        switch code {
        case "notFound":
            if let serverMessage,
               serverMessage.hasPrefix("Failed to retrieve ") {
                return serverMessage
            }
            if let query = query {
                return "No item found matching '\(query)'. Use 'authsia list' to see available items."
            }
            return "Item not found. Use 'authsia list' to see available items."
        case "multipleMatches":
            if let serverMessage = serverMessage {
                return serverMessage
            }
            if let query = query {
                return "Multiple items match '\(query)'. Use the item ID to be specific."
            }
            return "Multiple items match. Use the item ID to be specific."
        case "notAuthorized":
            return "Access denied. Approval was not granted in the Authsia app."
        case "policyDenied":
            if serverMessage?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "cli access is disabled" {
                return "CLI access is disabled. \(cliAccessGuidance)"
            }
            if let serverMessage, !serverMessage.isEmpty {
                return serverMessage
            }
            return "Access denied by security policy (CLI access is disabled for this item)."
        case "appUnavailable":
            if let serverMessage, !serverMessage.isEmpty {
                return serverMessage
            }
            return Self.cliUnavailableMessage
        case "invalidRequest":
            if let serverMessage, !serverMessage.isEmpty {
                return serverMessage
            }
            return "Invalid request. Please check your command and try again."
        default:
            return "An error occurred: \(code)"
        }
    }
}

extension BridgeRequestType {
    var mayRequireUserApproval: Bool {
        switch self {
        case .ping, .status, .lock, .workspaceMetadata, .auditVerify, .sshAgentSign:
            return false
        case .unlock,
             .list,
             .createAccess,
             .agentJITPreflight,
             .getOTP,
             .getPassword,
             .getAPIKey,
             .getCertificate,
             .getNote,
             .getSSH,
             .exportAccounts,
             .addPassword,
             .updatePassword,
             .deletePassword,
             .convertPasswordToAPIKey,
             .addAPIKey,
             .updateAPIKey,
             .deleteAPIKey,
             .addCertificate,
             .updateCertificate,
             .deleteCertificate,
             .addNote,
             .updateNote,
             .deleteNote,
             .addSSH,
             .updateSSH,
             .deleteSSH,
             .ensureVaultFolder,
             .deleteVaultFolder:
            return true
        }
    }
}

// MARK: - AuthsiaBridgeClient

final class AuthsiaBridgeClient: AccessCreateApproving, SessionLocking, @unchecked Sendable {
    static let shared = AuthsiaBridgeClient()
    private static let shellCompletionRequestedCommand = "completion"

    private let serviceName = "Authsia.Bridge"
    private let appBundleIdentifier = "Authsia"
    private let timeout: TimeInterval

    /// Retry delays for exponential backoff (in seconds)
    private let retryDelays: [TimeInterval] = [0.5, 1.0, 2.0]
    
    /// Session token for anti-replay protection (obtained from unlock or cache)
    private var sessionToken: String?

    typealias XPCReplyHandler = (Data?, NSError?) -> Void
    typealias XPCProxyErrorHandler = (Error) -> Void

    init(timeout: TimeInterval = 30) {
        self.timeout = timeout
        // Restore session token from disk cache if available
        self.sessionToken = SessionCache.load()
    }

    // MARK: - Connection Management

    private func createConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: AuthsiaBridgeXPCProtocol.self)
        connection.resume()
        return connection
    }

    // MARK: - Public API

    func ping() throws -> BridgePingPayload {
        try Self.withBridgeRecovery(
            retryDelays: retryDelays,
            recover: { self.recoverBridgeAvailability() },
            operation: { try self.executePing() }
        )
    }

    func status(sessionScope: String? = nil) throws -> BridgePingPayload {
        let request = BridgeRequest(
            id: UUID(),
            type: .status,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(sessionScope: sessionScope)
        )
        let response: BridgeResponse<BridgePingPayload> = try sendRequest(request)
        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }
        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload
    }

    private func executePing() throws -> BridgePingPayload {
        let connection = createConnection()
        defer { connection.invalidate() }

        let responseData = try Self.awaitResponse(timeout: timeout) { replyHandler, proxyErrorHandler in
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                proxyErrorHandler(error)
            } as? AuthsiaBridgeXPCProtocol

            guard let service = proxy else {
                proxyErrorHandler(BridgeClientError.connectionFailed)
                return
            }

            service.ping(replyHandler)
        }

        let response = try BridgeCoder.decode(BridgeResponse<BridgePingPayload>.self, from: responseData)
        if let errorPayload = response.error {
            throw BridgeClientError.bridgeError(
                code: errorPayload.code.rawValue,
                message: errorPayload.message,
                query: nil
            )
        }
        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload
    }

    /// Lightweight reachability check used by callers that only need a yes/no.
    func isBridgeReachable() -> Bool {
        (try? ping()) != nil
    }

    func unlock() throws -> UnlockResult {
        // Clear any existing session before unlocking
        sessionToken = nil
        SessionCache.clear()

        let request = BridgeRequest(
            id: UUID(),
            type: .unlock,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext()
        )
        let response: BridgeResponse<UnlockPayload> = try sendRequest(request)
        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        // Store the session token in memory and persist to disk for subsequent CLI invocations
        sessionToken = payload.sessionToken
        SessionCache.save(token: payload.sessionToken, expiresAt: payload.expiresAt)
        return UnlockResult(expiresAt: payload.expiresAt, ttlSeconds: payload.ttlSeconds, sessionToken: payload.sessionToken)
    }

    func lock(sessionToken token: String?, sessionScope: String? = nil) throws -> Bool {
        sessionToken = nil
        SessionCache.clear()

        let request = BridgeRequest(
            id: UUID(),
            type: .lock,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(sessionScope: sessionScope),
            sessionToken: token
        )
        let response: BridgeResponse<WriteResultPayload> = try sendRequest(request)
        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }
        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload.message == "Session locked"
    }

    func getOTP(query: String) throws -> OTPResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getOTP,
            query: query,
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<OTPPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return OTPResult(
            accountId: payload.accountId,
            issuer: payload.issuer,
            label: payload.label,
            code: payload.code,
            remaining: payload.remaining,
            expiresAt: payload.expiresAt,
            isFavorite: payload.isFavorite
        )
    }

    func getPassword(query: String, field: String? = nil) throws -> PasswordResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: query,
            options: BridgeOptions(field: field, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<PasswordPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return PasswordResult(
            id: payload.id,
            name: payload.name,
            username: payload.username,
            password: payload.password,
            website: payload.website,
            notes: payload.notes,
            createdAt: payload.createdAt,
            modifiedAt: payload.modifiedAt,
            isFavorite: payload.isFavorite
        )
    }

    func getAPIKey(query: String, field: String? = nil) throws -> APIKeyResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getAPIKey,
            query: query,
            options: BridgeOptions(field: field, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<APIKeyPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return APIKeyResult(
            id: payload.id,
            name: payload.name,
            key: payload.key,
            website: payload.website,
            notes: payload.notes,
            createdAt: payload.createdAt,
            modifiedAt: payload.modifiedAt,
            isFavorite: payload.isFavorite
        )
    }

    func getCertificate(query: String, field: String? = nil) throws -> CertificateResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getCertificate,
            query: query,
            options: BridgeOptions(field: field, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<CertificatePayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return CertificateResult(
            id: payload.id,
            name: payload.name,
            certificate: payload.certificate,
            privateKey: payload.privateKey,
            issuer: payload.issuer,
            subject: payload.subject,
            expirationDate: payload.expirationDate,
            notes: payload.notes,
            createdAt: payload.createdAt,
            modifiedAt: payload.modifiedAt,
            isFavorite: payload.isFavorite
        )
    }

    func getNote(query: String) throws -> NoteResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getNote,
            query: query,
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<NotePayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return NoteResult(
            id: payload.id,
            title: payload.title,
            content: payload.content,
            createdAt: payload.createdAt,
            modifiedAt: payload.modifiedAt,
            isFavorite: payload.isFavorite
        )
    }

    func getSSH(query: String, field: String? = nil) throws -> SSHKeyResult {
        let request = BridgeRequest(
            id: UUID(),
            type: .getSSH,
            query: query,
            options: BridgeOptions(field: field, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<SSHPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return SSHKeyResult(
            id: payload.id,
            name: payload.name,
            publicKey: payload.publicKey,
            privateKey: payload.privateKey,
            comment: payload.comment,
            fingerprint: payload.fingerprint,
            passphrase: payload.passphrase,
            keyType: payload.keyType ?? SSHKeyTypeDetector.detect(publicKey: payload.publicKey),
            approvalPolicy: payload.approvalPolicy ?? .sessionBased,
            boundHosts: payload.boundHosts ?? [],
            createdAt: payload.createdAt,
            modifiedAt: payload.modifiedAt,
            isFavorite: payload.isFavorite
        )
    }

    func list() throws -> BridgeListPayload {
        let request = BridgeRequest(
            id: UUID(),
            type: .list,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<BridgeListPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload
    }

    func workspaceMetadata(
        _ payload: WorkspaceMetadataRequestPayload,
        requestedCommand: String
    ) throws -> BridgeListPayload {
        try withRequestedCommand(requestedCommand, includeAutomationCredential: false) {
            let request = BridgeRequest(
                id: UUID(),
                type: .workspaceMetadata,
                query: "",
                options: BridgeOptions(field: nil, copy: false),
                context: currentContext(),
                body: try BridgeCoder.encode(payload)
            )
            let response: BridgeResponse<BridgeListPayload> = try sendRequest(request)
            if let error = response.error {
                throw BridgeClientError.bridgeError(
                    code: error.code.rawValue,
                    message: error.message,
                    query: nil
                )
            }
            guard let payload = response.payload else {
                throw BridgeClientError.invalidResponse
            }
            return payload
        }
    }

    func listForShellCompletion() throws -> BridgeListPayload? {
        guard Self.shouldRequestShellCompletionMetadata(sessionToken: sessionToken) else {
            return nil
        }

        return try withRequestedCommand(Self.shellCompletionRequestedCommand, includeAutomationCredential: false) {
            try list()
        }
    }

    func agentJITPreflight(_ payload: AgentJITPreflightPayload) throws -> AgentJITPreflightResultPayload {
        let request = BridgeRequest(
            id: UUID(),
            type: .agentJITPreflight,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(),
            body: try BridgeCoder.encode(payload),
            sessionToken: sessionToken
        )
        let response: BridgeResponse<AgentJITPreflightResultPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload
    }

    func auditVerify() throws -> Bool {
        let request = BridgeRequest(
            id: UUID(),
            type: .auditVerify,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext()
        )
        let response: BridgeResponse<AuditVerifyPayload> = try sendRequest(request)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }
        return payload.valid
    }

    func addPassword(
        name: String,
        username: String,
        password: String,
        website: String?,
        notes: String?,
        isScraped: Bool = false,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        environments: [String] = []
    ) throws -> WriteResult {
        let payload = PasswordWritePayload(
            name: name,
            username: username,
            password: password,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .addPassword, query: "", body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: nil)
    }

    func updatePassword(
        query: String,
        name: String?,
        username: String?,
        password: String?,
        website: String?,
        notes: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        clearExpiresAt: Bool = false,
        environments: [String]? = nil
    ) throws -> WriteResult {
        let payload = PasswordWritePayload(
            name: name,
            username: username,
            password: password,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            clearExpiresAt: clearExpiresAt ? true : nil,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .updatePassword, query: query, body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deletePassword(query: String) throws -> WriteResult {
        let request = WriteRequestBuilder.makeRequest(type: .deletePassword, query: query, body: nil, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func convertPasswordToAPIKey(query: String) throws -> WriteResult {
        let body = try BridgeCoder.encode(PasswordConversionPayload(targetType: "api-key"))
        let request = WriteRequestBuilder.makeRequest(
            type: .convertPasswordToAPIKey,
            query: query,
            body: body,
            sessionToken: sessionToken
        )
        return try handleWriteResponse(request, query: query)
    }

    func addAPIKey(
        name: String,
        key: String,
        website: String?,
        notes: String?,
        isScraped: Bool = false,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        environments: [String] = []
    ) throws -> WriteResult {
        let payload = APIKeyWritePayload(
            name: name,
            key: key,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .addAPIKey, query: "", body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: nil)
    }

    func updateAPIKey(
        query: String,
        name: String?,
        key: String?,
        website: String?,
        notes: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        clearExpiresAt: Bool = false,
        environments: [String]? = nil
    ) throws -> WriteResult {
        let payload = APIKeyWritePayload(
            name: name,
            key: key,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            clearExpiresAt: clearExpiresAt ? true : nil,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .updateAPIKey, query: query, body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deleteAPIKey(query: String) throws -> WriteResult {
        let request = WriteRequestBuilder.makeRequest(type: .deleteAPIKey, query: query, body: nil, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deleteVaultFolder(path: String) throws -> WriteResult {
        let payload = VaultFolderWritePayload(path: path)
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(
            type: .deleteVaultFolder,
            query: path,
            body: body,
            sessionToken: sessionToken
        )
        return try handleWriteResponse(request, query: path)
    }

    func addCertificate(
        name: String,
        certificate: String,
        privateKey: String?,
        notes: String?,
        folderPath: String? = nil,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) throws -> WriteResult {
        let payload = CertificateWritePayload(
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .addCertificate, query: "", body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: nil)
    }

    func updateCertificate(
        query: String,
        name: String?,
        certificate: String?,
        privateKey: String?,
        clearPrivateKey: Bool = false,
        notes: String?,
        folderPath: String? = nil,
        isScraped: Bool? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String]? = nil
    ) throws -> WriteResult {
        let payload = CertificateWritePayload(
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            clearPrivateKey: clearPrivateKey,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .updateCertificate, query: query, body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deleteCertificate(query: String) throws -> WriteResult {
        let request = WriteRequestBuilder.makeRequest(type: .deleteCertificate, query: query, body: nil, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?
    ) throws -> WriteResult {
        try addNote(
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: nil,
            scrapeMachineId: nil,
            environments: []
        )
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool = false,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) throws -> WriteResult {
        let payload = NoteWritePayload(
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .addNote, query: "", body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: nil)
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?
    ) throws -> WriteResult {
        try updateNote(
            query: query,
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: nil,
            scrapeMachineId: nil,
            environments: nil
        )
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String]? = nil
    ) throws -> WriteResult {
        let payload = NoteWritePayload(
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .updateNote, query: query, body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deleteNote(query: String) throws -> WriteResult {
        let request = WriteRequestBuilder.makeRequest(type: .deleteNote, query: query, body: nil, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func addSSH(
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        passphrase: String? = nil,
        keyType: SSHKeyType? = nil,
        approvalPolicy: SSHKeyApprovalPolicy? = nil,
        boundHosts: [String]? = nil,
        isScraped: Bool = false,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) throws -> WriteResult {
        let payload = SSHKeyWritePayload(
            name: name,
            publicKey: publicKey,
            privateKey: privateKey,
            comment: comment,
            fingerprint: fingerprint,
            passphrase: passphrase,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            keyType: keyType,
            approvalPolicy: approvalPolicy,
            boundHosts: boundHosts,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .addSSH, query: "", body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: nil)
    }

    func addSSH(
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        passphrase: String?,
        keyType: SSHKeyType?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try addSSH(
            name: name,
            publicKey: publicKey,
            privateKey: privateKey,
            comment: comment,
            fingerprint: fingerprint,
            passphrase: passphrase,
            keyType: keyType,
            approvalPolicy: nil,
            boundHosts: nil,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: []
        )
    }

    func updateSSH(
        query: String,
        name: String?,
        publicKey: String?,
        privateKey: String?,
        comment: String?,
        fingerprint: String?,
        passphrase: String? = nil,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        keyType: SSHKeyType? = nil,
        approvalPolicy: String? = nil,
        boundHosts: [String]? = nil,
        environments: [String]? = nil
    ) throws -> WriteResult {
        let mappedPolicy: SSHKeyApprovalPolicy? = approvalPolicy.flatMap { SSHKeyApprovalPolicy(rawValue: $0) }
        let payload = SSHKeyWritePayload(
            name: name,
            publicKey: publicKey,
            privateKey: privateKey,
            comment: comment,
            fingerprint: fingerprint,
            passphrase: passphrase,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            keyType: keyType,
            approvalPolicy: mappedPolicy,
            boundHosts: boundHosts,
            environments: environments
        )
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(type: .updateSSH, query: query, body: body, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func deleteSSH(query: String) throws -> WriteResult {
        let request = WriteRequestBuilder.makeRequest(type: .deleteSSH, query: query, body: nil, sessionToken: sessionToken)
        return try handleWriteResponse(request, query: query)
    }

    func ensureVaultFolder(path: String) throws -> WriteResult {
        let payload = VaultFolderWritePayload(path: path)
        let body = try BridgeCoder.encode(payload)
        let request = WriteRequestBuilder.makeRequest(
            type: .ensureVaultFolder,
            query: path,
            body: body,
            sessionToken: sessionToken
        )
        return try handleWriteResponse(request, query: path)
    }

    func approveAccessCreate(_ accessRequest: AccessCreateApprovalRequest) throws {
        let payload = AccessCreateApprovalPayload(
            name: accessRequest.name,
            scope: accessRequest.scope,
            ttlSeconds: Int(accessRequest.ttlSeconds),
            expiresAt: accessRequest.expiresAt,
            machineId: accessRequest.machineId,
            machineName: accessRequest.machineName,
            allowedCommands: accessRequest.allowedCommands.map(\.rawValue).sorted(),
            environmentScope: accessRequest.environmentScope
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .createAccess,
            query: AutomationCredentialScope.displayName(accessRequest.scope),
            options: BridgeOptions(field: nil, copy: false),
            context: currentContext(),
            body: body,
            sessionToken: nil
        )
        let response: BridgeResponse<WriteResultPayload> = try sendRequest(request)
        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: nil)
        }
        guard response.payload != nil else {
            throw BridgeClientError.invalidResponse
        }
    }

    // MARK: - Private Helpers

    /// If the server returned a new session token (after biometric approval), cache it for subsequent requests.
    private func cacheSessionToken<T: Codable & Equatable>(from response: BridgeResponse<T>) {
        guard let token = response.sessionToken else { return }
        sessionToken = token
        let expiresAt = response.sessionExpiresAt ?? Date().addingTimeInterval(300)
        SessionCache.save(token: token, expiresAt: expiresAt)
    }

    // Task-local tag so `currentContext()` can annotate each in-flight RPC with
    // the CLI command that initiated it, including async flows like `scrape`.
    private final class ApprovalPromptState: @unchecked Sendable {
        var hasShown = false
    }

    @TaskLocal private static var requestedCommand: String?
    @TaskLocal private static var includeAutomationCredential: Bool?
    @TaskLocal private static var approvalPromptState: ApprovalPromptState?
    private static let approvalPromptShownKey = "authsia.approvalPromptShown"

    func withRequestedCommand<R>(_ command: CapabilityCommand, _ body: () throws -> R) rethrows -> R {
        try withRequestedCommand(command.rawValue, includeAutomationCredential: true, body)
    }

    func withRequestedCommand<R>(
        _ command: String,
        includeAutomationCredential: Bool = true,
        _ body: () throws -> R
    ) rethrows -> R {
        defer {
            Thread.current.threadDictionary.removeObject(forKey: Self.approvalPromptShownKey)
        }
        return try Self.$approvalPromptState.withValue(ApprovalPromptState()) {
            try Self.$requestedCommand.withValue(command) {
                try Self.$includeAutomationCredential.withValue(includeAutomationCredential) {
                    try body()
                }
            }
        }
    }

    func withRequestedCommand<R>(
        _ command: String,
        includeAutomationCredential: Bool = true,
        _ body: () async throws -> R
    ) async rethrows -> R {
        return try await Self.$approvalPromptState.withValue(ApprovalPromptState()) {
            try await Self.$requestedCommand.withValue(command) {
                try await Self.$includeAutomationCredential.withValue(includeAutomationCredential) {
                    try await body()
                }
            }
        }
    }

    static func shouldRequestShellCompletionMetadata(
        sessionToken: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Bool {
        if sessionToken?.isEmpty == false {
            return true
        }
        return !isIntegratedIDETerminal(environment: environment)
    }

    private static func isIntegratedIDETerminal(environment: [String: String]) -> Bool {
        let termProgram = environment["TERM_PROGRAM"]?.lowercased() ?? ""
        let terminalEmulator = environment["TERMINAL_EMULATOR"]?.lowercased() ?? ""

        return termProgram.contains("vscode")
            || terminalEmulator.contains("jetbrains")
            || environment["VSCODE_INJECTION"] != nil
            || environment["VSCODE_GIT_IPC_HANDLE"] != nil
    }

    private func currentContext(sessionScope: String? = nil) -> BridgeContext {
        Self.currentContext(sessionScope: sessionScope)
    }

    static func currentContext(sessionScope: String? = nil) -> BridgeContext {
        let context = AutomationAccessResolver.bridgeContext(
            requestedCommand: requestedCommand,
            fullCommand: fullCommandForAudit(),
            includeAutomationCredential: includeAutomationCredential ?? true
        )
        guard let sessionScope else { return context }
        return BridgeContext(
            isTTY: context.isTTY,
            isPiped: context.isPiped,
            isSSH: context.isSSH,
            isCI: context.isCI,
            timestamp: context.timestamp,
            automationCredentialID: context.automationCredentialID,
            automationScope: context.automationScope,
            requestedCommand: context.requestedCommand,
            fullCommand: context.fullCommand,
            sessionScope: sessionScope,
            workingDirectory: context.workingDirectory,
            agentRuntimeContext: context.agentRuntimeContext,
            workspaceContext: context.workspaceContext
        )
    }

    static func fullCommandForAudit(arguments: [String] = CommandLine.arguments) -> String? {
        guard !arguments.isEmpty else { return nil }
        guard !isCompletionInvocation(arguments) else { return nil }
        guard !isAgentPluginBackgroundWorkspaceRun(arguments) else { return nil }

        var redactNext = false
        let rendered = arguments.enumerated().map { index, rawArgument in
            if redactNext {
                redactNext = false
                return shellQuote("<redacted>")
            }

            let argument = index == 0 ? URL(fileURLWithPath: rawArgument).lastPathComponent : rawArgument
            let lowercased = argument.lowercased()

            if let separatorIndex = argument.firstIndex(of: "=") {
                let key = String(argument[..<separatorIndex])
                if isSensitiveOption(key) {
                    return "\(key)=<redacted>"
                }
            }

            if isSensitiveOption(lowercased) {
                redactNext = true
            }

            return shellQuote(argument)
        }
        return rendered.joined(separator: " ")
    }

    private static func isCompletionInvocation(_ arguments: [String]) -> Bool {
        arguments.dropFirst().contains("---completion")
    }

    private static func isAgentPluginBackgroundWorkspaceRun(_ arguments: [String]) -> Bool {
        let commandArguments = Array(arguments.dropFirst())
        guard commandArguments.count >= 4,
              commandArguments[0] == "workspace",
              commandArguments[1] == "run",
              let separatorIndex = commandArguments.firstIndex(of: "--") else {
            return false
        }

        let childStartIndex = commandArguments.index(after: separatorIndex)
        guard childStartIndex < commandArguments.endIndex else { return false }
        let childArguments = commandArguments[childStartIndex...]
        return childArguments.contains(where: isClaudePluginCachePath)
            && childArguments.contains("hook")
            && childArguments.contains("claude-code")
    }

    private static func isClaudePluginCachePath(_ argument: String) -> Bool {
        argument.replacingOccurrences(of: "\\", with: "/").contains("/.claude/plugins/cache/")
    }

    private static func isSensitiveOption(_ option: String) -> Bool {
        let normalized = option.lowercased()
        let sensitiveOptions = [
            "--api-key",
            "--auth-token",
            "--key",
            "--password",
            "--secret",
            "--session-token",
            "--token",
        ]
        return sensitiveOptions.contains(normalized)
    }

    private static func shellQuote(_ argument: String) -> String {
        guard !argument.isEmpty else { return "''" }
        let safeCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_/:=.,+-"))
        if argument.rangeOfCharacter(from: safeCharacters.inverted) == nil {
            return argument
        }
        return "'\(argument.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    static func approvalPromptMessage(
        for requestType: BridgeRequestType,
        context: BridgeContext,
        hasSessionToken: Bool,
        stderrIsTTY: Bool,
        hasAlreadyShown: Bool
    ) -> String? {
        guard stderrIsTTY,
              !hasAlreadyShown,
              !hasSessionToken,
              !context.isCI,
              requestType.mayRequireUserApproval else {
            return nil
        }
        if requestType == .list, context.requestedCommand != "list" {
            return nil
        }
        guard context.automationCredentialID == nil || requestType == .createAccess else {
            return nil
        }
        if requestType == .agentJITPreflight {
            return BridgeClientError.agentJITApprovalPromptGuidance
        }
        if requestType == .createAccess {
            return BridgeClientError.accessCredentialApprovalPromptGuidance
        }
        return BridgeClientError.approvalPromptGuidance
    }

    private static func maybeWriteApprovalPrompt(for request: BridgeRequest) {
        let threadDictionary = Thread.current.threadDictionary
        let state = approvalPromptState
        let hasAlreadyShown = state?.hasShown ?? (threadDictionary[approvalPromptShownKey] as? Bool == true)
        guard let message = approvalPromptMessage(
            for: request.type,
            context: request.context,
            hasSessionToken: request.sessionToken?.isEmpty == false,
            stderrIsTTY: isatty(STDERR_FILENO) != 0,
            hasAlreadyShown: hasAlreadyShown
        ) else {
            return
        }
        StandardError.writeLine(message)
        if let state {
            state.hasShown = true
        } else {
            threadDictionary[approvalPromptShownKey] = true
        }
    }

    // MARK: - XPC Request Handling

    func sendRequest<T: Codable>(_ request: BridgeRequest) throws -> T {
        try Self.withBridgeRecovery(
            retryDelays: retryDelays,
            recover: { self.recoverBridgeAvailability() },
            operation: { try self.executeXPCRequest(request) },
            logFinalFailure: { error, attemptCount in
                // Only log on final failure; earlier attempts are expected during recovery.
                StandardError.writeLine(
                    "Bridge request failed after \(attemptCount) attempts: \(error.localizedDescription)"
                )
            }
        )
    }
    
    private func executeXPCRequest<T: Codable>(_ request: BridgeRequest) throws -> T {
        let connection = createConnection()
        defer { connection.invalidate() }

        let requestData = try BridgeCoder.encode(request)
        Self.maybeWriteApprovalPrompt(for: request)

        let responseData = try Self.awaitResponse(timeout: timeout) { replyHandler, proxyErrorHandler in
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                proxyErrorHandler(error)
            } as? AuthsiaBridgeXPCProtocol

            guard let service = proxy else {
                proxyErrorHandler(BridgeClientError.connectionFailed)
                return
            }

            switch request.type {
            case .ping:
                service.ping(replyHandler)
            case .status:
                service.status(requestData, replyHandler)
            case .unlock:
                service.unlock(requestData, replyHandler)
            case .lock:
                service.lock(requestData, replyHandler)
            case .getOTP:
                service.getOTP(requestData, replyHandler)
            case .getPassword:
                service.getPassword(requestData, replyHandler)
            case .getAPIKey:
                service.getAPIKey(requestData, replyHandler)
            case .getCertificate:
                service.getCertificate(requestData, replyHandler)
            case .getNote:
                service.getNote(requestData, replyHandler)
            case .getSSH:
                service.getSSH(requestData, replyHandler)
            case .list, .workspaceMetadata:
                service.list(requestData, replyHandler)
            case .auditVerify:
                service.auditVerify(requestData, replyHandler)
            case .exportAccounts:
                service.exportAccounts(requestData, replyHandler)
            case .addPassword, .addAPIKey, .addCertificate, .addNote, .addSSH, .ensureVaultFolder, .createAccess, .agentJITPreflight:
                service.addItem(requestData, replyHandler)
            case .updatePassword, .convertPasswordToAPIKey, .updateAPIKey, .updateCertificate, .updateNote, .updateSSH:
                service.updateItem(requestData, replyHandler)
            case .deletePassword, .deleteAPIKey, .deleteCertificate, .deleteNote, .deleteSSH, .deleteVaultFolder:
                service.deleteItem(requestData, replyHandler)
            case .sshAgentSign:
                proxyErrorHandler(BridgeClientError.bridgeError(
                    code: BridgeErrorCode.invalidRequest.rawValue,
                    message: "SSH-agent sign audit entries are not bridge requests.",
                    query: nil
                ))
            }
        }

        return try BridgeCoder.decode(T.self, from: responseData)
    }

    static func awaitResponse(
        timeout: TimeInterval,
        registerHandlers: (_ reply: @escaping XPCReplyHandler, _ proxyError: @escaping XPCProxyErrorHandler) -> Void
    ) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        let stateLock = NSLock()

        var responseData: Data?
        var resultError: Error?
        var isCompleted = false

        let complete: (_ data: Data?, _ error: Error?) -> Void = { data, error in
            stateLock.lock()
            defer { stateLock.unlock() }
            guard !isCompleted else {
                return
            }
            isCompleted = true
            responseData = data
            resultError = error
            semaphore.signal()
        }

        let replyHandler: XPCReplyHandler = { data, error in
            if let error {
                complete(nil, error)
            } else {
                complete(data, nil)
            }
        }

        let proxyErrorHandler: XPCProxyErrorHandler = { error in
            complete(nil, error)
        }

        registerHandlers(replyHandler, proxyErrorHandler)

        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            throw BridgeClientError.timeout
        }

        if let error = resultError {
            throw error
        }

        guard let responseData else {
            throw BridgeClientError.invalidResponse
        }

        return responseData
    }

    static func withBridgeRecovery<T>(
        retryDelays: [TimeInterval],
        sleep: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) },
        recover: () -> Bool,
        operation: () throws -> T,
        logFinalFailure: (Error, Int) -> Void = { _, _ in }
    ) throws -> T {
        var lastError: Error = BridgeClientError.connectionFailed
        var hasAttemptedRecovery = false

        for (attempt, delay) in retryDelays.enumerated() {
            do {
                return try operation()
            } catch {
                lastError = error

                if !hasAttemptedRecovery, shouldAttemptBridgeRecovery(for: error) {
                    hasAttemptedRecovery = true
                    _ = recover()
                }

                if attempt < retryDelays.count - 1 {
                    sleep(delay)
                } else {
                    logFinalFailure(error, retryDelays.count)
                }
            }
        }

        throw lastError
    }

    private func handleWriteResponse(_ request: BridgeRequest, query: String?) throws -> WriteResult {
        let response: BridgeResponse<WriteResultPayload> = try sendRequest(request)
        cacheSessionToken(from: response)

        if let error = response.error {
            throw BridgeClientError.bridgeError(code: error.code.rawValue, message: error.message, query: query)
        }

        guard let payload = response.payload else {
            throw BridgeClientError.invalidResponse
        }

        return WriteResult(id: payload.id, message: payload.message)
    }

    static func shouldAttemptBridgeRecovery(for error: Error) -> Bool {
        if let bridgeError = error as? BridgeClientError {
            switch bridgeError {
            case .connectionFailed, .timeout, .appUnavailable:
                return true
            case .invalidResponse, .bridgeError:
                return false
            }
        }

        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain,
           nsError.code == NSXPCConnectionInvalid || nsError.code == NSXPCConnectionInterrupted {
            return true
        }

        let message = nsError.localizedDescription.lowercased()
        return message.contains("helper application")
            || message.contains("connection invalid")
            || message.contains("xpc")
    }

    static func appBundlePath(fromExecutablePath executablePath: String) -> String? {
        let resolvedPath = URL(fileURLWithPath: executablePath)
            .resolvingSymlinksInPath()
            .path
        let components = URL(fileURLWithPath: resolvedPath).pathComponents
        guard let appIndex = components.firstIndex(where: { $0.hasSuffix(".app") }) else {
            return nil
        }
        return NSString.path(withComponents: Array(components.prefix(appIndex + 1)))
    }

    static func candidateAppBundlePaths(executablePath: String?) -> [String] {
        var candidates: [String] = []
        if let executablePath,
           let appBundlePath = appBundlePath(fromExecutablePath: executablePath) {
            candidates.append(appBundlePath)
        }
        candidates.append("/Applications/Authsia.app")

        var deduplicated: [String] = []
        for path in candidates where !deduplicated.contains(path) {
            deduplicated.append(path)
        }
        return deduplicated
    }

    static func candidateLaunchAgentPlistPaths(executablePath: String?) -> [String] {
        candidateAppBundlePaths(executablePath: executablePath)
            .map { "\($0)/Contents/Library/LaunchAgents/Authsia.Bridge.plist" }
    }

    @discardableResult
    private func recoverBridgeAvailability() -> Bool {
        let appLaunched = launchAppIfNeeded()
        let bootstrapped = bootstrapLaunchAgentIfNeeded()
        if appLaunched || bootstrapped {
            Thread.sleep(forTimeInterval: 0.4)
            return true
        }
        return false
    }

    @discardableResult
    private func bootstrapLaunchAgentIfNeeded() -> Bool {
        let launchDomain = "gui/\(getuid())"
        let executablePath = Bundle.main.executablePath

        for plistPath in Self.candidateLaunchAgentPlistPaths(executablePath: executablePath) {
            guard FileManager.default.fileExists(atPath: plistPath) else {
                continue
            }

            let bootstrap = runProcess(
                executablePath: "/bin/launchctl",
                arguments: ["bootstrap", launchDomain, plistPath]
            )
            let output = (bootstrap.standardOutput + bootstrap.standardError).lowercased()
            if output.contains("bootstrap failed") {
                continue
            }
            let alreadyLoaded = output.contains("already loaded")
                || output.contains("operation already in progress")
                || output.contains(" 37")

            if bootstrap.exitCode == 0 || alreadyLoaded {
                _ = runProcess(
                    executablePath: "/bin/launchctl",
                    arguments: ["kickstart", "-kp", "\(launchDomain)/\(serviceName)"]
                )
                return true
            }
        }

        return false
    }

    @discardableResult
    private func launchAppIfNeeded() -> Bool {
        let executablePath = Bundle.main.executablePath

        for appPath in Self.candidateAppBundlePaths(executablePath: executablePath) {
            let openResult = runProcess(
                executablePath: "/usr/bin/open",
                arguments: ["-gj", appPath]
            )
            let output = (openResult.standardOutput + openResult.standardError).lowercased()
            let openFailed = output.contains("failed")
                || output.contains("cannot be opened")
                || output.contains("kls")
            if !openFailed {
                return true
            }

            let appExecutablePath = "\(appPath)/Contents/MacOS/\(appBundleIdentifier)"
            if spawnDetachedProcess(executablePath: appExecutablePath) {
                return true
            }
        }

        return false
    }

    private func runProcess(executablePath: String, arguments: [String]) -> (
        exitCode: Int32,
        standardOutput: String,
        standardError: String
    ) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return (-1, "", error.localizedDescription)
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        return (process.terminationStatus, stdout, stderr)
    }

    private func spawnDetachedProcess(executablePath: String) -> Bool {
        guard FileManager.default.fileExists(atPath: executablePath) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = []
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            return true
        } catch {
            return false
        }
    }
}

// MARK: - Payload Structs (matching XPC service payloads)

struct OTPPayload: Codable, Equatable {
    let accountId: String
    let issuer: String
    let label: String
    let code: String
    let remaining: Int
    let expiresAt: Date
    let isFavorite: Bool
}

struct PasswordPayload: Codable, Equatable {
    let id: String
    let name: String
    let username: String
    let password: String
    let website: String?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct APIKeyPayload: Codable, Equatable {
    let id: String
    let name: String
    let key: String
    let website: String?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct CertificatePayload: Codable, Equatable {
    let id: String
    let name: String
    let certificate: String
    let privateKey: String?
    let issuer: String?
    let subject: String?
    let expirationDate: Date?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct NotePayload: Codable, Equatable {
    let id: String
    let title: String
    let content: String
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct SSHPayload: Codable, Equatable {
    let id: String
    let name: String
    let publicKey: String
    let privateKey: String
    let comment: String
    let fingerprint: String
    let passphrase: String?
    let keyType: SSHKeyType?
    let approvalPolicy: SSHKeyApprovalPolicy?
    let boundHosts: [String]?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct UnlockPayload: Codable, Equatable {
    let expiresAt: Date
    let ttlSeconds: Int
    let sessionToken: String
}

// MARK: - Result Structs

struct OTPResult {
    let accountId: String
    let issuer: String
    let label: String
    let code: String
    let remaining: Int
    let expiresAt: Date
    let isFavorite: Bool
}

struct PasswordResult {
    let id: String
    let name: String
    let username: String
    let password: String
    let website: String?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct APIKeyResult {
    let id: String
    let name: String
    let key: String
    let website: String?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct CertificateResult {
    let id: String
    let name: String
    let certificate: String
    let privateKey: String?
    let issuer: String?
    let subject: String?
    let expirationDate: Date?
    let notes: String?
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct NoteResult {
    let id: String
    let title: String
    let content: String
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct SSHKeyResult {
    let id: String
    let name: String
    let publicKey: String
    let privateKey: String
    let comment: String
    let fingerprint: String
    let passphrase: String?
    let keyType: SSHKeyType
    let approvalPolicy: SSHKeyApprovalPolicy
    let boundHosts: [String]
    let createdAt: Date
    let modifiedAt: Date
    let isFavorite: Bool
}

struct UnlockResult {
    let expiresAt: Date
    let ttlSeconds: Int
    let sessionToken: String
}
