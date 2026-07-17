#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    public func addItem(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode addItem request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(id: bridgeRequest.id, code: policyError.code, message: policyError.message, reply: reply)
            return
        }

        let callerIdentity = callerIdentityProvider()
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentity
        ) {
            replyError(id: bridgeRequest.id, code: denial.code, message: denial.message, reply: reply)
            return
        }

        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol

        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled", reply: reply)
                return
            }

            guard let body = bridgeRequest.body else {
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing request body", reply: reply)
                return
            }

            if bridgeRequest.type == .agentJITPreflight {
                await self.handleAgentJITPreflight(
                    bridgeRequest,
                    body: body,
                    callerIdentity: callerIdentity,
                    callback: callback,
                    reply: reply
                )
                return
            }

            if bridgeRequest.type == .createAccess {
                guard let payload = try? BridgeCoder.decode(AccessCreateApprovalPayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid access approval payload", reply: reply)
                    return
                }

                let allow = payload.allowedCommands.joined(separator: ",")
                let scopeName = AutomationCredentialScope.displayName(payload.scope)
                let environmentName: String
                switch payload.environmentScope {
                case .named(let name): environmentName = name
                case .defaultOnly: environmentName = "Default environment"
                case nil: environmentName = "All environments"
                }
                let prompt = "Approve automation access '\(payload.name)' on '\(payload.machineName)' for scope '\(scopeName)' " +
                    "environment='\(environmentName)' allow=\(allow) ttl=\(payload.ttlSeconds)s"
                let authorization = await self.requestLocalApproval(
                    prompt: prompt,
                    command: .createAccess,
                    itemLabel: scopeName,
                    field: nil,
                    callback: callback
                )
                guard case .allowed = authorization else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                let result = WriteResultPayload(id: bridgeRequest.id.uuidString, message: "Access credential approved")
                replyWriteSuccess(id: bridgeRequest.id, payload: result, reply: reply)
                return
            }

            do {
                try repository.load()
            } catch {
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to load items: \(error.localizedDescription)", reply: reply)
                return
            }

            switch bridgeRequest.type {
            case .ensureVaultFolder:
                guard let payload = try? BridgeCoder.decode(VaultFolderWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid vault folder payload", reply: reply)
                    return
                }
                let path = payload.path.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !path.isEmpty else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing vault folder path", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to create vault folder '\(path)'",
                    itemLabel: path,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                // Compatibility no-op for older CLIs. Workspace item writes register
                // their own typed folder, so an untyped request must not create both.
                let result = WriteResultPayload(id: path, message: "Vault folder ready")
                replyWriteSuccess(
                    id: bridgeRequest.id,
                    payload: result,
                    sessionToken: approval.newSessionToken,
                    sessionExpiresAt: approval.sessionExpiresAt,
                    reply: reply
                )

            case .addPassword:
                guard let payload = try? BridgeCoder.decode(PasswordWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid password payload", reply: reply)
                    return
                }
                guard let name = payload.name,
                      let username = payload.username,
                      let password = payload.password
                else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing required password fields", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to add a new password '\(name)'",
                    itemLabel: name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let isScraped = payload.isScraped ?? false
                    let provenance = BridgeScrapeProvenance.normalized(
                        isScraped: isScraped,
                        machineName: payload.scrapeMachineName,
                        machineId: payload.scrapeMachineId
                    )
                    let item = PasswordItem(
                        name: name,
                        username: username,
                        password: Data(password.utf8),
                        website: payload.website,
                        notes: payload.notes,
                        folderPath: payload.folderPath,
                        isCliEnabled: true,
                        isScraped: isScraped,
                        scrapeMachineName: provenance.machineName,
                        scrapeMachineId: provenance.machineId,
                        expiresAt: payload.expiresAt,
                        environments: payload.environments ?? []
                    )
                    try repository.addPassword(item)
                    let result = WriteResultPayload(id: item.id.uuidString, message: "Password added")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to add password: \(error.localizedDescription)", reply: reply)
                }

            case .addAPIKey:
                guard let payload = try? BridgeCoder.decode(APIKeyWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid API key payload", reply: reply)
                    return
                }
                guard let name = payload.name,
                      let key = payload.key
                else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing required API key fields", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to add a new API key '\(name)'",
                    itemLabel: name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let isScraped = payload.isScraped ?? false
                    let provenance = BridgeScrapeProvenance.normalized(
                        isScraped: isScraped,
                        machineName: payload.scrapeMachineName,
                        machineId: payload.scrapeMachineId
                    )
                    let item = APIKeyItem(
                        name: name,
                        key: Data(key.utf8),
                        website: payload.website,
                        notes: payload.notes,
                        folderPath: payload.folderPath,
                        isCliEnabled: true,
                        isScraped: isScraped,
                        scrapeMachineName: provenance.machineName,
                        scrapeMachineId: provenance.machineId,
                        expiresAt: payload.expiresAt,
                        environments: payload.environments ?? []
                    )
                    try repository.addAPIKey(item)
                    let result = WriteResultPayload(id: item.id.uuidString, message: "API key added")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to add API key: \(error.localizedDescription)", reply: reply)
                }

            case .addCertificate:
                guard let payload = try? BridgeCoder.decode(CertificateWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid certificate payload", reply: reply)
                    return
                }
                guard let name = payload.name,
                      let certificate = payload.certificate
                else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing required certificate fields", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to add a new certificate '\(name)'",
                    itemLabel: name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let isScraped = payload.isScraped ?? false
                    let provenance = BridgeScrapeProvenance.normalized(
                        isScraped: isScraped,
                        machineName: payload.scrapeMachineName,
                        machineId: payload.scrapeMachineId
                    )
                    let item = CertificateItem(
                        name: name,
                        certificateData: Data(certificate.utf8),
                        privateKeyData: payload.privateKey.map { Data($0.utf8) },
                        notes: payload.notes,
                        folderPath: payload.folderPath,
                        isCliEnabled: true,
                        isScraped: isScraped,
                        scrapeMachineName: provenance.machineName,
                        scrapeMachineId: provenance.machineId,
                        environments: payload.environments ?? []
                    )
                    try repository.addCertificate(item)
                    let result = WriteResultPayload(id: item.id.uuidString, message: "Certificate added")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to add certificate: \(error.localizedDescription)", reply: reply)
                }

            case .addNote:
                guard let payload = try? BridgeCoder.decode(NoteWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid note payload", reply: reply)
                    return
                }
                guard let title = payload.title,
                      let content = payload.content
                else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing required note fields", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to add a new note '\(title)'",
                    itemLabel: title,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let isScraped = payload.isScraped ?? false
                    let provenance = BridgeScrapeProvenance.normalized(
                        isScraped: isScraped,
                        machineName: payload.scrapeMachineName,
                        machineId: payload.scrapeMachineId
                    )
                    let item = SecureNoteItem(
                        title: title,
                        content: Data(content.utf8),
                        folderPath: payload.folderPath,
                        isCliEnabled: true,
                        isScraped: isScraped,
                        scrapeMachineName: provenance.machineName,
                        scrapeMachineId: provenance.machineId,
                        environments: payload.environments ?? []
                    )
                    try repository.addNote(item)
                    let result = WriteResultPayload(id: item.id.uuidString, message: "Note added")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to add note: \(error.localizedDescription)", reply: reply)
                }

            case .addSSH:
                guard let payload = try? BridgeCoder.decode(SSHKeyWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid SSH key payload", reply: reply)
                    return
                }
                guard let name = payload.name,
                      let publicKey = payload.publicKey,
                      let privateKey = payload.privateKey,
                      let comment = payload.comment,
                      let fingerprint = payload.fingerprint
                else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing required SSH key fields", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to add a new SSH key '\(name)'",
                    itemLabel: name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let isScraped = payload.isScraped ?? false
                    let provenance = BridgeScrapeProvenance.normalized(
                        isScraped: isScraped,
                        machineName: payload.scrapeMachineName,
                        machineId: payload.scrapeMachineId
                    )
                    let item = SSHKeyItem(
                        name: name,
                        publicKey: Data(publicKey.utf8),
                        privateKey: Data(privateKey.utf8),
                        comment: comment,
                        fingerprint: fingerprint,
                        keyType: payload.keyType ?? SSHKeyTypeDetector.detect(publicKey: publicKey),
                        approvalPolicy: payload.approvalPolicy ?? .sessionBased,
                        boundHosts: payload.boundHosts ?? [],
                        folderPath: payload.folderPath,
                        isCliEnabled: true,
                        isScraped: isScraped,
                        scrapeMachineName: provenance.machineName,
                        scrapeMachineId: provenance.machineId,
                        environments: payload.environments ?? []
                    )
                    try repository.addSSHKey(item)
                    if let passphrase = payload.passphrase, !passphrase.isEmpty {
                        try VaultKeychainStore.shared.saveSSHKeyPassphrase(Data(passphrase.utf8), for: item.id)
                    }
                    let result = WriteResultPayload(id: item.id.uuidString, message: "SSH key added")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to add SSH key: \(error.localizedDescription)", reply: reply)
                }

            default:
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Unsupported add operation", reply: reply)
            }
        }
    }

    public func updateItem(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode updateItem request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(id: bridgeRequest.id, code: policyError.code, message: policyError.message, reply: reply)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentity
        ) {
            replyError(id: bridgeRequest.id, code: denial.code, message: denial.message, reply: reply)
            return
        }

        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled", reply: reply)
                return
            }

            guard let body = bridgeRequest.body else {
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing request body", reply: reply)
                return
            }

            do {
                try repository.load()
            } catch {
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to load items: \(error.localizedDescription)", reply: reply)
                return
            }

            switch bridgeRequest.type {
            case .updatePassword:
                guard let payload = try? BridgeCoder.decode(PasswordWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid password payload", reply: reply)
                    return
                }
                if payload.name == nil,
                   payload.username == nil,
                   payload.password == nil,
                   payload.website == nil,
                   payload.notes == nil,
                   payload.folderPath == nil,
                   payload.isScraped == nil,
                   payload.scrapeMachineName == nil,
                   payload.scrapeMachineId == nil,
                   payload.expiresAt == nil,
                   payload.clearExpiresAt != true,
                   payload.environments == nil {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "No fields provided to update", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.passwords,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.username, $0.website ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching password found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to update password '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let full = try repository.getFullPassword(metadata: match)
                    let scrapeState = BridgeScrapeProvenance.resolved(
                        payloadIsScraped: payload.isScraped,
                        payloadMachineName: payload.scrapeMachineName,
                        payloadMachineId: payload.scrapeMachineId,
                        existingIsScraped: full.isScraped,
                        existingMachineName: full.scrapeMachineName,
                        existingMachineId: full.scrapeMachineId
                    )
                    let updated = PasswordItem(
                        id: full.id,
                        name: payload.name ?? full.name,
                        username: payload.username ?? full.username,
                        password: payload.password.map { Data($0.utf8) } ?? full.password,
                        website: payload.website ?? full.website,
                        notes: payload.notes ?? full.notes,
                        folderPath: payload.folderPath ?? full.folderPath,
                        createdAt: full.createdAt,
                        modifiedAt: Date(),
                        isFavorite: full.isFavorite,
                        isCliEnabled: full.isCliEnabled,
                        isScraped: scrapeState.isScraped,
                        scrapeMachineName: scrapeState.machineName,
                        scrapeMachineId: scrapeState.machineId,
                        expiresAt: payload.clearExpiresAt == true ? nil : (payload.expiresAt ?? full.expiresAt),
                        environments: payload.environments ?? full.environments
                    )
                    try repository.updatePassword(updated)
                    let result = WriteResultPayload(id: updated.id.uuidString, message: "Password updated")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to update password: \(error.localizedDescription)", reply: reply)
                }

            case .convertPasswordToAPIKey:
                guard let payload = try? BridgeCoder.decode(PasswordConversionPayload.self, from: body),
                      payload.targetType == "api-key" else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid conversion payload", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.passwords,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.username, $0.website ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching password found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to convert password '\(match.name)' to an API key",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    guard let converted = try repository.convertPasswordToAPIKey(id: match.id, modifiedAt: Date()) else {
                        replyError(id: bridgeRequest.id, code: .notFound, message: "No matching password found", reply: reply)
                        return
                    }
                    let result = WriteResultPayload(id: converted.id.uuidString, message: "Password converted to API key")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to convert password: \(error.localizedDescription)", reply: reply)
                }

            case .updateAPIKey:
                guard let payload = try? BridgeCoder.decode(APIKeyWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid API key payload", reply: reply)
                    return
                }
                if payload.name == nil,
                   payload.key == nil,
                   payload.website == nil,
                   payload.notes == nil,
                   payload.folderPath == nil,
                   payload.isScraped == nil,
                   payload.scrapeMachineName == nil,
                   payload.scrapeMachineId == nil,
                   payload.expiresAt == nil,
                   payload.clearExpiresAt != true,
                   payload.environments == nil {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "No fields provided to update", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.apiKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.website ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching API key found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to update API key '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let full = try repository.getFullAPIKey(metadata: match)
                    let scrapeState = BridgeScrapeProvenance.resolved(
                        payloadIsScraped: payload.isScraped,
                        payloadMachineName: payload.scrapeMachineName,
                        payloadMachineId: payload.scrapeMachineId,
                        existingIsScraped: full.isScraped,
                        existingMachineName: full.scrapeMachineName,
                        existingMachineId: full.scrapeMachineId
                    )
                    let updated = APIKeyItem(
                        id: full.id,
                        name: payload.name ?? full.name,
                        key: payload.key.map { Data($0.utf8) } ?? full.key,
                        website: payload.website ?? full.website,
                        notes: payload.notes ?? full.notes,
                        folderPath: payload.folderPath ?? full.folderPath,
                        createdAt: full.createdAt,
                        modifiedAt: Date(),
                        isFavorite: full.isFavorite,
                        isCliEnabled: full.isCliEnabled,
                        isScraped: scrapeState.isScraped,
                        scrapeMachineName: scrapeState.machineName,
                        scrapeMachineId: scrapeState.machineId,
                        expiresAt: payload.clearExpiresAt == true ? nil : (payload.expiresAt ?? full.expiresAt),
                        environments: payload.environments ?? full.environments
                    )
                    try repository.updateAPIKey(updated)
                    let result = WriteResultPayload(id: updated.id.uuidString, message: "API key updated")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to update API key: \(error.localizedDescription)", reply: reply)
                }

            case .updateCertificate:
                guard let payload = try? BridgeCoder.decode(CertificateWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid certificate payload", reply: reply)
                    return
                }
                if payload.name == nil,
                   payload.certificate == nil,
                   payload.privateKey == nil,
                   payload.clearPrivateKey != true,
                   payload.notes == nil,
                   payload.folderPath == nil,
                   payload.isScraped == nil,
                   payload.scrapeMachineName == nil,
                   payload.scrapeMachineId == nil,
                   payload.environments == nil {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "No fields provided to update", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.certificates,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.issuer ?? "", $0.subject ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching certificate found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to update certificate '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let full = try repository.getFullCertificate(metadata: match)
                    let scrapeState = BridgeScrapeProvenance.resolved(
                        payloadIsScraped: payload.isScraped,
                        payloadMachineName: payload.scrapeMachineName,
                        payloadMachineId: payload.scrapeMachineId,
                        existingIsScraped: full.isScraped,
                        existingMachineName: full.scrapeMachineName,
                        existingMachineId: full.scrapeMachineId
                    )
                    let updated = CertificateItem(
                        id: full.id,
                        name: payload.name ?? full.name,
                        certificateData: payload.certificate.map { Data($0.utf8) } ?? full.certificateData,
                        privateKeyData: payload.clearPrivateKey == true
                            ? nil
                            : (payload.privateKey.map { Data($0.utf8) } ?? full.privateKeyData),
                        expirationDate: full.expirationDate,
                        issuer: full.issuer,
                        subject: full.subject,
                        notes: payload.notes ?? full.notes,
                        folderPath: payload.folderPath ?? full.folderPath,
                        createdAt: full.createdAt,
                        modifiedAt: Date(),
                        isFavorite: full.isFavorite,
                        isCliEnabled: full.isCliEnabled,
                        isScraped: scrapeState.isScraped,
                        scrapeMachineName: scrapeState.machineName,
                        scrapeMachineId: scrapeState.machineId,
                        environments: payload.environments ?? full.environments
                    )
                    try repository.updateCertificate(updated)
                    if payload.clearPrivateKey == true {
                        repository.deleteCertificatePrivateKey(id: updated.id)
                    }
                    let result = WriteResultPayload(id: updated.id.uuidString, message: "Certificate updated")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to update certificate: \(error.localizedDescription)", reply: reply)
                }

            case .updateNote:
                guard let payload = try? BridgeCoder.decode(NoteWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid note payload", reply: reply)
                    return
                }
                if payload.title == nil,
                   payload.content == nil,
                   payload.folderPath == nil,
                   payload.isScraped == nil,
                   payload.scrapeMachineName == nil,
                   payload.scrapeMachineId == nil,
                   payload.environments == nil {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "No fields provided to update", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.notes,
                    id: { $0.id.uuidString },
                    searchable: { [$0.title] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching note found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.title)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to update note '\(match.title)'",
                    itemLabel: match.title,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let full = try repository.getFullNote(metadata: match)
                    let scrapeState = BridgeScrapeProvenance.resolved(
                        payloadIsScraped: payload.isScraped,
                        payloadMachineName: payload.scrapeMachineName,
                        payloadMachineId: payload.scrapeMachineId,
                        existingIsScraped: full.isScraped,
                        existingMachineName: full.scrapeMachineName,
                        existingMachineId: full.scrapeMachineId
                    )
                    let updated = SecureNoteItem(
                        id: full.id,
                        title: payload.title ?? full.title,
                        content: payload.content.map { Data($0.utf8) } ?? full.content,
                        folderPath: payload.folderPath ?? full.folderPath,
                        createdAt: full.createdAt,
                        modifiedAt: Date(),
                        isFavorite: full.isFavorite,
                        isCliEnabled: full.isCliEnabled,
                        isScraped: scrapeState.isScraped,
                        scrapeMachineName: scrapeState.machineName,
                        scrapeMachineId: scrapeState.machineId,
                        environments: payload.environments ?? full.environments
                    )
                    try repository.updateNote(updated)
                    let result = WriteResultPayload(id: updated.id.uuidString, message: "Note updated")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to update note: \(error.localizedDescription)", reply: reply)
                }

            case .updateSSH:
                guard let payload = try? BridgeCoder.decode(SSHKeyWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid SSH key payload", reply: reply)
                    return
                }
                if payload.name == nil,
                   payload.publicKey == nil,
                   payload.privateKey == nil,
                   payload.comment == nil,
                   payload.fingerprint == nil,
                   payload.folderPath == nil,
                   payload.isScraped == nil,
                   payload.scrapeMachineName == nil,
                   payload.scrapeMachineId == nil,
                   payload.keyType == nil,
                   payload.approvalPolicy == nil,
                   payload.boundHosts == nil,
                   payload.environments == nil {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "No fields provided to update", reply: reply)
                    return
                }
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.sshKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.comment, $0.fingerprint] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching SSH key found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to update SSH key '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    let current = try repository.getFullSSHKey(metadata: match)
                    let scrapeState = BridgeScrapeProvenance.resolved(
                        payloadIsScraped: payload.isScraped,
                        payloadMachineName: payload.scrapeMachineName,
                        payloadMachineId: payload.scrapeMachineId,
                        existingIsScraped: current.isScraped,
                        existingMachineName: current.scrapeMachineName,
                        existingMachineId: current.scrapeMachineId
                    )
                    let updated = SSHKeyItem(
                        id: current.id,
                        name: payload.name ?? current.name,
                        publicKey: Data((payload.publicKey ?? String(decoding: current.publicKey, as: UTF8.self)).utf8),
                        privateKey: Data((payload.privateKey ?? String(decoding: current.privateKey, as: UTF8.self)).utf8),
                        comment: payload.comment ?? current.comment,
                        fingerprint: payload.fingerprint ?? current.fingerprint,
                        keyType: payload.keyType ?? current.keyType,
                        approvalPolicy: payload.approvalPolicy ?? current.approvalPolicy,
                        boundHosts: payload.boundHosts ?? current.boundHosts,
                        folderPath: payload.folderPath ?? current.folderPath,
                        createdAt: current.createdAt,
                        modifiedAt: Date(),
                        isFavorite: current.isFavorite,
                        isCliEnabled: current.isCliEnabled,
                        isScraped: scrapeState.isScraped,
                        scrapeMachineName: scrapeState.machineName,
                        scrapeMachineId: scrapeState.machineId,
                        environments: payload.environments ?? current.environments
                    )
                    try repository.updateSSHKey(updated)
                    if let passphrase = payload.passphrase {
                        try VaultKeychainStore.shared.saveSSHKeyPassphrase(Data(passphrase.utf8), for: updated.id)
                    }
                    let result = WriteResultPayload(id: updated.id.uuidString, message: "SSH key updated")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to update SSH key: \(error.localizedDescription)", reply: reply)
                }

            default:
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Unsupported update operation", reply: reply)
            }
        }
    }

    public func deleteItem(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode deleteItem request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(id: bridgeRequest.id, code: policyError.code, message: policyError.message, reply: reply)
            return
        }

        let callerIdentity = callerIdentityProvider()
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentity
        ) {
            replyError(id: bridgeRequest.id, code: denial.code, message: denial.message, reply: reply)
            return
        }

        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled", reply: reply)
                return
            }

            do {
                try repository.load()
            } catch {
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to load items: \(error.localizedDescription)", reply: reply)
                return
            }

            switch bridgeRequest.type {
            case .deleteVaultFolder:
                guard let body = bridgeRequest.body,
                      let payload = try? BridgeCoder.decode(VaultFolderWritePayload.self, from: body) else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid vault folder payload", reply: reply)
                    return
                }
                let path = payload.path.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !path.isEmpty else {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing vault folder path", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete vault folder '\(path)'",
                    itemLabel: path,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    for type in VaultItemType.allCases {
                        try await repository.deleteFolder(path: path, type: type)
                    }
                    let result = WriteResultPayload(id: path, message: "Vault folder deleted")
                    replyWriteSuccess(
                        id: bridgeRequest.id,
                        payload: result,
                        sessionToken: approval.newSessionToken,
                        sessionExpiresAt: approval.sessionExpiresAt,
                        reply: reply
                    )
                } catch {
                    replyError(
                        id: bridgeRequest.id,
                        code: .invalidRequest,
                        message: "Failed to delete vault folder: \(error.localizedDescription)",
                        reply: reply
                    )
                }

            case .deletePassword:
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.passwords,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.username, $0.website ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching password found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete password '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    try repository.deletePassword(id: match.id)
                    let result = WriteResultPayload(id: match.id.uuidString, message: "Password deleted")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to delete password: \(error.localizedDescription)", reply: reply)
                }

            case .deleteAPIKey:
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.apiKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.website ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching API key found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete API key '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    try repository.deleteAPIKey(id: match.id)
                    let result = WriteResultPayload(id: match.id.uuidString, message: "API key deleted")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to delete API key: \(error.localizedDescription)", reply: reply)
                }

            case .deleteCertificate:
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.certificates,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.issuer ?? "", $0.subject ?? ""] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching certificate found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete certificate '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    try repository.deleteCertificate(id: match.id)
                    let result = WriteResultPayload(id: match.id.uuidString, message: "Certificate deleted")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to delete certificate: \(error.localizedDescription)", reply: reply)
                }

            case .deleteNote:
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.notes,
                    id: { $0.id.uuidString },
                    searchable: { [$0.title] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching note found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.title)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete note '\(match.title)'",
                    itemLabel: match.title,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    try repository.deleteNote(id: match.id)
                    let result = WriteResultPayload(id: match.id.uuidString, message: "Note deleted")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to delete note: \(error.localizedDescription)", reply: reply)
                }

            case .deleteSSH:
                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: repository.sshKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.comment, $0.fingerprint] }
                ) else {
                    replyError(id: bridgeRequest.id, code: .notFound, message: "No matching SSH key found", reply: reply)
                    return
                }

                if !match.isCliEnabled {
                    replyError(id: bridgeRequest.id, code: .policyDenied, message: "CLI access is disabled for '\(match.name)'", reply: reply)
                    return
                }

                let approval = await self.ensureApproval(
                    for: bridgeRequest,
                    prompt: "Allow CLI to delete SSH key '\(match.name)'",
                    itemLabel: match.name,
                    callerIdentity: callerIdentity,
                    callback: callback
                )
                guard approval.approved else {
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                do {
                    try repository.deleteSSHKey(id: match.id)
                    let result = WriteResultPayload(id: match.id.uuidString, message: "SSH key deleted")
                    replyWriteSuccess(id: bridgeRequest.id, payload: result, sessionToken: approval.newSessionToken, sessionExpiresAt: approval.sessionExpiresAt, reply: reply)
                } catch {
                    replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Failed to delete SSH key: \(error.localizedDescription)", reply: reply)
                }

            default:
                replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Unsupported delete operation", reply: reply)
            }
        }
    }

}
#endif
