#if os(macOS)
import Foundation
import Darwin
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

public final class SSHAgentListener: @unchecked Sendable {
    private let socketPath: String
    private var serverSocket: Int32 = -1
    private var isRunning = false
    private let auditLogger = BridgeAuditLogger()
    private let approvalProvider: SSHAgentApprovalProviding
    private let passphraseProvider: SSHKeyPassphraseProviding
    private let acceptQueue = DispatchQueue(label: "com.authsia.ssh-agent.accept", qos: .userInitiated)
    private let connectionQueue = DispatchQueue(label: "com.authsia.ssh-agent.connection", qos: .userInitiated, attributes: .concurrent)

    public init(
        approvalProvider: SSHAgentApprovalProviding,
        passphraseProvider: SSHKeyPassphraseProviding
    ) {
        self.approvalProvider = approvalProvider
        self.passphraseProvider = passphraseProvider
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        socketPath = "\(home)/.authsia/agent.sock"
    }

    public func start() {
        guard !isRunning else { return }

        let dir = (socketPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        // Remove stale socket
        unlink(socketPath)

        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            print("[SSHAgent] Failed to create socket: \(String(cString: strerror(errno)))")
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                sunPath.withMemoryRebound(to: CChar.self, capacity: 104) { dest in
                    _ = strlcpy(dest, ptr, 104)
                }
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(serverSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            print("[SSHAgent] Bind failed: \(String(cString: strerror(errno)))")
            close(serverSocket)
            return
        }

        chmod(socketPath, 0o600)

        guard listen(serverSocket, 5) == 0 else {
            print("[SSHAgent] Listen failed: \(String(cString: strerror(errno)))")
            close(serverSocket)
            return
        }

        isRunning = true
        #if DEBUG
        print("[SSHAgent] Listening on \(socketPath)")
        #endif

        acceptQueue.async { [weak self] in
            self?.acceptLoop()
        }
    }

    /// Starts the agent using a socket handed over by launchd (socket activation).
    /// launchd owns and listens on the socket, so the app is spawned on demand when
    /// a client connects — no need for the GUI app to be running. Falls back to
    /// binding the socket directly if activation is unavailable.
    public func startActivated(socketName: String) {
        guard !isRunning else { return }

        var fdsPtr: UnsafeMutablePointer<Int32>?
        var count = 0
        let err = withUnsafeMutablePointer(to: &fdsPtr) { storage in
            storage.withMemoryRebound(to: UnsafeMutablePointer<Int32>.self, capacity: 1) { rebound in
                socketName.withCString { launch_activate_socket($0, rebound, &count) }
            }
        }
        guard err == 0, let fdsPtr, count > 0 else {
            print("[SSHAgent] launch_activate_socket failed (\(err)); binding socket directly")
            start()
            return
        }

        serverSocket = fdsPtr[0]
        free(fdsPtr)
        chmod(socketPath, 0o600)

        isRunning = true
        #if DEBUG
        print("[SSHAgent] Adopted launchd socket on \(socketPath)")
        #endif

        acceptQueue.async { [weak self] in
            self?.acceptLoop()
        }
    }

    public func stop() {
        guard isRunning else { return }
        isRunning = false
        close(serverSocket)
        serverSocket = -1
        unlink(socketPath)
    }

    // MARK: - Connection Handling

    private func acceptLoop() {
        while isRunning {
            var clientAddr = sockaddr_un()
            var clientLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(serverSocket, sockPtr, &clientLen)
                }
            }
            guard clientSocket >= 0 else {
                if isRunning { continue }
                break
            }

            connectionQueue.async { [weak self] in
                self?.handleConnection(clientSocket)
            }
        }
    }

    private func handleConnection(_ fd: Int32) {
        defer { close(fd) }

        var sessionBindRequests: [Data] = []

        while true {
            var lengthBytes = [UInt8](repeating: 0, count: 4)
            let headerRead = recv(fd, &lengthBytes, 4, MSG_WAITALL)
            guard headerRead == 4 else { return }

            let length = Int(UInt32(bigEndian: Data(lengthBytes).withUnsafeBytes { $0.load(as: UInt32.self) }))
            guard length > 0, length < 256 * 1024 else { return }

            var payload = [UInt8](repeating: 0, count: length)
            let payloadRead = recv(fd, &payload, length, MSG_WAITALL)
            guard payloadRead == length else { return }

            var fullMessage = Data(lengthBytes)
            fullMessage.append(contentsOf: payload)

            let response: Data
            do {
                let message = try SSHAgentMessage.parse(fullMessage)
                response = handleMessage(
                    message,
                    clientFD: fd,
                    rawMessage: fullMessage,
                    sessionBindRequests: &sessionBindRequests
                )
            } catch {
                response = SSHAgentResponse.failure.serialize()
            }

            _ = response.withUnsafeBytes { ptr in
                send(fd, ptr.baseAddress!, response.count, 0)
            }
        }
    }

    // MARK: - Message Dispatch

    private func handleMessage(
        _ message: SSHAgentMessage,
        clientFD: Int32,
        rawMessage: Data,
        sessionBindRequests: inout [Data]
    ) -> Data {
        switch message {
        case .requestIdentities:
            return handleRequestIdentities(clientFD: clientFD)
        case .signRequest(let keyBlob, let data, let flags):
            return handleSignRequest(
                keyBlob: keyBlob,
                data: data,
                flags: flags,
                clientFD: clientFD,
                sessionBindRequests: sessionBindRequests
            )
        case .addIdentity, .removeIdentity:
            return SSHAgentResponse.failure.serialize()
        case .extensionRequest(let name, _):
            guard name == "session-bind@openssh.com" else {
                return SSHAgentResponse.failure.serialize()
            }
            sessionBindRequests.append(rawMessage)
            return SSHAgentResponse.success.serialize()
        case .unsupported:
            return SSHAgentResponse.failure.serialize()
        }
    }

    private func handleRequestIdentities(clientFD: Int32) -> Data {
        let keys: [(blob: Data, comment: String)]

        do {
            let metadata = try VaultMetadataStore.shared.loadSSHKeys()
            keys = Self.usableSSHIdentities(
                from: metadata,
                targetHost: resolveTargetHost(fd: clientFD),
                hasSSHKey: { id in
                    try VaultKeychainStore.shared.containsSSHKey(for: id)
                },
                hasRestoredLocalPrivateKey: { Self.hasRestoredLocalPrivateKey(for: $0) }
            )
        } catch {
            keys = []
        }

        return SSHAgentResponse.identitiesAnswer(keys: keys).serialize()
    }

    private func handleSignRequest(
        keyBlob: Data,
        data: Data,
        flags: UInt32,
        clientFD: Int32,
        sessionBindRequests: [Data]
    ) -> Data {
        guard let metadata = findKeyByBlob(keyBlob) else {
            return SSHAgentResponse.failure.serialize()
        }
        guard metadata.isCliEnabled else {
            debugLog("sign request failed: SSH key CLI access disabled")
            return SSHAgentResponse.failure.serialize()
        }

        let requester = resolveRequesterInfo(fd: clientFD)

        let keyItem: SSHKeyItem
        do {
            let keychainData = try VaultKeychainStore.shared.retrieveSSHKey(for: metadata.id)
            keyItem = SSHKeyItem(
                id: metadata.id,
                name: metadata.name,
                publicKey: keychainData.publicKey,
                privateKey: keychainData.privateKey,
                comment: metadata.comment,
                fingerprint: metadata.fingerprint,
                keyType: metadata.keyType,
                approvalPolicy: metadata.approvalPolicy,
                boundHosts: metadata.boundHosts,
                folderPath: metadata.folderPath
            )
        } catch {
            debugLog("sign request failed: keychain SSH key lookup failed")
            return SSHAgentResponse.failure.serialize()
        }

        return enforcePolicyAndSign(
            keyItem: keyItem,
            requester: requester,
            clientFD: clientFD,
            keyBlob: keyBlob,
            data: data,
            flags: flags,
            sessionBindRequests: sessionBindRequests
        )
    }

    private func enforcePolicyAndSign(
        keyItem: SSHKeyItem,
        requester: RequesterInfo,
        clientFD: Int32,
        keyBlob: Data,
        data: Data,
        flags: UInt32,
        sessionBindRequests: [Data]
    ) -> Data {
        // Enforce host binding if configured
        if !keyItem.boundHosts.isEmpty {
            let targetHost = resolveTargetHost(fd: clientFD)
            if let targetHost {
                if !SSHHostMatcher.keyMatchesHost(boundHosts: keyItem.boundHosts, targetHost: targetHost) {
                    return SSHAgentResponse.failure.serialize()
                }
            }
            // If we can't determine the target host, allow (fail open for bound keys)
            // since SSH clients don't transmit host info in the agent protocol
        }

        let automationDecision = SSHAgentAutomationAuthorization.authorize(
            environment: resolveProcessEnvironment(fd: clientFD),
            keyFolderPath: keyItem.folderPath,
            sessionScope: requester.sessionScope,
            ancestryPIDs: requester.ancestry.map { Int32($0.pid) }
        )
        let keyIsEncrypted = isEncryptedPrivateKey(keyItem.privateKey)
        let approvalRequest = SSHAgentApprovalRequest(
            keyID: keyItem.id,
            keyName: keyItem.name,
            approvalPolicy: keyItem.approvalPolicy,
            requester: SSHAgentRequester(
                peer: requester.peer?.auditRef,
                instigator: requester.instigator?.auditRef,
                ancestry: requester.ancestry.map(\.auditRef),
                targetHost: requester.targetHost,
                sessionScope: requester.sessionScope
            )
        )
        guard let authorized = authorizedSignature(
            approvalRequest: approvalRequest,
            automationDecision: automationDecision,
            keyIsEncrypted: keyIsEncrypted,
            storedPassphrase: {
                let data = try? VaultKeychainStore.shared.retrieveSSHKeyPassphrase(for: keyItem.id)
                return data.flatMap { String(data: $0, encoding: .utf8) }
            },
            sign: { passphrase in
                self.signWithKey(
                    keyItem: keyItem,
                    passphrase: passphrase,
                    keyBlob: keyBlob,
                    data: data,
                    flags: flags,
                    sessionBindRequests: sessionBindRequests
                )
            },
            persistPassphrase: { passphrase in
                try? VaultKeychainStore.shared.saveSSHKeyPassphrase(Data(passphrase.utf8), for: keyItem.id)
            }
        ) else {
            return SSHAgentResponse.failure.serialize()
        }

        recordSSHAgentAudit(
            keyItem: keyItem,
            requester: requester,
            approvedBy: authorized.approvedBy
        )

        return SSHAgentResponse.signResponse(signature: authorized.signature).serialize()
    }

    func authorizedSignature(
        approvalRequest: SSHAgentApprovalRequest,
        automationDecision: SSHAgentAutomationAuthorizationDecision,
        keyIsEncrypted: Bool,
        storedPassphrase: () -> String?,
        sign: (String?) -> Data?,
        persistPassphrase: (String) -> Void
    ) -> (signature: Data, approvedBy: String)? {
        let approvedBy: String
        switch automationDecision {
        case .allowWithoutApproval:
            approvedBy = "automation"
        case .deny(let message):
            debugLog("sign request failed: \(message)")
            return nil
        case .notAutomation:
            guard approvalProvider.evaluateApproval(approvalRequest) == .approved else {
                debugLog("sign request failed: approval denied")
                return nil
            }
            approvedBy = "biometric"
        }

        var passphrase = storedPassphrase()
        var shouldPersistPassphrase = false
        if keyIsEncrypted, passphrase?.isEmpty ?? true {
            guard let promptedPassphrase = passphraseProvider.passphrase(
                for: SSHKeyPassphraseRequest(
                    keyID: approvalRequest.keyID,
                    keyName: approvalRequest.keyName
                )
            ), !promptedPassphrase.isEmpty else {
                return nil
            }
            passphrase = promptedPassphrase
            shouldPersistPassphrase = true
        }

        var signature = sign(keyIsEncrypted ? passphrase : nil)
        if signature == nil, keyIsEncrypted {
            guard let promptedPassphrase = passphraseProvider.passphrase(
                for: SSHKeyPassphraseRequest(
                    keyID: approvalRequest.keyID,
                    keyName: approvalRequest.keyName
                )
            ), !promptedPassphrase.isEmpty else {
                return nil
            }
            passphrase = promptedPassphrase
            shouldPersistPassphrase = true
            signature = sign(promptedPassphrase)
        }

        guard let signature else { return nil }
        if shouldPersistPassphrase, let passphrase {
            persistPassphrase(passphrase)
        }
        return (signature, approvedBy)
    }

    // MARK: - Helpers

    static func usableSSHIdentities(
        from metadata: [SSHKeyMetadata],
        targetHost: String? = nil,
        hasSSHKey: (UUID) throws -> Bool,
        hasRestoredLocalPrivateKey: (SSHKeyMetadata) -> Bool = { _ in false }
    ) -> [(blob: Data, comment: String)] {
        let shouldBypassAgentForHost = metadata.contains { meta in
            hasRestoredLocalPrivateKey(meta) && restoredLocalPrivateKeyApplies(to: targetHost, metadata: meta)
        }
        guard !shouldBypassAgentForHost else { return [] }

        return metadata
            .filter { $0.isCliEnabled }
            .sorted { $0.modifiedAt > $1.modifiedAt }
            .compactMap { meta -> (Data, String)? in
                guard (try? hasSSHKey(meta.id)) == true else { return nil }
                guard !hasRestoredLocalPrivateKey(meta) else { return nil }
                guard let blobData = parseOpenSSHPublicKeyBlob(meta.publicKey) else { return nil }
                return (blobData, meta.name)
            }
    }

    static func restoredLocalPrivateKeyApplies(to targetHost: String?, metadata: SSHKeyMetadata) -> Bool {
        guard let targetHost, !metadata.boundHosts.isEmpty else { return false }
        return SSHHostMatcher.keyMatchesHost(boundHosts: metadata.boundHosts, targetHost: targetHost)
    }

    private static func parseOpenSSHPublicKeyBlob(_ publicKeyLine: String) -> Data? {
        let parts = publicKeyLine.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }
        return Data(base64Encoded: String(parts[1]))
    }

    private func findKeyByBlob(_ blob: Data) -> SSHKeyMetadata? {
        guard let allKeys = try? VaultMetadataStore.shared.loadSSHKeys() else { return nil }
        return allKeys.first { meta in
            guard meta.isCliEnabled else { return false }
            guard (try? VaultKeychainStore.shared.containsSSHKey(for: meta.id)) == true else { return false }
            guard !Self.hasRestoredLocalPrivateKey(for: meta) else { return false }
            guard let keyBlob = Self.parseOpenSSHPublicKeyBlob(meta.publicKey) else { return false }
            return keyBlob == blob
        }
    }

    static func hasRestoredLocalPrivateKey(
        for metadata: SSHKeyMetadata,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> Bool {
        guard metadata.isScraped else { return false }
        let keyName = metadata.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !keyName.isEmpty,
              keyName != ".",
              keyName != "..",
              (keyName as NSString).lastPathComponent == keyName else {
            return false
        }

        let keyURL = homeDirectory
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent(keyName, isDirectory: false)
        guard let content = try? String(contentsOf: keyURL, encoding: .utf8) else {
            return false
        }

        return looksLikeRestoredLocalPrivateKey(content)
    }

    static func looksLikeRestoredLocalPrivateKey(_ content: String) -> Bool {
        guard !content.contains("# This SSH key is managed by Authsia.") else {
            return false
        }
        return [
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY",
        ].contains { content.contains($0) }
    }

    private func resolveProcessName(fd: Int32) -> String? {
        guard let pid = peerProcessID(fd: fd) else { return nil }
        return Self.processName(pid: pid)
    }

    /// Resolves identifying info about the SSH agent client: the immediate peer process,
    /// the first non-ssh-tooling ancestor (the user's actual instigator), and the parent chain.
    private func resolveRequesterInfo(fd: Int32) -> RequesterInfo {
        guard let peerPID = peerProcessID(fd: fd) else {
            return RequesterInfo(peer: nil, instigator: nil, ancestry: [], targetHost: nil, sessionScope: nil)
        }
        let chain = Self.walkAncestors(pid: peerPID)
        let instigator = chain.first { proc in
            !Self.sshToolingNames.contains(proc.name.lowercased())
        }
        return RequesterInfo(
            peer: chain.first,
            instigator: instigator,
            ancestry: chain,
            targetHost: resolveTargetHost(fd: fd),
            sessionScope: Self.sessionScope(from: chain)
        )
    }

    static func sessionScope(pid: pid_t) -> String? {
        TerminalSessionScope.process(pid: Int32(pid))
    }

    static func sessionScope(from ancestry: [ProcessRef]) -> String? {
        for process in ancestry {
            if let scope = sessionScope(pid: process.pid) {
                return scope
            }
        }
        return nil
    }

    private static func processName(pid: pid_t) -> String? {
        let pathBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(MAXPATHLEN))
        defer { pathBuffer.deallocate() }
        let result = proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN))
        guard result > 0 else { return nil }
        let fullPath = String(cString: pathBuffer)
        return (fullPath as NSString).lastPathComponent
    }

    private static func processPath(pid: pid_t) -> String? {
        let pathBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(MAXPATHLEN))
        defer { pathBuffer.deallocate() }
        let result = proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN))
        guard result > 0 else { return nil }
        return String(cString: pathBuffer)
    }

    private static func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdshortinfo()
        let size = Int32(MemoryLayout<proc_bsdshortinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, size)
        guard result == size else { return nil }
        let ppid = pid_t(info.pbsi_ppid)
        guard ppid > 0, ppid != pid else { return nil }
        return ppid
    }

    /// Walks pid → ppid up to `maxHops` times. Stops at pid 1 (launchd) or on missing info.
    static func walkAncestors(pid: pid_t, maxHops: Int = 8) -> [ProcessRef] {
        var chain: [ProcessRef] = []
        var current: pid_t? = pid
        var hops = 0
        var seen = Set<pid_t>()
        while let pid = current, hops < maxHops, !seen.contains(pid), pid > 1 {
            seen.insert(pid)
            let name = processName(pid: pid) ?? "pid \(pid)"
            let path = processPath(pid: pid)
            chain.append(ProcessRef(pid: pid, name: name, path: path))
            current = parentPID(of: pid)
            hops += 1
        }
        return chain
    }

    /// Process names that are SSH plumbing rather than the user's intent.
    /// When walking ancestors we skip these to find the real instigator (`git`, `code`, etc.).
    private static let sshToolingNames: Set<String> = [
        "ssh", "ssh-add", "ssh-agent", "scp", "sftp", "ssh-keygen",
        "ssh-keyscan", "ssh-pkcs11-helper", "ssh-sk-helper",
    ]

    struct ProcessRef: Equatable {
        let pid: pid_t
        let name: String
        let path: String?

        var auditRef: SSHAgentProcessRef {
            SSHAgentProcessRef(pid: Int32(pid), name: name, path: path)
        }
    }

    struct RequesterInfo {
        let peer: ProcessRef?
        let instigator: ProcessRef?
        let ancestry: [ProcessRef]
        let targetHost: String?
        let sessionScope: String?

        var auditInfo: SSHAgentAuditInfo {
            SSHAgentAuditInfo(
                peer: peer?.auditRef,
                instigator: instigator?.auditRef,
                ancestry: ancestry.map(\.auditRef),
                targetHost: targetHost
            )
        }
    }

    private func recordSSHAgentAudit(
        keyItem: SSHKeyItem,
        requester: RequesterInfo,
        approvedBy: String
    ) {
        let record = BridgeAuditRecord(
            command: .sshAgentSign,
            itemId: keyItem.id.uuidString,
            itemName: keyItem.name,
            approvedBy: approvedBy,
            timestamp: Date(),
            sshAgent: requester.auditInfo
        )
        do {
            try auditLogger.record(record)
        } catch {
            debugLog("audit record failed: \(error)")
        }
    }

    private func resolveTargetHost(fd: Int32) -> String? {
        guard let pid = peerProcessID(fd: fd),
              let processInfo = processArgumentsAndEnvironment(pid: pid) else {
            return nil
        }
        let args = processInfo.arguments

        // Look for hostname in ssh-style arguments
        // Pattern: ssh [options] [user@]hostname
        // Skip the binary name (args[0]) and option flags
        var i = 1
        while i < args.count {
            let arg = args[i]
            if arg.hasPrefix("-") {
                // Options that take a value: skip next arg too
                let optsWithValue: Set<String> = [
                    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i",
                    "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
                    "-R", "-S", "-W", "-w",
                ]
                if optsWithValue.contains(arg) {
                    i += 2
                } else {
                    i += 1
                }
            } else {
                // First non-option argument is the destination
                // Strip user@ prefix if present
                if let atIndex = arg.lastIndex(of: "@") {
                    return String(arg[arg.index(after: atIndex)...])
                }
                return arg
            }
        }

        return nil
    }

    private func resolveProcessEnvironment(fd: Int32) -> [String: String] {
        guard let pid = peerProcessID(fd: fd),
              let processInfo = processArgumentsAndEnvironment(pid: pid) else {
            return [:]
        }
        return processInfo.environment
    }

    private func peerProcessID(fd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0 else {
            return nil
        }
        return pid
    }

    private func processArgumentsAndEnvironment(pid: pid_t) -> (arguments: [String], environment: [String: String])? {
        Self.kernelProcessArgumentsAndEnvironment(pid: pid)
    }

    static func kernelProcessArgumentsAndEnvironment(
        pid: pid_t
    ) -> (arguments: [String], environment: [String: String])? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = processArgumentsBufferSize()
        guard size > MemoryLayout<Int32>.size else { return nil }

        var buffer = [CChar](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return nil }
        return Self.parseProcessArgumentsAndEnvironment(buffer, size: size)
    }

    private static func processArgumentsBufferSize() -> Int {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        if sysctlbyname("kern.argmax", &argmax, &size, nil, 0) == 0, argmax > 0 {
            return Int(argmax)
        }
        return 1_048_576
    }

    static func parseProcessArgumentsAndEnvironment(
        _ buffer: [CChar],
        size: Int
    ) -> (arguments: [String], environment: [String: String])? {
        guard size > MemoryLayout<Int32>.size else { return nil }
        let argc = buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc >= 0 else { return nil }

        var offset = MemoryLayout<Int32>.size
        while offset < size && buffer[offset] != 0 { offset += 1 }
        while offset < size && buffer[offset] == 0 { offset += 1 }

        var args: [String] = []
        while offset < size && args.count < Int(argc) {
            if let value = readNullTerminatedString(buffer, size: size, offset: &offset),
               !value.isEmpty {
                args.append(value)
            }
        }

        var environment: [String: String] = [:]
        while offset < size {
            guard let value = readNullTerminatedString(buffer, size: size, offset: &offset) else {
                break
            }
            guard !value.isEmpty, let separator = value.firstIndex(of: "=") else {
                continue
            }
            let key = String(value[..<separator])
            let val = String(value[value.index(after: separator)...])
            environment[key] = val
        }

        return (args, environment)
    }

    private static func readNullTerminatedString(
        _ buffer: [CChar],
        size: Int,
        offset: inout Int
    ) -> String? {
        while offset < size && buffer[offset] == 0 { offset += 1 }
        guard offset < size else { return nil }

        var bytes: [UInt8] = []
        while offset < size && buffer[offset] != 0 {
            bytes.append(UInt8(bitPattern: buffer[offset]))
            offset += 1
        }
        if offset < size { offset += 1 }
        return String(bytes: bytes, encoding: .utf8)
    }

    private func signWithKey(
        keyItem: SSHKeyItem,
        passphrase: String?,
        keyBlob: Data,
        data: Data,
        flags: UInt32,
        sessionBindRequests: [Data]
    ) -> Data? {
        let tempDir = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("authsia-\(UUID().uuidString.prefix(12))")
        do {
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            chmod(tempDir.path, 0o700)
        } catch {
            debugLog("sign failed: temp directory create failed")
            return nil
        }
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let keyPath = tempDir.appendingPathComponent("key")
        let socketPath = tempDir.appendingPathComponent("agent.sock").path

        do {
            try keyItem.privateKey.write(to: keyPath)
            chmod(keyPath.path, 0o600)
        } catch {
            debugLog("sign failed: temp key write failed")
            return nil
        }

        let agent = Process()
        agent.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
        agent.arguments = ["-D", "-a", socketPath]
        agent.standardOutput = Pipe()
        agent.standardError = Pipe()

        do {
            try agent.run()
        } catch {
            debugLog("sign failed: nested ssh-agent launch failed")
            return nil
        }
        defer {
            agent.terminate()
            _ = waitForProcess(agent, timeout: 1)
            if agent.isRunning {
                kill(agent.processIdentifier, SIGKILL)
            }
        }

        guard waitForSocket(at: socketPath, timeout: Self.signingTimeout) else {
            debugLog("sign failed: nested ssh-agent socket timeout")
            return nil
        }

        let addProcess = Process()
        addProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
        addProcess.arguments = [keyPath.path]
        addProcess.standardOutput = Pipe()
        addProcess.standardError = Pipe()

        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = socketPath
        if let passphrase, !passphrase.isEmpty {
            guard let askPassPath = makeAskPassHelper(passphrase: passphrase, in: tempDir) else {
                debugLog("sign failed: askpass helper create failed")
                return nil
            }
            environment["SSH_ASKPASS"] = askPassPath
            environment["SSH_ASKPASS_REQUIRE"] = "force"
            environment["DISPLAY"] = environment["DISPLAY"] ?? ":0"
        }
        addProcess.environment = environment

        do {
            try addProcess.run()
        } catch {
            debugLog("sign failed: ssh-add launch failed")
            return nil
        }

        let completed = waitForProcess(addProcess, timeout: Self.signingTimeout)
        guard completed else {
            debugLog("sign failed: ssh-add timeout")
            addProcess.terminate()
            _ = waitForProcess(addProcess, timeout: 1)
            if addProcess.isRunning {
                kill(addProcess.processIdentifier, SIGKILL)
            }
            return nil
        }

        guard addProcess.terminationStatus == 0 else {
            debugLog("sign failed: ssh-add exited \(addProcess.terminationStatus)")
            return nil
        }

        return signUsingAgentSocket(
            socketPath: socketPath,
            keyBlob: keyBlob,
            data: data,
            flags: flags,
            sessionBindRequests: sessionBindRequests
        )
    }

    private func makeAskPassHelper(passphrase: String, in tempDir: URL) -> String? {
        let fifoURL = tempDir.appendingPathComponent("askpass.fifo")
        guard mkfifo(fifoURL.path, 0o600) == 0 else {
            return nil
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let deadline = Date().addingTimeInterval(Self.signingTimeout)
            var fd: Int32 = -1
            while Date() < deadline {
                fd = open(fifoURL.path, O_WRONLY | O_NONBLOCK)
                if fd >= 0 { break }
                usleep(20_000)
            }
            guard fd >= 0 else { return }
            defer { close(fd) }

            let passphraseBytes = Array(passphrase.utf8)
            passphraseBytes.withUnsafeBytes { ptr in
                guard let baseAddress = ptr.baseAddress else { return }
                var offset = 0
                while offset < passphraseBytes.count {
                    let written = Darwin.write(fd, baseAddress.advanced(by: offset), passphraseBytes.count - offset)
                    guard written > 0 else { return }
                    offset += written
                }
            }
        }

        let helperURL = tempDir.appendingPathComponent("askpass.sh")
        let fifoPath = shellSingleQuoted(fifoURL.path)
        let helper = "#!/bin/sh\nIFS= read -r passphrase < \(fifoPath)\nprintf '%s' \"$passphrase\"\n"
        do {
            try helper.write(to: helperURL, atomically: true, encoding: .utf8)
            chmod(helperURL.path, 0o700)
            return helperURL.path
        } catch {
            return nil
        }
    }

    private func shellSingleQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func waitForSocket(at path: String, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let fd = connectUnixSocket(path: path)
            if fd >= 0 {
                close(fd)
                return true
            }
            usleep(20_000)
        }
        return false
    }

    private func signUsingAgentSocket(
        socketPath: String,
        keyBlob: Data,
        data: Data,
        flags: UInt32,
        sessionBindRequests: [Data]
    ) -> Data? {
        let fd = connectUnixSocket(path: socketPath)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        for sessionBindRequest in sessionBindRequests {
            guard let bindResponse = sendAgentRequest(fd: fd, request: sessionBindRequest),
                  bindResponse.first == 6 else {
                debugLog("sign failed: nested agent rejected session-bind")
                return nil
            }
        }

        var body = Data([13])
        appendSSHString(&body, keyBlob)
        appendSSHString(&body, data)
        appendUInt32(&body, flags)

        var request = Data()
        appendUInt32(&request, UInt32(body.count))
        request.append(body)

        guard let payload = sendAgentRequest(fd: fd, request: request) else {
            debugLog("sign failed: nested agent sign request returned no payload")
            return nil
        }
        guard payload.first == 14 else {
            debugLog("sign failed: nested agent sign response type \(payload.first ?? 0)")
            return nil
        }

        var offset = 1
        return readSSHDataString(from: payload, offset: &offset)
    }

    private func sendAgentRequest(fd: Int32, request: Data) -> Data? {
        guard writeAll(fd: fd, data: request),
              let header = readExact(fd: fd, count: 4) else {
            return nil
        }

        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard length > 0, length < 1024 * 1024 else {
            return nil
        }
        return readExact(fd: fd, count: Int(length))
    }

    private func connectUnixSocket(path: String) -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return -1 }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        path.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                sunPath.withMemoryRebound(to: CChar.self, capacity: 104) { dest in
                    _ = strlcpy(dest, ptr, 104)
                }
            }
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            close(fd)
            return -1
        }
        return fd
    }

    private func writeAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return true }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, baseAddress.advanced(by: offset), buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard written > 0 else { return false }
                offset += written
            }
            return true
        }
    }

    private func readExact(fd: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        let success = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return count == 0 }
            var offset = 0
            while offset < count {
                let received = recv(fd, baseAddress.advanced(by: offset), count - offset, 0)
                if received < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard received > 0 else { return false }
                offset += received
            }
            return true
        }
        return success ? data : nil
    }

    private func appendUInt32(_ data: inout Data, _ value: UInt32) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    private func appendSSHString(_ data: inout Data, _ value: Data) {
        appendUInt32(&data, UInt32(value.count))
        data.append(value)
    }

    private func readSSHDataString(from data: Data, offset: inout Int) -> Data? {
        guard offset + 4 <= data.count else { return nil }
        let length = data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4

        let remainingBytes = data.count - offset
        guard UInt64(length) <= UInt64(remainingBytes) else {
            return nil
        }

        let value = data[offset..<offset + Int(length)]
        offset += Int(length)
        return Data(value)
    }

    private func waitForProcess(_ process: Process, timeout: TimeInterval) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            process.waitUntilExit()
            semaphore.signal()
        }
        return semaphore.wait(timeout: .now() + timeout) == .success
    }

    private func isEncryptedPrivateKey(_ privateKey: Data) -> Bool {
        guard let keyText = String(data: privateKey, encoding: .utf8) else {
            return false
        }

        if keyText.contains("ENCRYPTED") || keyText.contains("Proc-Type: 4,ENCRYPTED") {
            return true
        }

        guard keyText.contains("BEGIN OPENSSH PRIVATE KEY"),
              let body = openSSHPrivateKeyBody(from: keyText),
              let decoded = Data(base64Encoded: body) else {
            return false
        }

        return openSSHPrivateKeyCipherName(from: decoded).map { $0 != "none" } ?? false
    }

    private func openSSHPrivateKeyBody(from keyText: String) -> String? {
        let lines = keyText
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        var bodyLines: [String] = []
        var isInsideBody = false
        for line in lines {
            if line == "-----BEGIN OPENSSH PRIVATE KEY-----" {
                isInsideBody = true
                continue
            }
            if line == "-----END OPENSSH PRIVATE KEY-----" {
                break
            }
            if isInsideBody {
                bodyLines.append(line)
            }
        }

        guard !bodyLines.isEmpty else { return nil }
        return bodyLines.joined()
    }

    private func openSSHPrivateKeyCipherName(from data: Data) -> String? {
        let magic = Data("openssh-key-v1\0".utf8)
        guard data.starts(with: magic) else { return nil }

        var offset = magic.count
        return readSSHString(from: data, offset: &offset)
    }

    private func readSSHString(from data: Data, offset: inout Int) -> String? {
        guard offset + 4 <= data.count else { return nil }
        let length = data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4

        let remainingBytes = data.count - offset
        guard UInt64(length) <= UInt64(remainingBytes) else {
            return nil
        }

        let value = data[offset..<offset + Int(length)]
        offset += Int(length)
        return String(data: Data(value), encoding: .utf8)
    }

    private func debugLog(_ message: String) {
        NSLog("[SSHAgent] %@", message)
    }

    private static let signingTimeout: TimeInterval = 10
}
#endif
