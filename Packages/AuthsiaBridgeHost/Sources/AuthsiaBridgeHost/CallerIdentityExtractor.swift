#if os(macOS)
import Foundation
import Security
import Darwin
import AuthenticatorBridge

/// Extracts the identity of a connecting process from an NSXPCConnection.
/// Must be called synchronously (before entering async Task) since NSXPCConnection.current()
/// is not available in async contexts.
public enum CallerIdentityExtractor {

    public static func extract(from connection: NSXPCConnection?) -> CallerIdentity? {
        guard let connection else { return nil }
        return extract(fromPID: connection.processIdentifier)
    }

    @usableFromInline
    static func extract(fromPID pid: pid_t) -> CallerIdentity? {
        guard pid > 0, let processName = Self.processName(for: pid) else { return nil }
        let parentContext = parentProcessContext(for: pid)
        let controllingTerminal = TerminalSessionScope.controllingTerminal(pid: pid)
        let hostCommand = renderedCommand(processArguments(for: pid))

        var code: SecCode?
        let pidAttr = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, pidAttr, SecCSFlags(), &code) == errSecSuccess,
              let guestCode = code else {
            return CallerIdentity(
                pid: pid,
                processName: processName,
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcess: parentContext.parent,
                hostProcess: parentContext.host,
                controllingTerminal: controllingTerminal,
                shellAncestryPrefix: parentContext.shellAncestryPrefix,
                hostCommand: hostCommand
            )
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticGuestCode = staticCode else {
            return CallerIdentity(
                pid: pid,
                processName: processName,
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcess: parentContext.parent,
                hostProcess: parentContext.host,
                controllingTerminal: controllingTerminal,
                shellAncestryPrefix: parentContext.shellAncestryPrefix,
                hostCommand: hostCommand
            )
        }

        var info: CFDictionary?
        let signingInformationFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticGuestCode, signingInformationFlags, &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return CallerIdentity(
                pid: pid,
                processName: processName,
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcess: parentContext.parent,
                hostProcess: parentContext.host,
                controllingTerminal: controllingTerminal,
                shellAncestryPrefix: parentContext.shellAncestryPrefix,
                hostCommand: hostCommand
            )
        }

        let teamId = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
        let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String

        // Use the documented kSecCodeInfoCertificates key to get the certificate chain.
        // Extract the common name from the leaf certificate as the signing identity.
        let signingAuthority: String?
        if let certs = signingInfo[kSecCodeInfoCertificates as String] as? [SecCertificate],
           let leaf = certs.first {
            var cfName: CFString?
            if SecCertificateCopyCommonName(leaf, &cfName) == errSecSuccess {
                signingAuthority = cfName as String?
            } else {
                signingAuthority = nil
            }
        } else {
            signingAuthority = nil
        }

        return CallerIdentity(
            pid: pid,
            processName: processName,
            bundleIdentifier: identifier,
            signingTeamId: teamId,
            signingIdentity: signingAuthority,
            parentProcess: parentContext.parent,
            hostProcess: parentContext.host,
            controllingTerminal: controllingTerminal,
            shellAncestryPrefix: parentContext.shellAncestryPrefix,
            hostCommand: hostCommand
        )
    }

    private static func processName(for pid: pid_t) -> String? {
        processName(
            arguments: processArguments(for: pid),
            executablePath: executablePath(for: pid)
        )
    }

    private static func processName(arguments: [String], executablePath: String?) -> String? {
        guard let fullPath = executablePath else { return nil }
        let baseName = (fullPath as NSString).lastPathComponent

        // For generic runtimes, inspect argv to find the actual application name
        if runtimeNames.contains(baseName), let appName = applicationName(from: arguments) {
            return appName
        }
        return baseName
    }

    private static func executablePath(for pid: pid_t) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard length > 0 else { return nil }
        return String(cString: pathBuffer)
    }

    private static let runtimeNames: Set<String> = ["node", "python", "python3", "ruby", "java", "bun", "deno"]

    private static func applicationName(from arguments: [String]) -> String? {
        guard let argv0 = arguments.first else { return nil }
        let argv0Name = (argv0 as NSString).lastPathComponent
        if !runtimeNames.contains(argv0Name) {
            return argv0Name
        }
        guard let argv1 = arguments.dropFirst().first else { return nil }
        return (argv1 as NSString).lastPathComponent
    }

    /// Reads the process argv via sysctl KERN_PROCARGS2.
    private static func processArguments(for pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }

        // KERN_PROCARGS2 layout: [argc: Int32] [exec_path \0] [padding \0s] [argv[0] \0] [argv[1] \0] ...
        guard size > MemoryLayout<Int32>.size else { return [] }
        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        guard argc > 0 else { return [] }

        // Skip past argc and the exec_path
        var offset = MemoryLayout<Int32>.size
        while offset < size && buffer[offset] != 0 { offset += 1 } // skip exec_path
        while offset < size && buffer[offset] == 0 { offset += 1 } // skip null padding

        var arguments: [String] = []
        for _ in 0..<argc {
            guard offset < size else { break }
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            if start < offset,
               let argument = String(bytes: buffer[start..<offset], encoding: .utf8) {
                arguments.append(argument)
            }
            while offset < size && buffer[offset] == 0 { offset += 1 }
        }
        return arguments
    }

    private static func renderedCommand(_ arguments: [String]) -> String? {
        guard !arguments.isEmpty else { return nil }
        return arguments.map(shellQuote).joined(separator: " ")
    }

    private static func shellQuote(_ argument: String) -> String {
        guard !argument.isEmpty else { return "''" }
        let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_/:=.,+-"))
        guard argument.rangeOfCharacter(from: safe.inverted) != nil else { return argument }
        return "'\(argument.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    struct ParentProcessContext {
        let parent: ParentProcessInfo?
        let host: ParentProcessInfo?
        let shellAncestryPrefix: [ParentProcessInfo]
    }

    static func parentProcessContext(from ancestry: [ParentProcessInfo]) -> ParentProcessContext {
        let shellAncestryPrefix = Array(ancestry.prefix { process in
            AgentJITCallerContext.trustedShellProcessNames.contains(process.processName.lowercased())
        })
        let context = AgenticProcessDetector.parentProcessContext(from: ancestry)
        guard context.host == nil,
              let parent = context.parent,
              let parentIndex = ancestry.firstIndex(where: { $0.pid == parent.pid }),
              ancestry.indices.contains(parentIndex + 1) else {
            return ParentProcessContext(
                parent: context.parent,
                host: context.host,
                shellAncestryPrefix: shellAncestryPrefix
            )
        }
        let host = ancestry[parentIndex + 1]
        guard AgentJITCallerContext.isTrustedITermServer(parent, hostedBy: host) else {
            return ParentProcessContext(
                parent: context.parent,
                host: context.host,
                shellAncestryPrefix: shellAncestryPrefix
            )
        }
        // iTerm inserts its signed server between login and the app. Preserve the
        // helper as parent evidence while restoring the signed app as its host.
        return ParentProcessContext(parent: parent, host: host, shellAncestryPrefix: shellAncestryPrefix)
    }

    /// Walks up the process tree so bridge caller identity uses the same ancestry
    /// depth as CLI agent detection.
    private static func parentProcessContext(for childPID: pid_t) -> ParentProcessContext {
        var currentPID = childPID
        var ancestry: [ParentProcessInfo] = []
        // Walk up at most 8 levels to avoid infinite loops
        for _ in 0..<8 {
            guard let ppid = TerminalSessionScope.parentProcessIdentifier(pid: currentPID) else {
                return parentProcessContext(from: ancestry)
            }
            guard ppid > 1 else { return parentProcessContext(from: ancestry) }

            let arguments = processArguments(for: ppid)
            let executablePath = executablePath(for: ppid)
            let name = processName(arguments: arguments, executablePath: executablePath) ?? "unknown"
            let signing = processSigningInfo(for: ppid)
            let info = ParentProcessInfo(
                pid: ppid,
                processName: name,
                bundleIdentifier: signing?.identifier,
                signingTeamId: signing?.teamID,
                signingIdentity: signing?.identity,
                isPlatformBinary: signing?.isPlatformBinary,
                executablePath: executablePath,
                arguments: arguments,
                startTimeSeconds: TerminalSessionScope.startTimeSeconds(pid: ppid)
            )
            ancestry.append(info)
            currentPID = ppid
        }
        return parentProcessContext(from: ancestry)
    }

    private static func processSigningInfo(
        for pid: pid_t
    ) -> (identifier: String?, teamID: String?, identity: String?, isPlatformBinary: Bool)? {
        var code: SecCode?
        let pidAttr = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, pidAttr, SecCSFlags(), &code) == errSecSuccess,
              let guestCode = code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticGuestCode = staticCode else {
            return nil
        }
        var info: CFDictionary?
        let signingInformationFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticGuestCode, signingInformationFlags, &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return nil
        }
        let certificates = signingInfo[kSecCodeInfoCertificates as String] as? [SecCertificate]
        var commonName: CFString?
        let identity = certificates?.first.flatMap {
            SecCertificateCopyCommonName($0, &commonName) == errSecSuccess
                ? commonName as String?
                : nil
        }
        var appleRequirement: SecRequirement?
        let isAppleSigned =
            SecRequirementCreateWithString(
                "anchor apple" as CFString,
                SecCSFlags(),
                &appleRequirement
            ) == errSecSuccess
            && appleRequirement.map {
                SecCodeCheckValidity(guestCode, SecCSFlags(), $0) == errSecSuccess
            } == true
        return (
            signingInfo[kSecCodeInfoIdentifier as String] as? String,
            signingInfo[kSecCodeInfoTeamIdentifier as String] as? String,
            identity,
            isAppleSigned
        )
    }
}
#endif
