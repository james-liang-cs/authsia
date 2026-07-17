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
                hostProcess: parentContext.host
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
                hostProcess: parentContext.host
            )
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticGuestCode, SecCSFlags(), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return CallerIdentity(
                pid: pid,
                processName: processName,
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcess: parentContext.parent,
                hostProcess: parentContext.host
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
            hostProcess: parentContext.host
        )
    }

    private static func processName(for pid: pid_t) -> String? {
        let arguments = processArguments(for: pid)
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard length > 0 else { return nil }
        let fullPath = String(cString: pathBuffer)
        let baseName = (fullPath as NSString).lastPathComponent

        // For generic runtimes, inspect argv to find the actual application name
        if runtimeNames.contains(baseName), let appName = applicationName(from: arguments) {
            return appName
        }
        return baseName
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

    struct ParentProcessContext {
        let parent: ParentProcessInfo?
        let host: ParentProcessInfo?
    }

    static func parentProcessContext(from ancestry: [ParentProcessInfo]) -> ParentProcessContext {
        let context = AgenticProcessDetector.parentProcessContext(from: ancestry)
        return ParentProcessContext(parent: context.parent, host: context.host)
    }

    /// Walks up the process tree so bridge caller identity uses the same ancestry
    /// depth as CLI agent detection.
    private static func parentProcessContext(for childPID: pid_t) -> ParentProcessContext {
        var currentPID = childPID
        var ancestry: [ParentProcessInfo] = []
        // Walk up at most 8 levels to avoid infinite loops
        for _ in 0..<8 {
            var bsdInfo = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            let result = proc_pidinfo(currentPID, PROC_PIDTBSDINFO, 0, &bsdInfo, size)
            guard result == size else { return parentProcessContext(from: ancestry) }
            let ppid = pid_t(bsdInfo.pbi_ppid)
            guard ppid > 1 else { return parentProcessContext(from: ancestry) }

            let name = processName(for: ppid) ?? "unknown"
            let info = ParentProcessInfo(pid: ppid, processName: name, bundleIdentifier: bundleIdentifier(for: ppid))
            ancestry.append(info)
            currentPID = ppid
        }
        return parentProcessContext(from: ancestry)
    }

    private static func bundleIdentifier(for pid: pid_t) -> String? {
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
        guard SecCodeCopySigningInformation(staticGuestCode, SecCSFlags(), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return nil
        }
        return signingInfo[kSecCodeInfoIdentifier as String] as? String
    }
}
#endif
