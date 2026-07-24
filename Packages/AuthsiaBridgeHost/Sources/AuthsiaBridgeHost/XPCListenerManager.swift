#if os(macOS)
import Foundation
import Security
import Darwin
@preconcurrency import AuthenticatorBridge

/// Manages the XPC listener for CLI-to-App communication.
/// Uses CFMessagePort for reliable IPC that works in both GUI and headless modes.
public final class XPCListenerManager: NSObject, NSXPCListenerDelegate {
    private let serviceName = "Authsia.Bridge"
    private let bundledCLIPath: String
    private let bundledAppExecutablePath: String?
    private let trustedDevelopmentBuildRoots: [String]
    private var listener: NSXPCListener?
    private let handler: XPCRequestHandler

    public init(
        handler: XPCRequestHandler,
        bundledCLIPath: String,
        bundledAppExecutablePath: String? = nil,
        trustedDevelopmentBuildRoots: [String] = []
    ) {
        self.handler = handler
        self.bundledCLIPath = bundledCLIPath
        self.bundledAppExecutablePath = bundledAppExecutablePath
        self.trustedDevelopmentBuildRoots = trustedDevelopmentBuildRoots
        super.init()
    }

    /// Starts the XPC listener.
    /// Call this once during app launch.
    public func start() {
        guard listener == nil else {
            #if DEBUG
            print("[XPC] Listener already running")
            #endif
            return
        }

        // Create the listener for the Mach service
        // Since this is a launchd-managed service, we use the service name
        // that matches the MachService key in the launchd plist.
        listener = NSXPCListener(machServiceName: serviceName)
        listener?.delegate = self
        listener?.resume()
        
        #if DEBUG
        print("[XPC] NSXPCListener resumed on \(serviceName)")
        #endif
    }

    /// Stops the XPC listener.
    public func stop() {
        listener?.suspend()
        listener?.invalidate()
        listener = nil
        #if DEBUG
        print("[XPC] Listener stopped")
        #endif
    }

    // MARK: - NSXPCListenerDelegate

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        #if DEBUG
        print("[XPC] Request to accept new connection from pid: \(newConnection.processIdentifier)")
        #endif

        // Validate the connecting process's code signature and team ID (macOS only)
        guard validateConnection(newConnection) else {
            #if DEBUG
            print("[XPC] Connection rejected: code signature validation failed for pid: \(newConnection.processIdentifier)")
            #endif
            return false
        }

        #if DEBUG
        print("[XPC] Code signature validated for pid: \(newConnection.processIdentifier)")
        #endif
        
        // Configure the exported interface
        newConnection.exportedInterface = NSXPCInterface(with: AuthsiaBridgeXPCProtocol.self)
        newConnection.exportedObject = handler
        
        newConnection.invalidationHandler = {
            #if DEBUG
            print("[XPC] Connection invalidated (pid: \(newConnection.processIdentifier))")
            #endif
        }

        newConnection.interruptionHandler = {
            #if DEBUG
            print("[XPC] Connection interrupted (pid: \(newConnection.processIdentifier))")
            #endif
        }

        newConnection.resume()
        #if DEBUG
        print("[XPC] Connection resumed for pid: \(newConnection.processIdentifier)")
        #endif
        return true
    }
    
    /// Validates the connecting process's code signature and team ID
    private func validateConnection(_ connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        
        // Get the code object for the connecting process
        var code: SecCode?
        let pidAttr = [kSecGuestAttributePid as String: pid] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, pidAttr, SecCSFlags(), &code)
        
        guard status == errSecSuccess, let guestCode = code else {
            return allowConnectionUsingExecutableFallback(
                pid: pid,
                failureReason: "Failed to get code object (\(status))"
            )
        }
        
        // Create static code from dynamic code to get signing info
        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode)
        
        guard staticStatus == errSecSuccess, let staticGuestCode = staticCode else {
            return allowConnectionUsingExecutableFallback(
                pid: pid,
                failureReason: "Failed to get static code (\(staticStatus))"
            )
        }
        
        // Get the code signing information to verify team ID
        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(staticGuestCode, SecCSFlags(), &info)
        
        guard infoStatus == errSecSuccess, let signingInfo = info as? [String: Any] else {
            return allowConnectionUsingExecutableFallback(
                pid: pid,
                failureReason: "Failed to get signing information (\(infoStatus))"
            )
        }
        
        // Extract team identifier - in debug builds, CLI may be ad-hoc signed without team ID
        let teamIdentifier = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
        
        // Get our own team identifier for comparison
        let ourTeamID = getOurTeamIdentifier()
        
        // Debug logging
        #if DEBUG
        print("[XPC] Guest team ID: \(teamIdentifier ?? "nil"), Our team ID: \(ourTeamID ?? "nil")")
        #endif
        
        // If either team ID is missing (debug builds), fall back to basic code validation
        guard let guestTeamID = teamIdentifier, let selfTeamID = ourTeamID else {
            return allowConnectionUsingExecutableFallback(
                pid: pid,
                failureReason: "Team ID unavailable"
            )
        }
        
        // Verify team IDs match
        guard guestTeamID == selfTeamID else {
            #if DEBUG
            print("[XPC] Team ID mismatch: expected \(selfTeamID), got \(guestTeamID)")
            #endif
            return false
        }
        
        return true
    }

    private func allowConnectionUsingExecutableFallback(pid: pid_t, failureReason: String) -> Bool {
        guard let guestExecutablePath = executablePath(for: pid) else {
            #if DEBUG
            print("[XPC] Connection rejected: \(failureReason); executable path unavailable for pid \(pid)")
            #endif
            return false
        }

        let trusted = Self.isTrustedAppExecutablePath(
            guestExecutablePath,
            bundledAppExecutablePath: bundledAppExecutablePath
        ) || Self.isTrustedCLIExecutablePath(
            guestExecutablePath,
            bundledCLIPath: bundledCLIPath,
            trustedDevelopmentBuildRoots: trustedDevelopmentBuildRoots
        )
        if trusted {
            #if DEBUG
            print("[XPC] Allowing fallback trust for pid \(pid) at path: \(guestExecutablePath)")
            #endif
            return true
        }

        #if DEBUG
        print("[XPC] Connection rejected: \(failureReason); untrusted executable path: \(guestExecutablePath)")
        #endif
        return false
    }

    private func executablePath(for pid: pid_t) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard length > 0 else {
            return nil
        }
        return String(cString: pathBuffer)
    }

    public static func isTrustedAppExecutablePath(
        _ executablePath: String,
        bundledAppExecutablePath: String?
    ) -> Bool {
        guard let bundledAppExecutablePath else { return false }
        return URL(fileURLWithPath: executablePath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path == URL(fileURLWithPath: bundledAppExecutablePath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }

    public static func isTrustedCLIExecutablePath(
        _ executablePath: String,
        bundledCLIPath: String,
        trustedDevelopmentBuildRoots: [String] = []
    ) -> Bool {
        let resolvedExecutablePath = URL(fileURLWithPath: executablePath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
        let resolvedBundledCLIPath = URL(fileURLWithPath: bundledCLIPath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path

        if resolvedExecutablePath == resolvedBundledCLIPath {
            return true
        }

        guard URL(fileURLWithPath: resolvedExecutablePath).lastPathComponent == "authsia" else {
            return false
        }

        return trustedDevelopmentBuildRoots.contains { buildRoot in
            let resolvedBuildRoot = URL(fileURLWithPath: buildRoot)
                .resolvingSymlinksInPath()
                .standardizedFileURL
                .path
            return resolvedExecutablePath.hasPrefix(resolvedBuildRoot + "/")
        }
    }
    
    /// Retrieves the team identifier of the current process
    private func getOurTeamIdentifier() -> String? {
        var selfCode: SecCode?
        let status = SecCodeCopySelf(SecCSFlags(), &selfCode)
        
        guard status == errSecSuccess, let dynamicCode = selfCode else {
            return nil
        }
        
        // Create static code from dynamic code
        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(dynamicCode, SecCSFlags(), &staticCode)
        
        guard staticStatus == errSecSuccess, let staticSelfCode = staticCode else {
            return nil
        }
        
        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(staticSelfCode, SecCSFlags(), &info)
        
        guard infoStatus == errSecSuccess, let signingInfo = info as? [String: Any] else {
            return nil
        }
        
        return signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
    }
    
    /// Returns whether the XPC listener is currently running
    public var isRunning: Bool {
        return listener != nil
    }
}

#endif
