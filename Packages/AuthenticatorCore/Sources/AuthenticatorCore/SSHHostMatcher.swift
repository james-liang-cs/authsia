import Foundation

public enum SSHHostMatcher {

    public static func matches(host: String, pattern: String) -> Bool {
        let h = host.lowercased()
        let p = pattern.lowercased()

        if p.hasPrefix("*.") {
            let suffix = String(p.dropFirst(1)) // ".domain.com"
            return h.hasSuffix(suffix) && h != String(suffix.dropFirst())
        }

        return h == p
    }

    public static func keyMatchesHost(boundHosts: [String], targetHost: String) -> Bool {
        if boundHosts.isEmpty { return true }
        return boundHosts.contains { matches(host: targetHost, pattern: $0) }
    }
}
