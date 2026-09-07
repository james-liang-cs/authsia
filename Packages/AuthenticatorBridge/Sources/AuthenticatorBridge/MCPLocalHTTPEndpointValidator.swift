import Foundation

public enum MCPLocalHTTPEndpointValidationError: Error, Equatable, Sendable {
    case invalidURL
    case unsupportedScheme
    case nonLoopbackHost
    case missingPort
    case credentialsNotAllowed
    case queryOrFragmentNotAllowed
    case managerEndpointNotAllowed
}

public enum MCPLocalHTTPEndpointValidator {
    public static let allowedHosts: Set<String> = ["localhost", "127.0.0.1", "::1"]

    public static func validate(_ rawValue: String) throws -> URL {
        guard !rawValue.isEmpty,
              rawValue.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              let components = URLComponents(string: rawValue),
              let scheme = components.scheme?.lowercased(),
              let rawHost = components.host?.lowercased() else {
            throw MCPLocalHTTPEndpointValidationError.invalidURL
        }
        let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]")
            ? String(rawHost.dropFirst().dropLast())
            : rawHost
        guard scheme == "http" else {
            throw MCPLocalHTTPEndpointValidationError.unsupportedScheme
        }
        guard allowedHosts.contains(host) else {
            throw MCPLocalHTTPEndpointValidationError.nonLoopbackHost
        }
        guard let port = components.port, (1...65_535).contains(port) else {
            throw MCPLocalHTTPEndpointValidationError.missingPort
        }
        guard components.user == nil, components.password == nil else {
            throw MCPLocalHTTPEndpointValidationError.credentialsNotAllowed
        }
        guard components.query == nil, components.fragment == nil else {
            throw MCPLocalHTTPEndpointValidationError.queryOrFragmentNotAllowed
        }
        guard port != 8787, port != 8788 else {
            throw MCPLocalHTTPEndpointValidationError.managerEndpointNotAllowed
        }
        var canonical = components
        if host == "localhost" {
            canonical.host = "127.0.0.1"
        }
        guard let url = canonical.url else {
            throw MCPLocalHTTPEndpointValidationError.invalidURL
        }
        return url
    }
}
