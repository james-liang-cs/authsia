import Foundation

public struct NativeHostHandler {
    private let resolver: CredentialResolver
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public init(resolver: CredentialResolver? = nil) {
        self.resolver = resolver ?? CredentialResolver()
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
    }

    public func handleRequestData(_ data: Data) -> Data {
        let response: NativeHostResponse
        do {
            let request = try decoder.decode(NativeHostRequest.self, from: data)
            
            switch request.type {
            case "listCredentials":
                guard let host = request.host else {
                    response = .failure(.invalidHost)
                    break
                }
                response = try resolver.listCredentials(forHost: host, currentURL: request.currentURL)
            case "getCredentials":
                guard let host = request.host else {
                    response = .failure(.invalidHost)
                    break
                }
                response = try resolver.getCredential(
                    forHost: host,
                    currentURL: request.currentURL,
                    credentialId: request.credentialId
                )
            case "openApp":
                Self.openAuthsiaApp()
                response = NativeHostResponse(ok: true)
            default:
                response = .failure(.invalidRequest, detail: "Unknown message type: \(request.type)")
            }
        } catch {
            response = .failure(.invalidRequest, detail: String(describing: error))
        }

        return encode(response)
    }

    private static func openAuthsiaApp() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = ["-a", "Authsia"]
        try? process.run()
    }

    private func encode(_ response: NativeHostResponse) -> Data {
        do {
            return try encoder.encode(response)
        } catch {
            // Fall back to a minimal response if encoding ever fails.
            let fallback = NativeHostResponse.failure(.decodeFailure, detail: String(describing: error))
            return (try? encoder.encode(fallback)) ?? Data("{\"ok\":false,\"error\":\"decodeFailure\"}".utf8)
        }
    }
}
