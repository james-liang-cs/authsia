import AuthenticatorBridge
import CryptoKit
import Foundation

enum RemoteJITApprovalAuthorizationPolicy {
    enum Result: Equatable, Sendable {
        case allowed(source: RemoteJITApprovalSource, attribution: String)
        case denied(attribution: String)

        var attribution: String {
            switch self {
            case .allowed(_, let attribution), .denied(let attribution):
                return attribution
            }
        }
    }

    static func authorize(
        outcome: RemoteJITApprovalOutcome,
        command: BridgeRequestType,
        remoteRequests: [RemoteJITApprovalRequest]
    ) -> Result {
        switch outcome {
        case .approved(let source):
            guard command == .agentJITPreflight || remoteRequests.isEmpty else {
                return .denied(attribution: denialAttribution(for: source))
            }

            switch source {
            case .macBiometric, .macPanel:
                return .allowed(
                    source: source,
                    attribution: approvalAttribution(for: source)
                )
            case .pairedIPhone(let pairedSource):
                guard command == .agentJITPreflight,
                      !remoteRequests.isEmpty,
                      remoteRequests.allSatisfy({ request in
                          request.descriptor.pairingGenerationID == pairedSource.pairingGenerationID
                              && request.descriptor.iphoneSigningKeyFingerprint
                                  == pairedSource.signingKeyFingerprint
                      }) else {
                    return .denied(attribution: denialAttribution(for: source))
                }
                return .allowed(
                    source: source,
                    attribution: approvalAttribution(for: source)
                )
            }
        case .denied(let source):
            return .denied(attribution: denialAttribution(for: source))
        case .superseded:
            return .denied(attribution: "denied:superseded")
        case .timedOut:
            return .denied(attribution: "denied:timeout")
        }
    }

    private static func approvalAttribution(for source: RemoteJITApprovalSource) -> String {
        switch source {
        case .macBiometric:
            return "biometric"
        case .macPanel:
            return "mac-panel"
        case .pairedIPhone(let pairedSource):
            return remoteAttribution(for: pairedSource)
        }
    }

    private static func denialAttribution(for source: RemoteJITApprovalSource) -> String {
        "denied:\(approvalAttribution(for: source))"
    }

    private static func remoteAttribution(
        for source: RemoteJITApprovalPairedIPhoneSource
    ) -> String {
        var generationUUID = source.pairingGenerationID.uuid
        let generationBytes = withUnsafeBytes(of: &generationUUID) { Data($0) }
        let digest = SHA256.hash(data: generationBytes + source.signingKeyFingerprint)
        let alphabet = Array("0123456789abcdef".utf8)
        let suffix = digest.prefix(6).flatMap { byte in
            [alphabet[Int(byte >> 4)], alphabet[Int(byte & 0x0F)]]
        }
        return "ios-remote:\(String(decoding: suffix, as: UTF8.self))"
    }
}
