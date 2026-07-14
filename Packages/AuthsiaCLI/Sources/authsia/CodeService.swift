import Foundation
import AuthenticatorCore
import AuthenticatorData

struct CodeService {
    static func generate(metadata: AccountMetadata, secret: Data, now: Date) -> (code: String, remaining: Int) {
        let period = max(1, Int(metadata.period))
        let seconds = Int(now.timeIntervalSince1970)
        let remaining = period - (seconds % period)
        let code: String
        if metadata.type == .hotp {
            code = OTPGenerator.hotp(
                secret: secret,
                counter: metadata.counter,
                digits: metadata.digits,
                algorithm: metadata.algorithm
            )
        } else {
            code = OTPGenerator.totp(
                secret: secret,
                time: now,
                period: metadata.period,
                digits: metadata.digits,
                algorithm: metadata.algorithm
            )
        }
        return (code, remaining)
    }
}
