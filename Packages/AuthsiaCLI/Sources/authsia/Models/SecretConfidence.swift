import Foundation

enum SecretConfidence: String, CaseIterable, Comparable {
    case high = "high"
    case medium = "medium"
    case low = "low"
    
    static func < (lhs: SecretConfidence, rhs: SecretConfidence) -> Bool {
        let order: [SecretConfidence] = [.low, .medium, .high]
        guard let lhsIndex = order.firstIndex(of: lhs),
              let rhsIndex = order.firstIndex(of: rhs) else {
            return false
        }
        return lhsIndex < rhsIndex
    }
    
    var displayIcon: String {
        switch self {
        case .high: return "🔴"
        case .medium: return "🟡"
        case .low: return "🟢"
        }
    }
}
