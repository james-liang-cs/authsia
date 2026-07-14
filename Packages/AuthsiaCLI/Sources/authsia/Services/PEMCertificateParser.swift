import Foundation

struct PEMCertificateContent: Hashable {
    let certificate: String?
    let privateKey: String?

    var isEmpty: Bool {
        certificate == nil && privateKey == nil
    }

    var preferredReferenceField: String {
        certificate == nil && privateKey != nil ? "privateKey" : "certificate"
    }
}

enum PEMCertificateParser {
    static func parse(_ content: String) -> PEMCertificateContent? {
        let certificateBlocks = blocks(in: content) { label in
            label == "CERTIFICATE"
        }
        let privateKeyBlocks = blocks(in: content) { label in
            label != "OPENSSH PRIVATE KEY" && label.hasSuffix("PRIVATE KEY")
        }

        let certificate = joinedBlocks(certificateBlocks)
        let privateKey = joinedBlocks(privateKeyBlocks)
        guard certificate != nil || privateKey != nil else { return nil }
        return PEMCertificateContent(certificate: certificate, privateKey: privateKey)
    }

    static func isLegacySSHPrivateKeyOnly(_ content: String) -> Bool {
        let hasCertificate = !blocks(in: content) { label in
            label == "CERTIFICATE"
        }.isEmpty
        guard !hasCertificate else { return false }

        return !blocks(in: content) { label in
            label == "RSA PRIVATE KEY" ||
                label == "DSA PRIVATE KEY" ||
                label == "EC PRIVATE KEY"
        }.isEmpty
    }

    private static func joinedBlocks(_ blocks: [String]) -> String? {
        guard !blocks.isEmpty else { return nil }
        return blocks.joined(separator: "\n")
    }

    private static func blocks(
        in content: String,
        matching shouldInclude: (String) -> Bool
    ) -> [String] {
        var result: [String] = []
        var activeLabel: String?
        var activeLines: [String] = []

        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)

            if activeLabel == nil, let label = beginLabel(from: trimmed), shouldInclude(label) {
                activeLabel = label
                activeLines = [line]
                continue
            }

            guard let label = activeLabel else { continue }
            activeLines.append(line)

            if endLabel(from: trimmed) == label {
                result.append(activeLines.joined(separator: "\n"))
                activeLabel = nil
                activeLines.removeAll(keepingCapacity: true)
            }
        }

        return result
    }

    private static func beginLabel(from line: String) -> String? {
        label(from: line, prefix: "-----BEGIN ", suffix: "-----")
    }

    private static func endLabel(from line: String) -> String? {
        label(from: line, prefix: "-----END ", suffix: "-----")
    }

    private static func label(from line: String, prefix: String, suffix: String) -> String? {
        guard line.hasPrefix(prefix), line.hasSuffix(suffix) else { return nil }
        return String(line.dropFirst(prefix.count).dropLast(suffix.count))
    }
}
