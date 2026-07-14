import Foundation
import AuthenticatorBridge
import AuthenticatorCore

struct TableFormatter {
    static func formatOTPItems(_ otpItems: [BridgeAccount]) -> String {
        let headers = ["Issuer", "Label", "Favorite", "ID", "CLI", "Scraped", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = otpItems.map { otpItem in
            [
                otpItem.issuer,
                otpItem.label,
                otpItem.isFavorite ? "*" : "",
                otpItem.id.uuidString,
                otpItem.isCliEnabled ? "on" : "off",
                otpItem.isScraped ? "yes" : "no",
                dateFormatter.string(from: otpItem.createdAt),
                dateFormatter.string(from: otpItem.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatPasswords(_ passwords: [BridgePassword]) -> String {
        let headers = ["Name", "Folder", "Environments", "Machine", "Expires", "Favorite", "ID", "CLI", "Scraped", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = passwords.map { password in
            [
                password.name,
                password.folderPath ?? "-",
                environmentDisplay(password.environments),
                ScrapedItemMachineSupport.displayMachine(
                    isScraped: password.isScraped,
                    scrapeMachineName: password.scrapeMachineName,
                    scrapeMachineId: password.scrapeMachineId
                ),
                Self.displayExpiry(password.expiresAt, with: dateFormatter),
                password.isFavorite ? "*" : "",
                password.id.uuidString,
                password.isCliEnabled ? "on" : "off",
                password.isScraped ? "yes" : "no",
                dateFormatter.string(from: password.createdAt),
                dateFormatter.string(from: password.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatAPIKeys(_ apiKeys: [BridgeAPIKey]) -> String {
        let headers = ["Name", "Folder", "Environments", "Machine", "Expires", "Favorite", "ID", "CLI", "Scraped", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = apiKeys.map { apiKey in
            [
                apiKey.name,
                apiKey.folderPath ?? "-",
                environmentDisplay(apiKey.environments),
                ScrapedItemMachineSupport.displayMachine(
                    isScraped: apiKey.isScraped,
                    scrapeMachineName: apiKey.scrapeMachineName,
                    scrapeMachineId: apiKey.scrapeMachineId
                ),
                Self.displayExpiry(apiKey.expiresAt, with: dateFormatter),
                apiKey.isFavorite ? "*" : "",
                apiKey.id.uuidString,
                apiKey.isCliEnabled ? "on" : "off",
                apiKey.isScraped ? "yes" : "no",
                dateFormatter.string(from: apiKey.createdAt),
                dateFormatter.string(from: apiKey.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatCertificates(_ certificates: [BridgeCertificate]) -> String {
        let headers = ["Name", "Folder", "Environments", "Machine", "Issuer", "Expires", "Favorite", "ID", "CLI", "Scraped", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = certificates.map { cert in
            [
                cert.name,
                cert.folderPath ?? "-",
                environmentDisplay(cert.environments),
                ScrapedItemMachineSupport.displayMachine(
                    isScraped: cert.isScraped,
                    scrapeMachineName: cert.scrapeMachineName,
                    scrapeMachineId: cert.scrapeMachineId
                ),
                cert.issuer ?? "-",
                cert.expirationDate.map { dateFormatter.string(from: $0) } ?? "Never",
                cert.isFavorite ? "*" : "",
                cert.id.uuidString,
                cert.isCliEnabled ? "on" : "off",
                cert.isScraped ? "yes" : "no",
                dateFormatter.string(from: cert.createdAt),
                dateFormatter.string(from: cert.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatNotes(_ notes: [BridgeNote]) -> String {
        let headers = ["Title", "Folder", "Environments", "Machine", "Favorite", "ID", "CLI", "Scraped", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = notes.map { note in
            [
                note.title,
                note.folderPath ?? "-",
                environmentDisplay(note.environments),
                ScrapedItemMachineSupport.displayMachine(
                    isScraped: note.isScraped,
                    scrapeMachineName: note.scrapeMachineName,
                    scrapeMachineId: note.scrapeMachineId
                ),
                note.isFavorite ? "*" : "",
                note.id.uuidString,
                note.isCliEnabled ? "on" : "off",
                note.isScraped ? "yes" : "no",
                dateFormatter.string(from: note.createdAt),
                dateFormatter.string(from: note.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatSSHKeys(_ keys: [BridgeSSHKey]) -> String {
        let headers = ["Name", "Folder", "Environments", "Machine", "Type", "Approval", "Hosts", "Comment", "Fingerprint", "Favorite", "ID", "CLI", "Adopted", "Created", "Updated"]
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short

        let rows = keys.map { key in
            [
                key.name,
                key.folderPath ?? "-",
                environmentDisplay(key.environments),
                ScrapedItemMachineSupport.displayMachine(
                    isScraped: key.isScraped,
                    scrapeMachineName: key.scrapeMachineName,
                    scrapeMachineId: key.scrapeMachineId
                ),
                Self.displayKeyType(key.keyType),
                Self.displayApprovalPolicy(key.approvalPolicy),
                key.boundHosts.isEmpty ? "any" : key.boundHosts.joined(separator: ","),
                key.comment,
                key.fingerprint,
                key.isFavorite ? "*" : "",
                key.id.uuidString,
                key.isCliEnabled ? "on" : "off",
                key.isScraped ? "yes" : "no",
                dateFormatter.string(from: key.createdAt),
                dateFormatter.string(from: key.updatedAt)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    static func formatBackups(_ backups: [BackupService.BackupEntry]) -> String {
        let headers = ["File", "Machine", "Created", "Status", "Slot", "Backup Note Path"]
        let rows = backups.map { backup in
            [
                backup.originalPath,
                backup.displayMachine,
                backup.formattedDate,
                backup.isRestored ? "restored" : "active",
                backup.slot == .baseline ? "original" : "latest",
                backup.backupNotePath,
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    private static func displayExpiry(_ expiresAt: Date?, with dateFormatter: DateFormatter) -> String {
        expiresAt.map { dateFormatter.string(from: $0) } ?? "Never"
    }

    static func environmentDisplay(_ environments: [String]) -> String {
        environments.isEmpty ? "Default" : environments.joined(separator: ", ")
    }

    // MARK: - SSH Display Helpers

    private static func displayKeyType(_ keyType: SSHKeyType) -> String {
        switch keyType {
        case .ed25519: return "ed25519"
        case .rsa2048: return "rsa2048"
        case .rsa3072: return "rsa3072"
        case .rsa4096: return "rsa4096"
        }
    }

    private static func displayApprovalPolicy(_ policy: SSHKeyApprovalPolicy) -> String {
        switch policy {
        case .alwaysPrompt: return "always"
        case .sessionBased: return "session"
        case .autoApprove: return "auto"
        }
    }

    static func renderTable(headers: [String], rows: [[String]]) -> String {
        let widths = columnWidths(headers: headers, rows: rows)
        let border = "+" + widths.map { String(repeating: "-", count: $0 + 2) }.joined(separator: "+") + "+"
        let headerRow = rowLine(values: headers, widths: widths)
        let dataRows = rows.map { rowLine(values: $0, widths: widths) }
        return ([border, headerRow, border] + dataRows + [border]).joined(separator: "\n")
    }

    static func columnWidths(headers: [String], rows: [[String]]) -> [Int] {
        var widths = headers.map(\.count)
        for row in rows {
            for (index, value) in row.enumerated() where index < widths.count {
                widths[index] = max(widths[index], value.count)
            }
        }
        return widths
    }

    static func rowLine(values: [String], widths: [Int]) -> String {
        let padded = zip(values, widths).map { value, width in
            value + String(repeating: " ", count: max(0, width - value.count))
        }
        return "| " + padded.joined(separator: " | ") + " |"
    }
}
