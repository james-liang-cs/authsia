import Foundation

enum AuthsiaReferenceRewriteService {
    static func filesNeedingFolderRewrite(
        in paths: [String],
        folderPath: String,
        recursive: Bool = false
    ) throws -> [String] {
        try candidateFiles(in: paths, recursive: recursive).filter { filePath in
            guard let content = try? String(contentsOfFile: filePath, encoding: .utf8) else {
                return false
            }
            return rewriteContent(content, folderPath: folderPath) != content
        }
    }

    @discardableResult
    static func applyFolder(to paths: [String], folderPath: String, recursive: Bool = false) throws -> [String] {
        var modifiedFiles: [String] = []
        for filePath in try candidateFiles(in: paths, recursive: recursive) {
            let content = try String(contentsOfFile: filePath, encoding: .utf8)
            let rewritten = rewriteContent(content, folderPath: folderPath)
            guard rewritten != content else { continue }
            try AtomicFileWriter.writeString(rewritten, toFile: filePath)
            modifiedFiles.append(filePath)
        }
        return modifiedFiles
    }

    private static func rewriteContent(_ content: String, folderPath: String) -> String {
        guard let normalizedFolder = normalizeFolderPath(folderPath) else {
            return content
        }

        let pattern = #"authsia://[^\s"'<>()]+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return content
        }

        let nsContent = content as NSString
        let matches = regex.matches(
            in: content,
            range: NSRange(location: 0, length: nsContent.length)
        )

        var rewritten = content
        for match in matches.reversed() {
            let uri = nsContent.substring(with: match.range)
            guard SecretReference.isSecretReference(uri),
                  (try? SecretReference.parse(uri)) != nil else {
                continue
            }

            let base = uri.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
                .first
                .map(String.init) ?? uri
            let replacement = "\(base)?folder=\(percentEncodeQueryValue(normalizedFolder))"
            guard let range = Range(match.range, in: rewritten) else { continue }
            rewritten.replaceSubrange(range, with: replacement)
        }

        return rewritten
    }

    private static func candidateFiles(in paths: [String], recursive: Bool) throws -> [String] {
        var files: [String] = []
        for rawPath in paths {
            let path = FilePathNormalizer.absoluteStandardizedPath(rawPath)
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else {
                continue
            }

            if isDirectory.boolValue {
                files.append(
                    contentsOf: FileScannerService.directoryCandidateFiles(
                        in: path,
                        recursive: recursive,
                        includeSSHKeyCandidates: false
                    )
                )
            } else {
                files.append(path)
            }
        }
        return Array(Set(files)).sorted()
    }

    private static func percentEncodeQueryValue(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: ":#[]@!$&'()*+,;=/?")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}
