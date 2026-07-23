import ArgumentParser
import Foundation
import SMBee
#if os(Linux)
import Glibc
#else
import Darwin
#endif

func withBatchSession<T: Sendable>(
    _ session: SMBClientSession,
    operation: @Sendable () async throws -> T
) async throws -> T {
    do {
        let result = try await operation()
        await session.close()
        return result
    } catch {
        await session.close()
        throw error
    }
}

struct MGet: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mget",
        abstract: "Download files matching a glob from one SMB directory",
        discussion: "Quote glob patterns so the shell does not expand them."
    )

    @Argument(help: "smb://user@host[:445]/share/directory")
    var remoteDirectory: String

    @Argument(help: "File glob pattern, for example '*.log'")
    var pattern: String

    @Argument(help: "Existing local destination directory")
    var localDirectory: String

    @Option(name: .long, help: "Exclude files matching this glob. Repeatable.")
    var exclude: [String] = []

    @Flag(help: "Print planned transfers without downloading")
    var dryRun = false

    @Flag(help: "Output newline-delimited JSON actions and a final summary")
    var json = false

    @Flag(help: "Skip files whose local destination already exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively match files below the remote directory")
    var recursive = false

    @Flag(help: "Show per-file transfer progress")
    var progress = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: localDirectory, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ValidationError("Local destination directory does not exist: \(localDirectory)")
        }

        let (endpoint, credential) = try makeReadEndpointAndCredential(url: remoteDirectory, auth: auth)
        try await transport.withOperationDeadline {
            let session = try await SMBClient.connect(host: endpoint.host, port: endpoint.port, share: endpoint.share, credential: credential, timeout: transport.duration)
            try await withBatchSession(session) {
                let files: [RemoteBatchFile]
                if recursive {
                    files = try await remoteRecursiveBatchGlobEntries(session: session, rootPath: endpoint.path, include: pattern, exclude: exclude)
                } else {
                    let entries = try await remoteDirectoryEntries(session: session, path: endpoint.path)
                    for entry in entries { try validateRemoteEntryName(entry.name) }
                    files = batchGlobEntries(entries, include: pattern, exclude: exclude).map {
                        RemoteBatchFile(name: $0.name, relativePath: $0.name)
                    }
                }
                if files.isEmpty {
                    writeStandardError("Warning: no files matched \(pattern)\n")
                    return
                }

                try await download(files: files, endpoint: endpoint, credential: credential, session: session)
            }
        }
    }

    private func download(files: [RemoteBatchFile], endpoint: SMBURLParser.ReadURL, credential: SMBCredential, session: SMBClientSession) async throws {
        var transferred = 0
        var skipped = 0
        for file in files {
            let remotePath = try SMBPath.join(endpoint.path, file.relativePath)
            let localFile = URL(fileURLWithPath: localDirectory).appendingPathComponent(file.relativePath)
            if noOverwrite, FileManager.default.fileExists(atPath: localFile.path) {
                skipped += 1
                writeBatchAction(
                    kind: .skip,
                    source: remotePath,
                    destination: localFile.path,
                    json: json
                )
                continue
            }
            if dryRun {
                writeBatchAction(
                    kind: .download,
                    source: remotePath,
                    destination: localFile.path,
                    json: json
                )
                continue
            }
            try FileManager.default.createDirectory(at: localFile.deletingLastPathComponent(), withIntermediateDirectories: true)
            let progressWriter = progress ? TransferProgressWriter() : nil
            var onProgress: (@Sendable (SMBTransferProgress) -> Void)?
            if let progressWriter {
                onProgress = { progressWriter.emit($0) }
            }
            if progressWriter != nil {
                writeStandardError("\(file.relativePath)\n")
            }
            try await session.download(path: remotePath, localFile: localFile, overwrite: !noOverwrite, onProgress: onProgress)
            progressWriter?.finish()
            transferred += 1
            writeBatchAction(kind: .download, source: remotePath, destination: localFile.path, json: json)
        }
        let count = dryRun ? files.count - skipped : transferred
        writeBatchSummary(command: "mget", action: dryRun ? "planned" : "downloaded", count: count, skipped: skipped, dryRun: dryRun, json: json)
    }
}

struct MPut: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mput",
        abstract: "Upload files matching a glob from one local directory",
        discussion: "Quote glob patterns so the shell does not expand them."
    )

    @Argument(help: "Local source directory")
    var localDirectory: String

    @Argument(help: "File glob pattern, for example '*.log'")
    var pattern: String

    @Argument(help: "smb://user@host[:445]/share/directory")
    var remoteDirectory: String

    @Option(name: .long, help: "Exclude files matching this glob. Repeatable.")
    var exclude: [String] = []

    @Flag(help: "Print planned transfers without uploading")
    var dryRun = false

    @Flag(help: "Output newline-delimited JSON actions and a final summary")
    var json = false

    @Flag(help: "Skip files whose remote destination already exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively match files below the local directory")
    var recursive = false

    @Flag(help: "Show per-file transfer progress")
    var progress = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: localDirectory, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ValidationError("Local source directory does not exist: \(localDirectory)")
        }

        let files = recursive
            ? try localRecursiveBatchGlobEntries(directory: localDirectory, include: pattern, exclude: exclude)
            : try localBatchGlobEntries(directory: localDirectory, include: pattern, exclude: exclude)
        if files.isEmpty {
            writeStandardError("Warning: no files matched \(pattern)\n")
            return
        }

        let (endpoint, credential) = try makeEndpointAndCredential(url: remoteDirectory, auth: auth)
        try await transport.withOperationDeadline {
            let session = try await SMBClient.connect(host: endpoint.host, port: endpoint.port, share: endpoint.share, credential: credential, timeout: transport.duration)
            try await withBatchSession(session) {
                let remoteExisting = try await remoteExistingFileNames(session: session, path: endpoint.path)
                try await upload(files: files, endpoint: endpoint, credential: credential, remoteExisting: remoteExisting, session: session)
            }
        }
    }

    private func remoteExistingFileNames(session: SMBClientSession, path: String) async throws -> Set<String> {
        guard noOverwrite else { return [] }
        let entries = try await remoteDirectoryEntries(session: session, path: path)
        return Set(entries.filter { !$0.isDirectory }.map(\.name))
    }

    private func upload(
        files: [LocalBatchFile],
        endpoint: SMBURLParser.ReadURL,
        credential: SMBCredential,
        remoteExisting: Set<String>,
        session: SMBClientSession
    ) async throws {
        var transferred = 0
        var skipped = 0
        for file in files {
            let remotePath = try SMBPath.join(endpoint.path, file.name)
            let exists: Bool
            if recursive {
                exists = await sessionPathExists(session: session, path: remotePath)
            } else {
                exists = remoteExisting.contains(file.name)
            }
            if noOverwrite, exists {
                skipped += 1
                writeBatchAction(
                    kind: .skip,
                    source: file.url.path,
                    destination: remotePath,
                    json: json
                )
                continue
            }
            if dryRun {
                writeBatchAction(
                    kind: .upload,
                    source: file.url.path,
                    destination: remotePath,
                    json: json
                )
                continue
            }
            try await makeRemoteParentDirectories(session: session, remotePath: remotePath)
            let progressWriter = progress ? TransferProgressWriter() : nil
            var onProgress: (@Sendable (SMBTransferProgress) -> Void)?
            if let progressWriter {
                onProgress = { progressWriter.emit($0) }
            }
            if progressWriter != nil {
                writeStandardError("\(file.name)\n")
            }
            try await session.upload(path: remotePath, fileURL: file.url, overwrite: !noOverwrite, onProgress: onProgress)
            progressWriter?.finish()
            transferred += 1
            writeBatchAction(kind: .upload, source: file.url.path, destination: remotePath, json: json)
        }
        let count = dryRun ? files.count - skipped : transferred
        writeBatchSummary(command: "mput", action: dryRun ? "planned" : "uploaded", count: count, skipped: skipped, dryRun: dryRun, json: json)
    }

    private func makeRemoteParentDirectories(session: SMBClientSession, remotePath: String) async throws {
        let components = remotePath.split(separator: "\\").map(String.init)
        guard components.count > 1 else { return }
        var current = ""
        for component in components.dropLast() {
            current = try SMBPath.join(current, component)
            do {
                try await session.makeDirectory(path: current)
            } catch SMBError.nameCollision {
            }
        }
    }

    private func sessionPathExists(session: SMBClientSession, path: String) async -> Bool {
        do {
            _ = try await session.stat(path: path)
            return true
        } catch {
            return false
        }
    }
}

func globMatches(_ pattern: String, _ name: String) -> Bool {
    fnmatch(pattern, name, 0) == 0
}

func isExcludedByGlob(_ name: String, exclude patterns: [String]) -> Bool {
    patterns.contains { globMatches($0, name) }
}

func batchGlobEntries(_ entries: [SMBDirectoryEntry], include pattern: String, exclude: [String]) -> [SMBDirectoryEntry] {
    entries
        .filter { !$0.isDirectory }
        .filter { globMatches(pattern, $0.name) }
        .filter { !isExcludedByGlob($0.name, exclude: exclude) }
        .sorted { $0.name < $1.name }
}

struct LocalBatchFile: Equatable {
    var name: String
    var url: URL
}

struct RemoteBatchFile: Equatable {
    var name: String
    var relativePath: String
}

func localBatchGlobEntries(directory: String, include pattern: String, exclude: [String]) throws -> [LocalBatchFile] {
    let directoryURL = URL(fileURLWithPath: directory)
    return try FileManager.default.contentsOfDirectory(atPath: directory)
        .filter { globMatches(pattern, $0) }
        .filter { !isExcludedByGlob($0, exclude: exclude) }
        .compactMap { name in
            let url = directoryURL.appendingPathComponent(name)
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
                return nil
            }
            return LocalBatchFile(name: name, url: url)
        }
        .sorted { $0.name < $1.name }
}

func localRecursiveBatchGlobEntries(directory: String, include pattern: String, exclude: [String]) throws -> [LocalBatchFile] {
    let rootURL = URL(fileURLWithPath: directory).standardizedFileURL
    let fileManager = FileManager.default
    guard let enumerator = fileManager.enumerator(
        at: rootURL,
        includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
        options: [.skipsHiddenFiles]
    ) else {
        return []
    }

    var files: [LocalBatchFile] = []
    for case let url as URL in enumerator {
        let standardizedURL = url.standardizedFileURL
        let values = try standardizedURL.resourceValues(forKeys: [.isRegularFileKey])
        if (try? standardizedURL.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
            continue
        }
        guard values.isRegularFile == true else { continue }
        let relativePath = String(standardizedURL.path.dropFirst(rootURL.path.count + 1))
        let normalizedRelativePath = relativePath.replacingOccurrences(of: "/", with: "\\")
        guard globMatches(pattern, url.lastPathComponent),
              !isExcludedByGlob(url.lastPathComponent, exclude: exclude),
              !isExcludedByGlob(normalizedRelativePath, exclude: exclude)
        else {
            continue
        }
        files.append(LocalBatchFile(name: normalizedRelativePath, url: standardizedURL))
    }
    return files.sorted { $0.name < $1.name }
}

private func remoteRecursiveBatchGlobEntries(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    include pattern: String,
    exclude: [String],
    timeout: Duration?
) async throws -> [RemoteBatchFile] {
    var files: [RemoteBatchFile] = []
    try await appendRemoteRecursiveBatchGlobEntries(
        endpoint: endpoint,
        credential: credential,
        relativeDirectory: "",
        include: pattern,
        exclude: exclude,
        timeout: timeout,
        files: &files
    )
    return files.sorted { $0.relativePath < $1.relativePath }
}

private func remoteRecursiveBatchGlobEntries(
    session: SMBClientSession,
    rootPath: String,
    include pattern: String,
    exclude: [String]
) async throws -> [RemoteBatchFile] {
    var files: [RemoteBatchFile] = []
    try await appendRemoteRecursiveBatchGlobEntries(
        session: session, rootPath: rootPath, relativeDirectory: "",
        include: pattern, exclude: exclude, files: &files
    )
    return files.sorted { $0.relativePath < $1.relativePath }
}

private func appendRemoteRecursiveBatchGlobEntries(
    session: SMBClientSession,
    rootPath: String,
    relativeDirectory: String,
    include pattern: String,
    exclude: [String],
    files: inout [RemoteBatchFile]
) async throws {
    let directoryPath = relativeDirectory.isEmpty ? rootPath : try SMBPath.join(rootPath, relativeDirectory)
    let entries = try await remoteDirectoryEntries(session: session, path: directoryPath)
    for entry in entries {
        try validateRemoteEntryName(entry.name)
        let relativePath = relativeDirectory.isEmpty ? entry.name : try SMBPath.join(relativeDirectory, entry.name)
        if entry.isDirectory {
            try await appendRemoteRecursiveBatchGlobEntries(
                session: session, rootPath: rootPath, relativeDirectory: relativePath,
                include: pattern, exclude: exclude, files: &files
            )
        } else if globMatches(pattern, entry.name),
                  !isExcludedByGlob(entry.name, exclude: exclude),
                  !isExcludedByGlob(relativePath, exclude: exclude) {
            files.append(RemoteBatchFile(name: entry.name, relativePath: relativePath))
        }
    }
}

private func validateRemoteEntryName(_ name: String) throws {
    guard !name.isEmpty, name != ".", name != "..",
          !name.contains("/"), !name.contains("\\"),
          !name.unicodeScalars.contains(where: { $0.value == 0 }) else {
        throw SMBError.protocolError("invalid remote directory entry name")
    }
}

private func appendRemoteRecursiveBatchGlobEntries(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    relativeDirectory: String,
    include pattern: String,
    exclude: [String],
    timeout: Duration?,
    files: inout [RemoteBatchFile]
) async throws {
    let directoryPath = relativeDirectory.isEmpty ? endpoint.path : try SMBPath.join(endpoint.path, relativeDirectory)
    let entries = try await remoteDirectoryEntries(endpoint: endpoint, credential: credential, path: directoryPath, timeout: timeout)
    for entry in entries {
        let relativePath = relativeDirectory.isEmpty ? entry.name : try SMBPath.join(relativeDirectory, entry.name)
        if entry.isDirectory {
            try await appendRemoteRecursiveBatchGlobEntries(
                endpoint: endpoint,
                credential: credential,
                relativeDirectory: relativePath,
                include: pattern,
                exclude: exclude,
                timeout: timeout,
                files: &files
            )
            continue
        }
        guard globMatches(pattern, entry.name),
              !isExcludedByGlob(entry.name, exclude: exclude),
              !isExcludedByGlob(relativePath, exclude: exclude)
        else {
            continue
        }
        files.append(RemoteBatchFile(name: entry.name, relativePath: relativePath))
    }
}

private func remoteDirectoryEntries(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    path: String? = nil,
    timeout: Duration?
) async throws -> [SMBDirectoryEntry] {
    let collector = DirectoryEntryCollector()
    try await SMBee.withDirectoryStream(
        host: endpoint.host,
        port: endpoint.port,
        credential: credential,
        share: endpoint.share,
        path: path ?? endpoint.path,
        timeout: timeout
    ) { entry in
        collector.append(entry)
    }
    return collector.entries
}

private func remoteDirectoryEntries(session: SMBClientSession, path: String) async throws -> [SMBDirectoryEntry] {
    let collector = DirectoryEntryCollector()
    try await session.withDirectoryStream(path: path) { entry in
        collector.append(entry)
    }
    return collector.entries
}

enum BatchActionKind: String, Encodable {
    case download
    case upload
    case skip
}

private struct BatchActionOutput: Encodable {
    let action: BatchActionKind
    let source: String
    let destination: String
}

private struct BatchSummaryOutput: Encodable {
    let command: String
    let action: String
    let count: Int
    let skipped: Int
    let dryRun: Bool
    let ok = true
}

func batchActionLine(kind: BatchActionKind, source: String, destination: String, json: Bool) -> String {
    guard json else {
        return "\(kind.rawValue) \(source) -> \(destination)"
    }
    guard let data = try? JSONEncoder().encode(BatchActionOutput(action: kind, source: source, destination: destination)),
          let result = String(bytes: data, encoding: .utf8) else {
        return "{\"ok\":false,\"error\":\"failed to encode batch action\"}"
    }
    return result
}

func batchSummaryLine(command: String, action: String, count: Int, skipped: Int, dryRun: Bool, json: Bool) -> String {
    guard json else {
        if skipped == 0 {
            return "\(action): \(count)"
        }
        return "\(action): \(count), skipped: \(skipped)"
    }
    guard let data = try? JSONEncoder().encode(BatchSummaryOutput(command: command, action: action, count: count, skipped: skipped, dryRun: dryRun)),
          let result = String(bytes: data, encoding: .utf8) else {
        return "{\"ok\":false,\"error\":\"failed to encode batch summary\"}"
    }
    return result
}

private func writeBatchAction(kind: BatchActionKind, source: String, destination: String, json: Bool) {
    print(batchActionLine(kind: kind, source: source, destination: destination, json: json))
}

private func writeBatchSummary(command: String, action: String, count: Int, skipped: Int, dryRun: Bool, json: Bool) {
    print(batchSummaryLine(command: command, action: action, count: count, skipped: skipped, dryRun: dryRun, json: json))
}
