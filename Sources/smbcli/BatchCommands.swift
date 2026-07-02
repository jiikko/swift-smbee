import ArgumentParser
import Foundation
import SMBee
#if os(Linux)
import Glibc
#else
import Darwin
#endif

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

    @Flag(help: "Skip files whose local destination already exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively match files below the remote directory")
    var recursive = false

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
            let files: [RemoteBatchFile]
            if recursive {
                files = try await remoteRecursiveBatchGlobEntries(endpoint: endpoint, credential: credential, include: pattern, exclude: exclude, timeout: transport.duration)
            } else {
                let entries = try await remoteDirectoryEntries(endpoint: endpoint, credential: credential, timeout: transport.duration)
                files = batchGlobEntries(entries, include: pattern, exclude: exclude).map {
                    RemoteBatchFile(name: $0.name, relativePath: $0.name)
                }
            }
            if files.isEmpty {
                writeStandardError("Warning: no files matched \(pattern)\n")
                return
            }

            try await download(files: files, endpoint: endpoint, credential: credential)
        }
    }

    private func download(files: [RemoteBatchFile], endpoint: SMBURLParser.ReadURL, credential: SMBCredential) async throws {
        var transferred = 0
        var skipped = 0
        for file in files {
            let remotePath = try SMBPath.join(endpoint.path, file.relativePath)
            let localFile = URL(fileURLWithPath: localDirectory).appendingPathComponent(file.relativePath)
            if noOverwrite, FileManager.default.fileExists(atPath: localFile.path) {
                skipped += 1
                print("skip \(file.relativePath) (exists)")
                continue
            }
            if dryRun {
                print("download \(remotePath) -> \(localFile.path)")
                continue
            }
            try FileManager.default.createDirectory(at: localFile.deletingLastPathComponent(), withIntermediateDirectories: true)
            try await SMBee.download(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: remotePath,
                localFile: localFile,
                overwrite: !noOverwrite,
                timeout: transport.duration
            )
            transferred += 1
        }
        let count = dryRun ? files.count - skipped : transferred
        printBatchSummary(action: dryRun ? "planned" : "downloaded", count: count, skipped: skipped)
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

    @Flag(help: "Skip files whose remote destination already exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively match files below the local directory")
    var recursive = false

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
            let remoteExisting = try await remoteExistingFileNames(endpoint: endpoint, credential: credential)
            try await upload(files: files, endpoint: endpoint, credential: credential, remoteExisting: remoteExisting)
        }
    }

    private func remoteExistingFileNames(endpoint: SMBURLParser.ReadURL, credential: SMBCredential) async throws -> Set<String> {
        guard noOverwrite else { return [] }
        let entries = try await remoteDirectoryEntries(endpoint: endpoint, credential: credential, timeout: transport.duration)
        return Set(entries.filter { !$0.isDirectory }.map(\.name))
    }

    private func upload(
        files: [LocalBatchFile],
        endpoint: SMBURLParser.ReadURL,
        credential: SMBCredential,
        remoteExisting: Set<String>
    ) async throws {
        var transferred = 0
        var skipped = 0
        for file in files {
            let remotePath = try SMBPath.join(endpoint.path, file.name)
            let exists: Bool
            if recursive {
                exists = try await remotePathExists(endpoint: endpoint, credential: credential, path: remotePath)
            } else {
                exists = remoteExisting.contains(file.name)
            }
            if noOverwrite, exists {
                skipped += 1
                print("skip \(file.name) (exists)")
                continue
            }
            if dryRun {
                print("upload \(file.url.path) -> \(remotePath)")
                continue
            }
            try await makeRemoteParentDirectories(endpoint: endpoint, credential: credential, remotePath: remotePath)
            try await SMBee.upload(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: remotePath,
                localFile: file.url,
                overwrite: !noOverwrite,
                timeout: transport.duration
            )
            transferred += 1
        }
        let count = dryRun ? files.count - skipped : transferred
        printBatchSummary(action: dryRun ? "planned" : "uploaded", count: count, skipped: skipped)
    }

    private func makeRemoteParentDirectories(endpoint: SMBURLParser.ReadURL, credential: SMBCredential, remotePath: String) async throws {
        let components = remotePath.split(separator: "\\").map(String.init)
        guard components.count > 1 else { return }
        var current = ""
        for component in components.dropLast() {
            current = try SMBPath.join(current, component)
            do {
                try await SMBee.makeDirectory(
                    host: endpoint.host,
                    port: endpoint.port,
                    credential: credential,
                    share: endpoint.share,
                    path: current,
                    timeout: transport.duration
                )
            } catch SMBError.nameCollision {
            }
        }
    }

    private func remotePathExists(endpoint: SMBURLParser.ReadURL, credential: SMBCredential, path: String) async throws -> Bool {
        guard noOverwrite else { return false }
        do {
            _ = try await SMBee.stat(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: path,
                timeout: transport.duration
            )
            return true
        } catch SMBError.notFound {
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
        includingPropertiesForKeys: [.isRegularFileKey],
        options: [.skipsHiddenFiles]
    ) else {
        return []
    }

    var files: [LocalBatchFile] = []
    for case let url as URL in enumerator {
        let standardizedURL = url.standardizedFileURL
        let values = try standardizedURL.resourceValues(forKeys: [.isRegularFileKey])
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

private func printBatchSummary(action: String, count: Int, skipped: Int) {
    if skipped == 0 {
        print("\(action): \(count)")
    } else {
        print("\(action): \(count), skipped: \(skipped)")
    }
}
