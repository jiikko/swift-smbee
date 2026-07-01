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
        discussion: "Quote glob patterns so the shell does not expand them. Recursive transfers are not supported yet."
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
        let entries = try await remoteDirectoryEntries(endpoint: endpoint, credential: credential, timeout: transport.duration)
        let files = batchGlobEntries(entries, include: pattern, exclude: exclude)
        if files.isEmpty {
            writeStandardError("Warning: no files matched \(pattern)\n")
            return
        }

        try await download(files: files, endpoint: endpoint, credential: credential)
    }

    private func download(files: [SMBDirectoryEntry], endpoint: SMBURLParser.ReadURL, credential: SMBCredential) async throws {
        var transferred = 0
        var skipped = 0
        for file in files {
            let remotePath = try SMBPath.join(endpoint.path, file.name)
            let localFile = URL(fileURLWithPath: localDirectory).appendingPathComponent(file.name)
            if noOverwrite, FileManager.default.fileExists(atPath: localFile.path) {
                skipped += 1
                print("skip \(file.name) (exists)")
                continue
            }
            if dryRun {
                print("download \(remotePath) -> \(localFile.path)")
                continue
            }
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
        discussion: "Quote glob patterns so the shell does not expand them. Recursive transfers are not supported yet."
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

        let files = try localBatchGlobEntries(directory: localDirectory, include: pattern, exclude: exclude)
        if files.isEmpty {
            writeStandardError("Warning: no files matched \(pattern)\n")
            return
        }

        let (endpoint, credential) = try makeEndpointAndCredential(url: remoteDirectory, auth: auth)
        let remoteExisting = try await remoteExistingFileNames(endpoint: endpoint, credential: credential)
        try await upload(files: files, endpoint: endpoint, credential: credential, remoteExisting: remoteExisting)
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
            if noOverwrite, remoteExisting.contains(file.name) {
                skipped += 1
                print("skip \(file.name) (exists)")
                continue
            }
            if dryRun {
                print("upload \(file.url.path) -> \(remotePath)")
                continue
            }
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

private func remoteDirectoryEntries(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    timeout: Duration?
) async throws -> [SMBDirectoryEntry] {
    let collector = DirectoryEntryCollector()
    try await SMBee.withDirectoryStream(
        host: endpoint.host,
        port: endpoint.port,
        credential: credential,
        share: endpoint.share,
        path: endpoint.path,
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
