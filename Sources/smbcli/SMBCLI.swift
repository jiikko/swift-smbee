import ArgumentParser
import Dispatch
import Foundation
import SMBee
#if os(Linux)
import Glibc
#else
import Darwin
#endif
// swiftlint:disable file_length

struct SMBCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smbcli",
        abstract: "🐝 SMBee command-line client",
        version: SMBee.version,
        subcommands: [
            Probe.self, Ping.self, Shares.self, List.self, Stat.self, Readlink.self, ACL.self, DiskFree.self, Cat.self, Get.self,
            MGet.self, MakeDirectory.self, Put.self, MPut.self, Copy.self, Move.self, Remove.self, Watch.self, Dfs.self,
            SetACL.self
        ]
    )
}

@main
enum SMBCLIMain {
    static func main() async {
        do {
            var command = try await SMBCLI.asyncParseAsRoot()
            if var asyncCommand = command as? AsyncParsableCommand {
                try await asyncCommand.run()
            } else {
                try command.run()
            }
        } catch {
            exit(with: error)
        }
    }

    private static func exit(with error: Error) -> Never {
        let parserExitCode = SMBCLI.exitCode(for: error)
        if parserExitCode.isSuccess {
            SMBCLI.exit(withError: error)
        }
        if parserExitCode == .validationFailure {
            printError(error)
            Foundation.exit(SMBCLIExitCode.usage)
        }
        if let smbError = error as? SMBError {
            printError(smbError)
            Foundation.exit(SMBCLIExitCode.code(for: smbError))
        }
        printError(error)
        Foundation.exit(SMBCLIExitCode.other)
    }

    private static func printError(_ error: Error) {
        if case let SMBError.recursiveOperationIncomplete(failures) = error {
            writeStandardError("Error: recursive operation incomplete\n")
            for failure in failures {
                writeStandardError("\(failure.path): \(failure.message)\n")
            }
            return
        }
        let stderr = FileHandle.standardError
        if let data = "Error: \(error)\n".data(using: .utf8) {
            stderr.write(data)
        }
    }
}

/// `smbcli probe smb://host[:445]` — NEGOTIATE して交渉結果
/// (dialect / signing / encryption) を表示する。最初のマイルストーン。
struct Probe: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Negotiate with an SMB server and print the negotiated dialect/signing/encryption"
    )

    @Argument(help: "smb://host[:445]")
    var url: String

    @Flag(help: "Print JSON output")
    var json = false

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let endpoint = try SMBURLParser.parseServerURL(url)
        let result = try await SMBProbe.probe(
            host: endpoint.host,
            port: endpoint.port,
            makeTransport: { POSIXSocketTransport(timeout: transport.duration) }
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: result))
            return
        }
        print("dialect: \(formatHex(result.dialect, width: 4))")
        print("signingRequired: \(result.signingRequired)")
        print("signing: \(formatOptionalHex(result.signingAlgorithm, width: 4))")
        print("cipher: \(formatOptionalHex(result.cipher, width: 4))")
        print("preauthHash: \(formatOptionalHex(result.preauthHashAlgorithm, width: 4))")
        print("serverGuid: \(result.serverGuid.uuidString)")
        print("maxTransactSize: \(result.maxTransactSize)")
        print("maxReadSize: \(result.maxReadSize)")
        print("maxWriteSize: \(result.maxWriteSize)")
    }

    private func formatOptionalHex(_ value: UInt16?, width: Int) -> String {
        guard let value else { return "none" }
        return formatHex(value, width: width)
    }

    private func formatHex<T: FixedWidthInteger>(_ value: T, width: Int) -> String {
        "0x" + String(format: "%0\(width)x", Int(value))
    }
}

struct List: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ls", abstract: "List an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let collector = DirectoryEntryCollector()
        try await SMBee.withDirectoryStream(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        ) { entry in
            if json {
                collector.append(entry)
                return
            }
            let kind = entry.isDirectory ? "d" : "-"
            print("\(kind) \(entry.fileSize) \(entry.name)")
        }
        if json {
            print(try SMBCLIOutput.jsonString(for: collector.entries))
        }
    }
}

struct Ping: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ping", abstract: "Send an authenticated SMB2 ECHO")

    @Argument(help: "smb://user@host[:445]/share")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await SMBee.echo(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            timeout: transport.duration
        )
        print("ok")
    }
}

final class DirectoryEntryCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBDirectoryEntry] = []

    var entries: [SMBDirectoryEntry] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ entry: SMBDirectoryEntry) {
        lock.lock()
        storage.append(entry)
        lock.unlock()
    }
}

struct Watch: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "watch", abstract: "Watch an SMB directory for changes")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Flag(help: "Watch the full subtree")
    var recursive = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print newline-delimited JSON events")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let task = Task {
            try await SMBee.withChangeNotifications(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                watchTree: recursive,
                timeout: transport.duration
            ) { event in
                if json {
                    print(try SMBCLIOutput.jsonString(for: event))
                    return
                }
                switch event {
                case .overflow:
                    print("overflow: rescan needed")
                case .changes(let changes):
                    for change in changes {
                        print("\(formatChangeAction(change.action)) \(change.name)")
                    }
                }
            }
        }
        let sigint = makeSIGINTSource {
            task.cancel()
        }
        sigint.resume()
        do {
            try await task.value
        } catch is CancellationError {
        }
        sigint.cancel()
    }

    private func formatChangeAction(_ action: SMBFileChangeAction) -> String {
        switch action {
        case .added: return "added"
        case .removed: return "removed"
        case .modified: return "modified"
        case .renamedOldName: return "renamed-old"
        case .renamedNewName: return "renamed-new"
        case .other(let raw): return "other(\(raw))"
        }
    }

    private func makeSIGINTSource(_ handler: @escaping @Sendable () -> Void) -> DispatchSourceSignal {
        signal(SIGINT, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        source.setEventHandler(handler: handler)
        return source
    }
}

struct Shares: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "shares", abstract: "List SMB shares on a server")

    @Argument(help: "smb://user@host[:445]")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let endpoint = try SMBURLParser.parseServerURL(url)
        let credential = try makeCredential(username: endpoint.username, password: nil, auth: auth)
        let shares = try await SMBee.listShares(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: shares))
            return
        }
        for share in shares {
            print(share.name)
        }
    }
}

struct Dfs: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "dfs", abstract: "Resolve DFS referral targets")

    @Argument(help: "smb://user@host[:445]/dfsroot/link")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let dfsPath = makeDfsPath(endpoint)
        let result = try await SMBee.dfsReferral(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            path: dfsPath,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: result))
            return
        }
        print("pathConsumed: \(result.pathConsumed)")
        print("headerFlags: \(SMBCLIOutput.hex(result.headerFlags, width: 8))")
        for referral in result.referrals {
            let target = referral.networkAddress ?? "(no network address)"
            print("\(target) ttl=\(referral.timeToLive) serverType=\(referral.serverType) flags=\(SMBCLIOutput.hex(referral.flags, width: 4))")
        }
    }

    private func makeDfsPath(_ endpoint: SMBURLParser.ReadURL) -> String {
        let suffix = endpoint.path.isEmpty ? endpoint.share : "\(endpoint.share)\\\(endpoint.path)"
        return "\\\\\(endpoint.host)\\\(suffix)"
    }
}

struct Stat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "stat", abstract: "Stat an SMB path")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let stat = try await SMBee.stat(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: stat))
            return
        }
        print("size: \(stat.size)")
        print("type: \(stat.isDirectory ? "directory" : "file")")
        print("attributes: 0x\(String(format: "%08x", stat.attributes))")
        if stat.isReparsePoint {
            if let reparseTag = stat.reparseTag {
                print("reparseTag: 0x\(String(format: "%08x", reparseTag))")
            }
            if let reparseKind = stat.reparseKind {
                print("reparseKind: \(reparseKind.description)")
            }
        }
        if let creationTime = stat.creationTime {
            print("ctime: \(formatDate(creationTime))")
        }
        if let lastAccessTime = stat.lastAccessTime {
            print("atime: \(formatDate(lastAccessTime))")
        }
        if let modifiedTime = stat.modifiedTime {
            print("mtime: \(formatDate(modifiedTime))")
        }
        if let changeTime = stat.changeTime {
            print("chtime: \(formatDate(changeTime))")
        }
    }
}

struct Readlink: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "readlink", abstract: "Read SMB reparse point target data")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let reparsePoint = try await SMBee.readlink(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: reparsePoint))
            return
        }
        print("tag: \(SMBCLIOutput.hex(reparsePoint.tag, width: 8))")
        print("kind: \(reparsePoint.kind.description)")
        if let substituteName = reparsePoint.substituteName {
            print("substituteName: \(substituteName)")
        }
        if let printName = reparsePoint.printName {
            print("printName: \(printName)")
        }
        if let flags = reparsePoint.flags {
            print("flags: \(SMBCLIOutput.hex(flags, width: 8))")
        }
    }
}

struct DiskFree: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "df", abstract: "Show SMB share filesystem usage")

    @Argument(help: "smb://user@host[:445]/share")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let info = try await SMBee.volumeInfo(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: info))
            return
        }
        print("total: \(formatByteCount(info.totalBytes)) (\(info.totalBytes))")
        print("used: \(formatByteCount(info.usedBytes)) (\(info.usedBytes))")
        print("available: \(formatByteCount(info.availableBytes)) (\(info.availableBytes))")
        print("label: \(info.volumeLabel)")
        print("filesystem: \(info.filesystemName)")
    }
}

struct ACL: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "acl", abstract: "Show SMB owner, group, and DACL information")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    @Flag(help: "Print JSON output")
    var json = false

    @Flag(help: "Resolve well-known SIDs to names")
    var resolveSids = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let info = try await SMBee.securityInfo(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
        if json {
            print(try SMBCLIOutput.jsonString(for: info, resolveSIDs: resolveSids))
            return
        }
        print("owner: \(formatSID(info.ownerSID))")
        print("group: \(formatSID(info.groupSID))")
        print("control: 0x\(String(format: "%04x", info.controlFlags))")
        guard let dacl = info.dacl else {
            print("dacl: null")
            return
        }
        print("dacl:")
        for ace in dacl {
            print("  type=\(ace.type) flags=0x\(String(format: "%02x", ace.flags)) mask=0x\(String(format: "%08x", ace.accessMask)) sid=\(formatSID(ace.trusteeSID))")
        }
    }

    private func formatSID(_ sid: String?) -> String {
        guard let sid else { return "none" }
        guard resolveSids, let name = SMBWellKnownSID.name(for: sid) else { return sid }
        return "\(sid) (\(name))"
    }
}

struct SetACL: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "setacl", abstract: "Replace an SMB file DACL")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(name: .long, parsing: .upToNextOption, help: "ACCESS_ALLOWED ACE as SID:MASK, repeatable")
    var allow: [String] = []

    @Option(name: .long, parsing: .upToNextOption, help: "ACCESS_DENIED ACE as SID:MASK, repeatable")
    var deny: [String] = []

    @Flag(help: "Allow empty or deny-only DACLs")
    var force = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let dacl = try allow.map { try parseACE($0, type: 0) } + deny.map { try parseACE($0, type: 1) }
        try await SMBee.setSecurityInfo(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            dacl: dacl,
            force: force,
            timeout: transport.duration
        )
    }

    private func parseACE(_ value: String, type: UInt8) throws -> SMBAccessControlEntry {
        let parts = value.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            throw ValidationError("ACE must be SID:MASK")
        }
        let maskText = parts[1].hasPrefix("0x") || parts[1].hasPrefix("0X") ? String(parts[1].dropFirst(2)) : parts[1]
        guard let mask = UInt32(maskText, radix: parts[1].hasPrefix("0x") || parts[1].hasPrefix("0X") ? 16 : 10) else {
            throw ValidationError("ACE mask must be decimal or 0x-prefixed hex")
        }
        return SMBAccessControlEntry(type: type, flags: 0, accessMask: mask, trusteeSID: parts[0])
    }
}

struct Cat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "cat", abstract: "Read an SMB file")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "Byte range a-b")
    var range: String?

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        // ファイル全体をメモリに lift せず streaming で stdout へ流す (大ファイル対応)。
        let stdout = FileHandle.standardOutput
        try await SMBee.withReadStream(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            range: try range.map(parseRange),
            timeout: transport.duration
        ) { chunk in
            stdout.write(Data(chunk))
        }
    }
}

struct Get: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "get", abstract: "Download an SMB file")

    @Argument(help: "smb://user@host[:445]/share/path")
    var source: String

    @Argument(help: "Local destination file")
    var destination: String

    @Flag(help: "Fail if the destination exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively download a directory")
    var recursive = false

    @Flag(help: "Continue recursive transfers after item failures")
    var continueOnError = false

    @Flag(help: "Skip recursive items whose destination already exists")
    var skipExisting = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @Flag(help: "Show transfer progress")
    var progress = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        if recursive {
            // ⓥ Directory transfer progress is not exposed by the facade yet.
            try await SMBee.downloadDirectory(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localDirectory: URL(fileURLWithPath: destination),
                overwrite: !noOverwrite,
                continueOnError: continueOnError,
                skipExisting: skipExisting,
                dryRun: dryRun,
                timeout: transport.duration
            ) { action in writeRecursiveAction(action) }
            return
        }
        let progressWriter = progress ? TransferProgressWriter() : nil
        let onProgress: (@Sendable (SMBTransferProgress) -> Void)?
        if let progressWriter {
            onProgress = { progress in progressWriter.emit(progress) }
        } else {
            onProgress = nil
        }
        try await SMBee.download(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            localFile: URL(fileURLWithPath: destination),
            overwrite: !noOverwrite,
            timeout: transport.duration,
            onProgress: onProgress
        )
        progressWriter?.finish()
    }
}

struct MakeDirectory: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mkdir", abstract: "Create an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await SMBee.makeDirectory(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
    }
}

struct Put: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "put", abstract: "Upload a local file to SMB")

    @Argument(help: "Local source file")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/path")
    var destination: String

    @Flag(help: "Fail if the destination exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively upload a directory")
    var recursive = false

    @Flag(help: "Continue recursive transfers after item failures")
    var continueOnError = false

    @Flag(help: "Skip recursive items whose destination already exists")
    var skipExisting = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @Flag(help: "Show transfer progress")
    var progress = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: destination, auth: auth)
        if recursive {
            // ⓥ Directory transfer progress is not exposed by the facade yet.
            try await SMBee.uploadDirectory(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localDirectory: URL(fileURLWithPath: source),
                overwrite: !noOverwrite,
                continueOnError: continueOnError,
                skipExisting: skipExisting,
                dryRun: dryRun,
                timeout: transport.duration
            ) { action in writeRecursiveAction(action) }
            return
        }
        if progress {
            let progressWriter = TransferProgressWriter()
            let data = try Data(contentsOf: URL(fileURLWithPath: source))
            try await SMBee.upload(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                data: [UInt8](data),
                overwrite: !noOverwrite,
                timeout: transport.duration,
                onProgress: { progress in progressWriter.emit(progress) }
            )
            progressWriter.finish()
            return
        }
        try await SMBee.upload(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            localFile: URL(fileURLWithPath: source),
            overwrite: !noOverwrite,
            timeout: transport.duration
        )
    }
}

struct Move: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mv", abstract: "Rename an SMB path within one share")

    @Argument(help: "smb://user@host[:445]/share/source")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/destination")
    var destination: String

    @Flag(help: "Replace destination if it exists")
    var replace = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (from, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        let to = try SMBURLParser.parseReadURL(destination)
        try validateSameShare(source: from, destination: to, commandName: "mv")
        try await SMBee.rename(
            host: from.host,
            port: from.port,
            credential: credential,
            share: from.share,
            fromPath: from.path,
            toPath: to.path,
            replaceIfExists: replace,
            timeout: transport.duration
        )
    }
}

struct Copy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "cp", abstract: "Copy an SMB path within one share")

    @Argument(help: "smb://user@host[:445]/share/source")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/destination")
    var destination: String

    @Flag(help: "Replace destination if it exists")
    var replace = false

    @Flag(name: .shortAndLong, help: "Recursively copy a directory")
    var recursive = false

    @Flag(help: "Continue recursive copies after item failures")
    var continueOnError = false

    @Flag(help: "Skip recursive items whose destination already exists")
    var skipExisting = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (from, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        let to = try SMBURLParser.parseReadURL(destination)
        try validateSameShare(source: from, destination: to, commandName: "cp")
        if recursive {
            try await SMBee.copyDirectory(
                host: from.host,
                port: from.port,
                credential: credential,
                share: from.share,
                fromPath: from.path,
                toPath: to.path,
                overwrite: replace,
                continueOnError: continueOnError,
                skipExisting: skipExisting,
                dryRun: dryRun,
                timeout: transport.duration
            ) { action in writeRecursiveAction(action) }
            return
        }
        try await SMBee.copy(
            host: from.host,
            port: from.port,
            credential: credential,
            share: from.share,
            fromPath: from.path,
            toPath: to.path,
            overwrite: replace,
            timeout: transport.duration
        )
    }
}

struct Remove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "rm", abstract: "Delete an SMB file or empty directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Flag(help: "Open the target as a directory")
    var directory = false

    @Flag(name: .shortAndLong, help: "Recursively delete a non-empty directory")
    var recursive = false

    @Flag(help: "Continue recursive deletes after item failures")
    var continueOnError = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await SMBee.delete(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            directory: directory || recursive,
            recursive: recursive,
            continueOnError: continueOnError,
            dryRun: dryRun,
            timeout: transport.duration
        ) { action in writeRecursiveAction(action) }
    }
}

struct TransportOptions: ParsableArguments {
    @Option(name: .long, help: "Socket I/O timeout in seconds (connect and each recv/send)")
    var timeout: Double?

    var duration: Duration? {
        guard let timeout else { return nil }
        let wholeSeconds = timeout.rounded(.towardZero)
        let fractionalSeconds = timeout - wholeSeconds
        return .seconds(Int64(wholeSeconds)) + .nanoseconds(Int64((fractionalSeconds * 1_000_000_000).rounded()))
    }
}

private final class TransferProgressWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var didEmit = false

    func emit(_ progress: SMBTransferProgress) {
        lock.lock()
        defer { lock.unlock() }
        didEmit = true
        writeStandardError("\r\(formatTransferProgress(progress))    ")
    }

    func finish() {
        lock.lock()
        defer { lock.unlock() }
        if didEmit {
            writeStandardError("\n")
        }
    }
}

struct AuthOptions: ParsableArguments {
    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    @Option(help: "NT hash as 32 hexadecimal characters")
    var ntHash: String?

    @Flag(help: "Read password from standard input")
    var passwordStdin = false

    @Flag(help: "Authenticate anonymously")
    var anonymous = false

    @Flag(help: "Alias for --anonymous")
    var guest = false

    var usesAnonymousAuthentication: Bool {
        anonymous || guest
    }
}

struct DebugOptions: ParsableArguments {
    @Flag(help: "Enable redacted SMB debug logging")
    var debug = false

    @Flag(help: "Dump raw SMB wire hex; implies --debug")
    var traceWire = false

    func apply() {
        if debug || traceWire {
            setenv("SMBEE_DEBUG", "1", 1)
        }
        if traceWire {
            setenv("SMBEE_TRACE_WIRE", "1", 1)
        }
    }
}

func makeReadEndpointAndCredential(url: String, auth: AuthOptions) throws -> (SMBURLParser.ReadURL, SMBCredential) {
    try makeEndpointAndCredential(url: url, auth: auth)
}

// mv / cp は同一 authenticated session / tree 内の操作なので、source と destination が
// 同じ user/host/port/share を指すことを要求する。Move/Copy で重複していた guard を集約し、
// 単体テスト可能な pure helper にした (挙動は従来どおり、不一致で ValidationError)。
func validateSameShare(
    source: SMBURLParser.ReadURL,
    destination: SMBURLParser.ReadURL,
    commandName: String
) throws {
    guard source.host == destination.host,
          source.port == destination.port,
          source.username == destination.username,
          source.share == destination.share
    else {
        throw ValidationError("\(commandName) source and destination must use the same user, host, port, and share")
    }
}

func makeEndpointAndCredential(url: String, auth: AuthOptions) throws -> (SMBURLParser.ReadURL, SMBCredential) {
    let endpoint = try SMBURLParser.parseReadURL(url)
    return (endpoint, try makeCredential(username: endpoint.username, password: endpoint.password, auth: auth))
}

func makeCredential(username: String?, password urlPassword: String?, auth: AuthOptions) throws -> SMBCredential {
    if auth.usesAnonymousAuthentication || username?.isEmpty != false {
        guard (!auth.usesAnonymousAuthentication || username?.isEmpty != false),
              urlPassword == nil,
              auth.ntHash == nil,
              !auth.passwordStdin,
              ProcessInfo.processInfo.environment["SMB_PASSWORD"] == nil,
              ProcessInfo.processInfo.environment["SMB_NT_HASH"] == nil
        else {
            throw ValidationError("Anonymous authentication cannot be combined with a username, password, or NT hash")
        }
        return .anonymous
    }
    guard let username else {
        throw ValidationError("SMB URL must include a username")
    }
    if let ntHash = try readNTHash(options: auth) {
        guard urlPassword == nil, !auth.passwordStdin, ProcessInfo.processInfo.environment["SMB_PASSWORD"] == nil else {
            throw ValidationError("Use either an NT hash or a password, not both")
        }
        return try SMBCredential(username: username, ntHash: ntHash, domain: auth.domain)
    }
    guard let password = try urlPassword ?? readPassword(options: auth) else {
        throw ValidationError("Set SMB_PASSWORD, SMB_NT_HASH, pass --password-stdin/--nt-hash, or include a password in the SMB URL")
    }
    return SMBCredential(username: username, password: password, domain: auth.domain)
}

private func readNTHash(options: AuthOptions) throws -> [UInt8]? {
    guard let value = options.ntHash ?? ProcessInfo.processInfo.environment["SMB_NT_HASH"] else {
        return nil
    }
    return try parseNTHash(value)
}

private func readPassword(options: AuthOptions) throws -> String? {
    if options.passwordStdin {
        guard let password = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) else {
            throw ValidationError("Password from stdin must be valid UTF-8")
        }
        return password.trimmingCharacters(in: CharacterSet(charactersIn: "\r\n"))
    }
    if let envPassword = ProcessInfo.processInfo.environment["SMB_PASSWORD"] {
        return envPassword
    }
    // 最終フォールバック: 対話端末でのみ echo を切ってパスワード入力を促す。
    // 自動化 (パイプ/CI) では stdin が TTY でないため発火せず、既存の
    // ValidationError 経路 (SMB_PASSWORD/--password-stdin 等の要求) を維持する。
    if isatty(STDIN_FILENO) != 0 {
        return try promptPasswordInteractively()
    }
    return nil
}

private func promptPasswordInteractively() throws -> String {
    // getpass は /dev/tty から echo 無効で読み、末尾改行を含めない。
    // Glibc/Darwin 双方で利用可能。
    guard let raw = getpass("SMB password: ") else {
        throw ValidationError("Failed to read password from the terminal")
    }
    return String(cString: raw)
}

func parseNTHash(_ value: String) throws -> [UInt8] {
    let hex = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard hex.count == 32 else {
        throw ValidationError("NT hash must be 32 hexadecimal characters")
    }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(16)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw ValidationError("NT hash must contain only hexadecimal characters")
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

func formatTransferProgress(_ progress: SMBTransferProgress) -> String {
    let transferred = formatByteCount(progress.bytesTransferred)
    let speed = "\(formatByteCount(UInt64(max(0, progress.bytesPerSecond))))/s"
    guard let totalBytes = progress.totalBytes else {
        return "transferred \(transferred) at \(speed)"
    }
    let percent: UInt64
    if totalBytes == 0 {
        percent = 100
    } else {
        percent = min(100, progress.bytesTransferred * 100 / totalBytes)
    }
    return "transferred \(transferred) / \(formatByteCount(totalBytes)) (\(percent)%) at \(speed)"
}

private func formatByteCount(_ bytes: UInt64) -> String {
    let units = ["B", "KiB", "MiB", "GiB"]
    var value = Double(bytes)
    var unitIndex = 0
    while value >= 1024, unitIndex < units.count - 1 {
        value /= 1024
        unitIndex += 1
    }
    if unitIndex == 0 {
        return "\(bytes) \(units[unitIndex])"
    }
    return String(format: "%.1f %@", value, units[unitIndex])
}

func writeStandardError(_ string: String) {
    FileHandle.standardError.write(Data(string.utf8))
}

func writeRecursiveAction(_ action: SMBRecursiveAction) {
    FileHandle.standardOutput.write(Data("\(action.kind.rawValue) \(action.path)\n".utf8))
}

func parseRange(_ value: String) throws -> SMBReadRange {
    let parts = value.split(separator: "-", omittingEmptySubsequences: false)
    guard parts.count == 2,
          let start = UInt64(parts[0]),
          let end = UInt64(parts[1]),
          end >= start else {
        throw ValidationError("Range must be in a-b form with b >= a")
    }
    return SMBReadRange(offset: start, length: end - start + 1)
}

private func formatDate(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}
