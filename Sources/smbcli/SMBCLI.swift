import ArgumentParser
import Dispatch
import Foundation
import SMBee
#if os(Linux)
import Glibc
#else
import Darwin
#endif
struct SMBCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smbcli",
        abstract: "🐝 SMBee command-line client",
        version: SMBee.version,
        subcommands: [
            Probe.self, Ping.self, Shares.self, List.self, Stat.self, Readlink.self, ACL.self, DiskFree.self, Cat.self, Get.self,
            MGet.self, MakeDirectory.self, Put.self, MPut.self, Copy.self, Move.self, Remove.self, Watch.self, Dfs.self,
            SetACL.self, Sparse.self, ByteRangeLock.self
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
        if CommandLine.arguments.contains("--json") {
            writeStandardError((try? errorJSONString(error)) ?? "{\"ok\":false,\"error\":\"failed to encode error\"}")
            writeStandardError("\n")
            return
        }
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
        let result = try await transport.withOperationDeadline {
            try await SMBProbe.probe(
                host: endpoint.host,
                port: endpoint.port,
                makeTransport: { POSIXSocketTransport(timeout: transport.duration) }
            )
        }
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
        try await transport.withOperationDeadline {
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
        try await transport.withOperationDeadline {
            try await SMBee.echo(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                timeout: transport.duration
            )
        }
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

    @Flag(help: "Reconnect and resubscribe if the connection drops (emits an overflow after each reconnect)")
    var reconnect = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let json = json
        let recursive = recursive
        let emit: @Sendable (SMBChangeNotifyEvent) throws -> Void = { event in
            if json {
                print(try SMBCLIOutput.jsonString(for: event))
            } else {
                switch event {
                case .overflow:
                    print("overflow: rescan needed")
                case .changes(let changes):
                    for change in changes {
                        print("\(formatChangeAction(change.action)) \(change.name)")
                    }
                }
            }
            // stdout is fully buffered when redirected to a file/pipe (e.g. `watch --json > out.jsonl`),
            // so streamed events would not surface until the process exits. Flush after each event.
            // fflush(nil) flushes all open output streams and avoids referencing the mutable global
            // `stdout` (which is not Sendable under Swift 6 strict concurrency on Linux/Glibc).
            fflush(nil)
        }
        let task = Task {
            if reconnect {
                // Reconnect/resubscribe requires the persistent session that carries the
                // connection parameters; the one-shot facade cannot rebuild a dropped link.
                let session = try await SMBee.connect(
                    host: endpoint.host,
                    port: endpoint.port,
                    credential: credential,
                    share: endpoint.share,
                    timeout: transport.duration
                )
                do {
                    try await session.withChangeNotifications(
                        path: endpoint.path,
                        watchTree: recursive,
                        autoReconnect: true
                    ) { event in try emit(event) }
                    await session.close()
                } catch {
                    await session.close()
                    throw error
                }
                return
            }
            try await transport.withOperationDeadline {
                try await SMBee.withChangeNotifications(
                    host: endpoint.host,
                    port: endpoint.port,
                    credential: credential,
                    share: endpoint.share,
                    path: endpoint.path,
                    watchTree: recursive,
                    timeout: transport.duration
                ) { event in try emit(event) }
            }
        }
        let sigint = makeSIGINTSource {
            task.cancel()
        }
        sigint.resume()
        defer {
            task.cancel()
            sigint.cancel()
        }
        do {
            try await task.value
        } catch is CancellationError {
        }
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
        let shares = try await transport.withOperationDeadline {
            try await SMBee.listShares(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                timeout: transport.duration
            )
        }
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
        let result = try await transport.withOperationDeadline {
            try await SMBee.dfsReferral(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                path: dfsPath,
                timeout: transport.duration
            )
        }
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
        let stat = try await transport.withOperationDeadline {
            try await SMBee.stat(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                timeout: transport.duration
            )
        }
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
        let reparsePoint = try await transport.withOperationDeadline {
            try await SMBee.readlink(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                timeout: transport.duration
            )
        }
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
        let info = try await transport.withOperationDeadline {
            try await SMBee.volumeInfo(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                timeout: transport.duration
            )
        }
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

struct Sparse: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sparse",
        abstract: "Mark a file sparse, punch a hole, or query allocated ranges"
    )

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Flag(help: "Mark the file as sparse (FSCTL_SET_SPARSE) before other actions")
    var setSparse = false

    @Option(help: "Punch a hole: byte offset to start zeroing (requires --length)")
    var zeroOffset: UInt64?

    @Option(help: "Punch a hole: number of bytes to zero from --zero-offset")
    var length: UInt64?

    @Flag(help: "Print the allocated (non-hole) ranges after any changes")
    var query = false

    @Flag(help: "Print JSON output")
    var json = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        if (zeroOffset == nil) != (length == nil), !query {
            throw ValidationError("--zero-offset and --length must be used together")
        }
        guard setSparse || zeroOffset != nil || query else {
            throw ValidationError("sparse requires --set-sparse, --zero-offset/--length, or --query")
        }
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        try await transport.withOperationDeadline {
            let session = try await SMBee.connect(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                timeout: transport.duration
            )
            do {
                if setSparse {
                    try await session.setSparse(path: endpoint.path)
                }
                if let zeroOffset, let length {
                    try await session.zeroRange(path: endpoint.path, offset: zeroOffset, length: length)
                }
                if query {
                    let stat = try await session.stat(path: endpoint.path)
                    let ranges = try await session.allocatedRanges(path: endpoint.path, length: stat.size)
                    if json {
                        print(try sparseRangesJSONString(ranges))
                    } else {
                        for range in ranges {
                            print("offset=\(range.offset) length=\(range.length)")
                        }
                    }
                } else if json {
                    print(try successJSONString(command: "sparse", path: endpoint.path))
                }
                await session.close()
            } catch {
                await session.close()
                throw error
            }
        }
    }
}

struct ByteRangeLock: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "lock",
        abstract: "Acquire and release an SMB byte-range lock"
    )

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "Byte offset")
    var offset: UInt64

    @Option(help: "Number of bytes to lock")
    var length: UInt64

    @Flag(help: "Use a shared (read) lock")
    var shared = false

    @Flag(help: "Wait for the lock instead of failing immediately")
    var wait = false

    @Option(help: "Hold the lock for this many seconds before releasing it")
    var holdSeconds: Double?

    @Flag(help: "Print JSON success output")
    var json = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    static func validateOptions(length: UInt64, holdSeconds: Double?) throws {
        guard length > 0 else { throw ValidationError("--length must be greater than zero") }
        if let holdSeconds, !holdSeconds.isFinite || holdSeconds < 0 || holdSeconds > 7 * 24 * 60 * 60 {
            throw ValidationError("--hold-seconds must be finite, non-negative, and at most 7 days")
        }
    }

    func run() async throws {
        debug.apply()
        try Self.validateOptions(length: length, holdSeconds: holdSeconds)
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await transport.withOperationDeadline {
            let session = try await SMBee.connect(
                host: endpoint.host, port: endpoint.port, credential: credential,
                share: endpoint.share, timeout: transport.duration
            )
            do {
                _ = try await session.withFileLock(
                    path: endpoint.path, offset: offset, length: length,
                    shared: shared, failImmediately: !wait
                ) {
                    if let holdSeconds, holdSeconds > 0 {
                        try await Task.sleep(for: .milliseconds(Int64((holdSeconds * 1000).rounded())))
                    }
                }
                await session.close()
            } catch {
                await session.close()
                throw error
            }
        }
        if json { print(try successJSONString(command: "lock", path: endpoint.path)) }
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

    @Flag(help: "Resolve SIDs to names (well-known table + LSARPC lookup)")
    var resolveSids = false

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let info = try await transport.withOperationDeadline {
            try await SMBee.securityInfo(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                timeout: transport.duration
            )
        }
        let resolvedNames = resolveSids
            ? await lookupUnknownSIDs(info: info, endpoint: endpoint, credential: credential)
            : [:]
        if json {
            print(try SMBCLIOutput.jsonString(for: info, resolveSIDs: resolveSids, resolvedNames: resolvedNames))
            return
        }
        print("owner: \(formatSID(info.ownerSID, resolvedNames: resolvedNames))")
        print("group: \(formatSID(info.groupSID, resolvedNames: resolvedNames))")
        print("control: 0x\(String(format: "%04x", info.controlFlags))")
        guard let dacl = info.dacl else {
            print("dacl: null")
            return
        }
        print("dacl:")
        for ace in dacl {
            print("  type=\(ace.type) flags=0x\(String(format: "%02x", ace.flags)) mask=0x\(String(format: "%08x", ace.accessMask)) sid=\(formatSID(ace.trusteeSID, resolvedNames: resolvedNames))")
        }
    }

    /// Best-effort LSARPC lookup for SIDs the well-known table cannot resolve.
    /// Lookup failures degrade to plain SIDs rather than failing the command.
    private func lookupUnknownSIDs(
        info: SMBSecurityInfo,
        endpoint: SMBURLParser.ReadURL,
        credential: SMBCredential
    ) async -> [String: String] {
        var candidates: [String] = []
        for sid in [info.ownerSID, info.groupSID] + (info.dacl ?? []).map(\.trusteeSID) {
            if let sid, SMBWellKnownSID.name(for: sid) == nil, !candidates.contains(sid) {
                candidates.append(sid)
            }
        }
        guard !candidates.isEmpty else { return [:] }
        guard let names = try? await SMBee.lookupSIDs(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            sids: candidates,
            timeout: transport.duration
        ) else {
            return [:]
        }
        var map: [String: String] = [:]
        for (sid, name) in zip(candidates, names) {
            if let name {
                map[sid] = name.qualifiedName
            }
        }
        return map
    }

    private func formatSID(_ sid: String?, resolvedNames: [String: String]) -> String {
        guard let sid else { return "none" }
        guard resolveSids, let name = resolvedNames[sid] ?? SMBWellKnownSID.name(for: sid) else { return sid }
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

    @Option(name: .long, help: "Set owner SID (S-1-...). Requires WRITE_OWNER access.")
    var owner: String?

    @Option(name: .long, help: "Set group SID (S-1-...). Requires WRITE_OWNER access.")
    var group: String?

    @Flag(help: "Allow empty or deny-only DACLs")
    var force = false

    @Flag(help: "Output a JSON success object")
    var json = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let aces = try allow.map { try parseACE($0, type: 0) } + deny.map { try parseACE($0, type: 1) }
        guard !aces.isEmpty || owner != nil || group != nil else {
            throw ValidationError("setacl requires --allow/--deny ACEs, --owner, or --group")
        }
        // ACE なしで owner/group だけ更新する場合は DACL を書かない (nil)。
        let dacl: [SMBAccessControlEntry]? = aces.isEmpty ? nil : aces
        try await transport.withOperationDeadline {
            try await SMBee.setSecurityInfo(
                host: endpoint.host,
                port: endpoint.port,
                share: endpoint.share,
                path: endpoint.path,
                ownerSID: owner,
                groupSID: group,
                dacl: dacl,
                force: force,
                credential: credential,
                timeout: transport.duration
            )
        }
        if json {
            print(try successJSONString(command: "setacl", path: endpoint.path))
        }
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
        try await transport.withOperationDeadline {
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

    @Flag(help: "Resume partial downloads when possible")
    var resume = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @Option(help: "Include recursive files matching this glob. Can be repeated")
    var include: [String] = []

    @Option(help: "Exclude recursive files or directories matching this glob. Can be repeated")
    var exclude: [String] = []

    @Flag(help: "Show transfer progress")
    var progress = false

    @Flag(help: "Create local parent directories before downloading")
    var createDirs = false

    @Option(help: "Verify completed transfer: none, size, or hash (hash reads content back)")
    var verify: TransferVerifyMode = .none

    @Flag(help: "Output a JSON success object")
    var json = false

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
            if verify != .none && dryRun {
                throw ValidationError("--verify cannot be used with --dry-run")
            }
            let verifier = RecursiveTransferVerifier()
            let localDirectory = URL(fileURLWithPath: destination).standardizedFileURL
            let progressWriter = progress ? TransferProgressWriter() : nil
            try await transport.withOperationDeadline {
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
                    resume: resume,
                    dryRun: dryRun,
                    timeout: transport.duration,
                    include: include,
                    exclude: exclude,
                    perFileTimeout: transport.perFileDuration,
                    onAction: { action in
                        writeRecursiveAction(action, json: json)
                        verifier.record(action)
                    },
                    onProgress: { progress in
                        progressWriter?.emit(progress)
                    }
                )
            }
            progressWriter?.finish()
            if verify != .none {
                try await verifyRecursiveDownloads(
                    mode: verify,
                    actions: verifier.actions,
                    endpoint: endpoint,
                    credential: credential,
                    localDirectory: localDirectory,
                    transport: transport
                )
            }
            if json && !dryRun {
                print(try successJSONString(command: "get", path: endpoint.path))
            }
            return
        }
        let progressWriter = progress ? TransferProgressWriter() : nil
        let onProgress: (@Sendable (SMBTransferProgress) -> Void)?
        if let progressWriter {
            onProgress = { progress in progressWriter.emit(progress) }
        } else {
            onProgress = nil
        }
        let localFile = URL(fileURLWithPath: destination)
        if createDirs {
            try FileManager.default.createDirectory(at: localFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        try await transport.withOperationDeadline {
            try await SMBee.download(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localFile: localFile,
                overwrite: !noOverwrite,
                resume: resume,
                timeout: transport.duration,
                onProgress: onProgress
            )
        }
        try await verifyTransfer(mode: verify, download: true, endpoint: endpoint, credential: credential, localFile: URL(fileURLWithPath: destination), transport: transport)
        if json {
            print(try successJSONString(command: "get", path: endpoint.path))
        }
        progressWriter?.finish()
    }
}

struct MakeDirectory: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mkdir", abstract: "Create an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Flag(help: "Output a JSON success object")
    var json = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await transport.withOperationDeadline {
            try await SMBee.makeDirectory(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                timeout: transport.duration
            )
        }
        if json {
            print(try successJSONString(command: "mkdir", path: endpoint.path))
        }
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

    @Flag(help: "Resume partial uploads when possible")
    var resume = false

    @Flag(help: "Show planned recursive actions without modifying destinations")
    var dryRun = false

    @Option(help: "Include recursive files matching this glob. Can be repeated")
    var include: [String] = []

    @Option(help: "Exclude recursive files or directories matching this glob. Can be repeated")
    var exclude: [String] = []

    @Flag(help: "Show transfer progress")
    var progress = false

    @Flag(help: "Create remote parent directories before uploading")
    var createDirs = false

    @Option(help: "Verify completed transfer: none, size, or hash (hash reads content back)")
    var verify: TransferVerifyMode = .none

    @Flag(help: "Output a JSON success object")
    var json = false

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
            if verify != .none && dryRun {
                throw ValidationError("--verify cannot be used with --dry-run")
            }
            let verifier = RecursiveTransferVerifier()
            let localDirectory = URL(fileURLWithPath: source).standardizedFileURL
            let progressWriter = progress ? TransferProgressWriter() : nil
            try await transport.withOperationDeadline {
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
                    resume: resume,
                    dryRun: dryRun,
                    timeout: transport.duration,
                    include: include,
                    exclude: exclude,
                    perFileTimeout: transport.perFileDuration,
                    onAction: { action in
                        writeRecursiveAction(action, json: json)
                        verifier.record(action)
                    },
                    onProgress: { progress in
                        progressWriter?.emit(progress)
                    }
                )
            }
            progressWriter?.finish()
            if verify != .none {
                try await verifyRecursiveUploads(
                    mode: verify,
                    actions: verifier.actions,
                    endpoint: endpoint,
                    credential: credential,
                    localDirectory: localDirectory,
                    transport: transport
                )
            }
            if json && !dryRun {
                print(try successJSONString(command: "put", path: endpoint.path))
            }
            return
        }
        if progress {
            let progressWriter = TransferProgressWriter()
            try await transport.withOperationDeadline {
                if createDirs {
                    try await makeRemoteParentDirectories(endpoint: endpoint, credential: credential, remotePath: endpoint.path, timeout: transport.duration)
                }
                try await SMBee.upload(
                    host: endpoint.host,
                    port: endpoint.port,
                    credential: credential,
                    share: endpoint.share,
                    path: endpoint.path,
                    fileURL: URL(fileURLWithPath: source),
                    overwrite: !noOverwrite,
                    resume: resume,
                    timeout: transport.duration,
                    onProgress: { progress in progressWriter.emit(progress) }
                )
            }
            try await verifyTransfer(mode: verify, download: false, endpoint: endpoint, credential: credential, localFile: URL(fileURLWithPath: source), transport: transport)
            if json {
                print(try successJSONString(command: "put", path: endpoint.path))
            }
            progressWriter.finish()
            return
        }
        try await transport.withOperationDeadline {
            if createDirs {
                try await makeRemoteParentDirectories(endpoint: endpoint, credential: credential, remotePath: endpoint.path, timeout: transport.duration)
            }
            try await SMBee.upload(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localFile: URL(fileURLWithPath: source),
                overwrite: !noOverwrite,
                resume: resume,
                timeout: transport.duration
            )
        }
        try await verifyTransfer(mode: verify, download: false, endpoint: endpoint, credential: credential, localFile: URL(fileURLWithPath: source), transport: transport)
        if json {
            print(try successJSONString(command: "put", path: endpoint.path))
        }
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

    @Flag(help: "Output a JSON success object")
    var json = false

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
        try await transport.withOperationDeadline {
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
        if json {
            print(try successJSONString(command: "mv", path: to.path))
        }
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

    @Option(help: "Include recursive files matching this glob. Can be repeated")
    var include: [String] = []

    @Option(help: "Exclude recursive files or directories matching this glob. Can be repeated")
    var exclude: [String] = []

    @Flag(help: "Output a JSON success object")
    var json = false

    @Option(help: "Verify completed copy: none, size, or hash (hash reads content back)")
    var verify: TransferVerifyMode = .none

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
            if verify != .none && dryRun {
                throw ValidationError("--verify cannot be used with --dry-run")
            }
            let verifier = RecursiveTransferVerifier()
            try await transport.withOperationDeadline {
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
                    timeout: transport.duration,
                    include: include,
                    exclude: exclude,
                    perFileTimeout: transport.perFileDuration
                ) { action in
                    writeRecursiveAction(action, json: json)
                    verifier.record(action)
                }
            }
            if verify != .none {
                try await verifyRecursiveCopies(mode: verify, actions: verifier.actions, source: from, destination: to, credential: credential, transport: transport)
            }
            if json && !dryRun {
                print(try successJSONString(command: "cp", path: to.path))
            }
            return
        }
        try await transport.withOperationDeadline {
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
        try await verifyRemoteCopyPair(mode: verify, source: from, destination: to, credential: credential, transport: transport)
        if json {
            print(try successJSONString(command: "cp", path: to.path))
        }
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

    @Flag(help: "Output a JSON success object")
    var json = false

    @OptionGroup
    var auth: AuthOptions

    @OptionGroup
    var transport: TransportOptions

    @OptionGroup
    var debug: DebugOptions

    func run() async throws {
        debug.apply()
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await transport.withOperationDeadline {
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
            ) { action in writeRecursiveAction(action, json: json) }
        }
        if json && !dryRun {
            print(try successJSONString(command: "rm", path: endpoint.path))
        }
    }
}

struct TransportOptions: ParsableArguments {
    @Option(name: .long, help: "Socket I/O timeout in seconds (connect and each recv/send)")
    var timeout: Double?

    @Option(name: .long, help: "Overall operation timeout in seconds")
    var operationTimeout: Double?

    @Option(name: .long, help: "Per-file timeout for recursive transfers in seconds")
    var perFileTimeout: Double?

    var duration: Duration? {
        Self.duration(from: timeout)
    }

    var operationDuration: Duration? {
        Self.duration(from: operationTimeout)
    }

    var perFileDuration: Duration? {
        Self.duration(from: perFileTimeout)
    }

    func withOperationDeadline<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try validate()
        return try await SMBOperationDeadline.run(timeout: operationDuration, operation: operation)
    }

    func validate() throws {
        for value in [timeout, operationTimeout, perFileTimeout].compactMap({ $0 }) {
            guard value.isFinite, value > 0, value <= 7 * 24 * 60 * 60 else {
                throw ValidationError("timeout values must be finite, greater than zero, and at most 7 days")
            }
        }
    }

    private static func duration(from seconds: Double?) -> Duration? {
        guard let seconds else { return nil }
        let wholeSeconds = seconds.rounded(.towardZero)
        let fractionalSeconds = seconds - wholeSeconds
        return .seconds(Int64(wholeSeconds)) + .nanoseconds(Int64((fractionalSeconds * 1_000_000_000).rounded()))
    }
}

enum TransferVerifyMode: String, ExpressibleByArgument {
    case none
    case size
    case hash
}

private func verifyDownloadedSize(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localFile: URL,
    transport: TransportOptions
) async throws {
    let stat = try await statForVerify(endpoint: endpoint, credential: credential, transport: transport)
    let localSize = try localFileSize(localFile)
    guard stat.size == localSize else {
        throw ValidationError("size verification failed: remote=\(stat.size) local=\(localSize)")
    }
}

private func verifyUploadedSize(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localFile: URL,
    transport: TransportOptions
) async throws {
    let localSize = try localFileSize(localFile)
    let stat = try await statForVerify(endpoint: endpoint, credential: credential, transport: transport)
    guard stat.size == localSize else {
        throw ValidationError("size verification failed: local=\(localSize) remote=\(stat.size)")
    }
}

/// Compare SHA-256 of the local file with a full read-back of the remote file.
private func verifyLocalRemoteHash(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localFile: URL,
    transport: TransportOptions
) async throws {
    let localHash = try SMBTransferVerification.localSHA256Hex(fileURL: localFile)
    let remoteHash = try await transport.withOperationDeadline {
        try await SMBTransferVerification.remoteSHA256Hex(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
    }
    guard localHash == remoteHash else {
        throw ValidationError("hash verification failed: local=\(localHash) remote=\(remoteHash)")
    }
}

/// Single local⇄remote file verification dispatched by mode. `.none` is a no-op.
private func verifyTransfer(
    mode: TransferVerifyMode,
    download: Bool,
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localFile: URL,
    transport: TransportOptions
) async throws {
    switch mode {
    case .none:
        return
    case .size:
        if download {
            try await verifyDownloadedSize(endpoint: endpoint, credential: credential, localFile: localFile, transport: transport)
        } else {
            try await verifyUploadedSize(endpoint: endpoint, credential: credential, localFile: localFile, transport: transport)
        }
    case .hash:
        try await verifyLocalRemoteHash(endpoint: endpoint, credential: credential, localFile: localFile, transport: transport)
    }
}

private func localFileSize(_ url: URL) throws -> UInt64 {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard let raw = attributes[.size] else {
        throw ValidationError("local file size unavailable")
    }
    if let number = raw as? NSNumber { return number.uint64Value }
    if let value = raw as? UInt64 { return value }
    if let value = raw as? Int, value >= 0 { return UInt64(value) }
    throw ValidationError("local file size unavailable")
}

private final class RecursiveTransferVerifier: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBRecursiveAction] = []

    var actions: [SMBRecursiveAction] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func record(_ action: SMBRecursiveAction) {
        switch action.kind {
        case .download, .upload, .copy:
            lock.lock()
            storage.append(action)
            lock.unlock()
        case .delete, .mkdir, .skip:
            break
        }
    }
}

private func verifyRecursiveDownloads(
    mode: TransferVerifyMode,
    actions: [SMBRecursiveAction],
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localDirectory: URL,
    transport: TransportOptions
) async throws {
    for action in actions where action.kind == .download {
        let localFile = URL(fileURLWithPath: action.path).standardizedFileURL
        let relativePath = try localRelativePath(file: localFile, directory: localDirectory)
        let remotePath = try SMBPath.join(endpoint.path, relativePath)
        try await verifyTransfer(
            mode: mode,
            download: true,
            endpoint: endpoint.withPath(remotePath),
            credential: credential,
            localFile: localFile,
            transport: transport
        )
    }
}

private func verifyRecursiveUploads(
    mode: TransferVerifyMode,
    actions: [SMBRecursiveAction],
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    localDirectory: URL,
    transport: TransportOptions
) async throws {
    for action in actions where action.kind == .upload {
        let relativePath = try remoteRelativePath(path: action.path, root: endpoint.path)
        let localFile = localDirectory.appendingPathComponent(relativePath.replacingOccurrences(of: "\\", with: "/"))
        try await verifyTransfer(
            mode: mode,
            download: false,
            endpoint: endpoint.withPath(action.path),
            credential: credential,
            localFile: localFile,
            transport: transport
        )
    }
}

private func verifyRemoteCopyPair(
    mode: TransferVerifyMode,
    source: SMBURLParser.ReadURL,
    destination: SMBURLParser.ReadURL,
    credential: SMBCredential,
    transport: TransportOptions
) async throws {
    switch mode {
    case .none:
        return
    case .size:
        let sourceStat = try await statForVerify(endpoint: source, credential: credential, transport: transport)
        let destinationStat = try await statForVerify(endpoint: destination, credential: credential, transport: transport)
        guard sourceStat.size == destinationStat.size else {
            throw ValidationError("size verification failed: source=\(sourceStat.size) destination=\(destinationStat.size)")
        }
    case .hash:
        let sourceHash = try await remoteHashForVerify(endpoint: source, credential: credential, transport: transport)
        let destinationHash = try await remoteHashForVerify(endpoint: destination, credential: credential, transport: transport)
        guard sourceHash == destinationHash else {
            throw ValidationError("hash verification failed: source=\(sourceHash) destination=\(destinationHash)")
        }
    }
}

private func verifyRecursiveCopies(
    mode: TransferVerifyMode,
    actions: [SMBRecursiveAction],
    source: SMBURLParser.ReadURL,
    destination: SMBURLParser.ReadURL,
    credential: SMBCredential,
    transport: TransportOptions
) async throws {
    for action in actions where action.kind == .copy {
        let relativePath = try remoteRelativePath(path: action.path, root: destination.path)
        let sourcePath = try SMBPath.join(source.path, relativePath)
        try await verifyRemoteCopyPair(
            mode: mode,
            source: source.withPath(sourcePath),
            destination: destination.withPath(action.path),
            credential: credential,
            transport: transport
        )
    }
}

private func remoteHashForVerify(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    transport: TransportOptions
) async throws -> String {
    try await transport.withOperationDeadline {
        try await SMBTransferVerification.remoteSHA256Hex(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
    }
}

private func statForVerify(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    transport: TransportOptions
) async throws -> SMBFileStat {
    try await transport.withOperationDeadline {
        try await SMBee.stat(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            timeout: transport.duration
        )
    }
}

private func localRelativePath(file: URL, directory: URL) throws -> String {
    let filePath = file.standardizedFileURL.path
    let directoryPath = directory.standardizedFileURL.path
    let prefix = directoryPath.hasSuffix("/") ? directoryPath : directoryPath + "/"
    guard filePath.hasPrefix(prefix) else {
        throw ValidationError("downloaded file is outside destination directory: \(filePath)")
    }
    return String(filePath.dropFirst(prefix.count)).replacingOccurrences(of: "/", with: "\\")
}

private func remoteRelativePath(path: String, root: String) throws -> String {
    let normalizedPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
    let normalizedRoot = root.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
    guard !normalizedRoot.isEmpty else { return normalizedPath }
    guard normalizedPath == normalizedRoot || normalizedPath.hasPrefix(normalizedRoot + "\\") else {
        throw ValidationError("recursive action path is outside destination root: \(path)")
    }
    if normalizedPath == normalizedRoot { return "" }
    return String(normalizedPath.dropFirst(normalizedRoot.count + 1))
}

private extension SMBURLParser.ReadURL {
    func withPath(_ path: String) -> SMBURLParser.ReadURL {
        var copy = self
        copy.path = path
        return copy
    }
}

private func makeRemoteParentDirectories(
    endpoint: SMBURLParser.ReadURL,
    credential: SMBCredential,
    remotePath: String,
    timeout: Duration?
) async throws {
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
                timeout: timeout
            )
        } catch SMBError.nameCollision {
        }
    }
}

func successJSONString(command: String, path: String? = nil) throws -> String {
    var object: [String: Any] = [
        "ok": true,
        "command": command
    ]
    if let path {
        object["path"] = path
    }
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    guard let string = String(data: data, encoding: .utf8) else {
        throw ValidationError("failed to encode JSON")
    }
    return string
}

func errorJSONString(_ error: Error) throws -> String {
    var object: [String: Any] = [
        "ok": false,
        "error": String(describing: error)
    ]
    if let smbError = error as? SMBError {
        object["category"] = "smb"
        object["exitCode"] = Int(SMBCLIExitCode.code(for: smbError))
    } else if SMBCLI.exitCode(for: error) == .validationFailure {
        object["category"] = "usage"
        object["exitCode"] = Int(SMBCLIExitCode.usage)
    } else {
        object["category"] = "other"
        object["exitCode"] = Int(SMBCLIExitCode.other)
    }
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    guard let string = String(data: data, encoding: .utf8) else {
        throw ValidationError("failed to encode JSON")
    }
    return string
}

func sparseRangesJSONString(_ ranges: [SMBAllocatedRange]) throws -> String {
    let objects = ranges.map { ["offset": $0.offset, "length": $0.length] }
    let data = try JSONSerialization.data(withJSONObject: objects, options: [.sortedKeys])
    return String(decoding: data, as: UTF8.self)
}

final class TransferProgressWriter: @unchecked Sendable {
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
        guard !auth.usesAnonymousAuthentication || username?.isEmpty != false,
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

func recursiveActionLine(_ action: SMBRecursiveAction, json: Bool) -> String {
    guard json else {
        return "\(action.kind.rawValue) \(action.path)"
    }
    // Newline-delimited JSON, matching `watch --json`: keeps stdout machine-parseable
    // when recursive commands run with --json (issues/010).
    let object: [String: String] = ["action": action.kind.rawValue, "path": action.path]
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
          let line = String(data: data, encoding: .utf8) else {
        return "{\"action\":\"\(action.kind.rawValue)\"}"
    }
    return line
}

func writeRecursiveAction(_ action: SMBRecursiveAction, json: Bool = false) {
    FileHandle.standardOutput.write(Data((recursiveActionLine(action, json: json) + "\n").utf8))
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
