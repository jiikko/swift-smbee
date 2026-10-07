import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

enum SMBDownloadTestSeams {
    /// Lets deterministic tests hold resume-prefix validation at an async boundary.
    @TaskLocal static var beforeResumePrefixComparison: (@Sendable () async throws -> Void)?
    /// Lets deterministic tests hold after prefix equality has been computed and before it is acted on.
    @TaskLocal static var afterResumePrefixComparison: (@Sendable () async throws -> Void)?
    /// Marks the point at which a validated resume is about to start its append stream.
    @TaskLocal static var beforeResumeAppendConnection: (@Sendable () async throws -> Void)?
    /// Lets deterministic tests exercise cancellation immediately before destination installation.
    @TaskLocal static var beforeDestinationInstall: (@Sendable () async throws -> Void)?
    /// Replaces exclusive temporary-file creation in tests, including partial-create failures.
    @TaskLocal static var createTemporaryFile: (@Sendable (URL) throws -> FileHandle)?
}

/// Extracts the `.size` file attribute as `UInt64`. On Darwin the value bridges to `NSNumber`, but on
/// Linux swift-corelibs-foundation it is a plain `Int`, so `as? NSNumber` alone fails there. Handle both.
private func smbFileSizeValue(from attributes: [FileAttributeKey: Any]) -> UInt64? {
    guard let raw = attributes[.size] else { return nil }
    if let number = raw as? NSNumber { return number.uint64Value }
    if let value = raw as? UInt64 { return value }
    if let value = raw as? Int, value >= 0 { return UInt64(value) }
    return nil
}

private struct SMBLocalFileSnapshot: Equatable {
    let device: UInt64
    let inode: UInt64
    let size: UInt64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64

    init(handle: FileHandle) throws {
        var value = stat()
        guard fstat(handle.fileDescriptor, &value) == 0, value.st_size >= 0 else {
            throw SMBCodecError.invalidValue("unable to inspect local source file")
        }
        device = UInt64(value.st_dev)
        inode = UInt64(value.st_ino)
        size = UInt64(value.st_size)
#if os(Linux)
        modificationSeconds = Int64(value.st_mtim.tv_sec)
        modificationNanoseconds = Int64(value.st_mtim.tv_nsec)
#else
        modificationSeconds = Int64(value.st_mtimespec.tv_sec)
        modificationNanoseconds = Int64(value.st_mtimespec.tv_nsec)
#endif
    }
}

/// Replaces `destination` (file or directory) with `source`. `replaceItemAt` gives an atomic swap on
/// Darwin, but swift-corelibs-foundation implements it unreliably on Linux — it non-deterministically
/// either throws "file doesn't exist" or returns without actually swapping, leaving the old content.
/// So on Linux use a plain remove + move (loses cross-crash atomicity, which is best-effort anyway).
private func smbReplaceItem(at destination: URL, with source: URL, fileManager: FileManager) throws {
#if canImport(Darwin)
    _ = try fileManager.replaceItemAt(destination, withItemAt: source)
#else
    let backup = destination.deletingLastPathComponent()
        .appendingPathComponent(".(destination.lastPathComponent).smbee-backup-(UUID().uuidString)")
    let hadDestination = fileManager.fileExists(atPath: destination.path)
    if hadDestination { try fileManager.moveItem(at: destination, to: backup) }
    do {
        try fileManager.moveItem(at: source, to: destination)
        if hadDestination { try? fileManager.removeItem(at: backup) }
    } catch {
        if hadDestination, fileManager.fileExists(atPath: backup.path) {
            try? fileManager.moveItem(at: backup, to: destination)
        }
        throw error
    }
#endif
}

func makeSMBDownloadTemporaryFile(
    in directory: URL,
    prefix: String = ".smbee-",
    suffix: String = ".part"
) throws -> (url: URL, handle: FileHandle) {
    let fileManager = FileManager.default
    for _ in 0..<8 {
        let url = directory.appendingPathComponent("\(prefix)\(UUID().uuidString)\(suffix)")
        if let createTemporaryFile = SMBDownloadTestSeams.createTemporaryFile {
            do {
                return (url, try createTemporaryFile(url))
            } catch {
                try? fileManager.removeItem(at: url)
                throw error
            }
        }

        // 0o666 & ~umask keeps the installed destination's mode the same as the previous
        // FileManager.createFile path (typically 0644); a fixed 0o600 hid downloads from
        // group/other readers.
        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o666))
        guard descriptor >= 0 else {
            let openError = errno
            if openError == EEXIST { continue }
            // A failed open does not prove this call created the pathname (EMFILE can win over
            // EEXIST), so it must not unlink it.
            throw POSIXError(POSIXErrorCode(rawValue: openError) ?? .EIO)
        }
        return (url, FileHandle(fileDescriptor: descriptor, closeOnDealloc: true))
    }
    throw SMBCodecError.invalidValue("unable to create unique temporary download file")
}

private func smbGlobMatches(_ pattern: String, _ value: String) -> Bool {
    fnmatch(pattern, value, 0) == 0
}

private func recursiveEntryIsIncluded(name: String, relativePath: String, include: [String]) -> Bool {
    guard !include.isEmpty else { return true }
    return include.contains { recursiveGlobMatches($0, name: name, relativePath: relativePath) }
}

private func recursiveEntryIsExcluded(name: String, relativePath: String, exclude: [String]) -> Bool {
    exclude.contains { recursiveGlobMatches($0, name: name, relativePath: relativePath) }
}

private func recursiveGlobMatches(_ pattern: String, name: String, relativePath: String) -> Bool {
    let normalizedPattern = pattern.replacingOccurrences(of: "\\", with: "/")
    let normalizedRelativePath = relativePath.replacingOccurrences(of: "\\", with: "/")
    return smbGlobMatches(pattern, name)
        || smbGlobMatches(pattern, relativePath)
        || smbGlobMatches(normalizedPattern, name)
        || smbGlobMatches(normalizedPattern, normalizedRelativePath)
}

public struct SMBDirectoryEntry: Equatable, Sendable {
    public var name: String
    public var fileSize: UInt64
    public var isDirectory: Bool
    public var attributes: UInt32
    public var fileId: UInt64?
    public var modifiedTime: Date?
    public var creationTime: Date?

    public var isReparsePoint: Bool {
        (attributes & SMBFileAttributes.reparsePoint) != 0
    }

    public init(
        name: String,
        fileSize: UInt64,
        isDirectory: Bool,
        attributes: UInt32 = 0,
        fileId: UInt64? = nil,
        modifiedTime: Date? = nil,
        creationTime: Date? = nil
    ) {
        self.name = name
        self.fileSize = fileSize
        self.isDirectory = isDirectory
        self.attributes = attributes
        self.fileId = fileId
        self.modifiedTime = modifiedTime
        self.creationTime = creationTime
    }
}

public struct SMBFileStat: Equatable, Sendable {
    public var size: UInt64
    public var allocationSize: UInt64?
    public var creationTime: Date?
    public var lastAccessTime: Date?
    public var modifiedTime: Date?
    public var changeTime: Date?
    public var isDirectory: Bool
    public var attributes: UInt32
    public var reparseTag: UInt32?

    public var isReparsePoint: Bool {
        (attributes & SMBFileAttributes.reparsePoint) != 0
    }

    public var reparseKind: SMBReparseKind? {
        reparseTag.map(SMBReparseKind.init(tag:))
    }

    public init(
        size: UInt64,
        modifiedTime: Date?,
        isDirectory: Bool,
        attributes: UInt32 = 0,
        allocationSize: UInt64? = nil,
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        changeTime: Date? = nil,
        reparseTag: UInt32? = nil
    ) {
        self.size = size
        self.allocationSize = allocationSize
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.modifiedTime = modifiedTime
        self.changeTime = changeTime
        self.isDirectory = isDirectory
        self.attributes = attributes
        self.reparseTag = reparseTag
    }
}

public struct SMBReparsePoint: Equatable, Sendable {
    public var tag: UInt32
    public var kind: SMBReparseKind
    public var substituteName: String?
    public var printName: String?
    public var flags: UInt32?
    public var rawData: [UInt8]

    public init(
        tag: UInt32,
        substituteName: String? = nil,
        printName: String? = nil,
        flags: UInt32? = nil,
        rawData: [UInt8] = []
    ) {
        self.tag = tag
        self.kind = SMBReparseKind(tag: tag)
        self.substituteName = substituteName
        self.printName = printName
        self.flags = flags
        self.rawData = rawData
    }
}

public enum SMBReparseKind: Equatable, Sendable {
    case symlink
    case mountPoint
    case dfs
    case nfs
    case lxSymlink
    case other(UInt32)

    public init(tag: UInt32) {
        switch tag {
        case SMBReparseTags.symlink:
            self = .symlink
        case SMBReparseTags.mountPoint:
            self = .mountPoint
        case SMBReparseTags.dfs:
            self = .dfs
        case SMBReparseTags.nfs:
            self = .nfs
        case SMBReparseTags.lxSymlink:
            self = .lxSymlink
        default:
            self = .other(tag)
        }
    }
}

extension SMBReparseKind: CustomStringConvertible {
    public var description: String {
        switch self {
        case .symlink:
            "symlink"
        case .mountPoint:
            "mountPoint"
        case .dfs:
            "dfs"
        case .nfs:
            "nfs"
        case .lxSymlink:
            "lxSymlink"
        case .other(let tag):
            "other(0x" + String(format: "%08x", tag) + ")"
        }
    }
}

public struct SMBVolumeInfo: Equatable, Sendable {
    public var totalBytes: UInt64
    public var availableBytes: UInt64
    public var usedBytes: UInt64 { totalBytes >= availableBytes ? totalBytes - availableBytes : 0 }
    public var filesystemName: String
    public var volumeLabel: String
    public var maxComponentLength: UInt32
    public var filesystemAttributes: UInt32
    public var volumeSerialNumber: UInt32

    public init(
        totalBytes: UInt64,
        availableBytes: UInt64,
        filesystemName: String,
        volumeLabel: String,
        maxComponentLength: UInt32,
        filesystemAttributes: UInt32,
        volumeSerialNumber: UInt32
    ) {
        self.totalBytes = totalBytes
        self.availableBytes = availableBytes
        self.filesystemName = filesystemName
        self.volumeLabel = volumeLabel
        self.maxComponentLength = maxComponentLength
        self.filesystemAttributes = filesystemAttributes
        self.volumeSerialNumber = volumeSerialNumber
    }
}

public struct SMBSecurityInfo: Equatable, Sendable {
    public let ownerSID: String?
    public let groupSID: String?
    public let dacl: [SMBAccessControlEntry]?
    public let controlFlags: UInt16

    public init(ownerSID: String?, groupSID: String?, dacl: [SMBAccessControlEntry]?, controlFlags: UInt16) {
        self.ownerSID = ownerSID
        self.groupSID = groupSID
        self.dacl = dacl
        self.controlFlags = controlFlags
    }
}

public struct SMBAccessControlEntry: Equatable, Sendable {
    public let type: UInt8
    public let flags: UInt8
    public let accessMask: UInt32
    public let trusteeSID: String?

    public init(type: UInt8, flags: UInt8, accessMask: UInt32, trusteeSID: String?) {
        self.type = type
        self.flags = flags
        self.accessMask = accessMask
        self.trusteeSID = trusteeSID
    }
}

public enum SMBWellKnownSID {
    private static let names: [String: String] = [
        "S-1-0-0": "Null Authority",
        "S-1-1-0": "Everyone",
        "S-1-2-0": "Local",
        "S-1-2-1": "Console Logon",
        "S-1-3-0": "Creator Owner",
        "S-1-3-1": "Creator Group",
        "S-1-5-7": "Anonymous Logon",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-18": "Local System",
        "S-1-5-19": "Local Service",
        "S-1-5-20": "Network Service",
        "S-1-5-32-544": "BUILTIN\\Administrators",
        "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-546": "BUILTIN\\Guests",
        "S-1-5-32-547": "BUILTIN\\Power Users",
        "S-1-5-32-548": "BUILTIN\\Account Operators",
        "S-1-5-32-549": "BUILTIN\\Server Operators",
        "S-1-5-32-550": "BUILTIN\\Print Operators",
        "S-1-5-32-551": "BUILTIN\\Backup Operators",
        "S-1-5-32-552": "BUILTIN\\Replicators",
        "S-1-5-32-555": "BUILTIN\\Remote Desktop Users"
    ]

    public static func name(for sid: String) -> String? {
        names[sid]
    }
}

public enum SMBFileAttributes {
    public static let readOnly: UInt32 = 0x0000_0001
    public static let hidden: UInt32 = 0x0000_0002
    public static let system: UInt32 = 0x0000_0004
    public static let directory: UInt32 = 0x0000_0010
    public static let archive: UInt32 = 0x0000_0020
    public static let reparsePoint: UInt32 = 0x0000_0400
    public static let normal: UInt32 = 0x0000_0080
}

public enum SMBReparseTags {
    public static let symlink: UInt32 = 0xa000_000c
    public static let mountPoint: UInt32 = 0xa000_0003
    public static let dfs: UInt32 = 0x8000_000a
    // NFS tag is included for classification only; MS-FSCC marks its reparse data as
    // server-side interpretation only, so it stays opaque to this client.
    public static let nfs: UInt32 = 0x8000_0014
    // WSL symbolic link; reparse data layout is public (MS-FSCC §2.1.2.7).
    public static let lxSymlink: UInt32 = 0xa000_001d
}

public struct SMBFileMetadataUpdate: Equatable, Sendable {
    public var creationTime: Date?
    public var lastAccessTime: Date?
    public var modifiedTime: Date?
    public var changeTime: Date?
    public var attributes: UInt32?

    public init(
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        modifiedTime: Date? = nil,
        changeTime: Date? = nil,
        attributes: UInt32? = nil
    ) {
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.modifiedTime = modifiedTime
        self.changeTime = changeTime
        self.attributes = attributes
    }
}

public struct SMBShareInfo: Equatable, Sendable {
    public var name: String
    public var type: UInt32?
    public var comment: String?

    public init(name: String, type: UInt32? = nil, comment: String? = nil) {
        self.name = name
        self.type = type
        self.comment = comment
    }
}

struct SMBTreeConnectResult: Equatable, Sendable {
    var treeId: UInt32
    var shareType: UInt8
    var shareFlags: UInt32
    var capabilities: UInt32
    var maximalAccess: UInt32

    var encryptionRequired: Bool {
        (shareFlags & SMBTreeConnectConstants.shareFlagEncryptData) != 0
    }
}

enum SMBTreeConnectConstants {
    static let shareFlagEncryptData: UInt32 = 0x0000_8000
    static let shareCapDFS: UInt32 = 0x0000_0008
}

public struct SMBReadRange: Equatable, Sendable {
    public var offset: UInt64
    public var length: UInt64

    public init(offset: UInt64, length: UInt64) {
        self.offset = offset
        self.length = length
    }
}

enum SMBTransferLimits {
    static func negotiatedChunkSize(localLimit: Int, negotiatedLimit: UInt32, transformOverhead: Int = 0) -> Int {
        let usableNegotiatedLimit = max(0, Int(clamping: negotiatedLimit) - transformOverhead)
        return max(1, min(localLimit, usableNegotiatedLimit))
    }

    static func creditWindowChunkSize(
        localLimit: Int,
        negotiatedLimit: UInt32,
        transformOverhead: Int = 0,
        availableCredits: UInt32
    ) -> Int {
        let negotiated = negotiatedChunkSize(
            localLimit: localLimit,
            negotiatedLimit: negotiatedLimit,
            transformOverhead: transformOverhead
        )
        let usableCredits = max(1, availableCredits)
        let creditLimit = UInt64(usableCredits) * UInt64(SMB2Credit.unitSize)
        return max(1, min(negotiated, Int(min(creditLimit, UInt64(Int.max)))))
    }
}

enum SMBChunkedTransfer {
    static func nextWriteRange(cursor: Int, dataCount: Int, chunkSize: Int) throws -> Range<Int>? {
        guard cursor >= 0, cursor <= dataCount else {
            throw SMBCodecError.invalidValue("write cursor is outside data bounds")
        }
        guard chunkSize > 0 else {
            throw SMBCodecError.invalidValue("write chunk size must be positive")
        }
        guard cursor < dataCount else { return nil }
        let sum = cursor.addingReportingOverflow(chunkSize)
        let end = sum.overflow ? dataCount : min(sum.partialValue, dataCount)
        guard end > cursor, end <= dataCount else {
            throw SMBCodecError.invalidValue("invalid write chunk range")
        }
        return cursor..<end
    }

    static func advancedReadPosition(cursor: UInt64, remaining: UInt64, receivedCount: Int) throws -> (cursor: UInt64, remaining: UInt64) {
        guard receivedCount >= 0 else {
            throw SMBCodecError.invalidValue("read byte count must be non-negative")
        }
        let received = UInt64(receivedCount)
        guard received <= remaining else {
            throw SMBCodecError.invalidValue("SMB read returned more data than requested")
        }
        let nextCursor = cursor.addingReportingOverflow(received)
        guard !nextCursor.overflow else {
            throw SMBCodecError.invalidValue("SMB read offset overflow")
        }
        return (nextCursor.partialValue, remaining - received)
    }
}

private final class SMBReadStreamProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var yielded = false
    private var receivedBytes: UInt64 = 0

    var startedYielding: Bool {
        lock.lock()
        defer { lock.unlock() }
        return yielded
    }

    var received: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return receivedBytes
    }

    func markYielding() {
        lock.lock()
        yielded = true
        lock.unlock()
    }

    func recordReceived(byteCount: Int) {
        lock.lock()
        receivedBytes += UInt64(byteCount)
        lock.unlock()
    }
}

private enum SMBPrefixReadSink: Sendable {
    case accumulate
    case stream(
        progress: SMBReadStreamProgress,
        onChunk: @Sendable ([UInt8]) async throws -> Void
    )
}

/// Delivers callbacks away from protocol actors. At most one pending snapshot is retained; a slow
/// consumer observes monotonic coalesced values and the transfer awaits the final delivery.
private final class SMBTransferProgressEmitter: @unchecked Sendable {
    private let totalBytes: UInt64?
    private let onProgress: (@Sendable (SMBTransferProgress) -> Void)?
    private let clock = ContinuousClock()
    private let start: ContinuousClock.Instant
    private let queue = DispatchQueue(label: "SMBee.transfer-progress")
    private let lock = NSLock()
    private var latest: SMBTransferProgress?
    private var drainScheduled = false

    init(totalBytes: UInt64?, onProgress: (@Sendable (SMBTransferProgress) -> Void)?) {
        self.totalBytes = totalBytes
        self.onProgress = onProgress
        self.start = clock.now
    }

    func emit(bytesTransferred: UInt64) {
        guard onProgress != nil else { return }
        let elapsed = start.duration(to: clock.now)
        let components = elapsed.components
        let seconds = Double(components.seconds) + (Double(components.attoseconds) / 1_000_000_000_000_000_000)
        let bytesPerSecond = seconds > 0 ? Double(bytesTransferred) / seconds : 0
        let snapshot = SMBTransferProgress(
            bytesTransferred: bytesTransferred,
            totalBytes: totalBytes,
            bytesPerSecond: bytesPerSecond
        )
        lock.lock()
        latest = snapshot
        if drainScheduled {
            lock.unlock()
            return
        }
        drainScheduled = true
        lock.unlock()
        queue.async { self.drain() }
    }

    func finish() async {
        guard onProgress != nil else { return }
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume() }
        }
    }

    private func drain() {
        while true {
            lock.lock()
            guard let snapshot = latest else {
                drainScheduled = false
                lock.unlock()
                return
            }
            latest = nil
            lock.unlock()
            onProgress?(snapshot)
        }
    }
}

actor SMBDfsReferralCache {
    struct Key: Hashable {
        let host: String
        let port: UInt16
        let path: String
        let credentialIdentity: String

        init(host: String, port: UInt16, path: String, credential: SMBCredential) {
            self.host = host.lowercased()
            self.port = port
            self.path = path.lowercased()
            if credential.isAnonymous {
                credentialIdentity = "anonymous"
            } else {
                let mechanism = credential.ntHash == nil ? "password" : "nt-hash"
                credentialIdentity = "\(mechanism):\(credential.domain.lowercased()):\(credential.username.lowercased())"
            }
        }
    }

    private struct Entry {
        let referral: SMBDfsReferralResult
        let expiresAt: Date
    }

    private let maximumEntries: Int
    private var entries: [Key: Entry] = [:]

    init(maximumEntries: Int = 256) {
        precondition(maximumEntries > 0)
        self.maximumEntries = maximumEntries
    }

    func get(_ key: Key) -> SMBDfsReferralResult? {
        guard let entry = entries[key] else { return nil }
        guard entry.expiresAt > Date() else {
            entries.removeValue(forKey: key)
            return nil
        }
        return entry.referral
    }

    func put(_ referral: SMBDfsReferralResult, for key: Key, ttl: UInt32) {
        let now = Date()
        entries = entries.filter { $0.value.expiresAt > now }
        if entries[key] == nil, entries.count >= maximumEntries,
           let evictionKey = entries.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
            entries.removeValue(forKey: evictionKey)
        }
        entries[key] = Entry(referral: referral, expiresAt: Date().addingTimeInterval(TimeInterval(ttl)))
    }

    var count: Int { entries.count }
}

private final class SMBDirectoryEntryCollector: @unchecked Sendable {
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

private final class SMBReadAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt8] = []

    var bytes: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ chunk: [UInt8]) {
        lock.lock()
        storage += chunk
        lock.unlock()
    }
}

private final class SMBDownloadSink: @unchecked Sendable {
    let handle: FileHandle
    let onProgress: (@Sendable (SMBTransferProgress) -> Void)?
    var total: UInt64 = 0
    init(handle: FileHandle, onProgress: (@Sendable (SMBTransferProgress) -> Void)?) {
        self.handle = handle
        self.onProgress = onProgress
    }
}

enum SMBClientCloseEvent: Sendable, Equatable {
    case joinedExistingCleanup
    case returnedWithoutJoining
}

public actor SMBClientSession {
    // Keep writes comparable to reads; credit/negotiated limits still clamp this.
    static let localWriteChunkLimit = 1024 * 1024
    private static let closeSetupTimeout: Duration = .seconds(5)

    // Both prefix APIs share this bound. readPrefix needs it because it retains the complete
    // result. For withPrefixReadStream it keeps the prefix API from being used as an unbounded
    // download (issues/070): prefix reads are for small heads (the obaket thumbnail consumer reads
    // at most 4 MiB), and larger reads belong to withReadStream(range:). It does not bound how
    // long the handle stays open — a slow onChunk or server does; only a caller deadline does.
    static let maxPrefixReadLength: UInt64 = 64 * 1024 * 1024

    /// Everything needed to rebuild a dropped connection for opt-in watch resubscribe.
    /// Only sessions created via `connect(...)` carry this; `withTree`-derived sessions do not.
    struct ReconnectInfo: Sendable {
        let host: String
        let port: UInt16
        let share: String
        let credentialProvider: SMBCredentialProvider
        let makeTransport: @Sendable () -> SMBTransport
        let requestTimeout: Duration?
        let requestTimeoutSleeper: @Sendable (Duration) async throws -> Void
    }

    private struct ScopedTree: Sendable {
        let session: SMBSession
        let treeId: UInt32
        let child: SMBClientTreeSession
    }

    private var session: SMBSession
    private var treeId: UInt32
    private var childTrees: [UUID: ScopedTree] = [:]
    private var treeSetupSessions: [UUID: SMBSession] = [:]
    private let reconnectInfo: ReconnectInfo?
    private var keepAliveTask: Task<Void, Never>?
    private var isClosed = false
    private var closeTask: Task<Void, Never>?
    private var closeSetupDeadlineTask: Task<Void, Never>?
    private var closeSetupDrainWaiterID: UUID?
    private var closeSetupDrainContinuation: CheckedContinuation<Void, Never>?
    private var closeSetupDeadlineExpired = false
    private let closeSetupDeadlineSleeper: @Sendable (Duration) async throws -> Void
    private var sessionGeneration: UInt64 = 0
    private var reconnectTask: Task<Void, Never>?
    private var reconnectTaskID: UUID?
    private var reconnectWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var reconnectCandidate: (taskID: UUID, session: SMBSession)?

    init(
        session: SMBSession,
        treeId: UInt32,
        reconnectInfo: ReconnectInfo? = nil,
        closeSetupDeadlineSleeper: @escaping @Sendable (Duration) async throws -> Void = {
            try await Task.sleep(for: $0)
        }
    ) {
        self.session = session
        self.treeId = treeId
        self.reconnectInfo = reconnectInfo
        self.closeSetupDeadlineSleeper = closeSetupDeadlineSleeper
    }

    func retainsAuthenticationCredentialForTesting() async -> Bool {
        await session.retainsAuthenticationCredentialForTesting()
    }

    func wireSessionForTesting() -> SMBSession {
        session
    }

    func installSymbolicLinkReparsePointForTesting(path: String, target: String) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .setReparsePoint(path: path))
        do {
            try await session.setSymbolicLinkReparsePoint(
                treeId: treeId,
                fileId: fileId,
                target: target
            )
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Tear down the current connection and establish a fresh session + tree from the
    /// stored reconnect info. Throws `SMBError.connectionLost` if this session was not
    /// created with reconnect support.
    private func reconnect(
        expectedGeneration: UInt64,
        onRequest: (@Sendable () -> Void)? = nil
    ) async throws {
        onRequest?()
        guard !isClosed else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        guard expectedGeneration == sessionGeneration else { return }
        let waiterID = UUID()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                guard !isClosed else {
                    continuation.resume(throwing: SMBError.connectionLost(operation: "RECONNECT"))
                    return
                }
                guard expectedGeneration == sessionGeneration else {
                    continuation.resume()
                    return
                }
                reconnectWaiters[waiterID] = continuation
                guard reconnectTask == nil else { return }
                let taskID = UUID()
                reconnectTaskID = taskID
                reconnectTask = Task {
                    do {
                        try await self.performReconnect(taskID: taskID)
                        self.finishReconnect(taskID: taskID, result: .success(()))
                    } catch {
                        self.finishReconnect(taskID: taskID, result: .failure(error))
                    }
                }
            }
        }, onCancel: {
            Task { await self.cancelReconnectWaiter(waiterID) }
        })
    }

    /// Test entry point keeps deterministic concurrency tests on the same reconnect path.
    func reconnectForTesting(onRequest: @escaping @Sendable () -> Void) async throws {
        try await reconnect(expectedGeneration: sessionGeneration, onRequest: onRequest)
    }

    func reconnectTaskForTesting() -> Task<Void, Never>? {
        reconnectTask
    }

    func treeSetupCountForTesting() -> Int {
        treeSetupSessions.count
    }

    private func performReconnect(taskID: UUID) async throws {
        guard !isClosed else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        guard let info = reconnectInfo else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        let oldSession = session
        await oldSession.closeTransportAndWait(cause: "reconnect_old_session")
        try Task.checkCancellation()
        guard !isClosed else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        let credential = try await info.credentialProvider()
        try Task.checkCancellation()
        guard !isClosed else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        let newSession = SMBSession(
            host: info.host,
            port: info.port,
            credential: credential,
            transport: info.makeTransport(),
            requestTimeout: info.requestTimeout,
            requestTimeoutSleeper: info.requestTimeoutSleeper
        )
        reconnectCandidate = (taskID, newSession)
        do {
            try await newSession.connect()
            try Task.checkCancellation()
            guard !isClosed else {
                throw SMBError.connectionLost(operation: "RECONNECT")
            }
            let newTreeId = try await newSession.treeConnect(share: info.share)
            try Task.checkCancellation()
            guard !isClosed else {
                throw SMBError.connectionLost(operation: "RECONNECT")
            }
            session = newSession
            treeId = newTreeId
            sessionGeneration &+= 1
            reconnectCandidate = nil
        } catch {
            await newSession.closeTransportAndWait(cause: "reconnect_new_session", diagnosticError: error)
            if reconnectCandidate?.taskID == taskID {
                reconnectCandidate = nil
            }
            throw error
        }
    }

    private func finishReconnect(taskID: UUID, result: Result<Void, Error>) {
        guard reconnectTaskID == taskID else { return }
        reconnectTask = nil
        reconnectTaskID = nil
        if reconnectCandidate?.taskID == taskID {
            reconnectCandidate = nil
        }
        let waiters = Array(reconnectWaiters.values)
        reconnectWaiters.removeAll()
        waiters.forEach { $0.resume(with: result) }
    }

    private func cancelReconnectWaiter(_ waiterID: UUID) async {
        guard let continuation = reconnectWaiters.removeValue(forKey: waiterID) else { return }
        continuation.resume(throwing: CancellationError())
        guard reconnectWaiters.isEmpty, let taskID = reconnectTaskID else { return }
        let candidate = reconnectCandidate?.taskID == taskID ? reconnectCandidate?.session : nil
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectTaskID = nil
        reconnectCandidate = nil
        if let candidate {
            await candidate.closeTransportAndWait(cause: "reconnect_cancelled")
        }
    }

    public func close() async {
        await close(onEvent: nil)
    }

    func closeForTesting(onEvent: @escaping @Sendable (SMBClientCloseEvent) -> Void) async {
        await close(onEvent: onEvent)
    }

    private func close(onEvent: (@Sendable (SMBClientCloseEvent) -> Void)?) async {
        if let closeTask {
            onEvent?(.joinedExistingCleanup)
            await closeTask.value
            return
        }
        guard !isClosed else {
            onEvent?(.returnedWithoutJoining)
            return
        }

        isClosed = true
        let closingSession = session
        let closingTreeId = treeId
        let waiters = Array(reconnectWaiters.values)
        reconnectWaiters.removeAll()
        waiters.forEach { $0.resume(throwing: SMBError.connectionLost(operation: "RECONNECT")) }
        let candidateSession = reconnectCandidate?.session
        self.reconnectCandidate = nil
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectTaskID = nil
        let keepAliveTask = self.keepAliveTask
        self.keepAliveTask = nil
        keepAliveTask?.cancel()

        let task = Task {
            await self.performClose(
                session: closingSession,
                treeId: closingTreeId,
                candidateSession: candidateSession,
                keepAliveTask: keepAliveTask
            )
        }
        closeTask = task
        await task.value
    }

    private func performClose(
        session closingSession: SMBSession,
        treeId closingTreeId: UInt32,
        candidateSession: SMBSession?,
        keepAliveTask: Task<Void, Never>?
    ) async {
        if let candidateSession {
            await candidateSession.closeTransportAndWait(cause: "client_close_during_reconnect")
        }
        await waitForTreeSetupsOrCloseDeadline()
        await keepAliveTask?.value
        // On a drain timeout the shared transport is already closed, so children are still
        // released here (their close sends nothing) and only the graceful disconnect is skipped.
        let echoDrained = await closingSession.drainEchoResponsesBeforeDisconnect()

        let children = Array(childTrees.values)
        childTrees.removeAll()
        for child in children {
            await child.child.closeIfMatching(session: child.session, treeId: child.treeId)
        }
        guard echoDrained else { return }
        await closingSession.disconnect(treeId: closingTreeId)
    }

    private func waitForTreeSetupsOrCloseDeadline() async {
        guard !treeSetupSessions.isEmpty else { return }
        let waiterID = UUID()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            closeSetupDrainWaiterID = waiterID
            closeSetupDrainContinuation = continuation
            closeSetupDeadlineTask = Task {
                do {
                    try await self.closeSetupDeadlineSleeper(Self.closeSetupTimeout)
                } catch {
                    guard !Task.isCancelled else { return }
                }
                await self.closeTreeSetupDeadlineDidFire(waiterID: waiterID)
            }
        }
    }

    private func closeTreeSetupDeadlineDidFire(waiterID: UUID) async {
        guard closeSetupDrainWaiterID == waiterID,
              let continuation = closeSetupDrainContinuation
        else {
            return
        }
        closeSetupDrainWaiterID = nil
        closeSetupDrainContinuation = nil
        closeSetupDeadlineTask = nil
        closeSetupDeadlineExpired = true
        let setupSessions = Array(treeSetupSessions.values)
        for setupSession in setupSessions {
            await setupSession.closeTransport(cause: "client_close_tree_setup_deadline")
        }
        continuation.resume()
    }

    private func finishTreeSetup(_ setupID: UUID) {
        treeSetupSessions[setupID] = nil
        guard treeSetupSessions.isEmpty,
              let continuation = closeSetupDrainContinuation
        else {
            return
        }
        closeSetupDrainWaiterID = nil
        closeSetupDrainContinuation = nil
        closeSetupDeadlineTask?.cancel()
        closeSetupDeadlineTask = nil
        continuation.resume()
    }

    public func echo() async throws {
        try ensureOpen()
        try await session.echo()
    }

    /// Hold an SMB2 byte-range lock on `path` while `body` runs.
    ///
    /// The lock is taken on a dedicated open handle and released (UNLOCK + CLOSE) when `body`
    /// returns or throws. SMB byte-range locks are per-open-handle: an exclusive lock taken here
    /// also blocks this session's own read/write operations on the locked range, because those
    /// operations open their own handles. Use `shared: true` to coordinate readers.
    ///
    /// - Parameters:
    ///   - offset: Byte offset of the locked range.
    ///   - length: Byte length of the locked range.
    ///   - shared: `true` for a shared (read) lock, `false` for an exclusive lock.
    ///   - failImmediately: `true` to fail with `SMBError.lockConflict` instead of blocking
    ///     when the range is already locked by another open.
    public func withFileLock<T: Sendable>(
        path: String,
        offset: UInt64,
        length: UInt64,
        shared: Bool = false,
        failImmediately: Bool = true,
        _ body: @Sendable () async throws -> T
    ) async throws -> T {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .byteRangeLock(path: path))
        do {
            try await session.lock(
                treeId: treeId,
                fileId: fileId,
                elements: [.lock(offset: offset, length: length, shared: shared, failImmediately: failImmediately)]
            )
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
        do {
            let result = try await body()
            try? await session.lock(treeId: treeId, fileId: fileId, elements: [.unlock(offset: offset, length: length)])
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return result
        } catch {
            try? await session.lock(treeId: treeId, fileId: fileId, elements: [.unlock(offset: offset, length: length)])
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Start sending periodic authenticated SMB2 ECHO requests for this persistent session.
    /// If an ECHO fails, the underlying transport is closed and the keepalive loop stops.
    public func startKeepAlive(interval: Duration = .seconds(60)) throws {
        try ensureOpen()
        guard interval > .zero, interval <= .seconds(7 * 24 * 60 * 60) else {
            throw SMBCodecError.invalidValue("keep-alive interval must be greater than zero and at most 7 days")
        }
        keepAliveTask?.cancel()
        let session = session
        keepAliveTask = Task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: interval)
                    try Task.checkCancellation()
                    try await session.echo()
                } catch is CancellationError {
                    break
                } catch {
                    await session.closeTransportAndWait(cause: "keepalive_echo", diagnosticError: error)
                    break
                }
            }
        }
    }

    /// Stop the periodic keepalive task if one is active.
    public func stopKeepAlive() {
        keepAliveTask?.cancel()
        keepAliveTask = nil
    }

    public func withTree<T: Sendable>(
        share: String,
        operation: @Sendable (SMBClientTreeSession) async throws -> T
    ) async throws -> T {
        try ensureOpen()
        let setupID = UUID()
        let setupSession = session
        treeSetupSessions[setupID] = setupSession
        let childTreeId: UInt32
        do {
            childTreeId = try await setupSession.treeConnect(share: share)
        } catch {
            finishTreeSetup(setupID)
            throw error
        }
        guard !(isClosed && closeSetupDeadlineExpired) else {
            finishTreeSetup(setupID)
            throw SMBError.connectionLost(operation: "SESSION")
        }
        let child = SMBClientTreeSession(session: setupSession, treeId: childTreeId)
        let childID = UUID()
        // The child retains the exact wire session and TreeId that TREE_CONNECT returned, so
        // close cannot accidentally apply a stale TreeId to a replacement reconnect session.
        childTrees[childID] = ScopedTree(session: setupSession, treeId: childTreeId, child: child)
        finishTreeSetup(setupID)
        guard !isClosed else {
            throw SMBError.connectionLost(operation: "SESSION")
        }
        do {
            let result = try await operation(child)
            await child.close()
            childTrees[childID] = nil
            return result
        } catch {
            await child.close()
            childTrees[childID] = nil
            throw error
        }
    }

    /// Enumerate shares over IPC$ using this authenticated session.
    ///
    /// The temporary IPC$ tree is disconnected when enumeration completes; the
    /// session's original tree remains usable for subsequent operations.
    public func listShares() async throws -> [SMBShareInfo] {
        try await withTree(share: "IPC$") { tree in
            try await tree.listShares()
        }
    }

    /// Resolve DFS referral metadata through a scoped DFS-root tree on this session.
    public func dfsReferral(share: String, path: String) async throws -> SMBDfsReferralResult {
        try await withTree(share: share) { tree in
            try await tree.dfsReferral(path: path)
        }
    }

    public func list(path: String = "") async throws -> [SMBDirectoryEntry] {
        let collector = SMBDirectoryEntryCollector()
        try await withDirectoryStream(path: path) { entry in
            collector.append(entry)
        }
        return collector.entries
    }

    /// Resolve the server-side directory entry for `path` by querying its parent
    /// directory with the leaf name as the QUERY_DIRECTORY search pattern.
    ///
    /// On case-insensitive (case-preserving) shares — the Windows / macOS / Samba
    /// default — the server matches the pattern case-insensitively and returns the
    /// entry under its **canonical (case-preserved) name**. This is the cheap
    /// (single round-trip, no full listing) way to recover the canonical name after
    /// a write that was issued with a differently-cased path; `SMBFileStat` and the
    /// SMB2 CREATE response do not carry it.
    ///
    /// Only `SMBClientSession` provides this: the caller that needs canonical names
    /// (obaket's SMB adapter, issue 505) drives every write through a persistent
    /// session, and `SMBClientTreeSession` exists for scoped one-off trees (IPC$
    /// share enumeration, DFS referral) that never write. Add the tree-session
    /// counterpart when a consumer actually writes through a scoped tree.
    ///
    /// **The parent is enumerated in full and matched client-side.** Using the leaf
    /// as a QUERY_DIRECTORY search pattern would be cheaper, but the match is
    /// performed by the *server* and MS-SMB2 does not specify its semantics: macOS
    /// shares answer a `report.txt` pattern with an entry whose FileName is the
    /// requested spelling rather than the stored `Report.TXT` (measured 2026-08-19
    /// against a real share), which silently defeats the entire purpose of this
    /// call. Only a client-side comparison against the enumerated names is
    /// trustworthy across servers.
    ///
    /// Returns nil for the share root (no leaf to resolve) and when no entry
    /// matches. Names are compared exactly first, then case-insensitively.
    public func directoryEntry(matching path: String) async throws -> SMBDirectoryEntry? {
        try ensureOpen()
        let components = path.replacingOccurrences(of: "\\", with: "/")
            .split(separator: "/")
            .map(String.init)
        guard let leaf = components.last else { return nil }
        guard !components.contains("."), !components.contains("..") else {
            throw SMBCodecError.invalidValue("SMB path must not contain . or .. components")
        }
        let parent = components.dropLast().joined(separator: "/")
        return try await directoryEntry(inParent: parent, leaf: leaf)
    }

    private func directoryEntry(inParent parent: String, leaf: String) async throws -> SMBDirectoryEntry? {
        let fileId = try await session.create(treeId: treeId, path: parent, directory: true)
        do {
            let collector = SMBDirectoryEntryCollector()
            try await session.queryDirectory(treeId: treeId, fileId: fileId) { entry in
                collector.append(entry)
            }
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return SMBDirectoryEntrySelection.entry(matching: leaf, from: collector.entries)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func withDirectoryStream(
        path: String = "",
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: true)
        do {
            try await session.queryDirectory(treeId: treeId, fileId: fileId, onEntry: onEntry)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Watch `path` for changes, delivering each event to `onChange` until the task is
    /// cancelled.
    ///
    /// - Parameter autoReconnect: when true and this session was created via `connect(...)`,
    ///   a dropped connection (transport failure / connection lost) triggers a reconnect and
    ///   the watch resubscribes, rather than propagating the error. Because CHANGE_NOTIFY only
    ///   reports changes while a subscription is registered, events that occur during the
    ///   reconnect gap are missed; a `.overflow` (full rescan) event is delivered after each
    ///   successful resubscribe so callers can reconcile. Cancellation and non-connection
    ///   errors always propagate.
    /// - Parameter maxReconnectAttempts: consecutive reconnect failures tolerated before the
    ///   last error propagates. Reset to zero after any successful resubscribe.
    public func withChangeNotifications(
        path: String = "",
        filter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        autoReconnect: Bool = false,
        maxReconnectAttempts: Int = 5,
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        try ensureOpen()
        var reconnectAttempts = 0
        while true {
            guard !isClosed else { return }
            try Task.checkCancellation()
            let watchedSession = session
            let watchedTreeId = treeId
            let watchedGeneration = sessionGeneration
            do {
                let fileId = try await watchedSession.create(
                    treeId: watchedTreeId,
                    request: .changeNotify(path: path)
                )
                guard !isClosed else {
                    await watchedSession.bestEffortClose(treeId: watchedTreeId, fileId: fileId)
                    return
                }
                do {
                    try await watchedSession.changeNotify(
                        treeId: watchedTreeId,
                        fileId: fileId,
                        filter: filter,
                        watchTree: watchTree,
                        shouldContinue: { await self.isWatchingOpen() },
                        onChange: onChange
                    )
                    await watchedSession.bestEffortClose(treeId: watchedTreeId, fileId: fileId)
                    return
                } catch {
                    await watchedSession.bestEffortClose(treeId: watchedTreeId, fileId: fileId)
                    throw error
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                guard !isClosed else { return }
                guard autoReconnect, reconnectInfo != nil, Self.isReconnectable(error) else {
                    throw error
                }
                try Task.checkCancellation()
                do {
                    try await reconnect(expectedGeneration: watchedGeneration)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    guard !isClosed else { return }
                    reconnectAttempts += 1
                    if reconnectAttempts >= maxReconnectAttempts {
                        throw error
                    }
                    continue
                }
                guard !isClosed else { return }
                reconnectAttempts = 0
                // The subscription lapsed during the reconnect; signal a full rescan before
                // resubscribing so the caller can reconcile any changes missed in the gap.
                try await onChange(.overflow)
            }
        }
    }

    /// Connection-loss errors that justify a watch reconnect (vs. propagating).
    private static func isReconnectable(_ error: Error) -> Bool {
        switch error {
        case SMBError.connectionLost, SMBError.transport, SMBError.networkNameDeleted:
            return true
        case SMBTransportError.connectionClosed, SMBTransportError.timedOut:
            return true
        case SMBTransportError.socketFailure:
            return true
        default:
            return false
        }
    }

    private func isWatchingOpen() -> Bool {
        !isClosed
    }

    public func stat(path: String) async throws -> SMBFileStat {
        try ensureOpen()
        let fileId = try await session.createForMetadata(treeId: treeId, path: path)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return stat
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func readlink(path: String) async throws -> SMBReparsePoint {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .reparsePoint(path: path))
        do {
            let reparsePoint = try await session.reparsePoint(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return reparsePoint
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func securityInfo(path: String) async throws -> SMBSecurityInfo {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .querySecurity(path: path))
        do {
            let info = try await session.querySecurityInfo(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return info
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func setSecurityInfo(path: String, dacl: [SMBAccessControlEntry], force: Bool = false) async throws {
        try await setSecurityInfo(path: path, ownerSID: nil, groupSID: nil, dacl: dacl, force: force)
    }

    /// Write the provided security descriptor components. Non-nil components are set
    /// (AdditionalInformation OWNER/GROUP/DACL bits); nil components are left untouched
    /// by the server. Setting owner/group requires WRITE_OWNER access on the open and,
    /// for arbitrary owners, server-side privilege — setting the caller's own SID is the
    /// portable case. SACL is intentionally unsupported (requires SeSecurityPrivilege).
    public func setSecurityInfo(
        path: String,
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool = false
    ) async throws {
        try ensureOpen()
        if let dacl {
            try SMB2SetInfo.validateWritableDACL(dacl, force: force)
        }
        let includeOwner = ownerSID != nil || groupSID != nil
        let fileId = try await session.create(treeId: treeId, request: .setSecurity(path: path, includeOwner: includeOwner))
        do {
            try await session.setSecurityInfo(
                treeId: treeId,
                fileId: fileId,
                ownerSID: ownerSID,
                groupSID: groupSID,
                dacl: dacl,
                force: force
            )
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Mark `path` as a sparse file (FSCTL_SET_SPARSE). Idempotent on servers that
    /// already treat the file as sparse.
    public func setSparse(path: String, sparse: Bool = true) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .sparse(path: path))
        do {
            try await session.setSparse(treeId: treeId, fileId: fileId, sparse: sparse)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Zero (punch a hole in) `[offset, offset+length)` via FSCTL_SET_ZERO_DATA. On a sparse
    /// file this deallocates whole clusters; otherwise it writes zeroes. Call `setSparse`
    /// first to reclaim space.
    public func zeroRange(path: String, offset: UInt64, length: UInt64) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .sparse(path: path))
        do {
            try await session.setZeroData(treeId: treeId, fileId: fileId, offset: offset, length: length)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Query the allocated (non-hole) byte ranges within `[offset, offset+length)` via
    /// FSCTL_QUERY_ALLOCATED_RANGES. An empty result means the region is fully sparse.
    public func allocatedRanges(path: String, offset: UInt64 = 0, length: UInt64) async throws -> [SMBAllocatedRange] {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .sparse(path: path))
        do {
            let ranges = try await session.queryAllocatedRanges(treeId: treeId, fileId: fileId, offset: offset, length: length)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return ranges
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func volumeInfo() async throws -> SMBVolumeInfo {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: "", directory: true)
        do {
            let info = try await session.volumeInfo(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return info
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// - Parameter knownSize: `withReadStream(path:range:knownSize:...)` と同じ意味
    ///   (渡すと QUERY_INFO を送らない)。
    public func read(
        path: String,
        range: SMBReadRange? = nil,
        knownSize: UInt64? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let size = try await resolvedSize(knownSize: knownSize, fileId: fileId)
            let (start, requested) = try readBounds(size: size, range: range, sizeIsCallerProvided: knownSize != nil)
            let data = try await SMBClient.readAll(session: session, treeId: treeId, fileId: fileId, offset: start, length: requested, onProgress: onProgress)
            guard UInt64(data.count) == requested else {
                throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(data.count)")
            }
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return data
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// - Parameter knownSize: 呼び出し側が既に知っているファイルサイズ。渡すと EOF
    ///   クランプのための **QUERY_INFO を送らない** (往復 1 回の削減)。listing で size を
    ///   得ている consumer が、同一ファイルを複数の range に分けて読むときに効く
    ///   (`issues/067` の「動画 range read profile」)。値が実サイズより大きい場合は
    ///   short read として loud に失敗する (`resolvedSize` の doc 参照)。
    /// - Parameter operationTimeout: Deadline from CREATE through all READs and CLOSE.
    public nonisolated func withReadStream(
        path: String,
        range: SMBReadRange? = nil,
        knownSize: UInt64? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
        operationTimeout: Duration? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await self.withReadStreamCore(
                path: path,
                range: range,
                knownSize: knownSize,
                onProgress: onProgress,
                onChunk: onChunk
            )
        }
    }

    private func withReadStreamCore(
        path: String,
        range: SMBReadRange?,
        knownSize: UInt64?,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try ensureOpen()
        try Task.checkCancellation()
        let progress = SMBReadStreamProgress()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let size = try await resolvedSize(knownSize: knownSize, fileId: fileId)
            let (start, requested) = try readBounds(size: size, range: range, sizeIsCallerProvided: knownSize != nil)
            try await SMBClient.streamRead(
                session: session,
                treeId: treeId,
                fileId: fileId,
                offset: start,
                length: requested,
                progress: progress,
                onProgress: onProgress,
                onChunk: onChunk
            )
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            if progress.startedYielding, error.isSMBConnectionLoss {
                throw SMBError.connectionLost(operation: "READ")
            }
            throw error
        }
    }

    /// Read up to `maxLength` bytes from offset zero without issuing QUERY_INFO.
    ///
    /// A short success is treated as a best-effort EOF indication: it is not proof of the
    /// file size, but it ends this operation immediately and returns the bytes received.
    /// This API is intentionally session-only for now; the static facade and provider
    /// overloads are omitted because consumers use a persistent `SMBClientSession`.
    /// No `onProgress` is accepted because `maxLength` is not the actual file size and would
    /// report misleading completion for a shorter file.
    ///
    /// - Throws: If `maxLength` exceeds the in-memory accumulation limit.
    public func readPrefix(path: String, maxLength: UInt64) async throws -> [UInt8] {
        try ensureOpen()
        // The zero-length early return below skips every wire call, so this is the only
        // point where a pre-cancelled task gets rejected instead of "succeeding" with [].
        try Task.checkCancellation()
        guard maxLength <= Self.maxPrefixReadLength else {
            throw SMBCodecError.invalidValue("prefix read exceeds the in-memory limit")
        }
        guard maxLength > 0 else { return [] }

        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let data = try await SMBClient.prefixRead(
                session: session,
                treeId: treeId,
                fileId: fileId,
                maxLength: maxLength,
                sink: .accumulate
            )
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return data
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Stream a best-effort prefix from offset zero without issuing QUERY_INFO.
    ///
    /// A short success is not proof of the file size and ends the operation immediately.
    /// `maxLength` shares `readPrefix`'s limit even though nothing is accumulated, so this API is
    /// not used as an unbounded download; use `withReadStream(range:)` for larger reads. A connection
    /// loss after a chunk was yielded is normalized to `SMBError.connectionLost(operation: "READ")`.
    ///
    /// There is no built-in operation timeout (the same holds for `withReadStream`). A caller that
    /// needs a deadline wraps this call in `SMBOperationDeadline.run(timeout:)`: the cancellation it
    /// raises is observed after each chunk and by an in-flight READ, and the handle is then closed
    /// best-effort. If that CLOSE gets no response either, the session tears down the whole
    /// transport after its cleanup timeout, so the call can return up to that much later than the
    /// deadline and other operations on the same session fail too. A timeout parameter here could
    /// not do more: `SMBOperationDeadline` waits for the operation task, so an `onChunk` that ignores
    /// cancellation still keeps this call (and the handle) alive.
    ///
    /// - Throws: If `maxLength` exceeds the prefix read limit, before any request is sent.
    public func withPrefixReadStream(
        path: String,
        maxLength: UInt64,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try ensureOpen()
        // Same as readPrefix: reject a pre-cancelled task before the zero-length early return.
        try Task.checkCancellation()
        guard maxLength <= Self.maxPrefixReadLength else {
            throw SMBCodecError.invalidValue("prefix stream exceeds the prefix read limit; use withReadStream(range:)")
        }
        guard maxLength > 0 else { return }

        let progress = SMBReadStreamProgress()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            _ = try await SMBClient.prefixRead(
                session: session,
                treeId: treeId,
                fileId: fileId,
                maxLength: maxLength,
                sink: .stream(progress: progress, onChunk: onChunk)
            )
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            if progress.startedYielding, error.isSMBConnectionLoss {
                throw SMBError.connectionLost(operation: "READ")
            }
            throw error
        }
    }

    public func makeDirectory(path: String) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
        try await session.closeCreatedHandle(treeId: treeId, fileId: fileId)
    }

    public func upload(
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
        do {
            try await session.write(treeId: treeId, fileId: fileId, data: data, onProgress: onProgress)
            try await session.flush(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Upload bytes supplied asynchronously. The supplier receives the current credit-aware
    /// maximum chunk size for each request. Returning an empty chunk completes the byte stream.
    /// Progress is emitted after the supplier returns a non-empty chunk and before its WRITE is sent.
    public func upload(
        path: String,
        overwrite: Bool = true,
        totalBytes: UInt64,
        nextChunk: @escaping @Sendable (Int) async throws -> [UInt8],
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
        let progress = SMBTransferProgressEmitter(totalBytes: totalBytes, onProgress: onProgress)
        do {
            try await session.write(
                treeId: treeId,
                fileId: fileId,
                offset: 0,
                nextChunk: nextChunk,
                onProgress: { bytesTransferred in
                    progress.emit(bytesTransferred: bytesTransferred)
                }
            )
            await progress.finish()
            try await session.flush(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Download a file using this already-connected session.
    /// - Parameter operationTimeout: Deadline from temporary-file creation through stream cleanup and installation.
    public nonisolated func download(
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        operationTimeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await self.downloadCore(
                path: path,
                localFile: localFile,
                overwrite: overwrite,
                onProgress: onProgress
            )
        }
    }

    private func downloadCore(
        path: String,
        localFile: URL,
        overwrite: Bool,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?
    ) async throws {
        try ensureOpen()
        try Task.checkCancellation()
        if !overwrite && FileManager.default.fileExists(atPath: localFile.path) {
            throw SMBCodecError.invalidValue("local destination already exists")
        }
        let fileManager = FileManager.default
        let temporary = localFile.deletingLastPathComponent()
        let temporaryFile = try makeSMBDownloadTemporaryFile(in: temporary)
        let temporaryURL = temporaryFile.url
        defer { try? fileManager.removeItem(at: temporaryURL) }
        let handle = temporaryFile.handle
        defer { try? handle.close() }
        let sink = SMBDownloadSink(handle: handle, onProgress: onProgress)
        try await withReadStream(path: path) { chunk in
            try sink.handle.write(contentsOf: Data(chunk))
            sink.total += UInt64(chunk.count)
            sink.onProgress?(SMBTransferProgress(bytesTransferred: sink.total, totalBytes: nil, bytesPerSecond: 0))
        }
        try handle.close()
        try await SMBDownloadTestSeams.beforeDestinationInstall?()
        try Task.checkCancellation()
        if fileManager.fileExists(atPath: localFile.path) {
            try smbReplaceItem(at: localFile, with: temporaryURL, fileManager: fileManager)
        } else {
            try fileManager.moveItem(at: temporaryURL, to: localFile)
        }
    }

    public func upload(
        path: String,
        fileURL: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try ensureOpen()
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        let sourceSnapshot = try SMBLocalFileSnapshot(handle: handle)
        let totalBytes = sourceSnapshot.size
        let remoteSize: UInt64
        var fileId: [UInt8]
        if resume {
            do {
                fileId = try await session.create(treeId: treeId, request: .uploadResume(path: path))
                remoteSize = try await session.queryInfo(treeId: treeId, fileId: fileId).size
            } catch SMBError.notFound {
                remoteSize = 0
                fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: true))
            }
            guard remoteSize <= totalBytes else {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw SMBCodecError.invalidValue("remote file is larger than local source")
            }
        } else {
            remoteSize = 0
            fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
        }
        let progress = SMBTransferProgressEmitter(totalBytes: totalBytes, onProgress: onProgress)
        var bytesTransferred = remoteSize
        do {
            if remoteSize > 0 {
                try handle.seek(toOffset: 0)
                var compared: UInt64 = 0
                while compared < remoteSize {
                    let requested = min(remoteSize - compared, UInt64(Self.localWriteChunkLimit))
                    let remote = try await session.readChunk(
                        treeId: treeId,
                        fileId: fileId,
                        offset: compared,
                        length: requested
                    )
                    let local = try handle.read(upToCount: remote.count) ?? Data()
                    guard !remote.isEmpty, local.count == remote.count, Array(local) == remote else {
                        throw SMBCodecError.invalidValue("remote upload resume prefix does not match local source")
                    }
                    compared += UInt64(remote.count)
                }
                let verifiedSize = try await session.queryInfo(treeId: treeId, fileId: fileId).size
                guard verifiedSize == remoteSize else {
                    throw SMBCodecError.invalidValue("remote file changed during upload resume validation")
                }
            }
            try handle.seek(toOffset: remoteSize)
            try await session.write(treeId: treeId, fileId: fileId, offset: remoteSize) { maxLength in
                let remaining = totalBytes - bytesTransferred
                guard remaining > 0 else { return [] }
                let length = min(maxLength, Self.localWriteChunkLimit, Int(clamping: remaining))
                let data = try handle.read(upToCount: length) ?? Data()
                guard !data.isEmpty else {
                    throw SMBCodecError.invalidValue("local source file ended before its initial size")
                }
                bytesTransferred += UInt64(data.count)
                progress.emit(bytesTransferred: bytesTransferred)
                return Array(data)
            }
            await progress.finish()
            guard bytesTransferred == totalBytes else {
                throw SMBCodecError.invalidValue("local source file ended before its initial size")
            }
            guard try SMBLocalFileSnapshot(handle: handle) == sourceSnapshot else {
                throw SMBCodecError.invalidValue("local source file changed during upload")
            }
            try await session.flush(treeId: treeId, fileId: fileId)
            guard try SMBLocalFileSnapshot(handle: handle) == sourceSnapshot else {
                throw SMBCodecError.invalidValue("local source file changed during upload")
            }
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func copy(fromPath: String, toPath: String, overwrite: Bool = false) async throws {
        try ensureOpen()
        try await session.copyFile(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
    }

    public func copyDirectory(
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try ensureOpen()
        try SMBPath.validateDirectoryCopyTarget(fromPath: fromPath, toPath: toPath)
        try await session.copyDirectory(
            treeId: treeId,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            onAction: onAction
        )
    }

    public func rename(fromPath: String, toPath: String, replaceIfExists: Bool = false) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .rename(path: fromPath))
        do {
            try await session.rename(treeId: treeId, fileId: fileId, newPath: toPath, replaceIfExists: replaceIfExists)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func delete(
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        continueOnError: Bool = false,
        dryRun: Bool = false,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try ensureOpen()
        if recursive {
            try await session.deleteRecursively(
                treeId: treeId,
                path: path,
                directory: directory,
                continueOnError: continueOnError,
                dryRun: dryRun,
                onAction: onAction
            )
            return
        }
        if dryRun {
            onAction?(SMBRecursiveAction(kind: .delete, path: path))
            return
        }
        try await session.deleteNonRecursive(treeId: treeId, path: path, directory: directory)
    }

    public func updateMetadata(path: String, update: SMBFileMetadataUpdate, directory: Bool = false) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .metadata(path: path, directory: directory))
        do {
            try await session.setBasicInfo(treeId: treeId, fileId: fileId, update: update)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    private func ensureOpen() throws {
        if isClosed {
            throw SMBError.connectionLost(operation: "SESSION")
        }
    }

    /// - Parameter sizeIsCallerProvided: `size` が `knownSize` 由来か。
    ///
    ///   QUERY_INFO 由来 (= サーバの現在値) なら、要求 range が末尾を超えていても
    ///   **EOF クランプとして黙って短くしてよい** (従来どおりの正当な挙動)。
    ///   一方 `knownSize` 由来のときに range がその size を超えるのは **caller 内部の
    ///   矛盾**で、黙って短く返すと silent truncation になる。API doc が「silent
    ///   truncation にはならない」と宣言している以上、ここで loud に落とす。
    private func readBounds(
        size: UInt64,
        range: SMBReadRange?,
        sizeIsCallerProvided: Bool
    ) throws -> (offset: UInt64, length: UInt64) {
        let start = range?.offset ?? 0
        guard start <= size else {
            throw SMBCodecError.invalidValue("read range starts past end of file")
        }
        let available = size - start
        guard let range else { return (start, available) }
        guard !sizeIsCallerProvided || range.length <= available else {
            throw SMBCodecError.invalidValue(
                "read range exceeds caller-provided knownSize (requested \(range.length), available \(available))"
            )
        }
        return (start, min(range.length, available))
    }

    /// EOF クランプに使うファイルサイズを決める。`knownSize` が渡されていれば
    /// QUERY_INFO を **送らずに** それを使う (往復 1 回の削減)。
    ///
    /// `knownSize` が **実サイズより大きい** と、要求長がファイル末尾を超えるため READ が
    /// 要求より少なく返り、呼び出し元の契約 (`read` は short read = error、`withReadStream`
    /// は `streamRead` の short read 判定) で **loud に失敗**する。
    /// `knownSize` が **実サイズより小さい** 場合は、その size までしか読まない
    /// (= caller が宣言した範囲を読む)。range を明示しつつ `knownSize` を超える長さを
    /// 要求した場合は `readBounds` が loud に落とす。いずれも silent truncation にはしない。
    /// 正しい size を渡す責任は呼び出し側にある。
    private func resolvedSize(knownSize: UInt64?, fileId: [UInt8]) async throws -> UInt64 {
        if let knownSize { return knownSize }
        return try await session.queryInfo(treeId: treeId, fileId: fileId).size
    }
}

/// `directoryEntry(matching:)` の結果選択 (pure)。server の pattern match が
/// wildcard で over-match した場合に備え、leaf との一致 (exact 優先 →
/// case-insensitive) で絞り込む。
enum SMBDirectoryEntrySelection {
    static func entry(matching leaf: String, from entries: [SMBDirectoryEntry]) -> SMBDirectoryEntry? {
        if let exact = entries.first(where: { $0.name == leaf }) {
            return exact
        }
        return entries.first { $0.name.compare(leaf, options: [.caseInsensitive]) == .orderedSame }
    }
}

public actor SMBClientTreeSession {
    private let session: SMBSession
    private let treeId: UInt32
    private var isClosed = false
    private var closeTask: Task<Void, Never>?

    init(session: SMBSession, treeId: UInt32) {
        self.session = session
        self.treeId = treeId
    }

    public func close() async {
        await close(onEvent: nil)
    }

    func closeForTesting(onEvent: @escaping @Sendable (SMBClientCloseEvent) -> Void) async {
        await close(onEvent: onEvent)
    }

    func closeIfMatching(session expectedSession: SMBSession, treeId expectedTreeId: UInt32) async {
        guard session === expectedSession, treeId == expectedTreeId else { return }
        await close(onEvent: nil)
    }

    private func close(onEvent: (@Sendable (SMBClientCloseEvent) -> Void)?) async {
        if let closeTask {
            onEvent?(.joinedExistingCleanup)
            await closeTask.value
            return
        }
        guard !isClosed else {
            onEvent?(.returnedWithoutJoining)
            return
        }
        isClosed = true
        let task = Task {
            await session.bestEffortTreeDisconnect(treeId: treeId)
        }
        closeTask = task
        await task.value
    }

    public func list(path: String = "") async throws -> [SMBDirectoryEntry] {
        let collector = SMBDirectoryEntryCollector()
        try await withDirectoryStream(path: path) { entry in
            collector.append(entry)
        }
        return collector.entries
    }

    public func withDirectoryStream(
        path: String = "",
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: true)
        do {
            try await session.queryDirectory(treeId: treeId, fileId: fileId, onEntry: onEntry)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func stat(path: String) async throws -> SMBFileStat {
        try ensureOpen()
        let fileId = try await session.createForMetadata(treeId: treeId, path: path)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return stat
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func readlink(path: String) async throws -> SMBReparsePoint {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .reparsePoint(path: path))
        do {
            let reparsePoint = try await session.reparsePoint(treeId: treeId, fileId: fileId)
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            return reparsePoint
        } catch {
            await session.bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Enumerate server shares through the SRVSVC named pipe on this tree.
    /// This is intended for an IPC$ tree returned by `SMBClientSession.withTree`.
    public func listShares() async throws -> [SMBShareInfo] {
        try ensureOpen()
        return try await session.listShares(treeId: treeId)
    }

    public func dfsReferral(path: String) async throws -> SMBDfsReferralResult {
        try ensureOpen()
        return try await session.dfsReferral(treeId: treeId, path: path)
    }

    private func ensureOpen() throws {
        if isClosed {
            throw SMBError.connectionLost(operation: "TREE")
        }
    }
}

public enum SMBClient {
    private static let dfsReferralCache = SMBDfsReferralCache()

    private static func dfsShare(from path: String) throws -> String {
        let components = path.split(separator: "\\", omittingEmptySubsequences: true)
        guard components.count >= 2 else {
            throw SMBCodecError.invalidValue("DFS referral path must be in \\\\server\\share[\\path] form")
        }
        return try SMBShareName(String(components[1])).rawValue
    }

    static func dfsTarget(from networkAddress: String) throws -> SMBDfsReferralTarget {
        guard let target = SMBDfsReferralTarget(networkAddress: networkAddress) else {
            throw SMBCodecError.invalidValue("DFS referral target must be in \\\\server\\share form")
        }
        return target
    }

    private static func dfsRelativePath(from path: String) throws -> String {
        let components = path.split(separator: "\\", omittingEmptySubsequences: true)
        guard components.count >= 2 else {
            throw SMBCodecError.invalidValue("DFS path must be in \\\\server\\share[\\path] form")
        }
        return components.dropFirst(2).joined(separator: "\\")
    }

    static func dfsPathSuffix(_ path: String, consumedUTF16Bytes: Int) throws -> String {
        guard consumedUTF16Bytes >= 0, consumedUTF16Bytes.isMultiple(of: 2) else {
            throw SMBCodecError.invalidValue("DFS PathConsumed must be an even UTF-16 byte count")
        }
        let units = Array(path.utf16)
        // Samba reports PathConsumed from the first server-name character and
        // excludes one of the two UNC leading separators. Restore that UTF-16
        // code unit before slicing the caller's canonical UNC string.
        let uncAdjustment = path.hasPrefix("\\\\") ? 1 : 0
        let consumedUnits = consumedUTF16Bytes / 2 + uncAdjustment
        guard consumedUnits <= units.count else {
            throw SMBCodecError.invalidValue("DFS PathConsumed exceeds referral path length")
        }
        return String(decoding: units.dropFirst(consumedUnits), as: UTF16.self)
    }

    private static func resolveDFSPath(
        host: String,
        port: UInt16,
        credential: SMBCredential,
        path: String,
        timeout: Duration?,
        requestTimeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        maxHops: Int
    ) async throws -> SMBDfsResolvedPath {
        guard maxHops > 0 else {
            throw SMBCodecError.invalidValue("DFS maxHops must be greater than zero")
        }
        var currentPath = path
        var visited = Set<String>()

        for hop in 0..<maxHops {
            let endpoint = try dfsTarget(from: currentPath)
            let visitKey = "\(endpoint.host.lowercased())/\(endpoint.share.lowercased())/\(currentPath.lowercased())"
            guard visited.insert(visitKey).inserted else {
                throw SMBCodecError.invalidValue("DFS referral loop detected")
            }

            do {
                let referral = try await cachedDFSReferral(
                    host: endpoint.host, port: port, credential: credential, path: currentPath,
                    timeout: timeout, requestTimeout: requestTimeout, makeTransport: makeTransport
                )
                guard let target = referral.targets.first,
                      let networkAddress = referral.referrals.first(where: { $0.target == target })?.networkAddress else {
                    throw SMBCodecError.invalidValue("DFS referral did not include a share target")
                }
                currentPath = networkAddress + (try dfsPathSuffix(currentPath, consumedUTF16Bytes: referral.pathConsumed))
            } catch let error as SMBError {
                if case .unsupported = error {
                    return SMBDfsResolvedPath(
                        host: endpoint.host, share: endpoint.share,
                        path: try dfsRelativePath(from: currentPath), hops: hop
                    )
                }
                throw error
            }
        }
        throw SMBCodecError.invalidValue("DFS referral exceeded maxHops (\(maxHops))")
    }

    private static func cachedDFSReferral(
        host: String, port: UInt16, credential: SMBCredential, path: String,
        timeout: Duration?, requestTimeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?
    ) async throws -> SMBDfsReferralResult {
        let key = SMBDfsReferralCache.Key(host: host, port: port, path: path, credential: credential)
        if let cached = await dfsReferralCache.get(key) { return cached }
        let referral = try await dfsReferral(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, requestTimeout: requestTimeout, makeTransport: makeTransport
        )
        if let ttl = referral.referrals.map(\.timeToLive).min(), ttl > 0 {
            await dfsReferralCache.put(referral, for: key, ttl: ttl)
        }
        return referral
    }

    static func resolvedTransportFactory(
        _ makeTransport: (@Sendable () -> SMBTransport)?,
        timeout: Duration?
    ) -> @Sendable () -> SMBTransport {
        makeTransport ?? SMBTransportTestOverride.factory ?? { POSIXSocketTransport(timeout: timeout) }
    }

    private static func withSession<T>(
        host: String,
        port: UInt16,
        share: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        idempotent: Bool,
        operationName: String,
        operation: (SMBSession, UInt32) async throws -> T
    ) async throws -> T {
        let makeTransport = resolvedTransportFactory(makeTransport, timeout: timeout)
        var retryConnectionLoss = idempotent
        while true {
            let transport = makeTransport()
            let session = SMBSession(host: host, port: port, credential: credential, transport: transport)
            do {
                try await session.connect()
                let treeId = try await session.treeConnect(share: share)
                let result = try await operation(session, treeId)
                // Graceful teardown on success (best-effort TREE_DISCONNECT → LOGOFF → TCP close),
                // matching listShares / the persistent SMBClientSession.close() path. Error paths
                // below close the already-suspect session and retain the failure as a diagnostic.
                await session.disconnect(treeId: treeId)
                return result
            } catch {
                await session.closeTransportAndWait(cause: "with_session_failure", diagnosticError: error)
                guard error.isSMBConnectionLoss else {
                    throw error
                }
                guard retryConnectionLoss else {
                    throw SMBError.connectionLost(operation: operationName)
                }
                retryConnectionLoss = false
            }
        }
    }

    /// 既定の per-request response timeout (issue 010 §修正方針 3 の原設計値 60s)。
    ///
    /// 「server が応答を返さない / RST 無しの half-dead TCP (スリープ復帰後の典型)」は
    /// **本番の失敗モード**であり、応答待ちが unbounded だと consumer は無言でハングする
    /// (obaket issue 453 で実観測: 約 12.5h スリープ後の初回 read が永久に待った。
    /// エラーが出ないため上位のリトライも発火しない)。smbclient / macOS SMBX も
    /// request timeout を持つ。opt-in (nil 既定) は呼び忘れた consumer が全員この罠を
    /// 踏むため、**既定で有効**にする。無効化したい caller は明示的に
    /// `requestTimeout: nil` を渡す。long-poll 系 (change notify / blocking lock /
    /// named-pipe read) は `SMBRequestTimeoutPolicy` の除外により timer 対象外なので、
    /// この値を上げる必要はない。60s は 1 READ/WRITE 応答 (数 MiB frame) が低速回線でも
    /// 収まる寛容側の値。timeout 発火時は `requestDidTimeOut` が transport ごと閉じる
    /// (CommandSequenceWindow の穴を作らないため)。
    public static let defaultRequestTimeout: Duration = .seconds(60)

    /// - Parameters:
    ///   - timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    ///   - requestTimeout: Per-request response timeout that starts only after the complete SMB
    ///     request is sent. This is independent of the socket-level `timeout`. Defaults to
    ///     `defaultRequestTimeout`; pass `nil` explicitly to keep response waits unbounded.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        share: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        requestTimeout: Duration? = SMBClient.defaultRequestTimeout,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBClientSession {
        try await connect(
            host: host,
            port: port,
            share: share,
            credentialProvider: { credential },
            timeout: timeout,
            requestTimeout: requestTimeout,
            makeTransport: makeTransport
        )
    }

    /// - Parameters:
    ///   - timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    ///   - requestTimeout: Per-request response timeout that starts only after the complete SMB
    ///     request is sent. This is independent of the socket-level `timeout`. Defaults to
    ///     `defaultRequestTimeout`; pass `nil` explicitly to keep response waits unbounded.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        share: String,
        credentialProvider: @escaping SMBCredentialProvider,
        timeout: Duration? = nil,
        requestTimeout: Duration? = SMBClient.defaultRequestTimeout,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBClientSession {
        try await connectSession(
            host: host,
            port: port,
            share: share,
            credentialProvider: credentialProvider,
            timeout: timeout,
            requestTimeout: requestTimeout,
            makeTransport: makeTransport,
            requestTimeoutSleeper: { try await Task.sleep(for: $0) }
        )
    }

    private static func connectSession(
        host: String,
        port: UInt16,
        share: String,
        credentialProvider: @escaping SMBCredentialProvider,
        timeout: Duration?,
        requestTimeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        requestTimeoutSleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws -> SMBClientSession {
        let makeTransport = resolvedTransportFactory(makeTransport, timeout: timeout)
        let credential = try await credentialProvider()
        let session = SMBSession(
            host: host,
            port: port,
            credential: credential,
            transport: makeTransport(),
            requestTimeout: requestTimeout,
            requestTimeoutSleeper: requestTimeoutSleeper
        )
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: share)
            let reconnectInfo = SMBClientSession.ReconnectInfo(
                host: host,
                port: port,
                share: share,
                credentialProvider: credentialProvider,
                makeTransport: makeTransport,
                requestTimeout: requestTimeout,
                requestTimeoutSleeper: requestTimeoutSleeper
            )
            return SMBClientSession(session: session, treeId: treeId, reconnectInfo: reconnectInfo)
        } catch {
            await session.closeTransportAndWait(cause: "connect_failure", diagnosticError: error)
            throw error
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> [SMBShareInfo] {
        let makeTransport = resolvedTransportFactory(makeTransport, timeout: timeout)
        let session = SMBSession(host: host, port: port, credential: credential, transport: makeTransport())
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: "IPC$")
            let shares = try await session.listShares(treeId: treeId)
            await session.disconnect(treeId: treeId)
            return shares
        } catch {
            await session.closeTransportAndWait(cause: "list_shares_failure", diagnosticError: error)
            throw error
        }
    }

    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> [SMBShareInfo] {
        try await listShares(
            host: host,
            port: port,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// Resolve SIDs to account names over `IPC$` + `lsarpc` (MS-LSAT). Positional result;
    /// unmapped SIDs are nil.
    public static func lookupSIDs(
        host: String,
        port: UInt16 = 445,
        sids: [String],
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> [SMBResolvedSIDName?] {
        guard !sids.isEmpty else { return [] }
        let makeTransport = resolvedTransportFactory(makeTransport, timeout: timeout)
        let session = SMBSession(host: host, port: port, credential: credential, transport: makeTransport())
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: "IPC$")
            let names = try await session.lookupSIDs(treeId: treeId, sids: sids)
            await session.disconnect(treeId: treeId)
            return names
        } catch {
            await session.closeTransportAndWait(cause: "lookup_sids_failure", diagnosticError: error)
            throw error
        }
    }

    /// Send an authenticated SMB2 ECHO on a connected tree and return when the server replies.
    ///
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func echo(
        host: String,
        port: UInt16 = 445,
        share: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(
            host: host,
            port: port,
            share: share,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport,
            idempotent: true,
            operationName: "ECHO"
        ) { session, _ in
            try await session.echo()
        }
    }

    public static func echo(
        host: String,
        port: UInt16 = 445,
        share: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await echo(
            host: host,
            port: port,
            share: share,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func dfsReferral(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        path: String,
        timeout: Duration? = nil,
        requestTimeout: Duration? = SMBClient.defaultRequestTimeout,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBDfsReferralResult {
        let share = try dfsShare(from: path)
        let session = try await connect(
            host: host, port: port, share: share, credential: credential,
            timeout: timeout, requestTimeout: requestTimeout, makeTransport: makeTransport
        )
        let result = try await session.dfsReferral(share: share, path: path)
        await session.close()
        return result
    }

    /// Resolve `path` through DFS referrals and connect using the same credential.
    /// The returned relative path must be used with the returned session for the
    /// original DFS suffix (for example, `link\\file`).
    /// - Parameters:
    ///   - timeout: Socket-level timeout for connect and each recv/send I/O.
    ///   - requestTimeout: Per-request response timeout propagated to every referral-hop
    ///     connection and the returned target session. Defaults to
    ///     `SMBClient.defaultRequestTimeout`; pass `nil` explicitly to keep response waits unbounded.
    public static func connectFollowingDFS(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        path: String,
        timeout: Duration? = nil,
        requestTimeout: Duration? = SMBClient.defaultRequestTimeout,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBDfsConnection {
        let target = try await resolveDFSPath(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, requestTimeout: requestTimeout,
            makeTransport: makeTransport, maxHops: 8
        )
        let session = try await connect(
            host: target.host, port: port, share: target.share, credential: credential,
            timeout: timeout, requestTimeout: requestTimeout, makeTransport: makeTransport
        )
        return SMBDfsConnection(session: session, path: target.path, hops: target.hops)
    }

    public static func resolveDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        timeout: Duration? = nil, maxHops: Int = 8,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBDfsResolvedPath {
        try await resolveDFSPath(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, requestTimeout: SMBClient.defaultRequestTimeout,
            makeTransport: makeTransport, maxHops: maxHops
        )
    }

    public static func listFollowingDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        timeout: Duration? = nil, maxHops: Int = 8
    ) async throws -> [SMBDirectoryEntry] {
        let resolved = try await resolveDFS(host: host, port: port, credential: credential, path: path, timeout: timeout, maxHops: maxHops)
        return try await list(host: resolved.host, port: port, share: resolved.share, path: resolved.path, credential: credential, timeout: timeout)
    }

    public static func readFollowingDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        range: SMBReadRange? = nil, timeout: Duration? = nil, maxHops: Int = 8
    ) async throws -> [UInt8] {
        let resolved = try await resolveDFS(host: host, port: port, credential: credential, path: path, timeout: timeout, maxHops: maxHops)
        return try await read(host: resolved.host, port: port, share: resolved.share, path: resolved.path, range: range, credential: credential, timeout: timeout)
    }

    public static func dfsReferral(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        path: String,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> SMBDfsReferralResult {
        try await dfsReferral(
            host: host,
            port: port,
            credential: try await credentialProvider(),
            path: path,
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func list(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> [SMBDirectoryEntry] {
        let collector = SMBDirectoryEntryCollector()
        try await withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport
        ) { entry in
            collector.append(entry)
        }
        return collector.entries
    }

    public static func list(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> [SMBDirectoryEntry] {
        try await list(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "LIST") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: true)
            do {
                try await session.queryDirectory(treeId: treeId, fileId: fileId, onEntry: onEntry)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onEntry: onEntry
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall watch deadline.
    public static func withChangeNotifications(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        filter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "CHANGE_NOTIFY") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .changeNotify(path: path))
            do {
                try await session.changeNotify(treeId: treeId, fileId: fileId, filter: filter, watchTree: watchTree, onChange: onChange)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func withChangeNotifications(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        filter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        try await withChangeNotifications(
            host: host,
            port: port,
            share: share,
            path: path,
            filter: filter,
            watchTree: watchTree,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onChange: onChange
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func stat(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBFileStat {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "STAT") { session, treeId in
            let fileId = try await session.createForMetadata(treeId: treeId, path: path)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                return stat
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    /// Read reparse point target data using FSCTL_GET_REPARSE_POINT.
    ///
    /// This opens the path with FILE_OPEN_REPARSE_POINT so the target itself is not followed.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func readlink(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBReparsePoint {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "READLINK") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .reparsePoint(path: path))
            do {
                let reparsePoint = try await session.reparsePoint(treeId: treeId, fileId: fileId)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                return reparsePoint
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func securityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBSecurityInfo {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "QUERY_SECURITY") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .querySecurity(path: path))
            do {
                let info = try await session.querySecurityInfo(treeId: treeId, fileId: fileId)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                return info
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        dacl: [SMBAccessControlEntry],
        force: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await setSecurityInfo(
            host: host,
            port: port,
            share: share,
            path: path,
            ownerSID: nil,
            groupSID: nil,
            dacl: dacl,
            force: force,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport
        )
    }

    /// Write the provided security descriptor components (see `SMBClientSession.setSecurityInfo`).
    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "SET_SECURITY") { session, treeId in
            if let dacl {
                try SMB2SetInfo.validateWritableDACL(dacl, force: force)
            }
            let includeOwner = ownerSID != nil || groupSID != nil
            let writeFileId = try await session.create(treeId: treeId, request: .setSecurity(path: path, includeOwner: includeOwner))
            do {
                try await session.setSecurityInfo(
                    treeId: treeId,
                    fileId: writeFileId,
                    ownerSID: ownerSID,
                    groupSID: groupSID,
                    dacl: dacl,
                    force: force
                )
                await session.bestEffortClose(treeId: treeId, fileId: writeFileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: writeFileId)
                throw error
            }
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func volumeInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBVolumeInfo {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "QUERY_INFO") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: "", directory: true)
            do {
                let info = try await session.volumeInfo(treeId: treeId, fileId: fileId)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                return info
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func volumeInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> SMBVolumeInfo {
        try await volumeInfo(
            host: host,
            port: port,
            share: share,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    public static func stat(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> SMBFileStat {
        try await stat(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    public static func readlink(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> SMBReparsePoint {
        try await readlink(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    public static func securityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credentialProvider: SMBCredentialProvider,
        timeout: Duration? = nil,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> SMBSecurityInfo {
        try await securityInfo(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            timeout: timeout,
            makeTransport: makeTransport
        )
    }

    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        dacl: [SMBAccessControlEntry],
        force: Bool = false,
        credentialProvider: SMBCredentialProvider,
        timeout: Duration? = nil,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await setSecurityInfo(
            host: host,
            port: port,
            share: share,
            path: path,
            dacl: dacl,
            force: force,
            credential: try await credentialProvider(),
            timeout: timeout,
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func read(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        operationTimeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "READ") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                let start = range?.offset ?? 0
                guard start <= stat.size else {
                    throw SMBCodecError.invalidValue("read range starts past end of file")
                }
                let available = stat.size - start
                let requested = range.map { min($0.length, available) } ?? available
                let data = try await readAll(session: session, treeId: treeId, fileId: fileId, offset: start, length: requested, onProgress: onProgress)
                guard UInt64(data.count) == requested else {
                    throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(data.count)")
                }
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                return data
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
            }
        }
    }

    public static func read(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws -> [UInt8] {
        try await read(
            host: host,
            port: port,
            share: share,
            path: path,
            range: range,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    /// - Parameter operationTimeout: Deadline for connection setup, the complete stream, CLOSE, and session teardown.
    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        operationTimeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await withReadStreamCore(
                host: host,
                port: port,
                share: share,
                path: path,
                range: range,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport,
                onProgress: onProgress,
                onChunk: onChunk
            )
        }
    }

    private static func withReadStreamCore(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        range: SMBReadRange?,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try Task.checkCancellation()
        let progress = SMBReadStreamProgress()
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: true, operationName: "READ") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                let start = range?.offset ?? 0
                guard start <= stat.size else {
                    throw SMBCodecError.invalidValue("read range starts past end of file")
                }
                let available = stat.size - start
                let requested = range.map { min($0.length, available) } ?? available
                let transferProgress = SMBTransferProgressEmitter(totalBytes: requested, onProgress: onProgress)
                var cursor = start
                var remaining = requested
                while remaining > 0 {
                    try Task.checkCancellation()
                    let chunk = try await session.readChunk(treeId: treeId, fileId: fileId, offset: cursor, length: remaining)
                    if chunk.isEmpty { break }
                    let advanced = try SMBChunkedTransfer.advancedReadPosition(
                        cursor: cursor,
                        remaining: remaining,
                        receivedCount: chunk.count
                    )
                    try Task.checkCancellation()
                    progress.markYielding()
                    try await onChunk(chunk)
                    try Task.checkCancellation()
                    progress.recordReceived(byteCount: chunk.count)
                    transferProgress.emit(bytesTransferred: progress.received)
                    cursor = advanced.cursor
                    remaining = advanced.remaining
                }
                let received = progress.received
                guard received == requested else {
                    throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(received)")
                }
                await transferProgress.finish()
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                if progress.startedYielding, error.isSMBConnectionLoss {
                    throw SMBError.connectionLost(operation: "READ")
                }
                throw error
            }
        }
    }

    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await withReadStream(
            host: host,
            port: port,
            share: share,
            path: path,
            range: range,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onChunk: onChunk
        )
    }

    /// - Parameter operationTimeout: Deadline for connection setup, the complete stream, CLOSE, and session teardown.
    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credentialProvider: @escaping SMBCredentialProvider,
        operationTimeout: Duration?,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            let credential = try await credentialProvider()
            try await withReadStreamCore(
                host: host,
                port: port,
                share: share,
                path: path,
                range: range,
                credential: credential,
                timeout: nil,
                makeTransport: makeTransport,
                onProgress: nil,
                onChunk: onChunk
            )
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    /// - Parameter operationTimeout: Deadline for connection, resume-prefix validation, transfer, local file work, and install.
    public static func download(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        operationTimeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await downloadCore(
                host: host,
                port: port,
                share: share,
                path: path,
                localFile: localFile,
                overwrite: overwrite,
                resume: resume,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport,
                onProgress: onProgress
            )
        }
    }

    private static func downloadCore(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool,
        resume: Bool,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?
    ) async throws {
        try Task.checkCancellation()
        let fileManager = FileManager.default
        let destination = localFile.standardizedFileURL
        let directory = destination.deletingLastPathComponent()
        guard overwrite || resume || !fileManager.fileExists(atPath: destination.path) else {
            throw SMBCodecError.invalidValue("local destination already exists")
        }
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        if resume, fileManager.fileExists(atPath: destination.path) {
            let existingSize = try localFileSize(at: destination, fileManager: fileManager)
            if existingSize > 0 {
                let overlap = min(existingSize, UInt64(64 * 1024))
                let remotePrefix = try await read(
                    host: host, port: port, share: share, path: path,
                    range: SMBReadRange(offset: 0, length: overlap),
                    credential: credential, timeout: timeout, makeTransport: makeTransport
                )
                let localHandle = try FileHandle(forReadingFrom: destination)
                let localPrefix = try localHandle.read(upToCount: Int(overlap)) ?? Data()
                try localHandle.close()
                try await SMBDownloadTestSeams.beforeResumePrefixComparison?()
                try Task.checkCancellation()
                let prefixMatches = Data(remotePrefix) == localPrefix
                try await SMBDownloadTestSeams.afterResumePrefixComparison?()
                guard prefixMatches else {
                    throw SMBCodecError.invalidValue("local resume prefix does not match remote file")
                }
                try Task.checkCancellation()
            }
            let handle = try FileHandle(forWritingTo: destination)
            do {
                try handle.seekToEnd()
                try await SMBDownloadTestSeams.beforeResumeAppendConnection?()
                try await withReadStream(
                    host: host,
                    port: port,
                    share: share,
                    path: path,
                    range: SMBReadRange(offset: existingSize, length: UInt64.max),
                    credential: credential,
                    timeout: timeout,
                    makeTransport: makeTransport,
                    onProgress: onProgress
                ) { chunk in
                    try handle.write(contentsOf: Data(chunk))
                }
                try Task.checkCancellation()
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            return
        }
        let temporaryFile = try makeSMBDownloadTemporaryFile(
            in: directory,
            prefix: ".\(destination.lastPathComponent).smbee-",
            suffix: ".tmp"
        )
        let temporary = temporaryFile.url
        let handle = temporaryFile.handle
        do {
            try await withReadStream(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport,
                onProgress: onProgress
            ) { chunk in
                try handle.write(contentsOf: Data(chunk))
            }
            try await SMBDownloadTestSeams.beforeDestinationInstall?()
            try Task.checkCancellation()
            try handle.close()
            if overwrite, fileManager.fileExists(atPath: destination.path) {
                try smbReplaceItem(at: destination, with: temporary, fileManager: fileManager)
            } else {
                try fileManager.moveItem(at: temporary, to: destination)
            }
        } catch {
            try? handle.close()
            try? fileManager.removeItem(at: temporary)
            throw error
        }
    }

    public static func download(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await download(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            resume: resume,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter operationTimeout: Deadline for credential resolution, connection, resume validation,
    ///   transfer, local file work, temporary cleanup, and destination installation.
    public static func download(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credentialProvider: @escaping SMBCredentialProvider,
        operationTimeout: Duration?,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await SMBOperationDeadline.run(timeout: operationTimeout) {
            try await downloadCore(
                host: host,
                port: port,
                share: share,
                path: path,
                localFile: localFile,
                overwrite: overwrite,
                resume: resume,
                credential: try await credentialProvider(),
                timeout: nil,
                makeTransport: makeTransport,
                onProgress: nil
            )
        }
    }

    /// - Parameter atomic: When true, downloads into a hidden sibling staging directory and moves/replaces the
    ///   final destination after the full tree succeeds. This is best-effort local atomicity only: the final
    ///   move/replace is not transactional across filesystems or crashes. `dryRun` creates no staging directory,
    ///   and `skipExisting` and `resume` are ignored because atomic downloads always build a fresh staged tree.
    /// - Parameter resume: When true and `atomic` is false, skips files whose local destination size already
    ///   matches the source size. Files that are missing or size-mismatched are downloaded with overwrite enabled.
    ///   If both `resume` and `skipExisting` are true, `resume` takes precedence. This is size-based skip only,
    ///   not byte-level partial-file resume.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        atomic: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        let targetDirectory = localDirectory.standardizedFileURL
        let downloadDirectory: URL
        let actionDirectory: URL?
        let stagingDirectory: URL?
        if atomic && !dryRun {
            let parent = targetDirectory.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            let staging = parent.appendingPathComponent(
                ".\(targetDirectory.lastPathComponent).smbee-\(UUID().uuidString).tmp"
            )
            downloadDirectory = staging
            actionDirectory = targetDirectory
            stagingDirectory = staging
        } else {
            downloadDirectory = targetDirectory
            actionDirectory = nil
            stagingDirectory = nil
        }
        let failures = SMBRecursiveFailureCollector()
        do {
            try await downloadDirectoryRecursive(
                host: host,
                port: port,
                share: share,
                path: path,
                localDirectory: downloadDirectory,
                actionDirectory: actionDirectory,
                overwrite: overwrite,
                continueOnError: continueOnError,
                skipExisting: atomic ? false : skipExisting,
                resume: atomic ? false : resume,
                dryRun: dryRun,
                include: include,
                exclude: exclude,
                perFileTimeout: perFileTimeout,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport,
                failures: failures,
                onAction: onAction,
                onProgress: onProgress,
                depth: 0
            )
            try failures.throwIfNeeded()
            if let stagingDirectory {
                try replaceDownloadedDirectory(stagingDirectory, with: targetDirectory, overwrite: overwrite)
            }
        } catch {
            if let stagingDirectory {
                try? FileManager.default.removeItem(at: stagingDirectory)
            }
            throw error
        }
    }

    /// Best-effort local atomicity for directory downloads: stage in a sibling directory and then
    /// move/replace the destination. This does not make the final rename transactional across
    /// filesystems or process crashes during replacement.
    private static func replaceDownloadedDirectory(_ stagingDirectory: URL, with destination: URL, overwrite: Bool) throws {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: destination.path) {
            guard overwrite else {
                throw SMBCodecError.invalidValue("local destination already exists")
            }
            try smbReplaceItem(at: destination, with: stagingDirectory, fileManager: fileManager)
        } else {
            try fileManager.moveItem(at: stagingDirectory, to: destination)
        }
    }

    private static func localFileSize(at url: URL, fileManager: FileManager) throws -> UInt64 {
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        guard let size = smbFileSizeValue(from: attributes) else {
            throw SMBCodecError.invalidValue("local file size unavailable")
        }
        return size
    }

    private static func existingLocalFileSize(at url: URL, fileManager: FileManager) -> UInt64? {
        try? localFileSize(at: url, fileManager: fileManager)
    }

    private static func remoteFileMatchesSize(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        size: UInt64,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?
    ) async throws -> Bool {
        do {
            let stat = try await stat(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport
            )
            return !stat.isDirectory && stat.size == size
        } catch SMBError.notFound {
            return false
        }
    }

    private static func downloadDirectoryRecursive(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        localDirectory: URL,
        actionDirectory: URL?,
        overwrite: Bool,
        continueOnError: Bool,
        skipExisting: Bool,
        resume: Bool,
        dryRun: Bool,
        include: [String],
        exclude: [String],
        perFileTimeout: Duration?,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        failures: SMBRecursiveFailureCollector,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)?,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?,
        relativePath: String = "",
        depth: Int
    ) async throws {
        try SMBPath.validateRecursionDepth(depth)
        let fileManager = FileManager.default
        let reportedDirectory = actionDirectory ?? localDirectory
        if dryRun {
            onAction?(SMBRecursiveAction(kind: .mkdir, path: reportedDirectory.path))
        } else {
            try fileManager.createDirectory(at: localDirectory, withIntermediateDirectories: true)
            onAction?(SMBRecursiveAction(kind: .mkdir, path: reportedDirectory.path))
        }
        let entries = try await list(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport
        )
        for entry in entries {
            try Task.checkCancellation()
            try SMBPath.validateDirectoryEntryName(entry.name)
            let remoteChild = joinSMBPath(path, entry.name)
            let relativeChild = joinSMBPath(relativePath, entry.name)
            let localChild = localDirectory.appendingPathComponent(entry.name)
            let actionChild = reportedDirectory.appendingPathComponent(entry.name)
            if entry.isReparsePoint {
                onAction?(SMBRecursiveAction(kind: .skip, path: actionChild.path))
                continue
            }
            if recursiveEntryIsExcluded(name: entry.name, relativePath: relativeChild, exclude: exclude) {
                continue
            }
            if resume && !entry.isDirectory && existingLocalFileSize(at: localChild, fileManager: fileManager) == entry.fileSize {
                onAction?(SMBRecursiveAction(kind: .skip, path: actionChild.path))
                continue
            }
            if !resume && skipExisting && fileManager.fileExists(atPath: localChild.path) {
                onAction?(SMBRecursiveAction(kind: .skip, path: actionChild.path))
                continue
            }
            if entry.isDirectory {
                do {
                    try await downloadDirectoryRecursive(
                        host: host,
                        port: port,
                        share: share,
                        path: remoteChild,
                        localDirectory: localChild,
                        actionDirectory: actionChild,
                        overwrite: overwrite,
                        continueOnError: continueOnError,
                        skipExisting: skipExisting,
                        resume: resume,
                        dryRun: dryRun,
                        include: include,
                        exclude: exclude,
                        perFileTimeout: perFileTimeout,
                        credential: credential,
                        timeout: timeout,
                        makeTransport: makeTransport,
                        failures: failures,
                        onAction: onAction,
                        onProgress: onProgress,
                        relativePath: relativeChild,
                        depth: depth + 1
                    )
                } catch {
                    guard continueOnError else { throw error }
                    failures.record(path: remoteChild, error: error)
                }
            } else {
                guard recursiveEntryIsIncluded(name: entry.name, relativePath: relativeChild, include: include) else {
                    continue
                }
                do {
                    if dryRun {
                        onAction?(SMBRecursiveAction(kind: .download, path: actionChild.path))
                    } else {
                        try await SMBOperationDeadline.run(timeout: perFileTimeout) {
                            try await download(
                                host: host,
                                port: port,
                                share: share,
                                path: remoteChild,
                                localFile: localChild,
                                overwrite: resume ? true : overwrite,
                                credential: credential,
                                timeout: timeout,
                                makeTransport: makeTransport,
                                onProgress: onProgress
                            )
                        }
                        onAction?(SMBRecursiveAction(kind: .download, path: actionChild.path))
                    }
                } catch {
                    guard continueOnError else { throw error }
                    failures.record(path: remoteChild, error: error)
                }
            }
        }
    }

    /// - Parameter atomic: When true, downloads into a hidden sibling staging directory and moves/replaces the
    ///   final destination after the full tree succeeds. This is best-effort local atomicity only: the final
    ///   move/replace is not transactional across filesystems or crashes. `dryRun` creates no staging directory,
    ///   and `skipExisting` and `resume` are ignored because atomic downloads always build a fresh staged tree.
    /// - Parameter resume: When true and `atomic` is false, skips files whose local destination size already
    ///   matches the source size. Files that are missing or size-mismatched are downloaded with overwrite enabled.
    ///   If both `resume` and `skipExisting` are true, `resume` takes precedence. This is size-based skip only,
    ///   not byte-level partial-file resume.
    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        atomic: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await downloadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            atomic: atomic,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onAction: onAction,
            onProgress: onProgress
        )
    }

    fileprivate static func readAll(
        session: SMBSession,
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        let result = SMBReadAccumulator()
        let progress = SMBTransferProgressEmitter(totalBytes: length, onProgress: onProgress)
        var cursor = offset
        var remaining = length
        var received: UInt64 = 0
        while remaining > 0 {
            try Task.checkCancellation()
            let chunk = try await session.readChunk(treeId: treeId, fileId: fileId, offset: cursor, length: remaining)
            if chunk.isEmpty { break }
            let advanced = try SMBChunkedTransfer.advancedReadPosition(
                cursor: cursor,
                remaining: remaining,
                receivedCount: chunk.count
            )
            try Task.checkCancellation()
            result.append(chunk)
            received += UInt64(chunk.count)
            progress.emit(bytesTransferred: received)
            cursor = advanced.cursor
            remaining = advanced.remaining
        }
        await progress.finish()
        return result.bytes
    }

    fileprivate static func prefixRead(
        session: SMBSession,
        treeId: UInt32,
        fileId: [UInt8],
        maxLength: UInt64,
        sink: SMBPrefixReadSink
    ) async throws -> [UInt8] {
        var result: [UInt8] = []
        if case .accumulate = sink {
            // Prefix reads are capped at 64 MiB, but most prefixes are tiny. Reserve only
            // one local maximum chunk up front to avoid allocating the whole cap for them.
            result.reserveCapacity(Int(min(maxLength, UInt64(SMBSession.localReadChunkLimit))))
        }
        var cursor: UInt64 = 0
        var remaining = maxLength
        while remaining > 0 {
            try Task.checkCancellation()
            // The request length must come from the same calculation that encoded READ.
            // Recomputing it here would race with other operations consuming/replenishing credits.
            let read = try await session.readChunkReportingRequestedLength(
                treeId: treeId,
                fileId: fileId,
                offset: cursor,
                length: remaining
            )
            let chunk = read.data
            if chunk.isEmpty { break }
            let advanced = try SMBChunkedTransfer.advancedReadPosition(
                cursor: cursor,
                remaining: remaining,
                receivedCount: chunk.count
            )
            try Task.checkCancellation()
            switch sink {
            case let .stream(progress, onChunk):
                progress.markYielding()
                try await onChunk(chunk)
                try Task.checkCancellation()
                progress.recordReceived(byteCount: chunk.count)
            case .accumulate:
                result.append(contentsOf: chunk)
            }
            cursor = advanced.cursor
            remaining = advanced.remaining
            // A short success is best-effort only; do not probe with another READ.
            if UInt64(chunk.count) < UInt64(read.requestedLength) { break }
        }
        return result
    }

    fileprivate static func streamRead(
        session: SMBSession,
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64,
        progress: SMBReadStreamProgress,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        let transferProgress = SMBTransferProgressEmitter(totalBytes: length, onProgress: onProgress)
        var cursor = offset
        var remaining = length
        let perfStart = ContinuousClock.now
        var perfChunks = 0
        while remaining > 0 {
            try Task.checkCancellation()
            let chunk = try await session.readChunk(treeId: treeId, fileId: fileId, offset: cursor, length: remaining)
            if chunk.isEmpty { break }
            perfChunks += 1
            let advanced = try SMBChunkedTransfer.advancedReadPosition(
                cursor: cursor,
                remaining: remaining,
                receivedCount: chunk.count
            )
            try Task.checkCancellation()
            progress.markYielding()
            try await onChunk(chunk)
            try Task.checkCancellation()
            progress.recordReceived(byteCount: chunk.count)
            transferProgress.emit(bytesTransferred: progress.received)
            cursor = advanced.cursor
            remaining = advanced.remaining
        }
        let received = progress.received
        if SMBPerfLog.isEnabled {
            let elapsed = ContinuousClock.now - perfStart
            let seconds = Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
            let throughput = seconds > 0 ? Double(received) / seconds / 1e6 : 0
            SMBPerfLog.line(
                "stream total=\(received) elapsed=\(SMBPerfLog.milliseconds(elapsed))ms throughput=\(String(format: "%.2f", throughput))MB/s chunks=\(perfChunks)"
            )
        }
        guard received == length else {
            throw SMBCodecError.invalidValue("short SMB read: expected \(length) bytes, got \(received)")
        }
        await transferProgress.finish()
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "MKDIR") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
            try await session.closeCreatedHandle(treeId: treeId, fileId: fileId)
        }
    }

    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await makeDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "UPLOAD") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
            do {
                try await session.write(treeId: treeId, fileId: fileId, data: data, onProgress: onProgress)
                try await session.flush(treeId: treeId, fileId: fileId)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        fileURL: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "UPLOAD") { session, treeId in
            let clientSession = SMBClientSession(session: session, treeId: treeId)
            try await clientSession.upload(path: path, fileURL: fileURL, overwrite: overwrite, resume: resume, onProgress: onProgress)
        }
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        fileURL: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await upload(
            host: host,
            port: port,
            share: share,
            path: path,
            fileURL: fileURL,
            overwrite: overwrite,
            resume: resume,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onProgress: onProgress
        )
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await upload(
            host: host,
            port: port,
            share: share,
            path: path,
            data: data,
            overwrite: overwrite,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter resume: When true, skips files whose remote destination size already matches the local source
    ///   size. Files that are missing or size-mismatched are uploaded with overwrite enabled. If both `resume`
    ///   and `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not byte-level
    ///   partial-file resume.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        let failures = SMBRecursiveFailureCollector()
        try await uploadDirectoryRecursive(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport,
            failures: failures,
            onAction: onAction,
            onProgress: onProgress,
            depth: 0
        )
        try failures.throwIfNeeded()
    }

    private static func uploadDirectoryRecursive(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool,
        continueOnError: Bool,
        skipExisting: Bool,
        resume: Bool,
        dryRun: Bool,
        include: [String],
        exclude: [String],
        perFileTimeout: Duration?,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?,
        failures: SMBRecursiveFailureCollector,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)?,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)?,
        relativePath: String = "",
        depth: Int
    ) async throws {
        try SMBPath.validateRecursionDepth(depth)
        if !path.trimmingCharacters(in: CharacterSet(charactersIn: "\\/")).isEmpty {
            if dryRun {
                onAction?(SMBRecursiveAction(kind: .mkdir, path: path))
            } else {
                do {
                    let created = try await createDirectoryIfNeeded(
                        host: host,
                        port: port,
                        share: share,
                        path: path,
                        credential: credential,
                        timeout: timeout,
                        makeTransport: makeTransport
                    )
                    if skipExisting && !resume && !created {
                        onAction?(SMBRecursiveAction(kind: .skip, path: path))
                        return
                    }
                    onAction?(SMBRecursiveAction(kind: .mkdir, path: path))
                }
            }
        }
        let fileManager = FileManager.default
        let contents = try fileManager.contentsOfDirectory(
            at: localDirectory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: []
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for localChild in contents {
            try Task.checkCancellation()
            let resourceValues = try localChild.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if resourceValues.isSymbolicLink == true { continue }
            let remoteChild = joinSMBPath(path, localChild.lastPathComponent)
            let relativeChild = joinSMBPath(relativePath, localChild.lastPathComponent)
            if recursiveEntryIsExcluded(name: localChild.lastPathComponent, relativePath: relativeChild, exclude: exclude) {
                continue
            }
            if resourceValues.isDirectory == true {
                do {
                    try await uploadDirectoryRecursive(
                        host: host,
                        port: port,
                        share: share,
                        path: remoteChild,
                        localDirectory: localChild,
                        overwrite: overwrite,
                        continueOnError: continueOnError,
                        skipExisting: skipExisting,
                        resume: resume,
                        dryRun: dryRun,
                        include: include,
                        exclude: exclude,
                        perFileTimeout: perFileTimeout,
                        credential: credential,
                        timeout: timeout,
                        makeTransport: makeTransport,
                        failures: failures,
                        onAction: onAction,
                        onProgress: onProgress,
                        relativePath: relativeChild,
                        depth: depth + 1
                    )
                } catch {
                    guard continueOnError else { throw error }
                    failures.record(path: remoteChild, error: error)
                }
            } else {
                guard recursiveEntryIsIncluded(name: localChild.lastPathComponent, relativePath: relativeChild, include: include) else {
                    continue
                }
                do {
                    if resume {
                        let localSize = try localFileSize(at: localChild, fileManager: fileManager)
                        if try await remoteFileMatchesSize(
                            host: host,
                            port: port,
                            share: share,
                            path: remoteChild,
                            size: localSize,
                            credential: credential,
                            timeout: timeout,
                            makeTransport: makeTransport
                        ) {
                            onAction?(SMBRecursiveAction(kind: .skip, path: remoteChild))
                            continue
                        }
                    }
                    if dryRun {
                        onAction?(SMBRecursiveAction(kind: .upload, path: remoteChild))
                    } else {
                        try await SMBOperationDeadline.run(timeout: perFileTimeout) {
                            try await upload(
                                host: host,
                                port: port,
                                share: share,
                                path: remoteChild,
                                localFile: localChild,
                                overwrite: resume ? true : overwrite,
                                credential: credential,
                                timeout: timeout,
                                makeTransport: makeTransport,
                                onProgress: onProgress
                            )
                        }
                        onAction?(SMBRecursiveAction(kind: .upload, path: remoteChild))
                    }
                } catch SMBError.nameCollision where skipExisting && !resume {
                    onAction?(SMBRecursiveAction(kind: .skip, path: remoteChild))
                } catch {
                    guard continueOnError else { throw error }
                    failures.record(path: remoteChild, error: error)
                }
            }
        }
    }

    /// - Parameter resume: When true, skips files whose remote destination size already matches the local source
    ///   size. Files that are missing or size-mismatched are uploaded with overwrite enabled. If both `resume`
    ///   and `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not byte-level
    ///   partial-file resume.
    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await uploadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onAction: onAction,
            onProgress: onProgress
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await upload(
            host: host,
            port: port,
            share: share,
            path: path,
            fileURL: localFile,
            overwrite: overwrite,
            resume: resume,
            credential: credential,
            timeout: timeout,
            makeTransport: makeTransport,
            onProgress: onProgress
        )
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        resume: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await upload(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            resume: resume,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onProgress: onProgress
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func copy(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "COPY") { session, treeId in
            try await session.copyFile(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
        }
    }

    public static func copy(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await copy(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "COPY") { session, treeId in
            try SMBPath.validateDirectoryCopyTarget(fromPath: fromPath, toPath: toPath)
            try await session.copyDirectory(
                treeId: treeId,
                fromPath: fromPath,
                toPath: toPath,
                overwrite: overwrite,
                continueOnError: continueOnError,
                skipExisting: skipExisting,
                dryRun: dryRun,
                include: include,
                exclude: exclude,
                perFileTimeout: perFileTimeout,
                onAction: onAction
            )
        }
    }

    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await copyDirectory(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onAction: onAction
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        update: SMBFileMetadataUpdate,
        directory: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "SET_METADATA") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .metadata(path: path, directory: directory))
            do {
                try await session.setBasicInfo(treeId: treeId, fileId: fileId, update: update)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        update: SMBFileMetadataUpdate,
        directory: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await updateMetadata(
            host: host,
            port: port,
            share: share,
            path: path,
            update: update,
            directory: directory,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func rename(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        replaceIfExists: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "RENAME") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .rename(path: fromPath))
            do {
                try await session.rename(treeId: treeId, fileId: fileId, newPath: toPath, replaceIfExists: replaceIfExists)
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await session.bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func rename(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        replaceIfExists: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() }
    ) async throws {
        try await rename(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            replaceIfExists: replaceIfExists,
            credential: try await credentialProvider(),
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func delete(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        continueOnError: Bool = false,
        dryRun: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, timeout: timeout, makeTransport: makeTransport, idempotent: false, operationName: "DELETE") { session, treeId in
            if recursive {
                try await session.deleteRecursively(
                    treeId: treeId,
                    path: path,
                    directory: directory,
                    continueOnError: continueOnError,
                    dryRun: dryRun,
                    onAction: onAction
                )
                return
            }
            if dryRun {
                onAction?(SMBRecursiveAction(kind: .delete, path: path))
                return
            }
            try await session.deleteNonRecursive(treeId: treeId, path: path, directory: directory)
        }
    }

    public static func delete(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        continueOnError: Bool = false,
        dryRun: Bool = false,
        credentialProvider: SMBCredentialProvider,
        makeTransport: @Sendable @escaping () -> SMBTransport = { SMBTransportTestOverride.factory?() ?? POSIXSocketTransport() },
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await delete(
            host: host,
            port: port,
            share: share,
            path: path,
            directory: directory,
            recursive: recursive,
            continueOnError: continueOnError,
            dryRun: dryRun,
            credential: try await credentialProvider(),
            makeTransport: makeTransport,
            onAction: onAction
        )
    }

    @discardableResult
    private static func createDirectoryIfNeeded(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        credential: SMBCredential,
        timeout: Duration?,
        makeTransport: (@Sendable () -> SMBTransport)?
    ) async throws -> Bool {
        do {
            try await makeDirectory(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                timeout: timeout,
                makeTransport: makeTransport
            )
            return true
        } catch SMBError.nameCollision {
            return false
        }
    }

    private static func joinSMBPath(_ parent: String, _ child: String) -> String {
        let trimmedParent = parent.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
        if trimmedParent.isEmpty { return child }
        return "\(trimmedParent)\\\(child)"
    }

}

extension Error {
    var isSMBConnectionLoss: Bool {
        guard let transportError = self as? SMBTransportError else { return false }
        switch transportError {
        case .connectionClosed, .socketFailure, .timedOut:
            return true
        case .invalidAddress:
            return false
        }
    }
}

/// Demux 済み response frame とその wire 上の出自。SMB3 transform から復号された frame は
/// AEAD で完全性検証済みなので、署名必須の対象は平文で届いた frame だけ (MS-SMB2 §3.2.5.1.3)。
private struct SMBReceivedFrame {
    let bytes: [UInt8]
    // Transform SessionIds are required to be nonzero, so zero doubles as the plaintext
    // sentinel without enlarging the hot-path frame value with an Optional payload.
    let transformSessionId: UInt64
    var decryptedFromTransform: Bool { transformSessionId != 0 }
    let generation: UInt64
}

/// Stable session-local identity for a request before it has a wire MessageId.
/// The legacy transaction path attaches this identity to its existing pending record;
/// it does not use the identity to allocate or send packets yet.
struct SMBRequestIdentity: Hashable, Sendable {
    let sessionInstance: UUID
    let generation: UInt64
    // A per-session counter, not a UUID: identities are minted on every request, and on Linux
    // UUID() reads the system random source each time (issue 010 showed per-request costs show up
    // in the Linux performance gate). sessionInstance already makes the triple unique across sessions.
    let requestSequence: UInt64
}

/// Clock and sleeper used together by request retirement and future wire deadlines.
/// Task.sleep uses the same monotonic clock as ContinuousClock and retains the current
/// production timer behavior. Tests inject both closures from one virtual time source.
struct SMBSessionMonotonicTime: Sendable {
    let now: @Sendable () -> ContinuousClock.Instant
    let sleep: @Sendable (Duration) async throws -> Void

    static func production() -> SMBSessionMonotonicTime {
        let clock = ContinuousClock()
        return SMBSessionMonotonicTime(
            now: { clock.now },
            sleep: { try await Task.sleep(for: $0) }
        )
    }
}

enum SMBRequestCallerState: Equatable, Sendable {
    case pending
    case success
    case localRefusal
    case cancelled
    case timedOut
    case transportError
}

enum SMBRequestSendState: Equatable, Sendable {
    case notStarted
    case neverSubmitted
    case committed(messageId: UInt64, charge: UInt16)
    case fullySent
    case failed
}

enum SMBRequestWireState: Equatable, Sendable {
    case notApplicable
    case waiting
    case statusPending(asyncId: UInt64)
    case finalAccepted
    case sessionTerminal
}

enum SMBRequestCreditState: Equatable, Sendable {
    case waiting
    case reserved(maximumCharge: UInt16)
    case prepared(maximumCharge: UInt16, actualCharge: UInt16)
    case committed(actualCharge: UInt16)
    case refunded
    case discardedOnTerminal
}

struct SMBRequestRecordSnapshot: Sendable {
    let identity: SMBRequestIdentity
    let caller: SMBRequestCallerState
    let send: SMBRequestSendState
    let wire: SMBRequestWireState
    let credit: SMBRequestCreditState
    let outstandingAcknowledgements: Int
}

private final class SMBRetirementReceiptCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    var isComplete: Bool { lock.withLock { completed } }

    func wait() async {
        await withCheckedContinuation { continuation in
            let alreadyCompleted = lock.withLock { () -> Bool in
                if completed { return true }
                waiters.append(continuation)
                return false
            }
            if alreadyCompleted {
                continuation.resume()
            }
        }
    }

    func complete() {
        let parked = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            guard !completed else { return [] }
            completed = true
            defer { waiters.removeAll() }
            return waiters
        }
        parked.forEach { $0.resume() }
    }
}

/// Immutable handle-side receipt. Copies and duplicate retire calls share one completion.
struct SMBRetirementReceipt: Sendable, Equatable {
    let identity: SMBRequestIdentity
    private let receiptUUID: UUID
    private let completion: SMBRetirementReceiptCompletion

    fileprivate init(identity: SMBRequestIdentity, completion: SMBRetirementReceiptCompletion) {
        self.identity = identity
        self.receiptUUID = UUID()
        self.completion = completion
    }

    var id: UUID { receiptUUID }
    var isComplete: Bool { completion.isComplete }

    func wait() async {
        await completion.wait()
    }

    fileprivate func markComplete() {
        completion.complete()
    }

    static func == (lhs: SMBRetirementReceipt, rhs: SMBRetirementReceipt) -> Bool {
        lhs.receiptUUID == rhs.receiptUUID
    }
}

enum SMBUnsentRetirementDecision: Sendable {
    case retiredLocally(SMBRetirementReceipt)
    case alreadyRetired(SMBRetirementReceipt)
    case committedNeedsWireDrain(SMBRequestIdentity)
}

enum SMBRequestRefundOwner: Hashable, Sendable {
    case surplus
    case residual
    case lateReservation
}

enum SMBRequestRetirementEffectOwner: Hashable, Sendable {
    case removeQueuedItem
    case releaseTimer
    case completeCaller
}

enum SMBRequestAcknowledgementState: Equatable, Sendable {
    case pending
    case acknowledged
}

struct SMBRequestAcknowledgementSnapshot: Sendable {
    let reservationSettlement: SMBRequestAcknowledgementState?
    let refunds: [SMBRequestRefundOwner: SMBRequestAcknowledgementState]
    let effects: [SMBRequestRetirementEffectOwner: SMBRequestAcknowledgementState]

    var outstandingCount: Int {
        [reservationSettlement].compactMap { $0 }.filter { $0 == .pending }.count
            + refunds.values.filter { $0 == .pending }.count
            + effects.values.filter { $0 == .pending }.count
    }
}

/// One-shot credit refund right. The token is consumed synchronously before the async
/// credit-window acknowledgement begins, so overlapping retirement effects cannot refund
/// the same credit twice.
final class SMBOneShotCreditRefundToken: @unchecked Sendable {
    private let lock = NSLock()
    private let charge: UInt16
    private var consumed = false

    init(charge: UInt16) {
        self.charge = charge
    }

    func consume() -> UInt16? {
        lock.withLock {
            guard !consumed, charge > 0 else { return nil }
            consumed = true
            return charge
        }
    }
}

/// Commit-1 request record. It is prepared for future callers; existing post-auth callers
/// remain on the MessageId-first transaction path in this milestone.
actor SMBUnsentRequestRecord {
    let identity: SMBRequestIdentity
    private let maximumCharge: UInt16
    private let refundCredits: @Sendable (UInt16) async -> Void
    private let removeQueuedItem: @Sendable () async -> Void
    private let releaseTimer: @Sendable () async -> Void
    private let completeCaller: @Sendable () async -> Void
    private let onDeinit: @Sendable () -> Void

    private var caller: SMBRequestCallerState = .pending
    private var send: SMBRequestSendState = .notStarted
    private var wire: SMBRequestWireState = .notApplicable
    private var credit: SMBRequestCreditState
    private var sessionTerminal = false
    private var reservationTask: Task<UInt16, Error>?
    private var reservationSettlementState: SMBRequestAcknowledgementState?
    private var acknowledgementCountWaiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []
    private var onlyPendingRefundWaiters: [(owner: SMBRequestRefundOwner, continuation: CheckedContinuation<Void, Never>)] = []
    private var refundStates: [SMBRequestRefundOwner: SMBRequestAcknowledgementState] = [:]
    private var effectStates: [SMBRequestRetirementEffectOwner: SMBRequestAcknowledgementState] = [:]
    private var retired = false
    private var retirementReceipt: SMBRetirementReceipt?

    private var outstandingAcknowledgements: Int {
        acknowledgementSnapshot().outstandingCount
    }

    init(
        identity: SMBRequestIdentity,
        maximumCharge: UInt16,
        reservedCharge: UInt16? = nil,
        refundCredits: @escaping @Sendable (UInt16) async -> Void,
        removeQueuedItem: @escaping @Sendable () async -> Void = {},
        releaseTimer: @escaping @Sendable () async -> Void = {},
        completeCaller: @escaping @Sendable () async -> Void = {},
        onDeinit: @escaping @Sendable () -> Void = {}
    ) {
        precondition(maximumCharge > 0)
        self.identity = identity
        self.maximumCharge = maximumCharge
        self.refundCredits = refundCredits
        self.removeQueuedItem = removeQueuedItem
        self.releaseTimer = releaseTimer
        self.completeCaller = completeCaller
        self.onDeinit = onDeinit
        if let reservedCharge {
            precondition(reservedCharge > 0 && reservedCharge <= maximumCharge)
            self.credit = .reserved(maximumCharge: reservedCharge)
        } else {
            self.credit = .waiting
        }
    }

    deinit {
        onDeinit()
    }

    /// Reserves an exact charge using the credit window before handing its known charge
    /// to the settlement observer. No caller-supplied work can throw after acquisition.
    func startCreditReservation(window: SMB2CreditWindow, charge: UInt16) -> Bool {
        guard canStartCreditReservation(charge: charge) else { return false }
        reservationSettlementState = .pending
        let task = Task<UInt16, Error> {
            _ = try await window.reserve(charge: charge)
            return charge
        }
        ownCreditReservation(task)
        return true
    }

    /// Reserves up to the requested maximum directly from the credit window. Its acquired
    /// value is the Task result, with no intervening throwing processing before settlement.
    func startCreditReservation(window: SMB2CreditWindow, maximumCharge requestedMaximumCharge: UInt16) -> Bool {
        guard canStartCreditReservation(charge: requestedMaximumCharge) else { return false }
        reservationSettlementState = .pending
        let task = Task<UInt16, Error> {
            try await window.reserveUpTo(maximumCharge: requestedMaximumCharge)
        }
        ownCreditReservation(task)
        return true
    }

    private func canStartCreditReservation(charge: UInt16) -> Bool {
        guard !retired, !sessionTerminal, reservationTask == nil,
              reservationSettlementState == nil, case .waiting = credit,
              charge > 0, charge <= maximumCharge else {
            return false
        }
        return true
    }

    private func ownCreditReservation(_ task: Task<UInt16, Error>) {
        reservationTask = task
        Task { [self] in
            let result = await task.result
            creditReservationDidSettle(result)
        }
    }

    /// Claims the actual packet charge and starts a one-shot refund for a shrink surplus.
    func prepareCredit(actualCharge: UInt16) -> Bool {
        guard !retired, !sessionTerminal, actualCharge > 0, actualCharge <= maximumCharge,
              case .reserved(let reservedCharge) = credit,
              actualCharge <= reservedCharge else {
            return false
        }
        credit = .prepared(maximumCharge: reservedCharge, actualCharge: actualCharge)
        let surplus = reservedCharge - actualCharge
        if surplus > 0 {
            let token = SMBOneShotCreditRefundToken(charge: surplus)
            beginRefund(owner: .surplus, token: token)
        }
        return true
    }

    /// Synchronous commit boundary for later activation work. After commit, credit is
    /// consumed by the wire and local retirement cannot refund it.
    func commitSend(messageId: UInt64) -> Bool {
        guard !retired, !sessionTerminal, case .notStarted = send else { return false }
        let actualCharge: UInt16
        switch credit {
        case .reserved(let reservedCharge):
            actualCharge = reservedCharge
        case .prepared(_, let preparedCharge):
            actualCharge = preparedCharge
        case .waiting, .committed, .refunded, .discardedOnTerminal:
            return false
        }
        credit = .committed(actualCharge: actualCharge)
        send = .committed(messageId: messageId, charge: actualCharge)
        wire = .waiting
        return true
    }

    @discardableResult
    func markCallerTerminal(_ state: SMBRequestCallerState) -> Bool {
        guard case .pending = caller, state != .pending else { return false }
        caller = state
        beginEffect(owner: .completeCaller, completeCaller)
        return true
    }

    func markSendFullySent() {
        guard case .committed = send else { return }
        send = .fullySent
    }

    func markSendFailed() {
        guard case .committed = send else { return }
        send = .failed
    }

    func markWireStatusPending(asyncId: UInt64) {
        guard case .waiting = wire else { return }
        wire = .statusPending(asyncId: asyncId)
    }

    func markWireFinalAccepted() {
        switch wire {
        case .waiting, .statusPending:
            wire = .finalAccepted
        case .notApplicable, .finalAccepted, .sessionTerminal:
            break
        }
    }

    func markSessionTerminal() {
        guard !sessionTerminal else { return }
        sessionTerminal = true
        wire = .sessionTerminal
        reservationTask?.cancel()
        if reservationSettlementState == .pending, case .waiting = credit {
            // Keep the reservation pending until its already-owned settlement observer
            // learns whether a grant won before cancellation.
        } else if case .waiting = credit {
            credit = .discardedOnTerminal
        } else if case .reserved = credit {
            credit = .discardedOnTerminal
        } else if case .prepared = credit {
            credit = .discardedOnTerminal
        } else if case .committed = credit {
            credit = .discardedOnTerminal
        }
    }

    func retireUnsent() -> SMBUnsentRetirementDecision {
        if let retirementReceipt {
            return .alreadyRetired(retirementReceipt)
        }
        guard case .notStarted = send else {
            return .committedNeedsWireDrain(identity)
        }

        retired = true
        markCallerTerminal(.localRefusal)
        send = .neverSubmitted
        let completion = SMBRetirementReceiptCompletion()
        let receipt = SMBRetirementReceipt(identity: identity, completion: completion)
        retirementReceipt = receipt

        beginEffect(owner: .removeQueuedItem, removeQueuedItem)
        beginEffect(owner: .releaseTimer, releaseTimer)

        if reservationSettlementState == .pending {
            reservationTask?.cancel()
        } else if sessionTerminal {
            credit = .discardedOnTerminal
        } else {
            beginResidualRefundForRetirement()
        }
        completeReceiptIfReady()
        return .retiredLocally(receipt)
    }

    func snapshot() -> SMBRequestRecordSnapshot {
        SMBRequestRecordSnapshot(
            identity: identity,
            caller: caller,
            send: send,
            wire: wire,
            credit: credit,
            outstandingAcknowledgements: outstandingAcknowledgements
        )
    }

    func acknowledgementSnapshotForTesting() -> SMBRequestAcknowledgementSnapshot {
        acknowledgementSnapshot()
    }

    func waitForOnlyPendingRefundAcknowledgementForTesting(_ owner: SMBRequestRefundOwner) async {
        if onlyPendingRefundAcknowledgementIs(owner) { return }
        await withCheckedContinuation { continuation in
            if onlyPendingRefundAcknowledgementIs(owner) {
                continuation.resume()
            } else {
                onlyPendingRefundWaiters.append((owner, continuation))
            }
        }
    }

    func waitForAcknowledgementCountForTesting(atMost target: Int) async {
        if outstandingAcknowledgements <= target { return }
        await withCheckedContinuation { continuation in
            if outstandingAcknowledgements <= target {
                continuation.resume()
            } else {
                acknowledgementCountWaiters.append((target, continuation))
            }
        }
    }

    private func beginResidualRefundForRetirement() {
        let residual: UInt16
        switch credit {
        case .reserved(let reservedCharge):
            residual = reservedCharge
        case .prepared(_, let actualCharge):
            residual = actualCharge
        case .waiting, .committed, .refunded, .discardedOnTerminal:
            return
        }
        guard residual > 0 else { return }
        let token = SMBOneShotCreditRefundToken(charge: residual)
        beginRefund(owner: .residual, token: token)
    }

    private func beginRefund(owner: SMBRequestRefundOwner, token: SMBOneShotCreditRefundToken) {
        guard refundStates[owner] == nil, let charge = token.consume() else { return }
        refundStates[owner] = .pending
        resumeAcknowledgementWaiters()
        let refundCredits = self.refundCredits
        Task { [self] in
            await refundCredits(charge)
            refundDidAcknowledge(owner)
        }
    }

    private func beginEffect(
        owner: SMBRequestRetirementEffectOwner,
        _ effect: @escaping @Sendable () async -> Void
    ) {
        guard effectStates[owner] == nil else { return }
        effectStates[owner] = .pending
        resumeAcknowledgementWaiters()
        Task { [self] in
            await effect()
            retirementEffectDidAcknowledge(owner)
        }
    }

    private func creditReservationDidSettle(_ result: Result<UInt16, Error>) {
        reservationTask = nil
        if case .success(let reservedCharge) = result {
            if sessionTerminal {
                credit = .discardedOnTerminal
            } else if retired {
                let token = SMBOneShotCreditRefundToken(charge: reservedCharge)
                beginRefund(owner: .lateReservation, token: token)
            } else if reservedCharge > 0, reservedCharge <= maximumCharge {
                credit = .reserved(maximumCharge: reservedCharge)
            } else {
                credit = .refunded
            }
        } else if sessionTerminal {
            credit = .discardedOnTerminal
        } else if !retired {
            credit = .waiting
        }
        reservationSettlementState = .acknowledged
        resumeAcknowledgementWaiters()
        if retired && !sessionTerminal && refundStates.isEmpty {
            beginResidualRefundForRetirement()
        }
        completeReceiptIfReady()
    }

    private func refundDidAcknowledge(_ owner: SMBRequestRefundOwner) {
        guard refundStates[owner] == .pending else { return }
        refundStates[owner] = .acknowledged
        resumeAcknowledgementWaiters()
        completeReceiptIfReady()
    }

    private func retirementEffectDidAcknowledge(_ owner: SMBRequestRetirementEffectOwner) {
        guard effectStates[owner] == .pending else { return }
        effectStates[owner] = .acknowledged
        resumeAcknowledgementWaiters()
        completeReceiptIfReady()
    }

    private func acknowledgementSnapshot() -> SMBRequestAcknowledgementSnapshot {
        SMBRequestAcknowledgementSnapshot(
            reservationSettlement: reservationSettlementState,
            refunds: refundStates,
            effects: effectStates
        )
    }

    private func onlyPendingRefundAcknowledgementIs(_ owner: SMBRequestRefundOwner) -> Bool {
        let snapshot = acknowledgementSnapshot()
        guard snapshot.outstandingCount == 1,
              snapshot.reservationSettlement != .pending,
              snapshot.refunds[owner] == .pending,
              snapshot.refunds.allSatisfy({ $0.key == owner || $0.value == .acknowledged }),
              snapshot.effects.values.allSatisfy({ $0 == .acknowledged }) else {
            return false
        }
        return true
    }

    private func resumeAcknowledgementWaiters() {
        let readyCounts = acknowledgementCountWaiters.filter { outstandingAcknowledgements <= $0.target }
        acknowledgementCountWaiters.removeAll { outstandingAcknowledgements <= $0.target }
        readyCounts.forEach { $0.continuation.resume() }

        let readyRefunds = onlyPendingRefundWaiters.filter { onlyPendingRefundAcknowledgementIs($0.owner) }
        onlyPendingRefundWaiters.removeAll { onlyPendingRefundAcknowledgementIs($0.owner) }
        readyRefunds.forEach { $0.continuation.resume() }
    }

    private func completeReceiptIfReady() {
        guard retired, outstandingAcknowledgements == 0, let retirementReceipt else { return }
        if !sessionTerminal { credit = .refunded }
        retirementReceipt.markComplete()
    }
}

/// A variable length request reserves its CreditCharge before it fixes its payload and
/// MessageId. The send task claims the reservation exactly once; a caller that is cancelled
/// before the send task reaches it refunds the still-unclaimed credits.
private final class SMBPreReservedCredit: @unchecked Sendable {
    private let lock = NSLock()
    let charge: UInt16
    private var claimed = false
    private var released = false

    init(charge: UInt16) {
        self.charge = charge
    }

    var payloadLimit: UInt64 {
        UInt64(charge) * UInt64(SMB2Credit.unitSize)
    }

    /// Claims the reservation and returns unused credits, if the payload is shorter than
    /// the credit-limited maximum.
    func claim(for requiredCharge: UInt16) -> UInt16? {
        lock.withLock {
            guard !claimed, !released, requiredCharge <= charge else { return nil }
            claimed = true
            return charge - requiredCharge
        }
    }

    func releaseUnclaimed() -> UInt16? {
        lock.withLock {
            guard !claimed, !released else { return nil }
            released = true
            return charge
        }
    }
}

/// Wire-path classification for the session request timeout. Ordinary transactions opt in
/// by default; only protocol operations that are expected to wait indefinitely opt out.
private enum SMBRequestTimeoutPolicy: Sendable {
    enum Exclusion: Sendable {
        case longPoll
        case blockingLock
        case namedPipeReadOrTransceive
    }

    case eligible
    case excluded(Exclusion)

    var isEligible: Bool {
        if case .eligible = self { return true }
        return false
    }
}

private enum SMBPendingResponseSendPhase {
    case registered
    case sending
    case sent
}

enum SMBResponseProtectionPolicy: Sendable {
    case sessionDefault
    case signatureOrAEADRequired
    case encryptedRequest
}

private enum SMBVerifiedResponseProtection: Equatable {
    case unprotected
    case signature
    case authenticatedEncryption
}

private struct SMBResponseSlice {
    let frame: SMBReceivedFrame
    let header: SMB2Header
}

private struct SMBValidatedResponseEffect {
    enum Kind {
        case ignored
        case interim(asyncId: UInt64, pendingCount: Int)
        case final(
            asyncId: UInt64?,
            pendingCount: Int,
            frame: SMBReceivedFrame,
            status: UInt32,
            sendPhase: SMBPendingResponseSendPhase
        )
    }

    let messageId: UInt64
    let requestIdentity: SMBRequestIdentity?
    let credits: UInt16?
    let kind: Kind
}

private enum SMBValidatedResponseBatch {
    case single(SMBValidatedResponseEffect)
    case compound([SMBValidatedResponseEffect])
}

private struct SMBResponseCorrelationState {
    let messageId: UInt64
    let expectedCommand: UInt16
    let expectedSessionId: UInt64
    let expectedTreeId: UInt32
    let longPoll: Bool
    let cleanupFileId: SMBFileIdLedgerKey?
    let responseProtectionPolicy: SMBResponseProtectionPolicy
    var asyncId: UInt64?
    var pendingCount: Int
    var finalSeen: Bool
}

private struct SMBFileIdLedgerKey: Hashable {
    let bytes: [UInt8]
}

private enum SMBCleanupAttemptState: Equatable {
    case sending
    case draining(UInt64)
    case retiredUnknown
}

private enum SMBPendingResponseCompletionTarget {
    case transaction(CheckedContinuation<SMBReceivedFrame, Error>)
    // M2 supplies this ticket for transfer responses so the session can update its window.
    case transfer(SMBTransferTicket)
}

private struct SMBPendingResponse {
    let requestIdentity: SMBRequestIdentity
    let generation: UInt64
    let label: String
    let longPoll: Bool
    let requestTimeoutPolicy: SMBRequestTimeoutPolicy
    let responseProtectionPolicy: SMBResponseProtectionPolicy
    let expectedCommand: UInt16
    let expectedSessionId: UInt64
    let expectedTreeId: UInt32
    var pendingCount: Int = 0
    /// AsyncId observed on the first STATUS_PENDING interim (MS-SMB2 §3.2.5.1.5 requires
    /// storing it); nil until the request is seen going async.
    var asyncId: UInt64?
    var finalSeen = false
    var acceptedFinalFrame: SMBReceivedFrame?
    var acceptedFinalStatus: UInt32?
    let completionTarget: SMBPendingResponseCompletionTarget
    var sendTask: Task<Void, Never>?
    var timeoutTask: Task<Void, Never>?
    var timeoutIdentity: UUID?
    var sendPhase: SMBPendingResponseSendPhase
    var cancellationRequested = false
    var continuationResumed = false
    var cleanupFileId: SMBFileIdLedgerKey?
    var cleanupTombstone = false
    var cleanupTimeoutTask: Task<Void, Never>?
    var cleanupDrainTask: Task<Void, Never>?
    var cleanupTimeoutIdentity: UUID?
    var cleanupDrainIdentity: UUID?
}

private enum SMBReaderLifecycle {
    case dormant(generation: UInt64)
    case running(generation: UInt64, handle: UUID)
    case stopping(generation: UInt64, handle: UUID, reason: String)
    case stopped(generation: UInt64)

    var activeGeneration: UInt64? {
        switch self {
        case .dormant(let generation), .running(let generation, _):
            generation
        case .stopping, .stopped:
            nil
        }
    }

    var isTerminal: Bool {
        switch self {
        case .stopping, .stopped:
            true
        case .dormant, .running:
            false
        }
    }
}

private enum SMBTestingCountWaitKind: Equatable {
    case pendingResponses
    case pendingCommandResponseDrainWaiters(UInt16)
    case requestSent
    case requestSentWaiterRegistrations
    case cleanupLedger
    case cleanupDrainTimeoutCallbacks
    case receivedPacketDispatches
}

private struct SMBPendingCommandResponseDrainWaiter {
    let id: UUID
    let command: UInt16
    let continuation: CheckedContinuation<Void, Error>
}

private struct SMBTestingCountWaiter {
    let id: UInt64
    let kind: SMBTestingCountWaitKind
    let target: Int
    let isAtLeast: Bool
    let continuation: CheckedContinuation<Void, Never>
}

/// この actor は mutable wire state (messageId / sessionId / transformNonce / 鍵 / 交渉値) を隔離する。
/// actor reentrancy により `sendSigned` → response 待機の間で別の wire 操作が入り得るため、response は
/// `messageId` ごとの pending continuation へ demux する。これにより同一 `SMBSession` への並行
/// wire 操作でも複数 request を in-flight にでき、応答取り違えは起きない。READ/WRITE の
/// CreditCharge と server grant は `SMB2CreditWindow` で reserve/grant する。
///
/// 高レベル operation 全体はロックしない。複数 request からなる操作を並行実行した場合の意味論は
/// SMB server と呼び出し元の ordering に依存するため、共有 session API を公開する際に別途整理する。
actor SMBSession {
    private static let defaultCleanupTimeout: Duration = .seconds(5)
    private static let maxCleanupAttempts = 64
    private static let maxCancellationTombstones = 64
    private static let initialWireGeneration: UInt64 = 1
    private static let diagnosticSessionIdLock = NSLock()
    nonisolated(unsafe) private static var nextDiagnosticSessionNumber: UInt64 = 1

    private static func makeDiagnosticSessionId() -> String {
        diagnosticSessionIdLock.withLock {
            let number = nextDiagnosticSessionNumber
            nextDiagnosticSessionNumber += 1
            return String(number, radix: 36)
        }
    }

    private static func diagnosticError(_ error: Error) -> String {
        let description = String(describing: error).replacingOccurrences(of: "\n", with: " ")
        return "\(String(reflecting: type(of: error))): \(description)"
    }

    private static func fileIdPrefix(_ fileId: [UInt8]) -> String {
        fileId.prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    private let host: String
    private let port: UInt16
    private let diagnosticSessionId: String
    private let sessionInstanceIdentity = UUID()
    // The source credential is needed only while SESSION_SETUP is being built. Derived session
    // keys are sufficient afterwards; reconnect obtains a fresh value from its provider.
    private var authenticationCredential: SMBCredential?
    private var credentialWasAnonymous = false
    private let transport: SMBTransport
    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var signingKey: [UInt8]?
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
    private var signingCMACContext: AESCMAC.Context?
#endif
    private var signingRequired = false
    private var sessionFlags: UInt16 = 0
    private var negotiateRequestSnapshot: SMBNegotiateRequestSnapshot?
    private var negotiateResponseResult: SMBProbeResult?
    private var encryptionKey: [UInt8]?
    private var decryptionKey: [UInt8]?
    private var signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC
    private var encryptionAlgorithm: SMBSessionEncryptionAlgorithm = .aes128CCM
    private var transformNonceCounter: UInt64 = 0
    private var maxReadSize: UInt32 = UInt32.max
    private var maxWriteSize: UInt32 = UInt32.max
    private let creditWindow: SMB2CreditWindow
    private var pendingResponses: [UInt64: SMBPendingResponse] = [:]
    private var activeRequestIdentities: Set<SMBRequestIdentity> = []
    private var nextRequestSequence: UInt64 = 0
    private var cleanupLedger: [SMBFileIdLedgerKey: SMBCleanupAttemptState] = [:]
    private var pendingCommandResponseDrainWaiters: [SMBPendingCommandResponseDrainWaiter] = []
    private var testingCountWaiters: [SMBTestingCountWaiter] = []
    private var nextTestingCountWaiterId: UInt64 = 0
    private var requestSentWaiterRegistrationCountForTestingStorage = 0
    private var readerLifecycle = SMBReaderLifecycle.dormant(generation: initialWireGeneration)
    // A reader may become dormant before its Task returns. A later send can start its
    // replacement during that interval, so keep every live Task by handle until it exits.
    private var readerTasks: [UUID: Task<Void, Never>] = [:]
    private var readerHandle: UUID?
    private var readerTaskExitHookForTesting: (@Sendable (UUID) async -> Void)?
    private var readerTaskJoinSnapshotHookForTesting: (@Sendable (Int) -> Void)?
    private var readerTaskJoinWillAwaitHookForTesting: (@Sendable (UUID) -> Void)?
    private var creditFailureTask: Task<Void, Never>?
    private var activeSendTasks: [UUID: Task<Void, Never>] = [:]
    private var activeCancelTasks: [UUID: Task<Void, Never>] = [:]
    private var connectAttempted = false
    private var connectInFlight = false
    private var connectCompletionWaiters: [CheckedContinuation<Void, Never>] = []
    private var requestSentCountForTestingStorage = 0
    private var validateNegotiateSentCountForTestingStorage = 0
    private var validateNegotiateSuccessCountForTestingStorage = 0
    private var requestTimeoutCompletionCountForTestingStorage = 0
    private var receivedPacketDispatchCountForTestingStorage = 0
    private var lastFinalAcceptanceForTestingStorage: ContinuousClock.Instant?
    private var cleanupDrainTimeoutCallbackCountForTestingStorage = 0
    private var wireFailure: Error?
    private var creditGrantAfterAwaitHookForTesting: (@Sendable () async -> Void)?
    private let cleanupTimeout: Duration
    private let requestTimeout: Duration?
    private let requestTimeoutSleeper: @Sendable (Duration) async throws -> Void
    private let cleanupTimeoutSleeper: @Sendable (Duration) async throws -> Void
    private let sessionTime: SMBSessionMonotonicTime
    private let debugLogger: SMBSessionDebugLogger

    /// - Parameter requestTimeout: Per-request response timeout started only after the
    ///   complete request has been sent. It is independent of transport socket timeouts;
    ///   `nil` preserves the existing unbounded response wait.
    init(
        host: String,
        port: UInt16,
        credential: SMBCredential,
        transport: SMBTransport,
        signingKey: [UInt8]? = nil,
        signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC,
        signingRequired: Bool = false,
        initialCredits: UInt32 = 1,
        cleanupTimeout: Duration = SMBSession.defaultCleanupTimeout,
        requestTimeout: Duration? = nil,
        sessionTime: SMBSessionMonotonicTime = .production(),
        requestTimeoutSleeper: (@Sendable (Duration) async throws -> Void)? = nil,
        cleanupTimeoutSleeper: (@Sendable (Duration) async throws -> Void)? = nil,
        debugLogger: SMBSessionDebugLogger = .environment
    ) {
        // A locked monotonic base-36 ID is short, non-secret, collision-free within a run, and reproducible.
        let diagnosticSessionId = Self.makeDiagnosticSessionId()
        self.host = host
        self.port = port
        self.diagnosticSessionId = diagnosticSessionId
        self.authenticationCredential = credential
        self.credentialWasAnonymous = credential.isAnonymous
        self.transport = transport
        self.signingKey = signingKey
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
        if let signingKey {
            self.signingCMACContext = try? AESCMAC.Context(key: signingKey)
        }
#endif
        self.signingAlgorithm = signingAlgorithm
        self.signingRequired = signingRequired
        self.creditWindow = SMB2CreditWindow(
            initialCredits: initialCredits,
            diagnosticSessionId: diagnosticSessionId
        )
        self.cleanupTimeout = cleanupTimeout
        self.requestTimeout = requestTimeout
        self.sessionTime = sessionTime
        self.requestTimeoutSleeper = requestTimeoutSleeper ?? sessionTime.sleep
        self.cleanupTimeoutSleeper = cleanupTimeoutSleeper ?? sessionTime.sleep
        self.debugLogger = debugLogger
    }

    deinit {
        for task in readerTasks.values { task.cancel() }
        if !readerLifecycle.isTerminal {
            transport.close()
            let creditWindow = creditWindow
            Task { await creditWindow.failAllWaiters(SMBTransportError.connectionClosed) }
        }
    }

    func connect() async throws {
        guard !connectAttempted,
              !readerLifecycle.isTerminal,
              case .dormant = readerLifecycle else {
            throw SMBTransportError.connectionClosed
        }
        guard let credential = authenticationCredential else {
            throw SMBCodecError.invalidValue("SMB session authentication credential is unavailable")
        }
        connectAttempted = true
        connectInFlight = true
        defer { finishConnectAttempt() }
        let generation = Self.initialWireGeneration
        do {
            try Task.checkCancellation()
            try await transport.connect(host: host, port: port)
        } catch {
            if isGenerationActive(generation) {
                failWire(error: error)
                closeTransport(cause: "transport_connect_failure", diagnosticError: error)
            } else {
                // A transport may publish its connection after close() returned. Re-close
                // after connect unwinds so that late candidate cannot outlive this session.
                transport.close()
            }
            throw error
        }
        guard isGenerationActive(generation) else {
            // See the publication race above. The second idempotent transport close is
            // intentionally after connect returns, not a new session lifetime.
            transport.close()
            throw SMBTransportError.connectionClosed
        }
        let requestSnapshot = try SMBNegotiateRequestSnapshot(
            clientGuid: UUID().smbWireBytes,
            capabilities: SMBNegotiateConstants.globalCapEncryption,
            securityMode: SMBNegotiateConstants.signingEnabled,
            dialects: SMBNegotiateCodec.authenticatedDialects
        )
        negotiateRequestSnapshot = requestSnapshot
        let negotiate = try SMBNegotiateCodec.encodeRequest(
            snapshot: requestSnapshot,
            messageId: nextMessageId(),
            salt: Array(repeating: 0, count: 32)
        )
        var preauthMessages: [[UInt8]] = []
        debugDump("NEGOTIATE request", negotiate)
        let negotiateResponse = try await sendPreauthRequest(
            negotiate, responseLabel: "NEGOTIATE response",
            preauthMessages: &preauthMessages, foldResponse: true)
        let result = try SMBNegotiateCodec.decodeResponse(negotiateResponse)
        negotiateResponseResult = result
        signingRequired = result.signingRequired
        maxReadSize = result.maxReadSize
        maxWriteSize = result.maxWriteSize
        guard SMBNegotiateCodec.supportsAuthenticatedConnection(dialect: result.dialect) else {
            throw SMBError.protocolError(SMBNegotiateCodec.authenticatedUnsupportedMessage)
        }
        if result.dialect == SMBNegotiateConstants.dialect311 {
            guard result.preauthHashAlgorithm == SMBNegotiateConstants.sha512,
                  result.signingAlgorithm == SMBNegotiateConstants.aesGMAC,
                  result.cipher == nil || result.cipher == SMBNegotiateConstants.aes128GCM
            else {
                throw SMBCodecError.invalidValue("unsupported SMB 3.1.1 crypto negotiation")
            }
            signingAlgorithm = .aesGMAC
            if result.cipher == SMBNegotiateConstants.aes128GCM {
                encryptionAlgorithm = .aes128GCM
            }
        }
        await logNegotiatePerf(result)

        let type1Message = try NTLM.makeType1(domain: credential.domain)
        let type1 = SPNEGO.wrapNegTokenInit(type1Message)
        let challengePacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: 0,
            securityBlob: type1,
            signed: false
        )
        debugLine("SESSION_SETUP#1 request length=\(challengePacket.count)")
        let challengeResponse = try await sendPreauthRequest(
            challengePacket, responseLabel: "SESSION_SETUP#1 response",
            preauthMessages: &preauthMessages, foldResponse: true)
        let challengeHeader = try SMB2Header.decode(challengeResponse)
        if challengeHeader.status != SMB2Status.moreProcessingRequired {
            try SMBErrorMapper.throwIfFailure(status: challengeHeader.status, operation: "SESSION_SETUP#1")
            // Preserve the legacy mapping for unexpected successful SESSION_SETUP#1 replies.
            throw SMBErrorMapper.map(status: challengeHeader.status, operation: "SESSION_SETUP#1")
        }
        sessionId = challengeHeader.sessionId
        let challengeBlob = try SMB2SessionSetup.decodeResponse(challengeResponse)
        let challengeMessage = try SPNEGO.unwrapNTLMToken(challengeBlob)
        let challenge = try NTLM.parseChallenge(challengeMessage)
        let authenticate = try NTLM.makeType3(
            credential: credential,
            challenge: challenge,
            serverName: host,
            negotiateMessage: type1Message,
            challengeMessage: challengeMessage
        )
        let mechListMIC = credential.isAnonymous ? nil : NTLM.makeMechListMIC(exportedSessionKey: authenticate.exportedSessionKey)
        let authBlob = SPNEGO.wrapNegTokenResp(authenticate.message, mechListMIC: mechListMIC)
        let authPacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            securityBlob: authBlob,
            signed: false
        )
        debugLine("SESSION_SETUP#2 request length=\(authPacket.count)")
        // foldResponse: false — MS-SMB2 §3.2.5.3.1: the preauth integrity hash covers
        // messages up to the final SESSION_SETUP *request*. Folding the terminal
        // STATUS_SUCCESS response would derive a signing/encryption key that differs from
        // the server's, so every signed/encrypted 3.1.1 op would fail verification.
        let authResponse = try await sendPreauthRequest(
            authPacket, responseLabel: "SESSION_SETUP#2 response",
            preauthMessages: &preauthMessages, foldResponse: false)
        let authHeader = try SMB2Header.decode(authResponse)
        try SMBErrorMapper.throwIfFailure(status: authHeader.status, operation: "SESSION_SETUP")
        sessionId = authHeader.sessionId
        sessionFlags = try SMB2SessionSetup.decodeSessionFlags(authResponse)
        if credential.isAnonymous {
            // ⓥ Anonymous NTLM does not provide session key material, so SMB signing/encryption keys
            // cannot be derived here. If a server requires signing/encryption for guest access, the
            // later signed or encrypted operation is expected to fail until guest E2E coverage defines
            // a server-specific fallback.
            authenticationCredential = nil
            try requireEncryptionKeyIfSessionDemandsEncryption(sessionFlags)
            return
        }
        let isGuestOrNull = (sessionFlags & (SMB2SessionSetup.sessionFlagIsGuest | SMB2SessionSetup.sessionFlagIsNull)) != 0
        if isGuestOrNull,
           result.dialect == SMBNegotiateConstants.dialect300 || result.dialect == SMBNegotiateConstants.dialect302 {
            throw SMBError.protocolError("SMB 3.0.x credentials were mapped to a guest or null session")
        }
        if isGuestOrNull {
            authenticationCredential = nil
            try requireEncryptionKeyIfSessionDemandsEncryption(sessionFlags)
            return
        }
        if result.dialect == SMBNegotiateConstants.dialect311 {
            let preauthHash = SMBCrypto.smb311PreauthIntegrityHash(preauthMessages)
            signingKey = SMBCrypto.smb311SigningKey(sessionKey: authenticate.exportedSessionKey, preauthIntegrityHash: preauthHash)
            if result.cipher == SMBNegotiateConstants.aes128GCM {
                encryptionKey = SMBCrypto.smb311EncryptionKey(sessionKey: authenticate.exportedSessionKey, preauthIntegrityHash: preauthHash)
                decryptionKey = SMBCrypto.smb311DecryptionKey(sessionKey: authenticate.exportedSessionKey, preauthIntegrityHash: preauthHash)
            }
        } else {
            signingKey = SMBCrypto.smb3SigningKey(sessionKey: authenticate.exportedSessionKey)
            // MS-SMB2 §3.2.5.3.1 derives 3.0.x encryption keys only when the server supports encryption
            // (`SMB2_GLOBAL_CAP_ENCRYPTION`). sendSigned encrypts whenever encryptionKey exists, so deriving it
            // for a non-encrypting server sends TRANSFORM frames it rejects (Samba: INVALID_PARAMETER disconnect).
            if result.supportsEncryption {
                encryptionKey = SMBCrypto.smb302EncryptionKey(sessionKey: authenticate.exportedSessionKey)
                decryptionKey = SMBCrypto.smb302DecryptionKey(sessionKey: authenticate.exportedSessionKey)
            }
        }
        try requireEncryptionKeyIfSessionDemandsEncryption(sessionFlags)
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
        if let signingKey {
            signingCMACContext = try AESCMAC.Context(key: signingKey)
        }
#endif
        // Swift cannot guarantee zeroization of copied String/Array backing storage. Releasing the
        // session's owning reference here still bounds the plaintext credential lifetime instead of
        // retaining it for every subsequent operation.
        authenticationCredential = nil
    }

    func retainsAuthenticationCredentialForTesting() -> Bool {
        authenticationCredential != nil
    }

    func sessionFlagsForTesting() -> UInt16 {
        sessionFlags
    }

    func hasSigningKeyForTesting() -> Bool {
        signingKey != nil
    }

    func validateNegotiateCountsForTesting() -> (sent: Int, succeeded: Int) {
        (validateNegotiateSentCountForTestingStorage, validateNegotiateSuccessCountForTestingStorage)
    }

    func isTransportClosedForTesting() -> Bool {
        readerLifecycle.isTerminal
    }

    func installValidateNegotiateStateForTesting(
        snapshot: SMBNegotiateRequestSnapshot,
        serverResult: SMBProbeResult,
        sessionId: UInt64,
        sessionFlags: UInt16 = 0,
        encryptionKey: [UInt8]? = nil,
        decryptionKey: [UInt8]? = nil
    ) {
        negotiateRequestSnapshot = snapshot
        negotiateResponseResult = serverResult
        self.sessionId = sessionId
        self.sessionFlags = sessionFlags
        self.encryptionKey = encryptionKey
        self.decryptionKey = decryptionKey
    }

    func installEncryptionStateForTesting(
        encryptionKey: [UInt8],
        decryptionKey: [UInt8],
        sessionId: UInt64? = nil,
        algorithm: SMBSessionEncryptionAlgorithm = .aes128CCM
    ) {
        self.encryptionKey = encryptionKey
        self.decryptionKey = decryptionKey
        if let sessionId {
            self.sessionId = sessionId
        }
        encryptionAlgorithm = algorithm
    }

    private func logNegotiatePerf(_ result: SMBProbeResult) async {
        guard SMBPerfLog.isEnabled else { return }
        let cipherLabel: String
        switch result.cipher {
        case SMBNegotiateConstants.aes128GCM: cipherLabel = "gcm"
        case SMBNegotiateConstants.aes128CCM: cipherLabel = "ccm"
        case nil: cipherLabel = "none(pre-3.1.1-default:ccm)"
        case let other?: cipherLabel = "0x\(String(other, radix: 16))"
        }
        let signingLabel = signingAlgorithm == .aesGMAC ? "gmac" : "cmac"
        let credits = await creditWindow.balance
        SMBPerfLog.line(
            "negotiate dialect=0x\(String(result.dialect, radix: 16)) cipher=\(cipherLabel) signing=\(signingLabel) maxRead=\(result.maxReadSize) maxWrite=\(result.maxWriteSize) credits=\(credits)"
        )
    }

    func treeConnect(share: String) async throws -> UInt32 {
        let packet = try SMB2TreeConnect.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            path: "\\\\\(host)\\\(share)"
        )
        debugDump("TREE_CONNECT request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "TREE_CONNECT response")
        let result = try SMB2TreeConnect.decodeResponse(response)
        try await validateNegotiateAfterTreeConnect(treeId: result.treeId, shareEncryptionRequired: result.encryptionRequired)
        if result.encryptionRequired, encryptionKey == nil {
            throw SMBError.protocolError("TREE_CONNECT requires encryption but no SMB encryption key was negotiated")
        }
        return result.treeId
    }

    private func validateNegotiateAfterTreeConnect(treeId: UInt32, shareEncryptionRequired: Bool) async throws {
        // SMBee policy exception: anonymous credentials skip this check and receive no downgrade detection.
        guard let negotiated = negotiateResponseResult,
              negotiated.dialect == SMBNegotiateConstants.dialect300 || negotiated.dialect == SMBNegotiateConstants.dialect302,
              !credentialWasAnonymous
        else {
            return
        }
        do {
            guard let requestSnapshot = negotiateRequestSnapshot else {
                throw SMBCodecError.invalidValue("missing NEGOTIATE request snapshot")
            }
            guard signingKey != nil else {
                throw SMBCodecError.invalidValue("VALIDATE_NEGOTIATE_INFO requires a signing key")
            }
            let request = try SMB2ValidateNegotiateInfo.encodeRequest(
                messageId: nextMessageId(),
                sessionId: sessionId,
                treeId: treeId,
                snapshot: requestSnapshot
            )
            debugDump("FSCTL_VALIDATE_NEGOTIATE_INFO request", request)
            let encrypt = shareEncryptionRequired ||
                (sessionFlags & SMB2SessionSetup.sessionFlagEncryptData) != 0
            let frame = try await validateNegotiateWireTransaction(packet: request, encrypt: encrypt)
            let response = try SMB2ValidateNegotiateInfo.decodeResponse(frame.bytes)
            guard response.capabilities == negotiated.capabilities,
                  response.serverGuid == negotiated.serverGuid,
                  response.securityMode == negotiated.rawSecurityMode,
                  response.dialect == negotiated.dialect
            else {
                throw SMBCodecError.invalidValue("VALIDATE_NEGOTIATE_INFO response does not match NEGOTIATE")
            }
            validateNegotiateSuccessCountForTestingStorage += 1
        } catch {
            // Fail closed because a 3.0.x tree is not usable until the negotiated parameters are authenticated.
            closeTransport(cause: "validate_negotiate_failure", diagnosticError: error)
            throw error
        }
    }

    func create(treeId: UInt32, path: String, directory: Bool) async throws -> [UInt8] {
        try await create(treeId: treeId, request: .read(path: path, directory: directory))
    }

    func create(treeId: UInt32, request: SMB2CreateRequest) async throws -> [UInt8] {
        let packet = try SMB2Create.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            request: request
        )
        debugDump("CREATE request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "CREATE response")
        let fileId = try SMB2Create.decodeFileId(response)
        debugLine("CREATE response FileId: \(SMBDebug.hex(fileId))")
        return fileId
    }

    /// stat / metadata 取得用に handle を開く。まず file を想定して
    /// `directory: false` で CREATE し、対象が directory で
    /// `STATUS_FILE_IS_A_DIRECTORY` を返したら `directory: true` で 1 回だけ
    /// retry する (`deleteNonRecursive` の自動判定と同型)。これにより file /
    /// directory どちらの path でも stat が通る (実 Samba / macOS SMB server は
    /// directory を directory:false の CREATE で拒否する)。常に directory:true で
    /// 開かないのは、そうすると file の open が壊れるサーバがあり得るため。
    func createForMetadata(treeId: UInt32, path: String) async throws -> [UInt8] {
        do {
            return try await create(treeId: treeId, request: .readMetadata(path: path, directory: false))
        } catch SMBError.fileIsADirectory {
            return try await create(treeId: treeId, request: .readMetadata(path: path, directory: true))
        }
    }

    func deleteNonRecursive(treeId: UInt32, path: String, directory: Bool) async throws {
        do {
            let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: directory))
            try await closeCreatedHandle(treeId: treeId, fileId: fileId)
        } catch SMBError.fileIsADirectory where !directory {
            let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: true))
            try await closeCreatedHandle(treeId: treeId, fileId: fileId)
        }
    }

    /// - Note: `searchPattern` は MS-SMB2 の正式な機能だが、**SMBee 内部に利用者はいない**
    ///   (既定の `"*"` のみ)。canonical name 解決 (`directoryEntry(matching:)`) は当初
    ///   leaf を pattern に渡していたが、macOS 共有が要求表記をそのまま返して canonical を
    ///   隠すため、全列挙 + client 側照合へ切り替えた (obaket issue 505、2026-08-19 実測)。
    ///   server の pattern マッチ意味論に依存する新しい呼び出しを足す前に、その実測を思い出すこと。
    func queryDirectory(
        treeId: UInt32,
        fileId: [UInt8],
        searchPattern: String = "*",
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        var restartScan = true
        var pageFingerprints = Set<String>()
        while true {
            let entries = try await queryDirectoryPage(
                treeId: treeId,
                fileId: fileId,
                restartScan: restartScan,
                searchPattern: searchPattern
            )
            restartScan = false
            guard let entries else { return }
            guard !entries.isEmpty else { return }
            let fingerprint = entries.map { "\($0.name):\($0.fileSize):\($0.isDirectory)" }.joined(separator: "\u{1f}")
            guard pageFingerprints.insert(fingerprint).inserted else {
                throw SMBCodecError.invalidValue("QUERY_DIRECTORY response made no progress")
            }
            for entry in entries {
                try Task.checkCancellation()
                try await onEntry(entry)
            }
        }
    }

    private func queryDirectoryPage(
        treeId: UInt32,
        fileId: [UInt8],
        restartScan: Bool,
        searchPattern: String = "*"
    ) async throws -> [SMBDirectoryEntry]? {
        try Task.checkCancellation()
        // Cap the output buffer by the granted credit window: requesting 256KiB with only
        // 1 granted credit would either be rejected by the server (CreditCharge too low)
        // or deadlock waiting for grants that never come. A smaller buffer just pages more.
        let outputBufferLength = await creditCappedLength(SMB2QueryDirectory.outputBufferSize)
        let packet = try SMB2QueryDirectory.encodeRequest(
            messageId: nextMessageId(charge: SMB2Credit.charge(forPayloadLength: UInt64(outputBufferLength))),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            restartScan: restartScan,
            outputBufferLength: outputBufferLength,
            searchPattern: searchPattern
        )
        debugDump("QUERY_DIRECTORY request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_DIRECTORY response")
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.noMoreFiles || header.status == SMB2Status.noSuchFile {
            // noSuchFile は search pattern が 1 件もマッチしなかったときの標準応答
            // (Windows / Samba)。列挙としては「空」であってエラーではない。
            //
            // ⚠️ 本関数は pattern 指定の有無に関わらず全 QUERY_DIRECTORY 経路が共有する。
            // つまり既定の "*" を使う `list(path:)` / `withDirectoryStream` にも効き、
            // 空 directory に noSuchFile を返す server 実装では throw でなく空配列になる
            // (テスト: testListReturnsEmptyWhenServerReportsNoSuchFile)。
            return nil
        }
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "QUERY_DIRECTORY")
        try Task.checkCancellation()
        return try SMB2QueryDirectory.decodeResponse(response)
    }

    func changeNotify(
        treeId: UInt32,
        fileId: [UInt8],
        filter: SMBChangeNotifyFilter,
        watchTree: Bool,
        shouldContinue: @escaping @Sendable () async -> Bool = { true },
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        while true {
            guard await shouldContinue() else { return }
            try Task.checkCancellation()
            let event = try await changeNotifyOnce(treeId: treeId, fileId: fileId, filter: filter, watchTree: watchTree)
            try Task.checkCancellation()
            try await onChange(event)
        }
    }

    private func changeNotifyOnce(
        treeId: UInt32,
        fileId: [UInt8],
        filter: SMBChangeNotifyFilter,
        watchTree: Bool
    ) async throws -> SMBChangeNotifyEvent {
        let packet = try SMB2ChangeNotify.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            completionFilter: filter,
            watchTree: watchTree
        )
        debugDump("CHANGE_NOTIFY request", packet)
        let response = try await signedLongPollWireTransaction(packet: packet, responseLabel: "CHANGE_NOTIFY response")
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.notifyEnumDir {
            return .overflow
        }
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "CHANGE_NOTIFY")
        return .changes(try SMB2ChangeNotify.decodeResponse(response))
    }

    func queryInfo(treeId: UInt32, fileId: [UInt8]) async throws -> SMBFileStat {
        let packet = try SMB2QueryInfo.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId
        )
        debugDump("QUERY_INFO request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_INFO response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "QUERY_INFO")
        var stat = try SMB2QueryInfo.decodeNetworkOpenInformation(response)
        guard stat.isReparsePoint else { return stat }
        let tagInfo = try await queryAttributeTagInfo(treeId: treeId, fileId: fileId)
        stat.reparseTag = tagInfo.reparseTag
        return stat
    }

    private func queryAttributeTagInfo(treeId: UInt32, fileId: [UInt8]) async throws -> (attributes: UInt32, reparseTag: UInt32) {
        let packet = try SMB2QueryInfo.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            fileInfoClass: SMB2QueryInfo.fileAttributeTagInformation,
            outputBufferLength: 8
        )
        debugDump("QUERY_INFO attribute tag request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_INFO attribute tag response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "QUERY_INFO")
        return try SMB2QueryInfo.decodeAttributeTagInformation(response)
    }

    func querySecurityInfo(treeId: UInt32, fileId: [UInt8]) async throws -> SMBSecurityInfo {
        let packet = try SMB2QueryInfo.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            infoType: SMB2QueryInfo.infoTypeSecurity,
            fileInfoClass: 0,
            outputBufferLength: 65_536,
            additionalInformation: SMB2QueryInfo.securityOwner | SMB2QueryInfo.securityGroup | SMB2QueryInfo.securityDACL
        )
        debugDump("QUERY_INFO security request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_INFO security response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "QUERY_INFO")
        return try SMB2QueryInfo.decodeSecurityInfo(response)
    }

    func volumeInfo(treeId: UInt32, fileId: [UInt8]) async throws -> SMBVolumeInfo {
        let fullSize = try await queryFilesystemFullSizeInfo(treeId: treeId, fileId: fileId)
        let attributes = try await queryFilesystemAttributeInfo(treeId: treeId, fileId: fileId)
        let volume = try await queryFilesystemVolumeInfo(treeId: treeId, fileId: fileId)
        return SMBVolumeInfo(
            totalBytes: fullSize.totalBytes,
            availableBytes: fullSize.availableBytes,
            filesystemName: attributes.filesystemName,
            volumeLabel: volume.volumeLabel,
            maxComponentLength: attributes.maxComponentLength,
            filesystemAttributes: attributes.filesystemAttributes,
            volumeSerialNumber: volume.volumeSerialNumber
        )
    }

    private func queryFilesystemFullSizeInfo(treeId: UInt32, fileId: [UInt8]) async throws -> (totalBytes: UInt64, availableBytes: UInt64) {
        let response = try await queryFilesystemInfo(treeId: treeId, fileId: fileId, fileInfoClass: SMB2QueryInfo.fileFsFullSizeInformation)
        return try SMB2QueryInfo.decodeFullSizeInformation(response)
    }

    private func queryFilesystemAttributeInfo(treeId: UInt32, fileId: [UInt8]) async throws -> (filesystemName: String, maxComponentLength: UInt32, filesystemAttributes: UInt32) {
        let response = try await queryFilesystemInfo(treeId: treeId, fileId: fileId, fileInfoClass: SMB2QueryInfo.fileFsAttributeInformation)
        return try SMB2QueryInfo.decodeAttributeInformation(response)
    }

    private func queryFilesystemVolumeInfo(treeId: UInt32, fileId: [UInt8]) async throws -> (volumeLabel: String, volumeSerialNumber: UInt32) {
        let response = try await queryFilesystemInfo(treeId: treeId, fileId: fileId, fileInfoClass: SMB2QueryInfo.fileFsVolumeInformation)
        return try SMB2QueryInfo.decodeVolumeInformation(response)
    }

    private func queryFilesystemInfo(treeId: UInt32, fileId: [UInt8], fileInfoClass: UInt8) async throws -> [UInt8] {
        let packet = try SMB2QueryInfo.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            infoType: SMB2QueryInfo.infoTypeFilesystem,
            fileInfoClass: fileInfoClass
        )
        debugDump("QUERY_INFO request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_INFO response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "QUERY_INFO")
        return response
    }

    func readChunk(treeId: UInt32, fileId: [UInt8], offset: UInt64, length: UInt64) async throws -> [UInt8] {
        (try await readChunkReportingRequestedLength(
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            length: length,
            requestTimeoutPolicy: .eligible
        )).data
    }

    // Prefix short-success detection uses the length encoded by this READ. Credits are
    // reserved before assigning that length, so concurrent requests cannot stale its charge.
    func readChunkReportingRequestedLength(
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64
    ) async throws -> (data: [UInt8], requestedLength: UInt32) {
        try await readChunkReportingRequestedLength(
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            length: length,
            requestTimeoutPolicy: .eligible
        )
    }

    private func readChunkReportingRequestedLength(
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64,
        requestTimeoutPolicy: SMBRequestTimeoutPolicy
    ) async throws -> (data: [UInt8], requestedLength: UInt32) {
        guard length > 0 else { return ([], 0) }
        try Task.checkCancellation()
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        try validateFileIdAdmission(command: SMB2Commands.read, fileId: fileId, cleanupFileId: nil)
        let maximumLength = UInt32(min(UInt64(negotiatedReadChunkSize()), length))
        let reservation = try await reserveVariableCredit(
            maximumPayloadLength: maximumLength,
            command: SMB2Commands.read,
            generation: generation
        )
        let requestLength = UInt32(min(UInt64(maximumLength), reservation.payloadLimit))
        do {
            let packet = try SMB2Read.encodeRequest(
                messageId: nextMessageId(charge: reservation.charge),
                sessionId: sessionId,
                treeId: treeId,
                fileId: fileId,
                offset: offset,
                length: requestLength
            )
            debugDump("READ request", packet)
            let perfCreditsBefore = SMBPerfLog.isEnabled ? await creditWindow.balance : 0
            let perfStart = ContinuousClock.now
            let response = try await signedWireTransaction(
                packet: packet,
                responseLabel: "READ response",
                requestTimeoutPolicy: requestTimeoutPolicy,
                creditReservation: reservation
            )
            let header = try SMB2Header.decode(response)
            if header.status == SMB2Status.endOfFile {
                return ([], requestLength)
            }
            try SMBErrorMapper.throwIfFailure(status: header.status, operation: "READ")
            let data = try SMB2Read.decodeResponse(response)
            SMBPerfLog.line(
                "read req=\(requestLength) got=\(data.count) " +
                    "wire=\(SMBPerfLog.milliseconds(ContinuousClock.now - perfStart))ms credits=\(perfCreditsBefore)"
            )
            guard data.count <= Int(requestLength) else {
                throw SMBCodecError.invalidValue("SMB read returned more data than requested")
            }
            try Task.checkCancellation()
            return (data, requestLength)
        } catch {
            await refundUnclaimedCredit(reservation)
            throw error
        }
    }

    private func readNamedPipeChunk(
        treeId: UInt32,
        fileId: [UInt8],
        length: UInt64
    ) async throws -> [UInt8] {
        try await readChunkReportingRequestedLength(
            treeId: treeId,
            fileId: fileId,
            offset: 0,
            length: length,
            requestTimeoutPolicy: .excluded(.namedPipeReadOrTransceive)
        ).data
    }

    func write(
        treeId: UInt32,
        fileId: [UInt8],
        data: [UInt8],
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        let progress = SMBTransferProgressEmitter(totalBytes: UInt64(data.count), onProgress: onProgress)
        try await writeChunk(
            treeId: treeId,
            fileId: fileId,
            offset: 0,
            data: data,
            onProgress: { progress.emit(bytesTransferred: UInt64($0)) }
        )
        await progress.finish()
    }

    func write(treeId: UInt32, fileId: [UInt8], offset startOffset: UInt64, nextChunk: (Int) throws -> [UInt8]) async throws {
        var offset = startOffset
        while true {
            try Task.checkCancellation()
            let chunkSize = await creditAwareWriteChunkSize()
            let chunk = try nextChunk(chunkSize)
            if chunk.isEmpty { break }
            try await writeChunk(treeId: treeId, fileId: fileId, offset: offset, data: chunk)
            let nextOffset = offset.addingReportingOverflow(UInt64(chunk.count))
            guard !nextOffset.overflow else {
                throw SMBCodecError.invalidValue("SMB write offset overflow")
            }
            offset = nextOffset.partialValue
        }
    }

    func write(
        treeId: UInt32,
        fileId: [UInt8],
        offset startOffset: UInt64,
        nextChunk: @Sendable (Int) async throws -> [UInt8],
        onProgress: (@Sendable (UInt64) -> Void)? = nil
    ) async throws {
        var offset = startOffset
        while true {
            try Task.checkCancellation()
            let chunkSize = await creditAwareWriteChunkSize()
            let chunk = try await nextChunk(chunkSize)
            if chunk.isEmpty { break }
            let nextOffset = offset.addingReportingOverflow(UInt64(chunk.count))
            guard !nextOffset.overflow else {
                throw SMBCodecError.invalidValue("SMB write offset overflow")
            }
            onProgress?(nextOffset.partialValue)
            try await writeChunk(treeId: treeId, fileId: fileId, offset: offset, data: chunk)
            offset = nextOffset.partialValue
        }
    }

    func copyFile(treeId: UInt32, fromPath: String, toPath: String, overwrite: Bool) async throws {
        let sourceFileId = try await create(treeId: treeId, request: .read(path: fromPath, directory: false))
        do {
            let stat = try await queryInfo(treeId: treeId, fileId: sourceFileId)
            let destinationFileId = try await create(treeId: treeId, request: .upload(path: toPath, overwrite: overwrite))
            do {
                if stat.size > 0 {
                    do {
                        try await copyFileServerSide(treeId: treeId, sourceFileId: sourceFileId, destinationFileId: destinationFileId, size: stat.size)
                    } catch is SMBServerSideCopyFallback {
                        try await copyFileClientSide(treeId: treeId, sourceFileId: sourceFileId, destinationFileId: destinationFileId, size: stat.size)
                    }
                }
                try await flush(treeId: treeId, fileId: destinationFileId)
                await bestEffortClose(treeId: treeId, fileId: destinationFileId)
                await bestEffortClose(treeId: treeId, fileId: sourceFileId)
            } catch {
                await bestEffortClose(treeId: treeId, fileId: destinationFileId)
                throw error
            }
        } catch {
            await bestEffortClose(treeId: treeId, fileId: sourceFileId)
            throw error
        }
    }

    private func copyFileClientSide(treeId: UInt32, sourceFileId: [UInt8], destinationFileId: [UInt8], size: UInt64) async throws {
        var offset: UInt64 = 0
        var remaining = size
        while remaining > 0 {
            try Task.checkCancellation()
            let chunk = try await readChunk(treeId: treeId, fileId: sourceFileId, offset: offset, length: remaining)
            if chunk.isEmpty { break }
            let advanced = try SMBChunkedTransfer.advancedReadPosition(
                cursor: offset,
                remaining: remaining,
                receivedCount: chunk.count
            )
            try await writeChunk(treeId: treeId, fileId: destinationFileId, offset: offset, data: chunk)
            offset = advanced.cursor
            remaining = advanced.remaining
        }
        guard remaining == 0 else {
            throw SMBCodecError.invalidValue("short SMB copy: \(remaining) bytes remaining")
        }
    }

    private func copyFileServerSide(treeId: UInt32, sourceFileId: [UInt8], destinationFileId: [UInt8], size: UInt64) async throws {
        let resumeKey = try await requestResumeKey(treeId: treeId, sourceFileId: sourceFileId)
        var limits = SMB2CopyChunkLimits()
        var offset: UInt64 = 0
        while offset < size {
            try Task.checkCancellation()
            let chunks = try makeCopyChunks(offset: offset, remaining: size - offset, limits: limits)
            do {
                let written = try await writeCopyChunks(treeId: treeId, destinationFileId: destinationFileId, resumeKey: resumeKey, chunks: chunks)
                guard written > 0 else {
                    throw SMBCodecError.invalidValue("SMB copychunk made no progress")
                }
                let next = offset.addingReportingOverflow(written)
                guard !next.overflow else {
                    throw SMBCodecError.invalidValue("SMB copychunk offset overflow")
                }
                offset = next.partialValue
            } catch let limitError as SMBCopyChunkLimitError {
                limits = limitError.limits
            }
        }

        let destinationStat = try await queryInfo(treeId: treeId, fileId: destinationFileId)
        guard destinationStat.size == size else {
            throw SMBCodecError.invalidValue("server-side SMB copy size mismatch: expected \(size), got \(destinationStat.size)")
        }
    }

    private func requestResumeKey(treeId: UInt32, sourceFileId: [UInt8]) async throws -> [UInt8] {
        let response = try await ioctl(
            treeId: treeId,
            fileId: sourceFileId,
            ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey,
            input: [],
            maxOutputResponse: SMB2CopyChunk.resumeKeyResponseMaxSize,
            allowedStatuses: SMBServerSideCopyFallback.allowedStatuses
        )
        guard response.status == SMB2Status.success else { throw SMBServerSideCopyFallback() }
        return try SMB2CopyChunk.decodeResumeKeyResponse(response.output)
    }

    private func writeCopyChunks(
        treeId: UInt32,
        destinationFileId: [UInt8],
        resumeKey: [UInt8],
        chunks: [SMB2CopyChunkRange]
    ) async throws -> UInt64 {
        let input = try SMB2CopyChunk.encodeCopyChunkRequest(resumeKey: resumeKey, chunks: chunks)
        // Destination upload handles request FILE_WRITE_DATA without FILE_READ_DATA, so use COPYCHUNK_WRITE.
        let response = try await ioctl(
            treeId: treeId,
            fileId: destinationFileId,
            ctlCode: SMB2Ioctl.fsctlSrvCopychunkWrite,
            input: input,
            maxOutputResponse: 12,
            allowedStatuses: SMBServerSideCopyFallback.allowedStatuses.union([SMB2Status.invalidParameter])
        )
        if response.status == SMB2Status.invalidParameter {
            throw SMBCopyChunkLimitError(limits: try SMB2CopyChunkLimits.decode(response.output))
        }
        guard response.status == SMB2Status.success else { throw SMBServerSideCopyFallback() }
        return UInt64(try SMB2CopyChunk.decodeCopyChunkResponse(response.output).totalBytesWritten)
    }

    private func ioctl(
        treeId: UInt32,
        fileId: [UInt8],
        ctlCode: UInt32,
        input: [UInt8],
        maxOutputResponse: UInt32,
        allowedStatuses: Set<UInt32>
    ) async throws -> SMB2IoctlResponse {
        let packet = try SMB2Ioctl.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            ctlCode: ctlCode,
            input: input,
            maxOutputResponse: maxOutputResponse
        )
        debugDump("IOCTL request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "IOCTL response")
        return try SMB2Ioctl.decodeResponseWithStatus(response, allowedStatuses: allowedStatuses.union([SMB2Status.success]))
    }

    func setSparse(treeId: UInt32, fileId: [UInt8], sparse: Bool) async throws {
        _ = try await ioctl(
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlSetSparse,
            input: SMB2SparseFile.encodeSetSparseInput(sparse),
            maxOutputResponse: 0,
            allowedStatuses: []
        )
    }

    func setZeroData(treeId: UInt32, fileId: [UInt8], offset: UInt64, length: UInt64) async throws {
        _ = try await ioctl(
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlSetZeroData,
            input: try SMB2SparseFile.encodeSetZeroDataInput(offset: offset, length: length),
            maxOutputResponse: 0,
            allowedStatuses: []
        )
    }

    func queryAllocatedRanges(
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64
    ) async throws -> [SMBAllocatedRange] {
        // STATUS_BUFFER_OVERFLOW: the range list is larger than our buffer; the returned
        // prefix is still valid. A sparse file with many fragments could hit this, but the
        // 64 KiB buffer holds 4096 ranges, which is plenty for typical files.
        let response = try await ioctl(
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlQueryAllocatedRanges,
            input: SMB2SparseFile.encodeQueryAllocatedRangesInput(offset: offset, length: length),
            maxOutputResponse: 64 * 1024,
            allowedStatuses: [SMB2Status.bufferOverflow]
        )
        return try SMB2SparseFile.decodeAllocatedRanges(response.output)
    }

    private func makeCopyChunks(offset: UInt64, remaining: UInt64, limits: SMB2CopyChunkLimits) throws -> [SMB2CopyChunkRange] {
        let maxChunks = max(1, limits.maxChunks)
        let maxChunkSize = max(1, limits.maxChunkSize)
        let maxTotalSize = max(1, limits.maxTotalSize)
        var chunks: [SMB2CopyChunkRange] = []
        var chunkOffset = offset
        var requestRemaining = min(remaining, UInt64(maxTotalSize))
        while requestRemaining > 0 && chunks.count < Int(maxChunks) {
            let length64 = min(requestRemaining, UInt64(maxChunkSize), UInt64(UInt32.max))
            guard length64 > 0 else { break }
            let length = UInt32(length64)
            chunks.append(SMB2CopyChunkRange(sourceOffset: chunkOffset, targetOffset: chunkOffset, length: length))
            chunkOffset += UInt64(length)
            requestRemaining -= UInt64(length)
        }
        guard !chunks.isEmpty else {
            throw SMBCodecError.invalidValue("SMB copychunk limits produced no chunks")
        }
        return chunks
    }

    func copyDirectory(
        treeId: UInt32,
        fromPath: String,
        toPath: String,
        overwrite: Bool,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        depth: Int = 0,
        relativePath: String = "",
        failures: SMBRecursiveFailureCollector? = nil
    ) async throws {
        let collector = failures ?? SMBRecursiveFailureCollector()
        try Task.checkCancellation()
        try SMBPath.validateRecursionDepth(depth)
        try SMBPath.validateDirectoryCopyTarget(fromPath: fromPath, toPath: toPath)
        let sourceFileId = try await create(treeId: treeId, path: fromPath, directory: true)
        do {
            if dryRun {
                onAction?(SMBRecursiveAction(kind: .mkdir, path: toPath))
            } else {
                let destinationFileId = try await create(treeId: treeId, request: .makeDirectory(path: toPath))
                try await closeCreatedHandle(treeId: treeId, fileId: destinationFileId)
                onAction?(SMBRecursiveAction(kind: .mkdir, path: toPath))
            }
        } catch SMBError.nameCollision where overwrite {
            // Existing destination directories are reused only when overwrite is explicit.
        } catch SMBError.nameCollision where skipExisting {
            onAction?(SMBRecursiveAction(kind: .skip, path: toPath))
            await bestEffortClose(treeId: treeId, fileId: sourceFileId)
            if failures == nil {
                try collector.throwIfNeeded()
            }
            return
        } catch {
            await bestEffortClose(treeId: treeId, fileId: sourceFileId)
            throw error
        }

        do {
            try await queryDirectory(treeId: treeId, fileId: sourceFileId) { entry in
                try Task.checkCancellation()
                try SMBPath.validateDirectoryEntryName(entry.name)
                let sourceChild = self.joinSMBPath(fromPath, entry.name)
                let destinationChild = self.joinSMBPath(toPath, entry.name)
                let relativeChild = self.joinSMBPath(relativePath, entry.name)
                if recursiveEntryIsExcluded(name: entry.name, relativePath: relativeChild, exclude: exclude) {
                    return
                }
                if entry.isReparsePoint {
                    onAction?(SMBRecursiveAction(kind: .skip, path: destinationChild))
                    return
                }
                if entry.isDirectory {
                    do {
                        try await self.copyDirectory(
                            treeId: treeId,
                            fromPath: sourceChild,
                            toPath: destinationChild,
                            overwrite: overwrite,
                            continueOnError: continueOnError,
                            skipExisting: skipExisting,
                            dryRun: dryRun,
                            include: include,
                            exclude: exclude,
                            perFileTimeout: perFileTimeout,
                            onAction: onAction,
                            depth: depth + 1,
                            relativePath: relativeChild,
                            failures: collector
                        )
                    } catch {
                        guard continueOnError else { throw error }
                        collector.record(path: sourceChild, error: error)
                    }
                } else {
                    guard recursiveEntryIsIncluded(name: entry.name, relativePath: relativeChild, include: include) else {
                        return
                    }
                    do {
                        if dryRun {
                            onAction?(SMBRecursiveAction(kind: .copy, path: destinationChild))
                        } else {
                            try await SMBOperationDeadline.run(timeout: perFileTimeout) {
                                try await self.copyFile(treeId: treeId, fromPath: sourceChild, toPath: destinationChild, overwrite: overwrite)
                            }
                            onAction?(SMBRecursiveAction(kind: .copy, path: destinationChild))
                        }
                    } catch SMBError.nameCollision where skipExisting {
                        onAction?(SMBRecursiveAction(kind: .skip, path: destinationChild))
                    } catch {
                        guard continueOnError else { throw error }
                        collector.record(path: sourceChild, error: error)
                    }
                }
            }
            await bestEffortClose(treeId: treeId, fileId: sourceFileId)
        } catch {
            await bestEffortClose(treeId: treeId, fileId: sourceFileId)
            throw error
        }
        if failures == nil {
            try collector.throwIfNeeded()
        }
    }

    private func writeChunk(
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        data: [UInt8],
        onProgress: (@Sendable (Int) -> Void)? = nil
    ) async throws {
        var cursor = 0
        while cursor < data.count {
            try Task.checkCancellation()
            guard let generation = readerLifecycle.activeGeneration else {
                throw wireFailure ?? SMBTransportError.connectionClosed
            }
            try validateFileIdAdmission(command: SMB2Commands.write, fileId: fileId, cleanupFileId: nil)
            let maximumLength = min(data.count - cursor, negotiatedWriteChunkSize())
            guard maximumLength > 0 else {
                throw SMBCodecError.invalidValue("SMB negotiated write size is zero")
            }
            let reservation = try await reserveVariableCredit(
                maximumPayloadLength: UInt32(maximumLength),
                command: SMB2Commands.write,
                generation: generation
            )
            let payloadLength = min(maximumLength, Int(clamping: reservation.payloadLimit))
            let requestData = Array(data[cursor..<(cursor + payloadLength)])
            let nextOffset = offset.addingReportingOverflow(UInt64(cursor))
            guard !nextOffset.overflow else {
                await refundUnclaimedCredit(reservation)
                throw SMBCodecError.invalidValue("SMB write offset overflow")
            }
            do {
                let packet = try SMB2Write.encodeRequest(
                    messageId: nextMessageId(charge: reservation.charge),
                    sessionId: sessionId,
                    treeId: treeId,
                    fileId: fileId,
                    offset: nextOffset.partialValue,
                    data: requestData
                )
                debugDump("WRITE request", packet)
                let perfCreditsBefore = SMBPerfLog.isEnabled ? await creditWindow.balance : 0
                let perfStart = ContinuousClock.now
                let response = try await signedWireTransaction(
                    packet: packet,
                    responseLabel: "WRITE response",
                    creditReservation: reservation
                )
                let count = try SMB2Write.decodeResponseCount(response)
                SMBPerfLog.line(
                    "write req=\(requestData.count) got=\(count) " +
                        "wire=\(SMBPerfLog.milliseconds(ContinuousClock.now - perfStart))ms credits=\(perfCreditsBefore)"
                )
                guard count == requestData.count else {
                    throw SMBCodecError.invalidValue("short SMB write: expected \(requestData.count) bytes, got \(count)")
                }
                cursor += Int(count)
                onProgress?(cursor)
            } catch {
                await refundUnclaimedCredit(reservation)
                throw error
            }
        }
    }

    func pipeTransceive(treeId: UInt32, fileId: [UInt8], input: [UInt8], maxOutputResponse: UInt32 = 65_536) async throws -> [UInt8] {
        let packet = try SMB2Ioctl.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlPipeTransceive,
            input: input,
            maxOutputResponse: maxOutputResponse
        )
        debugDump("IOCTL FSCTL_PIPE_TRANSCEIVE request", packet)
        let response = try await signedWireTransaction(
            packet: packet,
            responseLabel: "IOCTL FSCTL_PIPE_TRANSCEIVE response",
            requestTimeoutPolicy: .excluded(.namedPipeReadOrTransceive)
        )
        let decoded = try SMB2Ioctl.decodeResponseWithStatus(
            response,
            allowedStatuses: [SMB2Status.success, SMB2Status.bufferOverflow]
        )
        guard decoded.status == SMB2Status.success || decoded.status == SMB2Status.bufferOverflow else {
            throw SMBErrorMapper.map(status: decoded.status, operation: "IOCTL")
        }
        var output = decoded.output
        let expectedCallId = try? DCERPC.callId(input)
        var fragmentCount = 1
        while !(try DCERPC.validateResponseFragments(output, expectedCallId: expectedCallId)) {
            try Task.checkCancellation()
            let chunk = try await readNamedPipeChunk(
                treeId: treeId,
                fileId: fileId,
                length: UInt64(negotiatedReadChunkSize())
            )
            guard !chunk.isEmpty else {
                throw SMBCodecError.invalidValue("short DCE/RPC pipe response")
            }
            fragmentCount += 1
            guard fragmentCount <= 256, output.count + chunk.count <= 16 * 1024 * 1024 else {
                throw SMBCodecError.invalidValue("DCE/RPC pipe response exceeds size limit")
            }
            output.append(contentsOf: chunk)
        }
        return output
    }

    func lock(treeId: UInt32, fileId: [UInt8], elements: [SMB2LockElement]) async throws {
        let packet = try SMB2Lock.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            elements: elements
        )
        debugDump("LOCK request", packet)
        let waitsForConflictingLock = elements.contains { element in
            (element.flags & SMB2LockElement.unlock) == 0 &&
                (element.flags & SMB2LockElement.failImmediately) == 0
        }
        let timeoutPolicy: SMBRequestTimeoutPolicy = waitsForConflictingLock
            ? .excluded(.blockingLock)
            : .eligible
        let response = try await signedWireTransaction(
            packet: packet,
            responseLabel: "LOCK response",
            requestTimeoutPolicy: timeoutPolicy
        )
        try SMB2Lock.decodeResponse(response)
    }

    func flush(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Flush.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("FLUSH request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "FLUSH response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "FLUSH")
    }

    func deleteRecursively(
        treeId: UInt32,
        path: String,
        directory: Bool,
        continueOnError: Bool = false,
        dryRun: Bool = false,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        depth: Int = 0,
        failures: SMBRecursiveFailureCollector? = nil
    ) async throws {
        let collector = failures ?? SMBRecursiveFailureCollector()
        try Task.checkCancellation()
        try SMBPath.validateRecursionDepth(depth)
        if directory {
            let fileId = try await create(treeId: treeId, path: path, directory: true)
            do {
                try await queryDirectory(treeId: treeId, fileId: fileId) { entry in
                    try Task.checkCancellation()
                    try SMBPath.validateDirectoryEntryName(entry.name)
                    let childPath = self.joinSMBPath(path, entry.name)
                    if entry.isReparsePoint {
                        do {
                            if dryRun {
                                onAction?(SMBRecursiveAction(kind: .delete, path: childPath))
                            } else {
                                let childFileId = try await self.create(
                                    treeId: treeId,
                                    request: .deleteReparsePoint(path: childPath, directory: entry.isDirectory)
                                )
                                try await self.closeCreatedHandle(treeId: treeId, fileId: childFileId)
                                onAction?(SMBRecursiveAction(kind: .delete, path: childPath))
                            }
                        } catch {
                            guard continueOnError else { throw error }
                            collector.record(path: childPath, error: error)
                        }
                        return
                    }
                    do {
                        try await self.deleteRecursively(
                            treeId: treeId,
                            path: childPath,
                            directory: entry.isDirectory,
                            continueOnError: continueOnError,
                            dryRun: dryRun,
                            onAction: onAction,
                            depth: depth + 1,
                            failures: collector
                        )
                    } catch {
                        guard continueOnError else { throw error }
                        collector.record(path: childPath, error: error)
                    }
                }
                await bestEffortClose(treeId: treeId, fileId: fileId)
            } catch {
                await bestEffortClose(treeId: treeId, fileId: fileId)
                throw error
            }
        }
        do {
            if dryRun {
                onAction?(SMBRecursiveAction(kind: .delete, path: path))
            } else {
                let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: directory))
                try await closeCreatedHandle(treeId: treeId, fileId: fileId)
                onAction?(SMBRecursiveAction(kind: .delete, path: path))
            }
        } catch {
            guard continueOnError else { throw error }
            collector.record(path: path, error: error)
        }
        if failures == nil {
            try collector.throwIfNeeded()
        }
    }

    func rename(treeId: UInt32, fileId: [UInt8], newPath: String, replaceIfExists: Bool) async throws {
        let packet = try SMB2SetInfo.encodeRenameRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            newPath: newPath,
            replaceIfExists: replaceIfExists
        )
        debugDump("SET_INFO rename request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "SET_INFO rename response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "SET_INFO rename")
    }

    func setBasicInfo(treeId: UInt32, fileId: [UInt8], update: SMBFileMetadataUpdate) async throws {
        let packet = try SMB2SetInfo.encodeBasicInfoRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            update: update
        )
        debugDump("SET_INFO basic request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "SET_INFO basic response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "SET_INFO basic")
    }

    func setSecurityInfo(
        treeId: UInt32,
        fileId: [UInt8],
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool
    ) async throws {
        let packet = try SMB2SetInfo.encodeSecurityDescriptorRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            ownerSID: ownerSID,
            groupSID: groupSID,
            dacl: dacl,
            force: force
        )
        debugDump("SET_INFO security request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "SET_INFO security response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "SET_INFO security")
    }

    func listShares(treeId: UInt32) async throws -> [SMBShareInfo] {
        let fileId = try await create(treeId: treeId, request: .namedPipe(path: "srvsvc"))
        do {
            let bind = try DCERPC.encodeBind(callId: 1, abstractSyntax: SRVSVC.interfaceUUID, abstractVersion: SRVSVC.interfaceVersion)
            try await write(treeId: treeId, fileId: fileId, data: bind)
            let bindAck = try await readNamedPipeChunk(treeId: treeId, fileId: fileId, length: 4_280)
            try DCERPC.decodeBindAck(bindAck)

            let request = try DCERPC.encodeRequest(
                callId: 2,
                opnum: SRVSVC.netrShareEnumOpnum,
                stub: SRVSVC.encodeNetrShareEnumRequest()
            )
            let response = try await pipeTransceive(treeId: treeId, fileId: fileId, input: request)
            let shares = try SRVSVC.decodeNetrShareEnumResponse(try DCERPC.decodeResponseStub(response))
            await bestEffortClose(treeId: treeId, fileId: fileId)
            return shares
        } catch {
            await bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    /// Resolve SIDs to account names via the `lsarpc` pipe (MS-LSAT LsarLookupSids).
    /// Returned array matches `sids` positionally; unmapped SIDs are nil.
    func lookupSIDs(treeId: UInt32, sids: [String]) async throws -> [SMBResolvedSIDName?] {
        guard !sids.isEmpty else { return [] }
        let fileId = try await create(treeId: treeId, request: .namedPipe(path: "lsarpc"))
        do {
            let bind = try DCERPC.encodeBind(callId: 1, abstractSyntax: LSARPC.interfaceUUID, abstractVersion: LSARPC.interfaceVersion)
            try await write(treeId: treeId, fileId: fileId, data: bind)
            let bindAck = try await readNamedPipeChunk(treeId: treeId, fileId: fileId, length: 4_280)
            try DCERPC.decodeBindAck(bindAck)

            let openRequest = try DCERPC.encodeRequest(
                callId: 2,
                opnum: LSARPC.opnumOpenPolicy2,
                stub: LSARPC.encodeOpenPolicy2Request()
            )
            let openResponse = try await pipeTransceive(treeId: treeId, fileId: fileId, input: openRequest)
            let handle = try LSARPC.decodePolicyHandleResponse(
                try DCERPC.decodeResponseStub(openResponse),
                operation: "LsarOpenPolicy2"
            )

            let lookupRequest = try DCERPC.encodeRequest(
                callId: 3,
                opnum: LSARPC.opnumLookupSids,
                stub: try LSARPC.encodeLookupSidsRequest(handle: handle, sids: sids)
            )
            let lookupResponse = try await pipeTransceive(treeId: treeId, fileId: fileId, input: lookupRequest)
            let names = try LSARPC.decodeLookupSidsResponse(try DCERPC.decodeResponseStub(lookupResponse))

            let closeRequest = try DCERPC.encodeRequest(
                callId: 4,
                opnum: LSARPC.opnumClose,
                stub: try LSARPC.encodeCloseRequest(handle: handle)
            )
            _ = try? await pipeTransceive(treeId: treeId, fileId: fileId, input: closeRequest)
            await bestEffortClose(treeId: treeId, fileId: fileId)
            // Positional guarantee: pad if the server returned fewer entries than requested.
            if names.count < sids.count {
                return names + Array(repeating: nil, count: sids.count - names.count)
            }
            return Array(names.prefix(sids.count))
        } catch {
            await bestEffortClose(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    func dfsReferral(treeId: UInt32, path: String) async throws -> SMBDfsReferralResult {
        let input = SMB2DfsReferral.encodeRequestInput(path: path)
        let response = try await ioctl(
            treeId: treeId,
            fileId: Array(repeating: 0xff, count: 16),
            ctlCode: SMB2Ioctl.fsctlDfsGetReferrals,
            input: input,
            maxOutputResponse: 65_536,
            allowedStatuses: []
        )
        return try SMB2DfsReferral.decodeResponse(response.output)
    }

    func reparsePoint(treeId: UInt32, fileId: [UInt8]) async throws -> SMBReparsePoint {
        let response = try await ioctl(
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlGetReparsePoint,
            input: [],
            maxOutputResponse: 16 * 1024,
            allowedStatuses: []
        )
        return try SMB2ReparsePoint.decode(response.output)
    }

    func setSymbolicLinkReparsePoint(treeId: UInt32, fileId: [UInt8], target: String) async throws {
        _ = try await ioctl(
            treeId: treeId,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlSetReparsePoint,
            input: try SMB2ReparsePoint.encodeSymbolicLink(
                substituteName: target,
                printName: target,
                relative: true
            ),
            maxOutputResponse: 0,
            allowedStatuses: []
        )
    }

    func close(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Close.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("CLOSE request", packet)
        let response = try await signedWireTransaction(
            packet: packet,
            responseLabel: "CLOSE response",
            cleanupFileId: fileId
        )
        let header = try SMB2Header.decode(response)
        if SMBPerfLog.effectiveIsEnabled {
            SMBPerfLog.line("[wire] close_status session=\(diagnosticSessionId) file=\(Self.fileIdPrefix(fileId)) status=0x\(String(format: "%08x", header.status))")
        }
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "CLOSE")
    }

    func closeCreatedHandle(treeId: UInt32, fileId: [UInt8]) async throws {
        try await close(treeId: treeId, fileId: fileId)
    }

    /// Cleanup path: do not inherit caller cancellation while trying to release a handle.
    func bestEffortClose(treeId: UInt32, fileId: [UInt8]) async {
        let task = Task.detached { [self] in
            let started = SMBPerfLog.effectiveIsEnabled ? ContinuousClock.now : nil
            do {
                try await self.close(treeId: treeId, fileId: fileId)
            } catch {
                if let started {
                    let elapsed = SMBPerfLog.milliseconds(ContinuousClock.now - started)
                    let timedOut = error is SMBTransportError && (error as? SMBTransportError) == .timedOut
                    SMBPerfLog.line("[wire] cleanup_close_failed session=\(diagnosticSessionId) file=\(Self.fileIdPrefix(fileId)) elapsed_ms=\(elapsed) error=\(Self.diagnosticError(error)) timeout=\(timedOut)")
                }
            }
        }
        await task.value
    }

    func treeDisconnect(treeId: UInt32) async throws {
        let packet = try SMB2TreeDisconnect.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId)
        debugDump("TREE_DISCONNECT request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "TREE_DISCONNECT response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "TREE_DISCONNECT")
    }

    /// Cleanup path for scoped trees. A missing response invalidates the shared transport,
    /// because the server-side tree lifetime can no longer be determined safely.
    func bestEffortTreeDisconnect(treeId: UInt32) async {
        let timeout = cleanupTimeout
        let task = Task.detached { [self] in
            do {
                try await SMBOperationDeadline.run(timeout: timeout, sleeper: cleanupTimeoutSleeper) {
                    try await self.treeDisconnect(treeId: treeId)
                }
            } catch {
                await self.closeTransportAndWait(cause: "best_effort_tree_disconnect", diagnosticError: error)
            }
        }
        await task.value
    }

    func logoff() async throws {
        let packet = try SMB2Logoff.encodeRequest(messageId: nextMessageId(), sessionId: sessionId)
        debugDump("LOGOFF request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "LOGOFF response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "LOGOFF")
    }

    func echo() async throws {
        let packet = try SMB2Echo.encodeRequest(messageId: nextMessageId(), sessionId: sessionId)
        debugDump("ECHO request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "ECHO response")
        try SMB2Echo.decodeResponse(response)
    }

    private func sendCancelWithoutGate(target: SMB2Cancel.Target, generation: UInt64) async {
        guard isGenerationActive(generation) else { return }
        do {
            let packet = try SMB2Cancel.encodeRequest(target: target, sessionId: sessionId)
            debugDump("CANCEL request", packet)
            try await sendSigned(packet, generation: generation)
        } catch {
            if isGenerationActive(generation), !(error is CancellationError) {
                failWire(error: error)
                closeTransport(cause: "cancel_send_failure", diagnosticError: error)
            }
            debugLine("CANCEL request failed: \(error)")
        }
    }

    private func scheduleCancel(messageId: UInt64, generation: UInt64, wait: Bool) async {
        guard isGenerationActive(generation) else { return }
        let operationID = UUID()
        let task = Task { [weak self] in
            guard let self else { return }
            await self.performScheduledCancel(
                operationID: operationID,
                messageId: messageId,
                generation: generation
            )
        }
        activeCancelTasks[operationID] = task
        if wait { await task.value }
    }

    private func performScheduledCancel(operationID: UUID, messageId: UInt64, generation: UInt64) async {
        if let target = cancelInFlightRequest(messageId: messageId, generation: generation),
           isGenerationActive(generation) {
            await sendCancelWithoutGate(target: target, generation: generation)
        }
        activeCancelTasks.removeValue(forKey: operationID)
    }

    func disconnect(treeId: UInt32) async {
        let timeout = cleanupTimeout
        let task = Task.detached { [self] in
            var diagnosticError: Error?
            do {
                try await SMBOperationDeadline.run(timeout: timeout, sleeper: cleanupTimeoutSleeper) {
                    try await self.treeDisconnect(treeId: treeId)
                }
                try await SMBOperationDeadline.run(timeout: timeout, sleeper: cleanupTimeoutSleeper) {
                    try await self.logoff()
                }
            } catch {
                diagnosticError = error
                // A graceful cleanup response is missing or invalid. The connection is now
                // suspect; closing it is the only bounded way to release server-side state.
            }
            await self.closeTransportAndWait(cause: "disconnect", diagnosticError: diagnosticError)
        }
        await task.value
    }

    func closeTransport(cause: String = "unspecified", diagnosticError: Error? = nil) {
        guard !readerLifecycle.isTerminal else { return }
        if SMBPerfLog.effectiveIsEnabled {
            let diagnostic = diagnosticError.map(Self.diagnosticError) ?? "none"
            SMBPerfLog.line("[wire] close_transport session=\(diagnosticSessionId) cause=\(cause) error=\(diagnostic)")
        }
        let generation = readerLifecycle.activeGeneration ?? Self.initialWireGeneration
        if let readerHandle {
            readerLifecycle = .stopping(generation: generation, handle: readerHandle, reason: cause)
        } else {
            readerLifecycle = .stopped(generation: generation)
        }
        let tasks = Array(activeSendTasks.values) + Array(activeCancelTasks.values)
        for task in tasks { task.cancel() }
        for task in readerTasks.values { task.cancel() }
        transport.close()
        failWire(error: SMBTransportError.connectionClosed, recordFirstFault: false)
        cleanupLedger.removeAll()
        resumeCleanupLedgerCountWaiters()
    }

    /// Explicit teardown observes the owned reader, send operations, CANCEL operations and
    /// credit drain. Fault paths remain synchronous so a reader never joins its own Task.
    func closeTransportAndWait(cause: String = "unspecified", diagnosticError: Error? = nil) async {
        closeTransport(cause: cause, diagnosticError: diagnosticError)
        // closeTransport made the lifecycle terminal before this snapshot, so no reader
        // can be added after it. Keep overlapping old/new readers in the same join set.
        let readers = Array(readerTasks)
        readerTaskJoinSnapshotHookForTesting?(readers.count)
        let joinWillAwait = readerTaskJoinWillAwaitHookForTesting
        await waitForConnectCompletion()
        let sendTasks = Array(activeSendTasks.values)
        let cancelTasks = Array(activeCancelTasks.values)
        for task in sendTasks { await task.value }
        for task in cancelTasks { await task.value }
        for (handle, reader) in readers {
            joinWillAwait?(handle)
            await reader.value
        }
        await creditFailureTask?.value
    }

    private func finishConnectAttempt() {
        connectInFlight = false
        let waiters = connectCompletionWaiters
        connectCompletionWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }

    private func waitForConnectCompletion() async {
        guard connectInFlight else { return }
        await withCheckedContinuation { continuation in
            if connectInFlight {
                connectCompletionWaiters.append(continuation)
            } else {
                continuation.resume()
            }
        }
    }

    // Internal-only seams keep deterministic diagnostics tests independent of the process
    // environment. They are not used by production code paths.
    func failWireForTesting(error: Error) {
        failWire(error: error)
    }

    func failPendingResponseForTesting(messageId: UInt64, error: Error = CancellationError()) {
        failPendingResponse(messageId: messageId, error: error)
    }

    func sendDidSucceedForTesting(messageId: UInt64, generation: UInt64? = nil) async {
        await sendDidSucceed(messageId: messageId, generation: generation ?? Self.initialWireGeneration)
    }

    /// Runs full-send completions without a suspension between ordinary requests so tests
    /// can exercise the actor-turn ordering at the reader bootstrap boundary.
    func sendDidSucceedInOrderForTesting(_ messageIds: [UInt64], generation: UInt64? = nil) async -> Int {
        let generation = generation ?? Self.initialWireGeneration
        for messageId in messageIds {
            guard let target = reconcileSuccessfulSend(messageId: messageId, generation: generation) else { continue }
            await sendCancelWithoutGate(target: target, generation: generation)
        }
        return readerTasks.count
    }

    func readerHandleForTesting() -> UUID? {
        readerHandle
    }

    func readerTaskForTesting(handle: UUID) -> Task<Void, Never>? {
        readerTasks[handle]
    }

    func readerTaskCountForTesting() -> Int {
        readerTasks.count
    }

    func waitForActiveSendTasksForTesting() async {
        let tasks = Array(activeSendTasks.values)
        for task in tasks { await task.value }
    }

    func setReaderTaskExitHookForTesting(_ hook: (@Sendable (UUID) async -> Void)?) {
        readerTaskExitHookForTesting = hook
    }

    func setReaderTaskJoinSnapshotHookForTesting(_ hook: (@Sendable (Int) -> Void)?) {
        readerTaskJoinSnapshotHookForTesting = hook
    }

    func setReaderTaskJoinWillAwaitHookForTesting(_ hook: (@Sendable (UUID) -> Void)?) {
        readerTaskJoinWillAwaitHookForTesting = hook
    }

    func readerDidExitForTesting(generation: UInt64, handle: UUID, error: Error?) {
        readerDidExit(generation: generation, handle: handle, error: error)
    }

    func setCreditGrantAfterAwaitHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        creditGrantAfterAwaitHookForTesting = hook
    }

    func setCreditGrantActorHookForTesting(_ hook: (@Sendable () async -> Void)?) async {
        await creditWindow.setGrantActorHookForTesting(hook)
    }

    func parkPendingForTesting(
        messageId: UInt64,
        command: UInt16,
        sent: Bool = false,
        sending: Bool = false,
        responseProtectionPolicy: SMBResponseProtectionPolicy = .sessionDefault,
        onRegistered: @Sendable () -> Void = {}
    ) async throws {
        let identity = makeRequestIdentity(generation: Self.initialWireGeneration)
        _ = try await withCheckedThrowingContinuation { continuation in
            storePendingResponse(messageId: messageId, pending: SMBPendingResponse(
                requestIdentity: identity,
                generation: Self.initialWireGeneration,
                label: "testing",
                longPoll: false,
                requestTimeoutPolicy: .eligible,
                responseProtectionPolicy: responseProtectionPolicy,
                expectedCommand: command,
                expectedSessionId: sessionId,
                expectedTreeId: 0,
                completionTarget: .transaction(continuation),
                sendTask: nil,
                timeoutTask: nil,
                timeoutIdentity: nil,
                sendPhase: sent ? .sent : (sending ? .sending : .registered),
                cancellationRequested: false,
                continuationResumed: false
            ))
            onRegistered()
            resumePendingCountWaiters()
        }
    }

    func activeRequestIdentityCountForTesting() -> Int {
        activeRequestIdentities.count
    }

    func requestIdentityForTesting(messageId: UInt64) -> SMBRequestIdentity? {
        pendingResponses[messageId]?.requestIdentity
    }

    func parkCreditWaiterForTesting(charge: UInt16) async throws {
        _ = try await creditWindow.reserve(charge: charge)
    }

    func creditWaiterCountForTesting() async -> Int {
        await creditWindow.pendingWaiterCount
    }

    func creditBalanceForTesting() async -> UInt32 {
        await creditWindow.balance
    }

    func creditGrantReceiptCountForTesting() async -> Int {
        await creditWindow.grantReceiptCountForTesting()
    }

    func readerTaskForTesting() -> Task<Void, Never>? {
        guard let readerHandle else { return nil }
        return readerTasks[readerHandle]
    }

    func startRequestTimeoutForTesting() -> Task<Void, Never> {
        startRequestTimeout(
            messageId: UInt64.max - 1,
            command: SMB2Commands.echo,
            generation: Self.initialWireGeneration,
            identity: UUID(),
            duration: .seconds(1)
        )
    }

    func waitForPendingCountForTesting(atLeast count: Int) async {
        await waitForTestingCount(.pendingResponses, atLeast: count)
    }

    func waitForRequestSentCountForTesting(atLeast count: Int) async {
        await waitForTestingCount(.requestSent, atLeast: count)
    }

    func waitForRequestSentWaiterRegistrationCountForTesting(atLeast count: Int) async {
        await waitForTestingCount(.requestSentWaiterRegistrations, atLeast: count)
    }

    func setSessionIdForTesting(_ sessionId: UInt64) {
        self.sessionId = sessionId
    }

    func pendingAsyncIdForTesting(messageId: UInt64) -> UInt64? {
        pendingResponses[messageId]?.asyncId
    }

    func pendingInterimCountForTesting(messageId: UInt64) -> Int {
        pendingResponses[messageId]?.pendingCount ?? 0
    }

    func pendingFinalSeenForTesting(messageId: UInt64) -> Bool {
        pendingResponses[messageId]?.finalSeen ?? false
    }

    func pendingContinuationResumedForTesting(messageId: UInt64) -> Bool {
        pendingResponses[messageId]?.continuationResumed ?? false
    }

    func lastFinalAcceptanceForTesting() -> ContinuousClock.Instant? {
        lastFinalAcceptanceForTestingStorage
    }

    func markRequestSentWithoutReaderForTesting(messageId: UInt64) {
        _ = markRequestSent(messageId: messageId, generation: Self.initialWireGeneration)
    }

    func parkCleanupPendingForTesting(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8]
    ) async throws {
        let fileKey = SMBFileIdLedgerKey(bytes: fileId)
        let requestIdentity = makeRequestIdentity(generation: Self.initialWireGeneration)
        cleanupLedger[fileKey] = .sending
        resumeCleanupLedgerCountWaiters()
        _ = try await withCheckedThrowingContinuation { continuation in
            storePendingResponse(messageId: messageId, pending: SMBPendingResponse(
                requestIdentity: requestIdentity,
                generation: Self.initialWireGeneration,
                label: "testing cleanup",
                longPoll: false,
                requestTimeoutPolicy: .eligible,
                responseProtectionPolicy: .sessionDefault,
                expectedCommand: SMB2Commands.close,
                expectedSessionId: sessionId,
                expectedTreeId: treeId,
                completionTarget: .transaction(continuation),
                sendTask: nil,
                timeoutTask: nil,
                timeoutIdentity: nil,
                sendPhase: .registered,
                cancellationRequested: false,
                continuationResumed: false,
                cleanupFileId: fileKey
            ))
            let identity = UUID()
            pendingResponses[messageId]?.cleanupTimeoutIdentity = identity
            pendingResponses[messageId]?.cleanupTimeoutTask = startCleanupTimeout(
                messageId: messageId,
                generation: Self.initialWireGeneration,
                identity: identity
            )
        }
    }

    func pendingCountForTesting() -> Int {
        pendingResponses.values.filter { !$0.continuationResumed }.count
    }

    func wirePendingRecordCountForTesting() -> Int {
        pendingResponses.count
    }

    func waitForPendingCommandResponseDrainWaiterCountForTesting(command: UInt16, atLeast count: Int) async {
        await waitForTestingCount(.pendingCommandResponseDrainWaiters(command), atLeast: count)
    }

    func cleanupTombstoneCountForTesting() -> Int {
        pendingResponses.values.filter(\.cleanupTombstone).count
    }

    func ordinaryCancellationTombstoneCountForTesting() -> Int {
        ordinaryCancellationTombstoneCount
    }

    func cleanupLedgerCountForTesting() -> Int {
        cleanupLedger.count
    }

    func waitForCleanupLedgerCountForTesting(_ target: Int) async {
        await waitForTestingCount(.cleanupLedger, equalTo: target)
    }

    func waitForCleanupDrainTimeoutCallbackCountForTesting(atLeast count: Int) async {
        await waitForTestingCount(.cleanupDrainTimeoutCallbacks, atLeast: count)
    }

    func cleanupDrainTimeoutIdentityForTesting(messageId: UInt64) -> UUID? {
        pendingResponses[messageId]?.cleanupDrainIdentity
    }

    func fireCleanupDrainTimeoutForTesting(messageId: UInt64, generation: UInt64, identity: UUID) {
        cleanupDrainTimeoutDidFire(messageId: messageId, generation: generation, identity: identity)
    }

    func waitForCreditWaiterCountForTesting(atLeast count: Int) async {
        await creditWindow.waitForPendingWaiterCount(atLeast: count)
    }

    func testingCountWaiterCountForTesting() -> Int {
        testingCountWaiters.count
    }

    func cleanupAttemptStateForTesting(fileId: [UInt8]) -> String? {
        guard let state = cleanupLedger[SMBFileIdLedgerKey(bytes: fileId)] else { return nil }
        return switch state {
        case .sending:
            "sending"
        case .draining(let messageId):
            "draining:\(messageId)"
        case .retiredUnknown:
            "retiredUnknown"
        }
    }

    func orphanResponseCountForTesting() -> Int {
        0
    }

    func requestDidTimeOutForTesting(messageId: UInt64, command: UInt16) {
        guard let pending = pendingResponses[messageId], let identity = pending.timeoutIdentity else { return }
        requestDidTimeOut(
            messageId: messageId,
            command: command,
            generation: pending.generation,
            identity: identity
        )
    }

    func requestTimeoutIdentityForTesting(messageId: UInt64) -> UUID? {
        pendingResponses[messageId]?.timeoutIdentity
    }

    func setRequestTimeoutIdentityForTesting(messageId: UInt64, identity: UUID) {
        pendingResponses[messageId]?.timeoutIdentity = identity
    }

    func requestDidTimeOutForTesting(
        messageId: UInt64,
        command: UInt16,
        generation: UInt64,
        identity: UUID
    ) {
        requestDidTimeOut(
            messageId: messageId,
            command: command,
            generation: generation,
            identity: identity
        )
    }

    func sentPendingResponseCountForTesting() -> Int {
        pendingResponses.values.filter {
            !$0.continuationResumed && $0.sendPhase == .sent
        }.count
    }

    func requestTimeoutTaskCountForTesting() -> Int {
        pendingResponses.values.filter {
            !$0.continuationResumed && $0.timeoutTask != nil
        }.count
    }

    func requestTimeoutDurationForTesting() -> Duration? {
        requestTimeout
    }

    func requestSentCountForTesting() -> Int {
        requestSentCountForTestingStorage
    }

    func requestTimeoutCompletionCountForTesting() -> Int {
        requestTimeoutCompletionCountForTestingStorage
    }

    func receiveLoopRunningForTesting() -> Bool {
        if case .running = readerLifecycle { return true }
        return false
    }

    func receivedPacketDispatchCountForTesting() -> Int {
        receivedPacketDispatchCountForTestingStorage
    }

    func waitForReceivedPacketDispatchCountForTesting(atLeast target: Int) async {
        await waitForTestingCount(.receivedPacketDispatches, atLeast: target)
    }

    func dispatchReceivedPacketForTesting(_ packet: [UInt8]) throws {
        try dispatchReceivedPacketForTesting(packet, generation: Self.initialWireGeneration)
    }

    func dispatchReceivedPacketForTesting(_ packet: [UInt8], generation: UInt64) throws {
        try dispatchReceivedPacket(SMBReceivedFrame(
            bytes: packet,
            transformSessionId: 0,
            generation: generation
        ))
    }

    func processRawFrameForTesting(_ packet: [UInt8], generation: UInt64, handle: UUID = UUID()) async throws -> Bool {
        try await processRawFrame(packet, generation: generation, handle: handle)
    }

    func dispatchReceivedPacketThenCancelForTesting(
        _ packet: [UInt8],
        cancel: @Sendable () -> Void
    ) throws {
        try dispatchReceivedPacket(SMBReceivedFrame(
            bytes: packet,
            transformSessionId: 0,
            generation: Self.initialWireGeneration
        ))
        cancel()
    }

    private func waitForTestingCount(
        _ kind: SMBTestingCountWaitKind,
        atLeast target: Int
    ) async {
        await waitForTestingCount(kind, target: target, isAtLeast: true)
    }

    private func waitForTestingCount(
        _ kind: SMBTestingCountWaitKind,
        equalTo target: Int
    ) async {
        await waitForTestingCount(kind, target: target, isAtLeast: false)
    }

    private func waitForTestingCount(
        _ kind: SMBTestingCountWaitKind,
        target: Int,
        isAtLeast: Bool
    ) async {
        let id = nextTestingCountWaiterId
        nextTestingCountWaiterId &+= 1
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled || wireFailure != nil || testingCountSatisfied(kind, target: target, isAtLeast: isAtLeast) {
                    continuation.resume()
                } else {
                    testingCountWaiters.append(SMBTestingCountWaiter(
                        id: id,
                        kind: kind,
                        target: target,
                        isAtLeast: isAtLeast,
                        continuation: continuation
                    ))
                    if kind == .requestSent {
                        requestSentWaiterRegistrationCountForTestingStorage += 1
                        resumeRequestSentWaiterRegistrationCountWaiters()
                    }
                }
            }
        } onCancel: {
            Task { await self.cancelTestingCountWaiter(id: id) }
        }
    }

    private func testingCountSatisfied(
        _ kind: SMBTestingCountWaitKind,
        target: Int,
        isAtLeast: Bool
    ) -> Bool {
        let value: Int
        switch kind {
        case .pendingResponses:
            value = pendingResponses.values.filter { !$0.continuationResumed }.count
        case .pendingCommandResponseDrainWaiters(let command):
            value = pendingCommandResponseDrainWaiters.filter { $0.command == command }.count
        case .requestSent:
            value = requestSentCountForTestingStorage
        case .requestSentWaiterRegistrations:
            value = requestSentWaiterRegistrationCountForTestingStorage
        case .cleanupLedger:
            value = cleanupLedger.count
        case .cleanupDrainTimeoutCallbacks:
            value = cleanupDrainTimeoutCallbackCountForTestingStorage
        case .receivedPacketDispatches:
            value = receivedPacketDispatchCountForTestingStorage
        }
        return isAtLeast ? value >= target : value == target
    }

    private func resumeSatisfiedTestingCountWaiters() {
        var remaining: [SMBTestingCountWaiter] = []
        for waiter in testingCountWaiters {
            if testingCountSatisfied(waiter.kind, target: waiter.target, isAtLeast: waiter.isAtLeast) {
                waiter.continuation.resume()
            } else {
                remaining.append(waiter)
            }
        }
        testingCountWaiters = remaining
    }

    private func resumeAllTestingCountWaiters() {
        let waiters = testingCountWaiters
        testingCountWaiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume()
        }
    }

    private func cancelTestingCountWaiter(id: UInt64) {
        guard let index = testingCountWaiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = testingCountWaiters.remove(at: index)
        waiter.continuation.resume()
    }

    private func resumePendingCountWaiters() {
        resumeSatisfiedTestingCountWaiters()
    }

    private func resumeRequestSentCountWaiters() {
        resumeSatisfiedTestingCountWaiters()
    }

    private func resumeRequestSentWaiterRegistrationCountWaiters() {
        resumeSatisfiedTestingCountWaiters()
    }

    private func resumeCleanupLedgerCountWaiters() {
        resumeSatisfiedTestingCountWaiters()
    }

    private func resumeReceivedPacketDispatchWaiters() {
        resumeSatisfiedTestingCountWaiters()
    }

    private func unsignedWireTransaction(packet: [UInt8], responseLabel: String) async throws -> [UInt8] {
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        return try await demuxedWireTransaction(
            packet: packet,
            responseLabel: responseLabel,
            longPoll: false,
            requestTimeoutPolicy: .eligible,
            send: { [weak self] packet, messageId in
                guard let self else { throw CancellationError() }
                try await self.sendUnsigned(packet, messageId: messageId, generation: generation)
            }
        ).bytes
    }

    /// Sends a NEGOTIATE / SESSION_SETUP request during connection setup, binding
    /// "fold request into the preauth hash → send it → fold the response" into a single
    /// path so the SMB 3.1.1 preauth-integrity hash always covers the exact bytes sent.
    ///
    /// This is a structural guard against the class of bug where a pre-send copy is
    /// appended to `preauthMessages` while a *different* (e.g. credit-patched) byte string
    /// goes on the wire: the derived signing/encryption keys then desync from the server's
    /// and every signed op fails verification. Preauth requests go out via sendUnsigned,
    /// which therefore must not mutate the packet (credit patching happens post-auth in
    /// sendSigned). Do not append a request to `preauthMessages` separately from this call.
    ///
    /// `foldResponse` folds the response into the hash for all but the terminal
    /// SESSION_SETUP#2: MS-SMB2 §3.2.5.3.1 covers messages up to the final SESSION_SETUP
    /// *request*, so folding its STATUS_SUCCESS response would derive keys the server does
    /// not use.
    private func sendPreauthRequest(
        _ packet: [UInt8],
        responseLabel: String,
        preauthMessages: inout [[UInt8]],
        foldResponse: Bool
    ) async throws -> [UInt8] {
        preauthMessages.append(packet)
        let response = try await unsignedWireTransaction(packet: packet, responseLabel: responseLabel)
        if foldResponse {
            preauthMessages.append(response)
        }
        return response
    }

    private func signedWireTransaction(
        packet: [UInt8],
        responseLabel: String,
        requestTimeoutPolicy: SMBRequestTimeoutPolicy = .eligible,
        cleanupFileId: [UInt8]? = nil,
        creditReservation: SMBPreReservedCredit? = nil
    ) async throws -> [UInt8] {
        let requestHeader = try SMB2Header.decode(packet)
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        let response = try await withTaskCancellationHandler {
            try await demuxedWireTransaction(
                packet: packet,
                responseLabel: responseLabel,
                longPoll: false,
                requestTimeoutPolicy: requestTimeoutPolicy,
                responseProtectionPolicy: encryptionKey == nil ? .sessionDefault : .encryptedRequest,
                cleanupFileId: cleanupFileId,
                send: { [weak self] packet, messageId in
                    guard let self else { throw CancellationError() }
                    try await self.sendSigned(
                        packet,
                        messageId: messageId,
                        generation: generation,
                        creditReservation: creditReservation
                    )
                }
            )
        } onCancel: {
            // Cleanup CLOSE has an actor-owned timer and retains correlation state until the
            // response is drained. Sending SMB CANCEL here would introduce a second, ambiguous
            // FileId lifetime transition while the original CLOSE may still be in flight.
            guard cleanupFileId == nil else { return }
            Task { [weak self] in
                await self?.scheduleCancel(messageId: requestHeader.messageId, generation: generation, wait: false)
            }
        }
        return response.bytes
    }

    private func validateNegotiateWireTransaction(packet: [UInt8], encrypt: Bool) async throws -> SMBReceivedFrame {
        let requestHeader = try SMB2Header.decode(packet)
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        let frame = try await withTaskCancellationHandler {
            try await demuxedWireTransaction(
                packet: packet,
                responseLabel: "VALIDATE_NEGOTIATE_INFO response",
                longPoll: false,
                requestTimeoutPolicy: .eligible,
                responseProtectionPolicy: encrypt ? .encryptedRequest : .signatureOrAEADRequired,
                send: { [weak self] packet, messageId in
                    guard let self else { throw CancellationError() }
                    try await self.sendValidateNegotiateSigned(
                        packet,
                        messageId: messageId,
                        encrypt: encrypt,
                        generation: generation
                    )
                }
            )
        } onCancel: {
            Task { [weak self] in
                await self?.scheduleCancel(messageId: requestHeader.messageId, generation: generation, wait: false)
            }
        }
        return frame
    }

    func validateNegotiateWireTransactionForTesting(packet: [UInt8]) async throws -> [UInt8] {
        try await validateNegotiateWireTransaction(packet: packet, encrypt: false).bytes
    }

    private func signedLongPollWireTransaction(packet: [UInt8], responseLabel: String) async throws -> [UInt8] {
        let requestHeader = try SMB2Header.decode(packet)
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        let response = try await withTaskCancellationHandler {
            try await demuxedWireTransaction(
                packet: packet,
                responseLabel: responseLabel,
                longPoll: true,
                requestTimeoutPolicy: .excluded(.longPoll),
                responseProtectionPolicy: encryptionKey == nil ? .sessionDefault : .encryptedRequest,
                send: { [weak self] packet, messageId in
                    guard let self else { throw CancellationError() }
                    try await self.sendSigned(packet, messageId: messageId, generation: generation)
                }
            )
        } onCancel: {
            Task { [weak self] in
                await self?.scheduleCancel(messageId: requestHeader.messageId, generation: generation, wait: false)
            }
        }
        return response.bytes
    }

    private func demuxedWireTransaction(
        packet: [UInt8],
        responseLabel: String,
        longPoll: Bool,
        requestTimeoutPolicy: SMBRequestTimeoutPolicy,
        responseProtectionPolicy: SMBResponseProtectionPolicy = .sessionDefault,
        cleanupFileId: [UInt8]? = nil,
        send: @escaping @Sendable ([UInt8], UInt64) async throws -> Void
    ) async throws -> SMBReceivedFrame {
        let requestHeader = try SMB2Header.decode(packet)
        guard let generation = readerLifecycle.activeGeneration else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        // A continuation may only be registered while the wire can still make progress.
        // Once failure/close is terminal, fail synchronously instead of creating a pending
        // response that no later closeTransport call can drain.
        if let wireFailure {
            // The receive side may have declared the wire dead without tearing the
            // transport down yet; failing fast here must not skip that teardown.
            closeTransport(cause: "request_after_wire_failure", diagnosticError: wireFailure)
            throw wireFailure
        }
        try validateFileIdAdmission(packet: packet, command: requestHeader.command, cleanupFileId: cleanupFileId)
        let cleanupKey = cleanupFileId.map(SMBFileIdLedgerKey.init(bytes:))
        if let cleanupKey {
            guard cleanupLedger[cleanupKey] == nil else {
                throw SMBCodecError.invalidValue("SMB FileId already has an unresolved CLOSE attempt")
            }
            guard cleanupLedger.count < Self.maxCleanupAttempts else {
                let error = SMBCodecError.invalidValue("SMB cleanup ledger limit exceeded")
                closeTransport(cause: "cleanup_ledger_limit", diagnosticError: error)
                throw SMBTransportError.connectionClosed
            }
            cleanupLedger[cleanupKey] = .sending
            resumeCleanupLedgerCountWaiters()
        }
        return try await withCheckedThrowingContinuation { continuation in
            let requestIdentity = makeRequestIdentity(generation: generation)
            storePendingResponse(messageId: requestHeader.messageId, pending: SMBPendingResponse(
                requestIdentity: requestIdentity,
                generation: generation,
                label: responseLabel,
                longPoll: longPoll,
                requestTimeoutPolicy: requestTimeoutPolicy,
                responseProtectionPolicy: responseProtectionPolicy,
                expectedCommand: requestHeader.command,
                expectedSessionId: requestHeader.sessionId,
                expectedTreeId: requestHeader.treeId,
                completionTarget: .transaction(continuation),
                sendTask: nil,
                timeoutTask: nil,
                timeoutIdentity: nil,
                sendPhase: .registered,
                cancellationRequested: false,
                continuationResumed: false,
                cleanupFileId: cleanupKey,
                cleanupTimeoutIdentity: nil,
                cleanupDrainIdentity: nil
            ))
            if cleanupKey != nil {
                let identity = UUID()
                pendingResponses[requestHeader.messageId]?.cleanupTimeoutIdentity = identity
                pendingResponses[requestHeader.messageId]?.cleanupTimeoutTask = startCleanupTimeout(
                    messageId: requestHeader.messageId,
                    generation: generation,
                    identity: identity
                )
            }
            SMBPerfLog.line("[wire] pending session=\(diagnosticSessionId) message_id=\(requestHeader.messageId) command=\(requestHeader.command) label=\(responseLabel) ts_ns=\(SMBPerfLog.timestampNanoseconds())")
            let sendOperationID = UUID()
            let diagnosticID = diagnosticSessionId
            // Strong self keeps this Task isolated to the session actor (as on master). A
            // `[weak self]` capture makes the closure nonisolated, which costs one extra
            // global-executor enqueue per request and regressed Linux read throughput
            // (issue 010 M3). The synchronous removeValue below only compiles while the
            // closure stays actor-isolated.
            let sendTask = Task {
                await self.performDemuxSend(
                    packet: packet,
                    messageId: requestHeader.messageId,
                    generation: generation,
                    diagnosticSessionId: diagnosticID,
                    send: send
                )
                self.activeSendTasks.removeValue(forKey: sendOperationID)
            }
            activeSendTasks[sendOperationID] = sendTask
            pendingResponses[requestHeader.messageId]?.sendTask = sendTask
        }
    }

    private func makeRequestIdentity(generation: UInt64) -> SMBRequestIdentity {
        nextRequestSequence &+= 1
        return SMBRequestIdentity(
            sessionInstance: sessionInstanceIdentity,
            generation: generation,
            requestSequence: nextRequestSequence
        )
    }

    private func storePendingResponse(messageId: UInt64, pending: SMBPendingResponse) {
        activeRequestIdentities.insert(pending.requestIdentity)
        pendingResponses[messageId] = pending
    }

    @discardableResult
    private func removePendingResponse(messageId: UInt64) -> SMBPendingResponse? {
        guard let pending = pendingResponses.removeValue(forKey: messageId) else { return nil }
        activeRequestIdentities.remove(pending.requestIdentity)
        resumePendingCommandResponseDrainWaiters()
        return pending
    }

    /// Waits until no response record for `command` remains. Cancelled callers keep a
    /// tombstone here until their final wire response is dispatched, so graceful teardown
    /// cannot mistake caller cancellation for completion of the SMB request itself.
    private func waitForPendingResponsesToDrain(command: UInt16) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                guard pendingResponses.values.contains(where: { $0.expectedCommand == command }) else {
                    continuation.resume()
                    return
                }
                pendingCommandResponseDrainWaiters.append(SMBPendingCommandResponseDrainWaiter(
                    id: waiterID,
                    command: command,
                    continuation: continuation
                ))
                resumeSatisfiedTestingCountWaiters()
            }
        } onCancel: {
            Task { await self.cancelPendingCommandResponseDrainWaiter(waiterID) }
        }
    }

    /// Close is graceful only while an in-flight keepalive ECHO can still be drained.
    /// If its server final never arrives, close the wire after the existing cleanup bound
    /// instead of sending TREE_DISCONNECT/LOGOFF across an unresolved request.
    func drainEchoResponsesBeforeDisconnect() async -> Bool {
        // Preserve the existing close path when there is no ECHO to drain. In
        // particular, avoid creating a deadline task group (and an extra actor
        // suspension) for the common case.
        guard pendingResponses.values.contains(where: { $0.expectedCommand == SMB2Commands.echo }) else {
            return true
        }
        do {
            try await SMBOperationDeadline.run(timeout: cleanupTimeout, sleeper: cleanupTimeoutSleeper) {
                try await self.waitForPendingResponsesToDrain(command: SMB2Commands.echo)
            }
            return true
        } catch {
            await closeTransportAndWait(cause: "keepalive_echo_drain_timeout", diagnosticError: error)
            return false
        }
    }

    private func resumePendingCommandResponseDrainWaiters() {
        var remaining: [SMBPendingCommandResponseDrainWaiter] = []
        var ready: [CheckedContinuation<Void, Error>] = []
        for waiter in pendingCommandResponseDrainWaiters {
            if pendingResponses.values.contains(where: { $0.expectedCommand == waiter.command }) {
                remaining.append(waiter)
            } else {
                ready.append(waiter.continuation)
            }
        }
        pendingCommandResponseDrainWaiters = remaining
        if !ready.isEmpty {
            resumeSatisfiedTestingCountWaiters()
        }
        ready.forEach { $0.resume() }
    }

    private func cancelPendingCommandResponseDrainWaiter(_ id: UUID) {
        guard let index = pendingCommandResponseDrainWaiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = pendingCommandResponseDrainWaiters.remove(at: index)
        resumeSatisfiedTestingCountWaiters()
        waiter.continuation.resume(throwing: CancellationError())
    }

    private func performDemuxSend(
        packet: [UInt8],
        messageId: UInt64,
        generation: UInt64,
        diagnosticSessionId: String,
        send: @escaping @Sendable ([UInt8], UInt64) async throws -> Void
    ) async {
        do {
            try await Self.sendAndLog(
                packet: packet,
                messageId: messageId,
                diagnosticSessionId: diagnosticSessionId,
                send: send
            )
            await sendDidSucceed(messageId: messageId, generation: generation)
        } catch {
            SMBPerfLog.line("[wire] send_failed session=\(diagnosticSessionId) message_id=\(messageId) error=\(Self.diagnosticError(error))")
            let isCancellation = error is CancellationError
            let responseError: Error = isCancellation
                ? error
                : (wireFailure ?? SMBTransportError.connectionClosed)
            // Every failure after continuation registration terminates this transaction,
            // even when an earlier close made the terminal transition a no-op.
            failPendingResponse(messageId: messageId, error: responseError)
            if !isCancellation {
                closeTransport(cause: "send_failure", diagnosticError: error)
            }
        }
    }

    /// FileIds are never returned by the public API (SMBDirectoryEntry.fileId is a file
    /// index). Open/read/write/list/stat/watch/ACL/reparse/rename/copy paths keep each wire
    /// FileId in a local operation scope and await all work using it before either CLOSE
    /// helper runs. This admission check is a backstop for any later internal path: once a
    /// CLOSE attempt starts, no new handle operation may use that 16-byte identity until a
    /// successful CLOSE response resolves it. A failed or unknown identity stays retired.
    private func validateFileIdAdmission(packet: [UInt8], command: UInt16, cleanupFileId: [UInt8]?) throws {
        guard let offset = Self.fileIdOffsetInRequest(command: command) else {
            if cleanupFileId != nil {
                throw SMBCodecError.invalidValue("cleanup CLOSE packet does not carry a FileId")
            }
            return
        }
        guard offset + 16 <= packet.count else { throw SMBCodecError.truncated }
        let fileId = Array(packet[offset..<offset + 16])
        try validateFileIdAdmission(command: command, fileId: fileId, cleanupFileId: cleanupFileId)
    }

    private func validateFileIdAdmission(command: UInt16, fileId: [UInt8], cleanupFileId: [UInt8]?) throws {
        guard Self.fileIdOffsetInRequest(command: command) != nil else {
            if cleanupFileId != nil {
                throw SMBCodecError.invalidValue("cleanup CLOSE packet does not carry a FileId")
            }
            return
        }
        guard fileId.count == 16 else {
            throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes")
        }
        if let cleanupFileId {
            guard command == SMB2Commands.close, fileId == cleanupFileId else {
                throw SMBCodecError.invalidValue("cleanup CLOSE FileId does not match its ledger key")
            }
            return
        }
        guard cleanupLedger[SMBFileIdLedgerKey(bytes: fileId)] == nil else {
            throw SMBCodecError.invalidValue("SMB FileId is unresolved after CLOSE")
        }
    }

    private static func fileIdOffsetInRequest(command: UInt16) -> Int? {
        switch command {
        case SMB2Commands.close, SMB2Commands.flush, SMB2Commands.lock,
             SMB2Commands.ioctl, SMB2Commands.queryDirectory, SMB2Commands.changeNotify:
            SMB2Header.encodedSize + 8
        case SMB2Commands.read, SMB2Commands.write, SMB2Commands.setInfo:
            SMB2Header.encodedSize + 16
        case SMB2Commands.queryInfo:
            SMB2Header.encodedSize + 24
        default:
            nil
        }
    }

    private func startCleanupTimeout(messageId: UInt64, generation: UInt64, identity: UUID) -> Task<Void, Never> {
        let duration = cleanupTimeout
        let sleeper = cleanupTimeoutSleeper
        return Task.detached { [weak self] in
            do {
                try await sleeper(duration)
            } catch {
                return
            }
            await self?.cleanupTimeoutDidFire(messageId: messageId, generation: generation, identity: identity)
        }
    }

    private func startCleanupDrainTimeout(
        messageId: UInt64,
        generation: UInt64,
        identity: UUID,
        duration: Duration
    ) -> Task<Void, Never> {
        let sleeper = requestTimeoutSleeper
        return Task.detached { [weak self] in
            do {
                try await sleeper(duration)
            } catch {
                return
            }
            await self?.cleanupDrainTimeoutDidFire(messageId: messageId, generation: generation, identity: identity)
        }
    }

    private func startRequestTimeout(
        messageId: UInt64,
        command: UInt16,
        generation: UInt64,
        identity: UUID,
        duration: Duration
    ) -> Task<Void, Never> {
        let sleeper = requestTimeoutSleeper
        return Task.detached { [weak self] in
            do {
                try await sleeper(duration)
            } catch {
                return
            }
            await self?.requestDidTimeOut(
                messageId: messageId,
                command: command,
                generation: generation,
                identity: identity
            )
        }
    }

    private func cleanupTimeoutDidFire(messageId: UInt64, generation: UInt64, identity: UUID) {
        guard var pending = pendingResponses[messageId],
              isGenerationActive(generation),
              pending.generation == generation,
              pending.cleanupTimeoutIdentity == identity,
              let fileId = pending.cleanupFileId,
              !pending.continuationResumed else {
            return
        }
        pending.cleanupTimeoutTask = nil
        pending.cleanupTimeoutIdentity = nil
        pending.timeoutTask?.cancel()
        pending.timeoutTask = nil
        pending.timeoutIdentity = nil

        switch pending.sendPhase {
        case .registered:
            removePendingResponse(messageId: messageId)
            pending.sendTask?.cancel()
            cleanupLedger[fileId] = .retiredUnknown
            resumeCleanupLedgerCountWaiters()
            pending.continuationResumed = true
            resolvePendingCompletion(
                pending.completionTarget,
                with: .failure(SMBTransportError.timedOut)
            )
            resumePendingCountWaiters()
        case .sending:
            // The transport has no complete-frame send acknowledgement. At this point a CLOSE
            // may be partial or complete, so this is a wire fault and the session must close.
            closeTransport(cause: "cleanup_close_timeout_sending", diagnosticError: SMBTransportError.timedOut)
        case .sent:
            pending.cleanupTombstone = true
            pending.continuationResumed = true
            cleanupLedger[fileId] = .draining(messageId)
            if let requestTimeout {
                let drainIdentity = UUID()
                pending.cleanupDrainIdentity = drainIdentity
                pending.cleanupDrainTask = startCleanupDrainTimeout(
                    messageId: messageId,
                    generation: generation,
                    identity: drainIdentity,
                    duration: requestTimeout
                )
            }
            pendingResponses[messageId] = pending
            resolvePendingCompletion(
                pending.completionTarget,
                with: .failure(SMBTransportError.timedOut)
            )
        }
    }

    private func cleanupDrainTimeoutDidFire(messageId: UInt64, generation: UInt64, identity: UUID) {
        cleanupDrainTimeoutCallbackCountForTestingStorage += 1
        resumeSatisfiedTestingCountWaiters()
        guard let pending = pendingResponses[messageId],
              isGenerationActive(generation),
              pending.generation == generation,
              pending.cleanupTombstone,
              pending.cleanupDrainIdentity == identity,
              let fileId = pending.cleanupFileId,
              cleanupLedger[fileId] == .draining(messageId) else {
            return
        }
        // requestTimeout is the response tolerance for this session; a nil value intentionally
        // leaves only the 64-entry ledger bound. We cannot restore credit until the server grants it,
        // so unrelated credit waiters may remain parked until this bound closes the session.
        closeTransport(cause: "cleanup_close_drain_timeout", diagnosticError: SMBTransportError.timedOut)
    }

    nonisolated private static func sendAndLog(
        packet: [UInt8],
        messageId: UInt64,
        diagnosticSessionId: String,
        send: @Sendable ([UInt8], UInt64) async throws -> Void
    ) async throws {
        try await send(packet, messageId)
        guard SMBPerfLog.effectiveIsEnabled else { return }
        // Scheduling may still invert sent/recv; causality needs transport observation, so consumers reject inversions as invalid.
        let timestamp = SMBPerfLog.timestampNanoseconds()
        SMBPerfLog.line(
            "[wire] sent session=\(diagnosticSessionId) message_id=\(messageId) ts_ns=\(timestamp)"
        )
    }

    private func sendUnsigned(
        _ packet: [UInt8],
        messageId: UInt64? = nil,
        generation: UInt64,
        creditReservation: SMBPreReservedCredit? = nil
    ) async throws {
        // Deliberately NOT patched here. sendUnsigned carries the NEGOTIATE / SESSION_SETUP
        // preauth messages (via unsignedWireTransaction), whose exact sent bytes must match
        // the copies folded into the SMB 3.1.1 preauth-integrity hash (see setup path). A
        // CreditRequest patch here would desync client/server key derivation and fail every
        // signed/encrypted op. Post-auth traffic is patched in sendSigned before it delegates
        // here for anonymous (unsigned) sessions.
        try Task.checkCancellation()
        try await sendPlaintext(
            packet,
            messageId: messageId,
            generation: generation,
            creditReservation: creditReservation
        )
    }

    /// MS-SMB2 §3.2.5.3.1: a session whose SESSION_SETUP response sets SMB2_SESSION_FLAG_ENCRYPT_DATA must
    /// not send plaintext. Without an encryption key (anonymous session, or a server that did not advertise
    /// encryption support) fail closed instead of letting sendSigned fall back to signed/unsigned plaintext.
    private func requireEncryptionKeyIfSessionDemandsEncryption(_ sessionFlags: UInt16) throws {
        if (sessionFlags & SMB2SessionSetup.sessionFlagEncryptData) != 0, encryptionKey == nil {
            throw SMBError.protocolError("SESSION_SETUP requires encryption but no SMB encryption key was negotiated")
        }
    }

    private func sendSigned(
        _ packet: [UInt8],
        messageId: UInt64? = nil,
        generation: UInt64,
        creditReservation: SMBPreReservedCredit? = nil
    ) async throws {
        // Single credit-patch point for all post-auth traffic: sendSigned handles every
        // signedWireTransaction op, so patching once here (before signing/sealing) covers signed,
        // encrypted, and anonymous paths while leaving the preauth NEGOTIATE/SESSION_SETUP messages
        // (sent directly via sendUnsigned) untouched for 3.1.1 preauth-integrity.
        var packet = packet
        await applyCreditRequest(to: &packet)
        guard isGenerationActive(generation) else { throw SMBTransportError.connectionClosed }
        try Task.checkCancellation()
        if encryptionKey != nil {
            try await sendEncrypted(
                packet,
                messageId: messageId,
                generation: generation,
                creditReservation: creditReservation
            )
            return
        }
        // No signing key means an anonymous/guest session (NTLM anonymous yields no session key
        // material). Such sessions cannot sign; the server granted access without requiring signing
        // (signingRequired was false at NEGOTIATE), so send the packet unsigned.
        guard signingKey != nil else {
            try await sendUnsigned(
                packet,
                messageId: messageId,
                generation: generation,
                creditReservation: creditReservation
            )
            return
        }
        packet = try signedPacket(packet)
        try await sendPlaintext(
            packet,
            messageId: messageId,
            generation: generation,
            creditReservation: creditReservation
        )
    }

    private func sendValidateNegotiateSigned(
        _ packet: [UInt8],
        messageId: UInt64,
        encrypt: Bool,
        generation: UInt64
    ) async throws {
        var packet = packet
        await applyCreditRequest(to: &packet)
        guard isGenerationActive(generation) else { throw SMBTransportError.connectionClosed }
        guard signingKey != nil else {
            throw SMBCodecError.invalidValue("VALIDATE_NEGOTIATE_INFO request requires a signing key")
        }
        // MS-SMB2 §3.2.5.5 requires signing before §3.1.4.3 applies transform encryption.
        packet = try signedPacket(packet)
        if encrypt {
            guard encryptionKey != nil else {
                throw SMBCodecError.invalidValue("VALIDATE_NEGOTIATE_INFO requires unavailable SMB encryption")
            }
            try await sendEncrypted(packet, messageId: messageId, generation: generation)
        } else {
            try await sendPlaintext(packet, messageId: messageId, generation: generation)
        }
        validateNegotiateSentCountForTestingStorage += 1
    }

    private func signedPacket(_ packet: [UInt8]) throws -> [UInt8] {
        guard let signingKey else {
            throw SMBCodecError.invalidValue("SMB packet signing requires a signing key")
        }
        var packet = packet
        packet[16] |= UInt8(SMB2Flags.signed & 0xff)
        for index in 48..<64 { packet[index] = 0 }
        let signature: [UInt8]
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
        if signingAlgorithm == .aesCMAC, let signingCMACContext {
            signature = signingCMACContext.authenticationCode(message: packet)
        } else {
            signature = try SMBSessionSigning.signatureForNormalizedPacket(
                algorithm: signingAlgorithm, key: signingKey, packet: packet, sender: .client
            )
        }
#else
        signature = try SMBSessionSigning.signatureForNormalizedPacket(
            algorithm: signingAlgorithm, key: signingKey, packet: packet, sender: .client
        )
#endif
        for index in 0..<16 { packet[48 + index] = signature[index] }
        return packet
    }

    private func sendPlaintext(
        _ packet: [UInt8],
        messageId: UInt64?,
        generation: UInt64,
        creditReservation: SMBPreReservedCredit? = nil
    ) async throws {
        let reservedCharge = try await claimOrReserveCredit(
            packet,
            generation: generation,
            creditReservation: creditReservation
        )
        guard isGenerationActive(generation) else {
            await refundCredit(charge: reservedCharge)
            throw SMBTransportError.connectionClosed
        }
        guard !Task.isCancelled else {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        if let messageId, !markSendStarted(messageId: messageId, generation: generation) {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        do {
            try await transport.send(DirectTCPFraming.segments([packet]))
            guard isGenerationActive(generation) else { throw SMBTransportError.connectionClosed }
        } catch {
            await refundCredit(charge: reservedCharge)
            throw error
        }
    }

    private func sendEncrypted(
        _ packet: [UInt8],
        messageId: UInt64? = nil,
        generation: UInt64,
        creditReservation: SMBPreReservedCredit? = nil
    ) async throws {
        // Callers patch credits before signing/sealing; do not patch the packet again here.
        guard let encryptionKey else { throw SMBCodecError.invalidValue("missing SMB encryption key") }
        let nonceLength = encryptionAlgorithm == .aes128GCM ? 12 : 11
        let nonce = nextTransformNonce(length: nonceLength)
        let nonce16 = nonce + Array(repeating: UInt8(0), count: 16 - nonceLength)
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce16,
            originalMessageSize: UInt32(packet.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: sessionId
        )
        let sealed: (ciphertext: [UInt8], tag: [UInt8])
        switch encryptionAlgorithm {
        case .aes128CCM:
            sealed = try AESCCM.seal(
                key: encryptionKey,
                nonce: nonce,
                plaintext: packet,
                authenticatedData: header.authenticatedData(),
                tagLength: 16
            )
        case .aes128GCM:
            sealed = try SMBCrypto.aesGCMSeal(
                key: encryptionKey,
                nonce: nonce,
                plaintext: packet,
                authenticatedData: header.authenticatedData()
            )
        }
        header.signature = sealed.tag
        try Task.checkCancellation()
        let reservedCharge = try await claimOrReserveCredit(
            packet,
            generation: generation,
            creditReservation: creditReservation
        )
        guard isGenerationActive(generation) else {
            await refundCredit(charge: reservedCharge)
            throw SMBTransportError.connectionClosed
        }
        guard !Task.isCancelled else {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        if let messageId, !markSendStarted(messageId: messageId, generation: generation) {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        do {
            try await transport.send(DirectTCPFraming.segments([try header.encode(), sealed.ciphertext]))
            guard isGenerationActive(generation) else { throw SMBTransportError.connectionClosed }
        } catch {
            await refundCredit(charge: reservedCharge)
            throw error
        }
    }

    private func verifySigned(_ frame: SMBReceivedFrame) throws {
        if frame.decryptedFromTransform { return }
        let packet = frame.bytes
        guard let signingKey else {
            // Anonymous sessions have no signing key; accept unsigned replies even when the server
            // advertises required signing, following the MS-SMB2 anonymous-session exception.
            return
        }
        let header = try SMB2Header.decode(packet)
        guard (header.flags & SMB2Flags.signed) != 0 else {
            guard !signingRequired else {
                throw SMBCodecError.invalidValue("SMB response missing required signature")
            }
            return
        }
        let expected = try SMBSessionSigning.signature(
            algorithm: signingAlgorithm,
            key: signingKey,
            packet: packet,
            sender: .server
        )
        guard AESCCM.constantTimeEqual(expected, header.signature) else {
            throw SMBCodecError.invalidValue("SMB signature verification failed")
        }
    }

    func verifySignedForTesting(_ packet: [UInt8]) throws {
        try verifySigned(SMBReceivedFrame(
            bytes: packet,
            transformSessionId: 0,
            generation: Self.initialWireGeneration
        ))
    }

    private func startReaderIfNeeded(generation: UInt64) {
        guard case .dormant(let currentGeneration) = readerLifecycle,
              currentGeneration == generation else {
            return
        }
        let handle = UUID()
        readerHandle = handle
        readerLifecycle = .running(generation: generation, handle: handle)
        let exitHook = readerTaskExitHookForTesting
        let task = Task { [self] in
            let failure = await runActorRawReader(generation: generation, handle: handle)
            if let exitHook { await exitHook(handle) }
            readerDidExit(generation: generation, handle: handle, error: failure)
        }
        readerTasks[handle] = task
    }

    /// Receive suspension leaves the session actor available to senders. Framing, decrypt,
    /// credit grant ordering and dispatch then run on that same actor without a frame-level
    /// actor handoff. Like the master receiveLoop, this task reads only while a sent request
    /// still owes a wire response (including a cancelled request's final-response tombstone).
    private func runActorRawReader(generation: UInt64, handle: UUID) async -> Error? {
        do {
            while true {
                try Task.checkCancellation()
                // A dormant reader can remain scheduled after send completion retires its
                // request. It must not read alongside a replacement reader for this epoch.
                guard isCurrentReader(generation: generation, handle: handle) else { return nil }
                guard hasSentResponseOutstanding else {
                    makeReaderDormantIfIdle(generation: generation, handle: handle)
                    return nil
                }
                let body = try await receiveRawFrame()
                try Task.checkCancellation()
                guard try await processRawFrame(body, generation: generation, handle: handle) else { return nil }
            }
        } catch {
            return error
        }
    }

    private func isCurrentReader(generation: UInt64, handle: UUID) -> Bool {
        guard isGenerationActive(generation),
              case .running(let currentGeneration, let currentHandle) = readerLifecycle else {
            return false
        }
        return currentGeneration == generation && currentHandle == handle
    }

    private func receiveRawFrame() async throws -> [UInt8] {
        let header = try await receiveExactly(4)
        let length = try DirectTCPFraming.length(from: header)
        return try await receiveExactly(length)
    }

    private func receiveExactly(_ count: Int) async throws -> [UInt8] {
        var bytes: [UInt8] = []
        while bytes.count < count {
            try Task.checkCancellation()
            let chunk = try await transport.receive(maxLength: count - bytes.count)
            guard !chunk.isEmpty else { throw SMBTransportError.connectionClosed }
            bytes += chunk
        }
        try Task.checkCancellation()
        return bytes
    }

    private func processRawFrame(_ body: [UInt8], generation: UInt64, handle: UUID) async throws -> Bool {
        guard isGenerationActive(generation) else { return false }
        let decryptedFromTransform = body.starts(with: SMB3TransformHeader.protocolId)
        if debugLogger.isEnabled {
            // Framing consumes the 4-byte header before this actor-isolated method sees the
            // body; re-create it here so the trace keeps issue 102 #19's metadata line.
            let label = "SMB response"
            if let header = try? DirectTCPFraming.segments([body]).first {
                debugDump("\(label) direct-TCP header length=\(body.count)", header, provenance: .metadata)
            }
            debugDump(label, body, provenance: decryptedFromTransform ? .ciphertext : .plaintext)
        }
        let packet: [UInt8]
        let transformSessionId: UInt64
        if decryptedFromTransform {
            let decrypted = try decryptTransform(body)
            packet = decrypted.plaintext
            transformSessionId = decrypted.sessionId
        } else {
            packet = body
            transformSessionId = 0
        }
        let frame = SMBReceivedFrame(
            bytes: packet,
            transformSessionId: transformSessionId,
            generation: generation
        )
        let effects = try validateResponseFrame(frame)
        try commitResponseEffects(effects, generation: generation)
        // Correlation state, final acceptance time, and caller release are committed before
        // this one credit-window hop. A delayed credit acknowledgement cannot move the final
        // acceptance time or release an unvalidated slice.
        await recordCreditGrants(effects, generation: generation)
        guard isGenerationActive(generation) else { return false }
        guard hasSentResponseOutstanding else {
            // Commit the stop and lifecycle transition in this actor turn, with no await
            // after the final dispatch. A send completion therefore sees either this reader
            // as running or the dormant state and starts a replacement; it cannot fall into
            // the gap before the old Task returns.
            makeReaderDormantIfIdle(generation: generation, handle: handle)
            return false
        }
        return true
    }

    private func readerDidExit(generation: UInt64, handle: UUID, error: Error?) {
        // The dictionary is the complete set of Tasks that shutdown must join. Removing
        // this handle and the return below have no suspension point between them.
        readerTasks.removeValue(forKey: handle)
        switch readerLifecycle {
        case .running(let currentGeneration, let currentHandle)
            where currentGeneration == generation && currentHandle == handle:
            let failure = error ?? SMBTransportError.connectionClosed
            // Reader cancellation/error while the epoch is active is terminal even if
            // there are no callers or cleanup records left to observe it.
            terminateForReceiveFault(failure, cause: "receive_failure")
            readerLifecycle = .stopped(generation: generation)
            readerHandle = nil
        case .stopping(let currentGeneration, let currentHandle, _)
            where currentGeneration == generation && currentHandle == handle:
            readerLifecycle = .stopped(generation: generation)
            readerHandle = nil
        default:
            // A stale reader cannot clear a newer handle or recreate an active lifecycle.
            break
        }
    }

    private var hasSentResponseOutstanding: Bool {
        pendingResponses.values.contains { $0.sendPhase == .sent }
    }

    /// This is the master receiveLoop predicate. A cancelled request remains `.sent` as a
    /// tombstone until its final response is consumed, so that late final is still read and
    /// drained. Once the last sent record is gone, the reader stops before another receive;
    /// a duplicate or unsolicited frame arriving while dormant stays in the transport until
    /// a later send, just as it does with the master's idle receiveLoop. The caller gate is
    /// separate from response correlation so a valid early final can be held without replay.
    private func makeReaderDormantIfIdle(generation: UInt64, handle: UUID? = nil) {
        guard !hasSentResponseOutstanding,
              case .running(let currentGeneration, let currentHandle) = readerLifecycle,
              currentGeneration == generation,
              handle == nil || handle == currentHandle else {
            return
        }
        readerLifecycle = .dormant(generation: generation)
        readerHandle = nil
    }

    private func terminateForReceiveFault(_ error: Error, cause: String) {
        if pendingResponses.values.contains(where: { $0.cleanupFileId != nil }) {
            closeTransport(cause: "cleanup_close_receive_failure", diagnosticError: error)
        } else {
            failWire(error: error)
            closeTransport(cause: cause, diagnosticError: error)
        }
    }

    private func splitResponseChain(
        _ frame: SMBReceivedFrame,
        firstHeader: SMB2Header
    ) throws -> [SMBResponseSlice] {
        var slices: [SMBResponseSlice] = []
        var offset = 0
        var header = firstHeader
        while true {
            let remaining = frame.bytes.count - offset
            guard remaining >= SMB2Header.encodedSize else {
                throw SMBCodecError.invalidValue("SMB2 compound response has a short header at offset \(offset)")
            }
            logReceivedResponseHeader(header)
            let end: Int
            if header.nextCommand == 0 {
                end = frame.bytes.count
            } else {
                let next = Int(header.nextCommand)
                guard next >= SMB2Header.encodedSize,
                      next.isMultiple(of: 8),
                      next <= remaining - SMB2Header.encodedSize else {
                    throw SMBCodecError.invalidValue(
                        "SMB2 compound response NextCommand is out of bounds or unaligned at offset \(offset)"
                    )
                }
                end = offset + next
            }
            let sliceFrame = SMBReceivedFrame(
                bytes: offset == 0 && end == frame.bytes.count
                    ? frame.bytes
                    : Array(frame.bytes[offset..<end]),
                transformSessionId: frame.transformSessionId,
                generation: frame.generation
            )
            slices.append(SMBResponseSlice(frame: sliceFrame, header: header))
            if header.nextCommand == 0 { return slices }
            offset = end
            let headerBytes = Array(frame.bytes[offset..<(offset + SMB2Header.encodedSize)])
            header = try SMB2Header.decode(headerBytes)
        }
    }

    private func logReceivedResponseHeader(_ header: SMB2Header) {
        SMBPerfLog.line(
            "[wire] recv session=\(diagnosticSessionId) message_id=\(header.messageId) command=\(header.command) " +
                "status=0x\(String(format: "%08x", header.status))\(header.status == SMB2Status.pending ? " STATUS_PENDING" : "") " +
                "ts_ns=\(SMBPerfLog.timestampNanoseconds())"
        )
    }

    /// Decodes once, then keeps a single un-compounded response out of the temporary arrays.
    /// Both forms below call `validateResponseSlice`, so the single-frame route enforces the
    /// same per-slice authentication, correlation, policy, and speculative-state rules.
    private func validateResponseFrame(_ frame: SMBReceivedFrame) throws -> SMBValidatedResponseBatch {
        guard frame.bytes.count >= SMB2Header.encodedSize else { throw SMBCodecError.truncated }
        let firstHeader = try SMB2Header.decode(frame.bytes)
        if firstHeader.nextCommand == 0 {
            logReceivedResponseHeader(firstHeader)
            var stagedStates: [SMBRequestIdentity: SMBResponseCorrelationState] = [:]
            let effect = try validateResponseSlice(
                frame,
                header: firstHeader,
                stagedStates: &stagedStates,
                tracksWireOrderState: false
            )
            return .single(effect)
        }

        let slices = try splitResponseChain(frame, firstHeader: firstHeader)
        return .compound(try validateResponseChain(slices))
    }

    private func validateResponseChain(_ slices: [SMBResponseSlice]) throws -> [SMBValidatedResponseEffect] {
        var effects: [SMBValidatedResponseEffect] = []
        var stagedStates: [SMBRequestIdentity: SMBResponseCorrelationState] = [:]
        let tracksWireOrderState = slices.count > 1
        effects.reserveCapacity(slices.count)
        if tracksWireOrderState {
            stagedStates.reserveCapacity(slices.count)
        }

        for slice in slices {
            effects.append(try validateResponseSlice(
                slice.frame,
                header: slice.header,
                stagedStates: &stagedStates,
                tracksWireOrderState: tracksWireOrderState
            ))
        }
        return effects
    }

    private func validateResponseSlice(
        _ frame: SMBReceivedFrame,
        header: SMB2Header,
        stagedStates: inout [SMBRequestIdentity: SMBResponseCorrelationState],
        tracksWireOrderState: Bool
    ) throws -> SMBValidatedResponseEffect {
        if frame.decryptedFromTransform {
            try verifyTransformResponseSessionId(frame, header: header)
        }

        // MessageId-free notifications are discarded before signature verification, as
        // required by MS-SMB2 §3.2.5.1.3. Transform SessionId binding is checked above; they
        // have no request to authenticate or credit.
        if header.command == SMB2Commands.oplockBreak || header.messageId == UInt64.max {
            return SMBValidatedResponseEffect(
                messageId: header.messageId,
                requestIdentity: nil,
                credits: nil,
                kind: .ignored
            )
        }

        let pendingAtArrival = pendingResponses[header.messageId]
        if pendingAtArrival?.finalSeen == true {
            // A final accepted in an earlier frame is no longer wire-outstanding, so drop this
            // frame before its protection checks, including the encrypted-request policy below:
            // a later plaintext frame for a finished request must not fail the shared session.
            // Same-chain duplicates still reach the staged finalSeen guard below because pending
            // state commits after the whole chain.
            return SMBValidatedResponseEffect(
                messageId: header.messageId,
                requestIdentity: nil,
                credits: nil,
                kind: .ignored
            )
        }

        if encryptionKey != nil,
           !frame.decryptedFromTransform,
           let pendingAtArrival,
           pendingAtArrival.generation == frame.generation,
           pendingAtArrival.sendPhase != .registered,
           case .encryptedRequest = pendingAtArrival.responseProtectionPolicy {
            throw SMBCodecError.invalidValue(
                "plaintext SMB response to an encrypted request MessageId \(header.messageId) " +
                    "command=\(header.command) status=0x\(String(header.status, radix: 16))"
            )
        }

        let isInterim = try SMB2AsyncInterim.isInterim(header)
        let protection: SMBVerifiedResponseProtection = isInterim && !frame.decryptedFromTransform
            ? .unprotected
            : try verifyResponseProtection(frame, header: header)
        guard let pending = pendingAtArrival,
              pending.generation == frame.generation,
              pending.sendPhase != .registered else {
            // Unknown and not-yet-committed requests are discarded without retaining a
            // MID-keyed replay candidate. A later request reusing this MID gets no frame.
            return SMBValidatedResponseEffect(
                messageId: header.messageId,
                requestIdentity: nil,
                credits: nil,
                kind: .ignored
            )
        }

        let identity = pending.requestIdentity
        var state: SMBResponseCorrelationState
        if tracksWireOrderState, let stagedState = stagedStates[identity] {
            state = stagedState
        } else {
            state = SMBResponseCorrelationState(
                messageId: header.messageId,
                expectedCommand: pending.expectedCommand,
                expectedSessionId: pending.expectedSessionId,
                expectedTreeId: pending.expectedTreeId,
                longPoll: pending.longPoll,
                cleanupFileId: pending.cleanupFileId,
                responseProtectionPolicy: pending.responseProtectionPolicy,
                asyncId: pending.asyncId,
                pendingCount: pending.pendingCount,
                finalSeen: pending.finalSeen
            )
        }
        guard state.messageId == header.messageId else {
            throw SMBCodecError.invalidValue("SMB response identity was rebound to another MessageId")
        }
        try validateResponseHeader(header, isInterim: isInterim, state: state)
        guard !state.finalSeen else {
            throw SMBCodecError.invalidValue("SMB duplicate or post-final response for MessageId \(header.messageId)")
        }

        if !isInterim, signingRequired, signingKey != nil {
            guard protection == .signature || protection == .authenticatedEncryption else {
                throw SMBCodecError.invalidValue("SMB response missing required signature")
            }
        }

        if isInterim {
            guard let interimAsyncId = header.asyncId, interimAsyncId != 0 else {
                throw SMBCodecError.invalidValue("SMB2 STATUS_PENDING interim carries a zero AsyncId")
            }
            if let storedAsyncId = state.asyncId, storedAsyncId != interimAsyncId {
                throw SMBCodecError.invalidValue(
                    "SMB2 interim AsyncId mismatch \(interimAsyncId)/\(storedAsyncId)"
                )
            }
            // issue 106: cross-identity AsyncId uniqueness is not checked here; enforcing it
            // requires an AsyncId-to-identity index.
            state.asyncId = interimAsyncId
            state.pendingCount += 1
            if !state.longPoll && state.pendingCount > SMB2AsyncInterim.maxPendingResponses {
                let label = state.cleanupFileId == nil ? "SMB2" : "SMB2 cleanup CLOSE"
                throw SMBCodecError.invalidValue("too many \(label) STATUS_PENDING responses")
            }
            if tracksWireOrderState {
                stagedStates[identity] = state
            }
            return SMBValidatedResponseEffect(
                messageId: header.messageId,
                requestIdentity: identity,
                credits: header.credits,
                kind: .interim(asyncId: interimAsyncId, pendingCount: state.pendingCount)
            )
        }

        if case .signatureOrAEADRequired = state.responseProtectionPolicy {
            guard protection == .signature || protection == .authenticatedEncryption else {
                throw SMBCodecError.invalidValue(
                    "VALIDATE_NEGOTIATE_INFO response has no authenticated protection"
                )
            }
        }
        state.finalSeen = true
        if tracksWireOrderState {
            stagedStates[identity] = state
        }
        return SMBValidatedResponseEffect(
            messageId: header.messageId,
            requestIdentity: identity,
            credits: header.credits,
            kind: .final(
                asyncId: state.asyncId,
                pendingCount: state.pendingCount,
                frame: frame,
                status: header.status,
                sendPhase: pending.sendPhase
            )
        )
    }

    private func validateResponseHeader(
        _ header: SMB2Header,
        isInterim: Bool,
        state: SMBResponseCorrelationState
    ) throws {
        guard header.command == state.expectedCommand else {
            throw SMBCodecError.invalidValue(
                "SMB response correlation mismatch command=\(header.command)/\(state.expectedCommand)"
            )
        }
        if state.cleanupFileId != nil {
            guard header.sessionId == state.expectedSessionId else {
                throw SMBCodecError.invalidValue(
                    "SMB cleanup response correlation mismatch session=\(header.sessionId)/\(state.expectedSessionId)"
                )
            }
        } else {
            // SESSION_SETUP and legacy responses may carry zero before authentication.
            guard state.expectedSessionId == 0 || header.sessionId == 0 || header.sessionId == state.expectedSessionId else {
                throw SMBCodecError.invalidValue(
                    "SMB response correlation mismatch session=\(header.sessionId)/\(state.expectedSessionId)"
                )
            }
        }
        if isInterim {
            return
        }
        if header.isAsync {
            guard let storedAsyncId = state.asyncId, header.asyncId == storedAsyncId else {
                throw SMBCodecError.invalidValue(
                    "SMB2 async final AsyncId mismatch \(header.asyncId.map(String.init) ?? "nil")/\(state.asyncId.map(String.init) ?? "no interim")"
                )
            }
        } else {
            guard state.asyncId == nil else {
                throw SMBCodecError.invalidValue("SMB2 sync final response after async interim (message id \(header.messageId))")
            }
            if state.cleanupFileId != nil {
                guard header.treeId == state.expectedTreeId else {
                    throw SMBCodecError.invalidValue(
                        "SMB cleanup response correlation mismatch tree=\(header.treeId)/\(state.expectedTreeId)"
                    )
                }
            } else {
                guard state.expectedTreeId == 0 || header.treeId == 0 || header.treeId == state.expectedTreeId else {
                    throw SMBCodecError.invalidValue(
                        "SMB response correlation mismatch tree=\(header.treeId)/\(state.expectedTreeId)"
                    )
                }
            }
        }
    }

    private func verifyResponseProtection(
        _ frame: SMBReceivedFrame,
        header: SMB2Header
    ) throws -> SMBVerifiedResponseProtection {
        if frame.decryptedFromTransform {
            return .authenticatedEncryption
        }
        guard (header.flags & SMB2Flags.signed) != 0,
              let signingKey else {
            // Anonymous sessions have no signing key; preserve the existing session-wide
            // exception. STATUS_PENDING may be unsigned; request-specific policies can still
            // require authenticated protection for their final response.
            return .unprotected
        }
        let expected = try SMBSessionSigning.signature(
            algorithm: signingAlgorithm,
            key: signingKey,
            packet: frame.bytes,
            sender: .server
        )
        guard AESCCM.constantTimeEqual(expected, header.signature) else {
            throw SMBCodecError.invalidValue("SMB signature verification failed")
        }
        return .signature
    }

    private func verifyTransformResponseSessionId(
        _ frame: SMBReceivedFrame,
        header: SMB2Header
    ) throws {
        guard frame.transformSessionId != 0,
              header.sessionId == frame.transformSessionId else {
            throw SMBCodecError.invalidValue(
                "SMB3 transform inner session id mismatch \(header.sessionId)/\(frame.transformSessionId)"
            )
        }
    }

    private func commitResponseEffects(
        _ effects: SMBValidatedResponseBatch,
        generation: UInt64
    ) throws {
        switch effects {
        case .single(let effect):
            guard isGenerationActive(generation) else { return }
            // Validation and commit run in one actor turn with no suspension between them.
            // The slice validator already checked the pending identity and send phase.
            applyResponseEffect(effect)
        case .compound(let compoundEffects):
            try commitResponseEffects(compoundEffects, generation: generation)
        }
    }

    private func commitResponseEffects(
        _ effects: [SMBValidatedResponseEffect],
        generation: UInt64
    ) throws {
        guard isGenerationActive(generation) else { return }
        // Preflight every identity before any record or continuation changes. Actor isolation
        // and the non-suspending commit make rebinding impossible between validation and here.
        for effect in effects {
            try preflightResponseEffect(effect, generation: generation)
        }

        for effect in effects {
            applyResponseEffect(effect)
        }
    }

    private func preflightResponseEffect(
        _ effect: SMBValidatedResponseEffect,
        generation: UInt64
    ) throws {
        guard let identity = effect.requestIdentity else { return }
        guard let pending = pendingResponses[effect.messageId],
              pending.requestIdentity == identity,
              pending.generation == generation,
              pending.sendPhase != .registered else {
            throw SMBCodecError.invalidValue("SMB response request identity changed before commit")
        }
    }

    private func applyResponseEffect(_ effect: SMBValidatedResponseEffect) {
        receivedPacketDispatchCountForTestingStorage += 1
        resumeReceivedPacketDispatchWaiters()
        guard let identity = effect.requestIdentity else {
            debugLine("discarded SMB response for unknown MessageId \(effect.messageId)")
            return
        }
        switch effect.kind {
        case .ignored:
            return
        case .interim(let asyncId, let pendingCount):
            guard var pending = pendingResponses[effect.messageId],
                  pending.requestIdentity == identity else { return }
            pending.asyncId = asyncId
            pending.pendingCount = pendingCount
            pendingResponses[effect.messageId] = pending
            debugLine("\(pending.label) accepted interim STATUS_PENDING AsyncId=\(asyncId)")
        case .final(let asyncId, let pendingCount, let frame, let status, let sendPhase):
            let acceptedAt = sessionTime.now()
            lastFinalAcceptanceForTestingStorage = acceptedAt
            if sendPhase == .sent {
                finishAcceptedFinal(messageId: effect.messageId, frame: frame, status: status)
                return
            }
            guard var pending = pendingResponses[effect.messageId],
                  pending.requestIdentity == identity else { return }
            pending.asyncId = asyncId
            pending.pendingCount = pendingCount
            pending.finalSeen = true
            pending.acceptedFinalFrame = frame
            pending.acceptedFinalStatus = status
            pendingResponses[effect.messageId] = pending
        }
    }

    private func resolvePendingCompletion(
        _ target: SMBPendingResponseCompletionTarget,
        with result: Result<SMBReceivedFrame, Error>
    ) {
        switch target {
        case .transaction(let continuation):
            switch result {
            case .success(let frame):
                continuation.resume(returning: frame)
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        case .transfer(let ticket):
            // M2 dispatches this ticket to the transfer window on the session actor.
            _ = ticket
        }
    }

    private func finishAcceptedFinal(messageId: UInt64, frame: SMBReceivedFrame, status: UInt32) {
        guard var pending = removePendingResponse(messageId: messageId) else { return }
        pending.timeoutTask?.cancel()
        pending.cleanupTimeoutTask?.cancel()
        pending.cleanupDrainTask?.cancel()
        if let cleanupFileId = pending.cleanupFileId {
            if status == SMB2Status.success {
                cleanupLedger.removeValue(forKey: cleanupFileId)
            } else {
                cleanupLedger[cleanupFileId] = .retiredUnknown
            }
            resumeCleanupLedgerCountWaiters()
        }
        if !pending.continuationResumed {
            pending.continuationResumed = true
            resolvePendingCompletion(pending.completionTarget, with: .success(frame))
        }
    }

    private func dispatchReceivedPacket(_ frame: SMBReceivedFrame) throws {
        guard isGenerationActive(frame.generation) else { return }
        let effects = try validateResponseFrame(frame)
        try commitResponseEffects(effects, generation: frame.generation)
    }

    private func markSendStarted(messageId: UInt64, generation: UInt64) -> Bool {
        guard isGenerationActive(generation),
              var pending = pendingResponses[messageId],
              pending.generation == generation else {
            return false
        }
        pending.sendPhase = .sending
        pendingResponses[messageId] = pending
        return true
    }

    private func sendDidSucceed(messageId: UInt64, generation: UInt64) async {
        let target = reconcileSuccessfulSend(messageId: messageId, generation: generation)
        guard let target else { return }
        await sendCancelWithoutGate(target: target, generation: generation)
    }

    /// Reconcile the full-send callback with receive correlation already bound to this
    /// RequestIdentity. An accepted early final is released only at this caller gate.
    private func reconcileSuccessfulSend(messageId: UInt64, generation: UInt64) -> SMB2Cancel.Target? {
        guard isGenerationActive(generation) else { return nil }
        let target = markRequestSent(messageId: messageId, generation: generation)
        if hasSentResponseOutstanding {
            startReaderIfNeeded(generation: generation)
        }
        return target
    }

    @discardableResult
    private func markRequestSent(messageId: UInt64, generation: UInt64) -> SMB2Cancel.Target? {
        guard isGenerationActive(generation),
              var pending = pendingResponses[messageId],
              pending.generation == generation else { return nil }
        requestSentCountForTestingStorage += 1
        pending.sendPhase = .sent
        pendingResponses[messageId] = pending
        resumeRequestSentCountWaiters()
        if pending.finalSeen,
           let frame = pending.acceptedFinalFrame,
           let status = pending.acceptedFinalStatus {
            finishAcceptedFinal(messageId: messageId, frame: frame, status: status)
            return nil
        }
        if let cleanupFileId = pending.cleanupFileId {
            cleanupLedger[cleanupFileId] = .draining(messageId)
            resumeCleanupLedgerCountWaiters()
        } else if pending.cancellationRequested {
            // Keep the cancellation tombstone: a later interim must still be able to
            // store its AsyncId so the final response can be correlated (issues/078).
        } else if pending.requestTimeoutPolicy.isEligible, let requestTimeout {
            let command = pending.expectedCommand
            let identity = UUID()
            pending.timeoutIdentity = identity
            pending.timeoutTask = startRequestTimeout(
                messageId: messageId,
                command: command,
                generation: generation,
                identity: identity,
                duration: requestTimeout
            )
        }
        pendingResponses[messageId] = pending
        guard pendingResponses[messageId]?.cancellationRequested == true else {
            return nil
        }
        if let asyncId = pendingResponses[messageId]?.asyncId {
            return .async(messageId: messageId, asyncId: asyncId)
        }
        return .sync(messageId: messageId)
    }

    private func requestDidTimeOut(messageId: UInt64, command: UInt16, generation: UInt64, identity: UUID) {
        // Check eligibility before removal: cancellation may invalidate a timer whose
        // callback is already queued for actor delivery.
        guard isGenerationActive(generation),
              let current = pendingResponses[messageId],
              current.generation == generation,
              current.timeoutIdentity == identity,
              !current.continuationResumed,
              !current.cleanupTombstone,
              var pending = removePendingResponse(messageId: messageId) else {
            return
        }
        pending.timeoutTask?.cancel()
        pending.timeoutTask = nil
        pending.timeoutIdentity = nil
        pending.continuationResumed = true
        SMBPerfLog.line(
            "[wire] request_timeout session=\(diagnosticSessionId) message_id=\(messageId) " +
                "command=\(command) send_started=\(pending.sendPhase == .registered ? 0 : 1)"
        )
        resolvePendingCompletion(
            pending.completionTarget,
            with: .failure(SMBTransportError.timedOut)
        )
        // A timed-out sent MessageId cannot be abandoned while the connection remains usable:
        // closing the whole session avoids creating a CommandSequenceWindow hole. Credits are
        // deliberately not refunded because the request reached the wire.
        closeTransport(cause: "request_timeout", diagnosticError: SMBTransportError.timedOut)
        requestTimeoutCompletionCountForTestingStorage += 1
    }

    private func failPendingResponse(messageId: UInt64, error: Error) {
        guard var pending = pendingResponses[messageId] else { return }
        pending.timeoutTask?.cancel()
        pending.timeoutTask = nil
        pending.timeoutIdentity = nil
        if pending.sendPhase != .registered {
            if error is CancellationError {
                pending.cancellationRequested = true
                pendingResponses[messageId] = pending
            } else {
                removePendingResponse(messageId: messageId)
            }
        } else {
            removePendingResponse(messageId: messageId)
            pending.sendTask?.cancel()
        }
        // Cancellation releases the caller but the wire response is unfinished — retain the
        // same record until its final response so it can keep correlating late frames.
        if !pending.continuationResumed {
            pending.continuationResumed = true
            resolvePendingCompletion(pending.completionTarget, with: .failure(error))
            if pending.sendPhase != .registered, pending.cancellationRequested {
                pendingResponses[messageId] = pending
                if ordinaryCancellationTombstoneCount > Self.maxCancellationTombstones {
                    closeTransport(
                        cause: "cancel_tombstone_limit",
                        diagnosticError: SMBCodecError.invalidValue("SMB cancelled request tombstone limit exceeded")
                    )
                }
            }
        }
    }

    private var ordinaryCancellationTombstoneCount: Int {
        pendingResponses.values.filter {
            $0.cleanupFileId == nil && $0.cancellationRequested && $0.continuationResumed
        }.count
    }

    /// Resolves the CANCEL form in the same actor turn that observes the cancellation:
    /// if an interim already stored an AsyncId the async form is required, otherwise sync.
    /// The decision is atomic (no suspension between reading the pending state and
    /// choosing the form) and at most one CANCEL is ever produced per request; however
    /// the actual send suspends afterwards, so an interim processed in that window can
    /// make an already-decided sync CANCEL stale on the wire. That is harmless: servers
    /// fall back to MessageId lookup for sync CANCEL (MS-SMB2 §3.3.5.16).
    private func cancelInFlightRequest(messageId: UInt64, generation: UInt64) -> SMB2Cancel.Target? {
        guard isGenerationActive(generation),
              let pending = pendingResponses[messageId],
              pending.generation == generation,
              !pending.cancellationRequested else { return nil }
        let wasSent = pending.sendPhase == .sent
        let asyncId = pendingResponses[messageId]?.asyncId
        failPendingResponse(messageId: messageId, error: CancellationError())
        guard wasSent, isGenerationActive(generation) else { return nil }
        if let asyncId {
            return .async(messageId: messageId, asyncId: asyncId)
        }
        return .sync(messageId: messageId)
    }

    private func failAllPendingResponses(error: Error) {
        let pending = pendingResponses
        let livePending = pending.filter { !$0.value.continuationResumed }
        if SMBPerfLog.effectiveIsEnabled {
            let details = livePending.sorted { $0.key < $1.key }.prefix(16).map {
                "\($0.key):\($0.value.expectedCommand):\($0.value.continuationResumed ? 1 : 0)"
            }
            let remaining = livePending.count - details.count
            let detail = details.joined(separator: ",") + (remaining > 0 ? ",(+\(remaining) more)" : "")
            // `resumed` counts cancellation tombstones (already-resumed records kept for
            // late-frame correlation). Losing that number makes a post-mortem unable to tell
            // "no victims" from "all victims were already cancelled".
            let resumed = pending.count - livePending.count
            SMBPerfLog.line("[wire] victim session=\(diagnosticSessionId) count=\(pending.count) resumed=\(resumed) pending=\(livePending.count) detail=\(detail)")
        }
        pendingResponses.removeAll()
        resumePendingCommandResponseDrainWaiters()
        activeRequestIdentities.removeAll()
        for var waiter in pending.values {
            waiter.timeoutTask?.cancel()
            waiter.cleanupTimeoutTask?.cancel()
            waiter.cleanupDrainTask?.cancel()
            // A cancelled tombstone may still own a blocked send task. It must be cancelled
            // even though its continuation has already been resumed.
            waiter.sendTask?.cancel()
            // A cancellation tombstone may have already resumed its continuation;
            // wire failure must not resume it a second time.
            if waiter.continuationResumed { continue }
            waiter.continuationResumed = true
            // failAllPendingResponses is only reached after the receive side has
            // declared the shared wire dead. Cancelling a send that already started
            // is therefore safe: the transport/socket is being torn down as a unit,
            // and it prevents a blocked send task from surviving session failure.
            resolvePendingCompletion(waiter.completionTarget, with: .failure(error))
        }
        // Credit waiters are only ever resumed by grants from received responses; once the
        // receive path is dead they must be drained too (issues/010 §B invariant: every
        // session-owned continuation is resumed by some terminal event).
        if creditFailureTask == nil {
            let creditWindow = creditWindow
            creditFailureTask = Task { await creditWindow.failAllWaiters(error) }
        }
    }

    private func failWire(error: Error, recordFirstFault: Bool = true) {
        let firstFault = wireFailure == nil
        let failure = wireFailure ?? error
        wireFailure = failure
        if firstFault, recordFirstFault {
            SMBPerfLog.line("[wire] first_fault session=\(diagnosticSessionId) error=\(Self.diagnosticError(error))")
        }
        resumeAllTestingCountWaiters()
        failAllPendingResponses(error: failure)
    }

    private func isGenerationActive(_ generation: UInt64) -> Bool {
        readerLifecycle.activeGeneration == generation && wireFailure == nil
    }

    private func reserveCredit(_ packet: [UInt8], generation: UInt64) async throws -> UInt16 {
        guard isGenerationActive(generation) else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        // The packet was produced by our own encoders; a decode failure means an internal
        // bug. Failing here keeps the credit window in sync with what is actually sent —
        // a silent charge=1 fallback would drift the window against the embedded
        // CreditCharge (issues/012).
        let header = try SMB2Header.decode(packet)
        // MS-SMB2 §3.2.4.1.2: CANCEL is exempt from the credit window — it must go out
        // while the request it cancels still holds the window (e.g. a parked CHANGE_NOTIFY
        // owns the last credit); gating it here would deadlock the cancellation path.
        if header.command == SMB2Commands.cancel {
            return 0
        }
        // MS-SMB2 §3.2.4.1.2: CreditCharge 0 and 1 both consume one credit. Reserving 0
        // would let charge-0 requests inflate the window (each response still grants), so
        // the effective charge is what gets reserved and later refunded on send failure.
        let effectiveCharge = max(1, header.creditCharge)
        let balance = try await creditWindow.reserve(
            charge: effectiveCharge,
            messageId: header.messageId,
            command: header.command
        )
        guard isGenerationActive(generation) else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        debugLine("SMB credit charge=\(effectiveCharge) balance=\(balance)")
        return effectiveCharge
    }

    private func claimOrReserveCredit(
        _ packet: [UInt8],
        generation: UInt64,
        creditReservation: SMBPreReservedCredit?
    ) async throws -> UInt16 {
        guard let creditReservation else {
            return try await reserveCredit(packet, generation: generation)
        }
        guard isGenerationActive(generation) else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        let header = try SMB2Header.decode(packet)
        guard header.command == SMB2Commands.read || header.command == SMB2Commands.write else {
            throw SMBCodecError.invalidValue("pre-reserved credits are valid only for variable-length READ/WRITE")
        }
        let charge = max(1, header.creditCharge)
        guard charge <= creditReservation.charge else {
            throw SMBCodecError.invalidValue("variable-length request exceeds its reserved SMB credits")
        }
        guard let unusedCharge = creditReservation.claim(for: charge) else {
            throw CancellationError()
        }
        if unusedCharge > 0 {
            await refundCredit(charge: unusedCharge)
        }
        guard isGenerationActive(generation) else {
            await refundCredit(charge: charge)
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        return charge
    }

    private func reserveVariableCredit(
        maximumPayloadLength: UInt32,
        command: UInt16,
        generation: UInt64
    ) async throws -> SMBPreReservedCredit {
        guard maximumPayloadLength > 0, isGenerationActive(generation) else {
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        let maximumCharge = SMB2Credit.charge(forPayloadLength: UInt64(maximumPayloadLength))
        let charge = try await creditWindow.reserveUpTo(
            maximumCharge: maximumCharge,
            command: command
        )
        guard isGenerationActive(generation) else {
            await refundCredit(charge: charge)
            throw wireFailure ?? SMBTransportError.connectionClosed
        }
        return SMBPreReservedCredit(charge: charge)
    }

    private func refundUnclaimedCredit(_ reservation: SMBPreReservedCredit) async {
        if let charge = reservation.releaseUnclaimed() {
            await refundCredit(charge: charge)
        }
    }

    private func applyCreditRequest(to packet: inout [UInt8]) async {
        let balance = await creditWindow.balance
        SMB2Credit.patchCreditRequest(into: &packet, balance: balance, target: SMB2Credit.targetWindowCredits)
    }

    private func refundCredit(charge: UInt16) async {
        let balance = await creditWindow.refund(charge: charge)
        debugLine("SMB credit refund=\(charge) balance=\(balance)")
    }

    private func recordCreditGrants(_ effects: [SMBValidatedResponseEffect], generation: UInt64) async {
        var totalCredits: UInt64 = 0
        var receiptCount = 0
        for effect in effects {
            guard let credits = effect.credits else { continue }
            totalCredits += UInt64(credits)
            receiptCount += 1
        }
        guard let balance = await applyCreditGrants(
            totalCredits: totalCredits,
            receiptCount: receiptCount,
            generation: generation
        ) else { return }
        for effect in effects {
            if let credits = effect.credits {
                debugLine("SMB response credit grant=\(credits) balance=\(balance)")
            }
        }
    }

    private func recordCreditGrants(_ effects: SMBValidatedResponseBatch, generation: UInt64) async {
        switch effects {
        case .single(let effect):
            await recordCreditGrant(effect.credits, generation: generation)
        case .compound(let compoundEffects):
            await recordCreditGrants(compoundEffects, generation: generation)
        }
    }

    private func recordCreditGrant(_ credits: UInt16?, generation: UInt64) async {
        guard let credits,
              let balance = await applyCreditGrants(
                  totalCredits: UInt64(credits),
                  receiptCount: 1,
                  generation: generation
              ) else { return }
        debugLine("SMB response credit grant=\(credits) balance=\(balance)")
    }

    private func applyCreditGrants(
        totalCredits: UInt64,
        receiptCount: Int,
        generation: UInt64
    ) async -> UInt32? {
        guard receiptCount > 0, isGenerationActive(generation) else { return nil }
        let balance = await creditWindow.grant(totalCredits: totalCredits, receiptCount: receiptCount)
        await creditGrantAfterAwaitHookForTesting?()
        guard isGenerationActive(generation) else { return nil }
        return balance
    }

    private func decryptTransform(_ packet: [UInt8]) throws -> (plaintext: [UInt8], sessionId: UInt64) {
        guard let decryptionKey else { throw SMBCodecError.invalidValue("missing SMB decryption key") }
        let header = try SMB3TransformHeader.decode(packet)
        guard header.flags == SMB3TransformHeader.encryptedFlag else {
            throw SMBCodecError.invalidValue("unsupported SMB3 transform flags")
        }
        guard header.sessionId != 0, header.sessionId == sessionId else {
            throw SMBCodecError.invalidValue("SMB3 transform session id mismatch")
        }
        let ciphertext = Array(packet.dropFirst(SMB3TransformHeader.encodedSize))
        guard UInt64(ciphertext.count) == UInt64(header.originalMessageSize) else {
            throw SMBCodecError.invalidValue("SMB3 transform original message size mismatch")
        }
        let perfStart = ContinuousClock.now
        let plaintext: [UInt8]
        switch encryptionAlgorithm {
        case .aes128CCM:
            plaintext = try AESCCM.open(
                key: decryptionKey,
                nonce: Array(header.nonce.prefix(11)),
                ciphertext: ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            )
        case .aes128GCM:
            plaintext = try SMBCrypto.aesGCMOpen(
                key: decryptionKey,
                nonce: Array(header.nonce.prefix(12)),
                ciphertext: ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            )
        }
        SMBPerfLog.line(
            "decrypt cipher=\(encryptionAlgorithm == .aes128CCM ? "ccm" : "gcm") bytes=\(ciphertext.count) ms=\(SMBPerfLog.milliseconds(ContinuousClock.now - perfStart))"
        )
        debugDump("decrypted \(packet.count)-byte SMB3 transform", plaintext)
        return (plaintext, header.sessionId)
    }

    /// MS-SMB2 §3.2.4.1.6: the next MessageId must advance by the CreditCharge of the
    /// request being sent, so a multi-credit READ/WRITE consumes `charge` sequence numbers.
    private func nextMessageId(charge: UInt16 = 1) -> UInt64 {
        defer { messageId += UInt64(max(1, charge)) }
        return messageId
    }

    private func nextTransformNonce(length: Int = 11) -> [UInt8] {
        defer { transformNonceCounter += 1 }
        return Self.transformNonce(counter: transformNonceCounter, length: length)
    }

    static func transformNonce(counter value: UInt64, length: Int) -> [UInt8] {
        precondition(length >= 8 && length <= 16)
        let bytes = [
            UInt8((value >> 56) & 0xff),
            UInt8((value >> 48) & 0xff),
            UInt8((value >> 40) & 0xff),
            UInt8((value >> 32) & 0xff),
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ]
        return bytes + Array(repeating: 0, count: length - bytes.count)
    }

    // READ 1 リクエストの local 上限。READ は「投げて応答を待つ」直列往復なので、
    // チャンクが小さいとスループット上限が RTT × チャンクで決まる (64 KiB × ~19ms
    // RTT = 実測 3.3 MB/s、obaket issue 389)。1 MiB に上げると往復回数が 1/16 に
    // なる。実際のリクエスト長は negotiate の maxRead と credit 残高
    // (1 MiB = 16 credits) で常に clamp されるため、サーバ制約は破らない。
    // write 側 (`localWriteChunkLimit` / `creditAwareWriteChunkSize`) は別途計測して
    // から判断する (読みだけが preview 律速のため先行)。
    // internal: SMBeePerformanceRegressionTests が期待チャンク数の導出に参照する。
    static let localReadChunkLimit = 1024 * 1024

    private func negotiatedReadChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(localLimit: Self.localReadChunkLimit, negotiatedLimit: maxReadSize, transformOverhead: transformOverhead)
    }

    private func creditAwareWriteChunkSize() async -> Int {
        Int(clamping: await creditCappedLength(UInt32(min(negotiatedWriteChunkSize(), Int(clamping: UInt32.max)))))
    }

    private func negotiatedWriteChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(
            localLimit: SMBClientSession.localWriteChunkLimit,
            negotiatedLimit: maxWriteSize,
            transformOverhead: transformOverhead
        )
    }

    private func creditCappedLength(_ requested: UInt32) async -> UInt32 {
        let balance = await creditWindow.balance
        let cap = min(UInt64(max(1, balance)) * UInt64(SMB2Credit.unitSize), UInt64(UInt32.max))
        return min(requested, UInt32(cap))
    }

    private nonisolated func joinSMBPath(_ parent: String, _ child: String) -> String {
        let trimmedParent = parent.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
        if trimmedParent.isEmpty { return child }
        return "\(trimmedParent)\\\(child)"
    }

    private func debugDump(_ label: String, _ bytes: [UInt8]) {
        debugDump(label, bytes, provenance: .plaintext)
    }

    private func debugDump(_ label: String, _ bytes: [UInt8], provenance: SMBWireDataProvenance) {
        debugLogger.dump(
            label,
            bytes: bytes,
            provenance: provenance,
            encryptedSession: encryptionKey != nil
        )
    }

    private func debugLine(_ message: String) {
        debugLogger.line(message)
    }
}

enum SMB2Status {
    static let success: UInt32 = 0x0000_0000
    static let pending: UInt32 = 0x0000_0103
    static let notifyEnumDir: UInt32 = 0x0000_010c
    static let bufferOverflow: UInt32 = 0x8000_0005
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let noSuchFile: UInt32 = 0xc000_000f
    static let invalidParameter: UInt32 = 0xc000_000d
    static let invalidDeviceRequest: UInt32 = 0xc000_0010
    static let endOfFile: UInt32 = 0xc000_0011
    static let cancelled: UInt32 = 0xc000_0120
    static let moreProcessingRequired: UInt32 = 0xc000_0016
    static let accessDenied: UInt32 = 0xc000_0022
    static let objectNameInvalid: UInt32 = 0xc000_0033
    static let objectNameNotFound: UInt32 = 0xc000_0034
    static let objectNameCollision: UInt32 = 0xc000_0035
    static let objectPathNotFound: UInt32 = 0xc000_003a
    static let sharingViolation: UInt32 = 0xc000_0043
    static let fileLockConflict: UInt32 = 0xc000_0054
    static let lockNotGranted: UInt32 = 0xc000_0055
    static let rangeNotLocked: UInt32 = 0xc000_007e
    static let logonFailure: UInt32 = 0xc000_006d
    static let diskFull: UInt32 = 0xc000_007f
    static let fileIsADirectory: UInt32 = 0xc000_00ba
    static let notSupported: UInt32 = 0xc000_00bb
    static let networkNameDeleted: UInt32 = 0xc000_00c9
    static let directoryNotEmpty: UInt32 = 0xc000_0101
    static let notADirectory: UInt32 = 0xc000_0103
}

private struct SMBServerSideCopyFallback: Error {
    static let allowedStatuses: Set<UInt32> = [
        SMB2Status.notSupported,
        SMB2Status.invalidDeviceRequest
    ]
}

private struct SMBCopyChunkLimitError: Error {
    var limits: SMB2CopyChunkLimits
}

private struct SMB2CopyChunkLimits {
    var maxChunks: UInt32 = SMB2CopyChunk.defaultMaxChunks
    var maxChunkSize: UInt32 = SMB2CopyChunk.defaultMaxChunkSize
    var maxTotalSize: UInt32 = SMB2CopyChunk.defaultMaxTotalSize

    static func decode(_ output: [UInt8]) throws -> SMB2CopyChunkLimits {
        let response = try SMB2CopyChunk.decodeCopyChunkResponse(output)
        return SMB2CopyChunkLimits(
            maxChunks: response.chunksWritten,
            maxChunkSize: response.chunkBytesWritten,
            maxTotalSize: response.totalBytesWritten
        )
    }
}

enum SMB2Flags {
    static let asyncCommand: UInt32 = 0x0000_0002
    static let signed: UInt32 = 0x0000_0008
}

enum SMB2AsyncInterim {
    static let maxPendingResponses = 16

    static func isInterim(_ header: SMB2Header) throws -> Bool {
        guard header.status == SMB2Status.pending else { return false }
        guard header.isAsync else {
            throw SMBCodecError.invalidValue("SMB2 STATUS_PENDING response missing ASYNC_COMMAND flag")
        }
        return true
    }
}
