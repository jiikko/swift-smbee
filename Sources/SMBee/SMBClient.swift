import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif
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

func makeSMBDownloadTemporaryFile(in directory: URL) throws -> (url: URL, handle: FileHandle) {
    let fileManager = FileManager.default
    for _ in 0..<8 {
        let url = directory.appendingPathComponent(".smbee-\(UUID().uuidString).part")
        guard !fileManager.fileExists(atPath: url.path), fileManager.createFile(atPath: url.path, contents: nil) else { continue }
        return (url, try FileHandle(forWritingTo: url))
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
        (shareFlags & SMBTreeConnectConstants.shareFlagEncryptData) != 0 ||
            (capabilities & SMBTreeConnectConstants.shareCapEncryptData) != 0
    }
}

enum SMBTreeConnectConstants {
    static let shareFlagEncryptData: UInt32 = 0x0000_8000
    static let shareCapEncryptData: UInt32 = 0x0000_0008
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

public actor SMBClientSession {
    // Keep writes comparable to reads; credit/negotiated limits still clamp this.
    static let localWriteChunkLimit = 1024 * 1024

    // Prefix reads are intentionally bounded because readPrefix retains the complete result.
    // The stream API has no equivalent limit because it does not accumulate data.
    static let maxPrefixReadLength: UInt64 = 64 * 1024 * 1024

    /// Everything needed to rebuild a dropped connection for opt-in watch resubscribe.
    /// Only sessions created via `connect(...)` carry this; `withTree`-derived sessions do not.
    struct ReconnectInfo: Sendable {
        let host: String
        let port: UInt16
        let share: String
        let credentialProvider: SMBCredentialProvider
        let makeTransport: @Sendable () -> SMBTransport
    }

    private var session: SMBSession
    private var treeId: UInt32
    private var childTreeIds: Set<UInt32> = []
    private let reconnectInfo: ReconnectInfo?
    private var keepAliveTask: Task<Void, Never>?
    private var isClosed = false

    init(session: SMBSession, treeId: UInt32, reconnectInfo: ReconnectInfo? = nil) {
        self.session = session
        self.treeId = treeId
        self.reconnectInfo = reconnectInfo
    }

    func retainsAuthenticationCredentialForTesting() async -> Bool {
        await session.retainsAuthenticationCredentialForTesting()
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
    private func reconnect() async throws {
        guard let info = reconnectInfo else {
            throw SMBError.connectionLost(operation: "RECONNECT")
        }
        await session.closeTransport(cause: "reconnect_old_session")
        let credential = try await info.credentialProvider()
        let newSession = SMBSession(
            host: info.host,
            port: info.port,
            credential: credential,
            transport: info.makeTransport()
        )
        do {
            try await newSession.connect()
            let newTreeId = try await newSession.treeConnect(share: info.share)
            session = newSession
            treeId = newTreeId
        } catch {
            await newSession.closeTransport(cause: "reconnect_new_session", diagnosticError: error)
            throw error
        }
    }

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        keepAliveTask?.cancel()
        await keepAliveTask?.value
        keepAliveTask = nil
        for childTreeId in childTreeIds {
            await session.bestEffortTreeDisconnect(treeId: childTreeId)
        }
        childTreeIds.removeAll()
        await session.disconnect(treeId: treeId)
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
                    await session.closeTransport(cause: "keepalive_echo", diagnosticError: error)
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
        let childTreeId = try await session.treeConnect(share: share)
        childTreeIds.insert(childTreeId)
        let child = SMBClientTreeSession(session: session, treeId: childTreeId)
        do {
            let result = try await operation(child)
            await child.close()
            childTreeIds.remove(childTreeId)
            return result
        } catch {
            await child.close()
            childTreeIds.remove(childTreeId)
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
            try Task.checkCancellation()
            do {
                let fileId = try await session.create(treeId: treeId, request: .changeNotify(path: path))
                do {
                    try await session.changeNotify(
                        treeId: treeId,
                        fileId: fileId,
                        filter: filter,
                        watchTree: watchTree,
                        onChange: onChange
                    )
                    await session.bestEffortClose(treeId: treeId, fileId: fileId)
                    return
                } catch {
                    await session.bestEffortClose(treeId: treeId, fileId: fileId)
                    throw error
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                guard autoReconnect, reconnectInfo != nil, Self.isReconnectable(error) else {
                    throw error
                }
                try Task.checkCancellation()
                do {
                    try await reconnect()
                } catch {
                    reconnectAttempts += 1
                    if reconnectAttempts >= maxReconnectAttempts {
                        throw error
                    }
                    continue
                }
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

    public func read(
        path: String,
        range: SMBReadRange? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            let (start, requested) = try readBounds(stat: stat, range: range)
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

    public func withReadStream(
        path: String,
        range: SMBReadRange? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try ensureOpen()
        let progress = SMBReadStreamProgress()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            let (start, requested) = try readBounds(stat: stat, range: range)
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
    /// Unlike `readPrefix`, this method does not impose an accumulation limit. A connection
    /// loss after a chunk was yielded is normalized to `SMBError.connectionLost(operation: "READ")`.
    public func withPrefixReadStream(
        path: String,
        maxLength: UInt64,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try ensureOpen()
        // Same as readPrefix: reject a pre-cancelled task before the zero-length early return.
        try Task.checkCancellation()
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

    /// Download a file using this already-connected session.
    public func download(path: String, localFile: URL, overwrite: Bool = true,
                         onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil) async throws {
        try ensureOpen()
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

    private func readBounds(stat: SMBFileStat, range: SMBReadRange?) throws -> (offset: UInt64, length: UInt64) {
        let start = range?.offset ?? 0
        guard start <= stat.size else {
            throw SMBCodecError.invalidValue("read range starts past end of file")
        }
        let available = stat.size - start
        return (start, range.map { min($0.length, available) } ?? available)
    }
}

public actor SMBClientTreeSession {
    private let session: SMBSession
    private let treeId: UInt32
    private var isClosed = false

    init(session: SMBSession, treeId: UInt32) {
        self.session = session
        self.treeId = treeId
    }

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        await session.bestEffortTreeDisconnect(treeId: treeId)
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
                    timeout: timeout, makeTransport: makeTransport
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
        timeout: Duration?, makeTransport: (@Sendable () -> SMBTransport)?
    ) async throws -> SMBDfsReferralResult {
        let key = SMBDfsReferralCache.Key(host: host, port: port, path: path, credential: credential)
        if let cached = await dfsReferralCache.get(key) { return cached }
        let referral = try await dfsReferral(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, makeTransport: makeTransport
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
                await session.closeTransport(cause: "with_session_failure", diagnosticError: error)
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

    private static func withSession<T>(
        host: String,
        port: UInt16,
        share: String,
        credentialProvider: SMBCredentialProvider,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        idempotent: Bool,
        operationName: String,
        operation: (SMBSession, UInt32) async throws -> T
    ) async throws -> T {
        let credential = try await credentialProvider()
        return try await withSession(
            host: host,
            port: port,
            share: share,
            credential: credential,
            makeTransport: makeTransport,
            idempotent: idempotent,
            operationName: operationName,
            operation: operation
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        share: String,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBClientSession {
        try await connect(
            host: host,
            port: port,
            share: share,
            credentialProvider: { credential },
            timeout: timeout,
            makeTransport: makeTransport
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        share: String,
        credentialProvider: @escaping SMBCredentialProvider,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBClientSession {
        let makeTransport = resolvedTransportFactory(makeTransport, timeout: timeout)
        let credential = try await credentialProvider()
        let session = SMBSession(host: host, port: port, credential: credential, transport: makeTransport())
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: share)
            let reconnectInfo = SMBClientSession.ReconnectInfo(
                host: host,
                port: port,
                share: share,
                credentialProvider: credentialProvider,
                makeTransport: makeTransport
            )
            return SMBClientSession(session: session, treeId: treeId, reconnectInfo: reconnectInfo)
        } catch {
            await session.closeTransport(cause: "connect_failure", diagnosticError: error)
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
            await session.closeTransport(cause: "list_shares_failure", diagnosticError: error)
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
            await session.closeTransport(cause: "lookup_sids_failure", diagnosticError: error)
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
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBDfsReferralResult {
        let share = try dfsShare(from: path)
        let session = try await connect(
            host: host, port: port, share: share, credential: credential,
            timeout: timeout, makeTransport: makeTransport
        )
        let result = try await session.dfsReferral(share: share, path: path)
        await session.close()
        return result
    }

    /// Resolve `path` through DFS referrals and connect using the same credential.
    /// The returned relative path must be used with the returned session for the
    /// original DFS suffix (for example, `link\\file`).
    public static func connectFollowingDFS(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        path: String,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil
    ) async throws -> SMBDfsConnection {
        let target = try await resolveDFSPath(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, makeTransport: makeTransport, maxHops: 8
        )
        let session = try await connect(
            host: target.host, port: port, share: target.share, credential: credential,
            timeout: timeout, makeTransport: makeTransport
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
            timeout: timeout, makeTransport: makeTransport, maxHops: maxHops
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
    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credential: SMBCredential,
        timeout: Duration? = nil,
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
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

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
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
        makeTransport: (@Sendable () -> SMBTransport)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        let fileManager = FileManager.default
        let destination = localFile.standardizedFileURL
        let directory = destination.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".\(destination.lastPathComponent).smbee-\(UUID().uuidString).tmp")

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
                guard Data(remotePrefix) == localPrefix else {
                    throw SMBCodecError.invalidValue("local resume prefix does not match remote file")
                }
            }
            let handle = try FileHandle(forWritingTo: destination)
            do {
                try handle.seekToEnd()
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
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            return
        }
        fileManager.createFile(atPath: temporary.path, contents: nil)
        let handle = try FileHandle(forWritingTo: temporary)
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
    let decryptedFromTransform: Bool
}

private struct SMBPendingResponse {
    let label: String
    let longPoll: Bool
    let expectedCommand: UInt16
    let expectedSessionId: UInt64
    let expectedTreeId: UInt32
    var pendingCount: Int = 0
    let continuation: CheckedContinuation<SMBReceivedFrame, Error>
    var sendTask: Task<Void, Never>?
    var sendStarted = false
    var cancellationRequested = false
    var continuationResumed = false
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

    private static func diagnosticError(_ error: Error) -> String {
        let description = String(describing: error).replacingOccurrences(of: "\n", with: " ")
        return "\(String(reflecting: type(of: error))): \(description)"
    }

    private static func fileIdPrefix(_ fileId: [UInt8]) -> String {
        fileId.prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    private let host: String
    private let port: UInt16
    // The source credential is needed only while SESSION_SETUP is being built. Derived session
    // keys are sufficient afterwards; reconnect obtains a fresh value from its provider.
    private var authenticationCredential: SMBCredential?
    private let transport: SMBTransport
    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var signingKey: [UInt8]?
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
    private var signingCMACContext: AESCMAC.Context?
#endif
    private var signingRequired = false
    private var encryptionKey: [UInt8]?
    private var decryptionKey: [UInt8]?
    private var signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC
    private var encryptionAlgorithm: SMBSessionEncryptionAlgorithm = .aes128CCM
    private var transformNonceCounter: UInt64 = 0
    private var maxReadSize: UInt32 = UInt32.max
    private var maxWriteSize: UInt32 = UInt32.max
    private let creditWindow: SMB2CreditWindow
    private let initialCredits: UInt32
    private var pendingResponses: [UInt64: SMBPendingResponse] = [:]
    private var pendingCountWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var sentResponseMessageIds: Set<UInt64> = []
    private var orphanResponses: [UInt64: SMBReceivedFrame] = [:]
    private static let maxOrphanResponses = 64
    private var receiveLoopRunning = false
    private var wireFailure: Error?
    private var transportClosed = false
    private let cleanupTimeout: Duration

    init(
        host: String,
        port: UInt16,
        credential: SMBCredential,
        transport: SMBTransport,
        signingKey: [UInt8]? = nil,
        signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC,
        signingRequired: Bool = false,
        initialCredits: UInt32 = 1,
        cleanupTimeout: Duration = SMBSession.defaultCleanupTimeout
    ) {
        self.host = host
        self.port = port
        self.authenticationCredential = credential
        self.transport = transport
        self.signingKey = signingKey
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
        if let signingKey {
            self.signingCMACContext = try? AESCMAC.Context(key: signingKey)
        }
#endif
        self.signingAlgorithm = signingAlgorithm
        self.signingRequired = signingRequired
        self.initialCredits = initialCredits
        self.creditWindow = SMB2CreditWindow(initialCredits: initialCredits)
        self.cleanupTimeout = cleanupTimeout
    }

    func connect() async throws {
        guard let credential = authenticationCredential else {
            throw SMBCodecError.invalidValue("SMB session authentication credential is unavailable")
        }
        try Task.checkCancellation()
        try await transport.connect(host: host, port: port)
        wireFailure = nil
        transportClosed = false
        await creditWindow.reset(initialCredits: initialCredits)
        let negotiate = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(),
            messageId: nextMessageId(),
            offeredDialects: SMBNegotiateCodec.authenticatedDialects
        )
        var preauthMessages: [[UInt8]] = []
        debugDump("NEGOTIATE request", negotiate)
        let negotiateResponse = try await sendPreauthRequest(
            negotiate, responseLabel: "NEGOTIATE response",
            preauthMessages: &preauthMessages, foldResponse: true)
        let result = try SMBNegotiateCodec.decodeResponse(negotiateResponse)
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
        guard challengeHeader.status == SMB2Status.moreProcessingRequired else {
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
        if credential.isAnonymous {
            // ⓥ Anonymous NTLM does not provide session key material, so SMB signing/encryption keys
            // cannot be derived here. If a server requires signing/encryption for guest access, the
            // later signed or encrypted operation is expected to fail until guest E2E coverage defines
            // a server-specific fallback.
            authenticationCredential = nil
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
            encryptionKey = SMBCrypto.smb302EncryptionKey(sessionKey: authenticate.exportedSessionKey)
            decryptionKey = SMBCrypto.smb302DecryptionKey(sessionKey: authenticate.exportedSessionKey)
        }
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
        if result.encryptionRequired, encryptionKey == nil {
            throw SMBError.protocolError("TREE_CONNECT requires encryption but no SMB encryption key was negotiated")
        }
        return result.treeId
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

    func queryDirectory(treeId: UInt32, fileId: [UInt8]) async throws -> [SMBDirectoryEntry] {
        let collector = SMBDirectoryEntryCollector()
        try await queryDirectory(treeId: treeId, fileId: fileId) { entry in
            collector.append(entry)
        }
        return collector.entries
    }

    func queryDirectory(
        treeId: UInt32,
        fileId: [UInt8],
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        var restartScan = true
        var pageFingerprints = Set<String>()
        while true {
            let entries = try await queryDirectoryPage(treeId: treeId, fileId: fileId, restartScan: restartScan)
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

    private func queryDirectoryPage(treeId: UInt32, fileId: [UInt8], restartScan: Bool) async throws -> [SMBDirectoryEntry]? {
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
            outputBufferLength: outputBufferLength
        )
        debugDump("QUERY_DIRECTORY request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "QUERY_DIRECTORY response")
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.noMoreFiles {
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
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        while true {
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
        (try await readChunkReportingRequestedLength(treeId: treeId, fileId: fileId, offset: offset, length: length)).data
    }

    // Prefix short-success detection must use the length encoded by this READ, not a
    // separately predicted value: concurrent operations can change the credit window.
    func readChunkReportingRequestedLength(
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64
    ) async throws -> (data: [UInt8], requestedLength: UInt32) {
        guard length > 0 else { return ([], 0) }
        try Task.checkCancellation()
        let requestLength = UInt32(min(UInt64(await creditAwareReadChunkSize()), length))
        let packet = try SMB2Read.encodeRequest(
            messageId: nextMessageId(charge: SMB2Credit.charge(forPayloadLength: UInt64(requestLength))),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            length: requestLength
        )
        debugDump("READ request", packet)
        let perfCreditsBefore = SMBPerfLog.isEnabled ? await creditWindow.balance : 0
        let perfStart = ContinuousClock.now
        let response = try await signedWireTransaction(packet: packet, responseLabel: "READ response")
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.endOfFile {
            return ([], requestLength)
        }
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "READ")
        let data = try SMB2Read.decodeResponse(response)
        SMBPerfLog.line(
            "read req=\(requestLength) got=\(data.count) wire=\(SMBPerfLog.milliseconds(ContinuousClock.now - perfStart))ms credits=\(perfCreditsBefore)"
        )
        guard data.count <= Int(requestLength) else {
            throw SMBCodecError.invalidValue("SMB read returned more data than requested")
        }
        try Task.checkCancellation()
        return (data, requestLength)
    }

    func write(
        treeId: UInt32,
        fileId: [UInt8],
        data: [UInt8],
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        let progress = SMBTransferProgressEmitter(totalBytes: UInt64(data.count), onProgress: onProgress)
        var cursor = 0
        var chunkSize = await creditAwareWriteChunkSize()
        while let range = try SMBChunkedTransfer.nextWriteRange(cursor: cursor, dataCount: data.count, chunkSize: chunkSize) {
            try Task.checkCancellation()
            let chunk = Array(data[range])
            try await writeChunk(treeId: treeId, fileId: fileId, offset: UInt64(cursor), data: chunk)
            cursor = range.upperBound
            progress.emit(bytesTransferred: UInt64(cursor))
            chunkSize = await creditAwareWriteChunkSize()
        }
        await progress.finish()
    }

    func write(treeId: UInt32, fileId: [UInt8], nextChunk: (Int) throws -> [UInt8]) async throws {
        try await write(treeId: treeId, fileId: fileId, offset: 0, nextChunk: nextChunk)
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

    private func writeChunk(treeId: UInt32, fileId: [UInt8], offset: UInt64, data: [UInt8]) async throws {
        let packet = try SMB2Write.encodeRequest(
            messageId: nextMessageId(charge: SMB2Credit.charge(forPayloadLength: data.count)),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            data: data
        )
        debugDump("WRITE request", packet)
        let perfCreditsBefore = SMBPerfLog.isEnabled ? await creditWindow.balance : 0
        let perfStart = ContinuousClock.now
        let response = try await signedWireTransaction(packet: packet, responseLabel: "WRITE response")
        let count = try SMB2Write.decodeResponseCount(response)
        SMBPerfLog.line(
            "write req=\(data.count) got=\(count) wire=\(SMBPerfLog.milliseconds(ContinuousClock.now - perfStart))ms credits=\(perfCreditsBefore)"
        )
        guard count == data.count else {
            throw SMBCodecError.invalidValue("short SMB write: expected \(data.count) bytes, got \(count)")
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
        let response = try await signedWireTransaction(packet: packet, responseLabel: "IOCTL FSCTL_PIPE_TRANSCEIVE response")
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
            let chunk = try await readChunk(treeId: treeId, fileId: fileId, offset: 0, length: UInt64(negotiatedReadChunkSize()))
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
        let response = try await signedWireTransaction(packet: packet, responseLabel: "LOCK response")
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
            let bindAck = try await readChunk(treeId: treeId, fileId: fileId, offset: 0, length: 4_280)
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
            let bindAck = try await readChunk(treeId: treeId, fileId: fileId, offset: 0, length: 4_280)
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
        let response = try await signedWireTransaction(packet: packet, responseLabel: "CLOSE response")
        if SMBPerfLog.effectiveIsEnabled, let header = try? SMB2Header.decode(response) {
            SMBPerfLog.line("[wire] close_status file=\(Self.fileIdPrefix(fileId)) status=0x\(String(format: "%08x", header.status))")
        }
    }

    /// CLOSE is part of the operation result for create/delete-on-close paths. If it fails,
    /// the FileId lifetime is unknown and the session must not remain reusable.
    func closeCreatedHandle(treeId: UInt32, fileId: [UInt8]) async throws {
        do {
            try await SMBOperationDeadline.run(timeout: cleanupTimeout) {
                try await self.close(treeId: treeId, fileId: fileId)
            }
        } catch {
            closeTransport(cause: "close_created_handle", diagnosticError: error)
            throw error
        }
    }

    /// Cleanup path: do not inherit caller cancellation while trying to release a handle.
    func bestEffortClose(treeId: UInt32, fileId: [UInt8]) async {
        let timeout = cleanupTimeout
        let task = Task.detached { [self] in
            let started = SMBPerfLog.effectiveIsEnabled ? ContinuousClock.now : nil
            do {
                try await SMBOperationDeadline.run(timeout: timeout) {
                    try await self.close(treeId: treeId, fileId: fileId)
                }
            } catch {
                if let started {
                    let elapsed = SMBPerfLog.milliseconds(ContinuousClock.now - started)
                    let timedOut = error is SMBTransportError && (error as? SMBTransportError) == .timedOut
                    SMBPerfLog.line("[wire] cleanup_close_failed file=\(Self.fileIdPrefix(fileId)) elapsed_ms=\(elapsed) error=\(Self.diagnosticError(error)) timeout=\(timedOut)")
                }
                await self.closeTransport(cause: "best_effort_close", diagnosticError: error)
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
                try await SMBOperationDeadline.run(timeout: timeout) {
                    try await self.treeDisconnect(treeId: treeId)
                }
            } catch {
                await self.closeTransport(cause: "best_effort_tree_disconnect", diagnosticError: error)
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

    func sendCancel(messageId: UInt64, treeId: UInt32 = 0) async throws {
        let packet = try SMB2Cancel.encodeRequest(messageId: messageId, sessionId: sessionId, treeId: treeId)
        debugDump("CANCEL request", packet)
        try await sendSigned(packet)
    }

    private func sendCancelWithoutGate(messageId: UInt64, treeId: UInt32) async {
        do {
            let packet = try SMB2Cancel.encodeRequest(messageId: messageId, sessionId: sessionId, treeId: treeId)
            debugDump("CANCEL request", packet)
            try await sendSigned(packet)
        } catch {
            debugLine("CANCEL request failed: \(error)")
        }
    }

    func disconnect(treeId: UInt32) async {
        let timeout = cleanupTimeout
        let task = Task.detached { [self] in
            var diagnosticError: Error?
            do {
                try await SMBOperationDeadline.run(timeout: timeout) {
                    try await self.treeDisconnect(treeId: treeId)
                }
                try await SMBOperationDeadline.run(timeout: timeout) {
                    try await self.logoff()
                }
            } catch {
                diagnosticError = error
                // A graceful cleanup response is missing or invalid. The connection is now
                // suspect; closing it is the only bounded way to release server-side state.
            }
            await self.closeTransport(cause: "disconnect", diagnosticError: diagnosticError)
        }
        await task.value
    }

    func closeTransport(cause: String = "unspecified", diagnosticError: Error? = nil) {
        guard !transportClosed else { return }
        if SMBPerfLog.effectiveIsEnabled {
            let diagnostic = diagnosticError.map(Self.diagnosticError) ?? "none"
            SMBPerfLog.line("[wire] close_transport cause=\(cause) error=\(diagnostic)")
        }
        transportClosed = true
        transport.close()
        failWire(error: SMBTransportError.connectionClosed)
    }

    // Internal-only seams keep deterministic diagnostics tests independent of the process
    // environment. They are not used by production code paths.
    func failWireForTesting(error: Error) {
        failWire(error: error)
    }

    func parkPendingForTesting(messageId: UInt64, command: UInt16) async throws {
        _ = try await withCheckedThrowingContinuation { continuation in
            pendingResponses[messageId] = SMBPendingResponse(
                label: "testing",
                longPoll: false,
                expectedCommand: command,
                expectedSessionId: 0,
                expectedTreeId: 0,
                continuation: continuation,
                sendTask: nil,
                sendStarted: false,
                cancellationRequested: false,
                continuationResumed: false
            )
            resumePendingCountWaiters()
        }
    }

    func waitForPendingCountForTesting(atLeast count: Int) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            if pendingResponses.count >= count {
                continuation.resume()
            } else {
                pendingCountWaiters.append((count, continuation))
            }
        }
    }

    func pendingCountForTesting() -> Int {
        pendingResponses.count
    }

    private func resumePendingCountWaiters() {
        var ready: [CheckedContinuation<Void, Never>] = []
        var pending: [(Int, CheckedContinuation<Void, Never>)] = []
        for (target, continuation) in pendingCountWaiters {
            if pendingResponses.count >= target {
                ready.append(continuation)
            } else {
                pending.append((target, continuation))
            }
        }
        pendingCountWaiters = pending
        for continuation in ready {
            continuation.resume()
        }
    }

    private func unsignedWireTransaction(packet: [UInt8], responseLabel: String) async throws -> [UInt8] {
        try await demuxedWireTransaction(
            packet: packet,
            responseLabel: responseLabel,
            longPoll: false,
            send: { packet, messageId in try await self.sendUnsigned(packet, messageId: messageId) }
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

    private func signedWireTransaction(packet: [UInt8], responseLabel: String, verifySignature: Bool = true) async throws -> [UInt8] {
        let requestHeader = try SMB2Header.decode(packet)
        let response = try await withTaskCancellationHandler {
            try await demuxedWireTransaction(
                packet: packet,
                responseLabel: responseLabel,
                longPoll: false,
                send: { packet, messageId in try await self.sendSigned(packet, messageId: messageId) }
            )
        } onCancel: {
            Task {
                if await self.cancelInFlightRequest(messageId: requestHeader.messageId) {
                    await self.sendCancelWithoutGate(messageId: requestHeader.messageId, treeId: requestHeader.treeId)
                }
            }
        }
        if verifySignature {
            try verifySigned(response)
        }
        return response.bytes
    }

    private func signedLongPollWireTransaction(packet: [UInt8], responseLabel: String, verifySignature: Bool = true) async throws -> [UInt8] {
        let requestHeader = try SMB2Header.decode(packet)
        let response = try await withTaskCancellationHandler {
            try await demuxedWireTransaction(
                packet: packet,
                responseLabel: responseLabel,
                longPoll: true,
                send: { packet, messageId in try await self.sendSigned(packet, messageId: messageId) }
            )
        } onCancel: {
            Task {
                if await self.cancelInFlightRequest(messageId: requestHeader.messageId) {
                    await self.sendCancelWithoutGate(messageId: requestHeader.messageId, treeId: requestHeader.treeId)
                }
            }
        }
        if verifySignature {
            try verifySigned(response)
        }
        return response.bytes
    }

    private func demuxedWireTransaction(
        packet: [UInt8],
        responseLabel: String,
        longPoll: Bool,
        send: @escaping ([UInt8], UInt64) async throws -> Void
    ) async throws -> SMBReceivedFrame {
        let requestHeader = try SMB2Header.decode(packet)
        return try await withCheckedThrowingContinuation { continuation in
            pendingResponses[requestHeader.messageId] = SMBPendingResponse(
                label: responseLabel,
                longPoll: longPoll,
                expectedCommand: requestHeader.command,
                expectedSessionId: requestHeader.sessionId,
                expectedTreeId: requestHeader.treeId,
                continuation: continuation,
                sendTask: nil,
                sendStarted: false,
                cancellationRequested: false,
                continuationResumed: false
            )
            SMBPerfLog.line("[wire] pending message_id=\(requestHeader.messageId) command=\(requestHeader.command) label=\(responseLabel)")
            let sendTask = Task {
                do {
                    try await send(packet, requestHeader.messageId)
                    let shouldSendCancel = self.markRequestSent(messageId: requestHeader.messageId)
                    if shouldSendCancel {
                        await self.sendCancelWithoutGate(messageId: requestHeader.messageId, treeId: requestHeader.treeId)
                    }
                } catch {
                    SMBPerfLog.line("[wire] send_failed message_id=\(requestHeader.messageId) error=\(Self.diagnosticError(error))")
                    if error is CancellationError {
                        self.failPendingResponse(messageId: requestHeader.messageId, error: error)
                    } else {
                        self.closeTransport(cause: "send_failure", diagnosticError: error)
                    }
                }
            }
            pendingResponses[requestHeader.messageId]?.sendTask = sendTask
        }
    }

    private func sendUnsigned(_ packet: [UInt8], messageId: UInt64? = nil) async throws {
        // Deliberately NOT patched here. sendUnsigned carries the NEGOTIATE / SESSION_SETUP
        // preauth messages (via unsignedWireTransaction), whose exact sent bytes must match
        // the copies folded into the SMB 3.1.1 preauth-integrity hash (see setup path). A
        // CreditRequest patch here would desync client/server key derivation and fail every
        // signed/encrypted op. Post-auth traffic is patched in sendSigned before it delegates
        // here for anonymous (unsigned) sessions.
        try Task.checkCancellation()
        let reservedCharge = try await reserveCredit(packet)
        if let messageId, !markSendStarted(messageId: messageId) {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        do {
            try await transport.send(DirectTCPFraming.segments([packet]))
        } catch {
            await refundCredit(charge: reservedCharge)
            throw error
        }
    }

    private func sendSigned(_ packet: [UInt8], messageId: UInt64? = nil) async throws {
        // Single credit-patch point for all post-auth traffic: sendSigned handles every
        // signedWireTransaction op and delegates to sendEncrypted / sendUnsigned below, so
        // patching once here (before signing/sealing) covers signed, encrypted, and anonymous
        // paths while leaving the preauth NEGOTIATE/SESSION_SETUP messages (sent directly via
        // sendUnsigned) untouched for 3.1.1 preauth-integrity.
        var packet = packet
        await applyCreditRequest(to: &packet)
        try Task.checkCancellation()
        if encryptionKey != nil {
            try await sendEncrypted(packet, messageId: messageId)
            return
        }
        // No signing key means an anonymous/guest session (NTLM anonymous yields no session key
        // material). Such sessions cannot sign; the server granted access without requiring signing
        // (signingRequired was false at NEGOTIATE), so send the packet unsigned.
        guard let signingKey else {
            try await sendUnsigned(packet, messageId: messageId)
            return
        }
        // Sign it in place: mutation gives this local buffer unique ownership, avoiding
        // a second payload-sized copy before the transport framing copy.
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
        let reservedCharge = try await reserveCredit(packet)
        if let messageId, !markSendStarted(messageId: messageId) {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        do {
            try await transport.send(DirectTCPFraming.segments([packet]))
        } catch {
            await refundCredit(charge: reservedCharge)
            throw error
        }
    }

    private func sendEncrypted(_ packet: [UInt8], messageId: UInt64? = nil) async throws {
        // packet is already credit-patched by sendSigned (the sole caller); do not re-patch.
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
        let reservedCharge = try await reserveCredit(packet)
        if let messageId, !markSendStarted(messageId: messageId) {
            await refundCredit(charge: reservedCharge)
            throw CancellationError()
        }
        do {
            try await transport.send(DirectTCPFraming.segments([try header.encode(), sealed.ciphertext]))
        } catch {
            await refundCredit(charge: reservedCharge)
            throw error
        }
    }

    private func verifySigned(_ frame: SMBReceivedFrame) throws {
        if frame.decryptedFromTransform { return }
        let packet = frame.bytes
        guard let signingKey else { return }
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
        guard expected == header.signature else {
            throw SMBCodecError.invalidValue("SMB signature verification failed")
        }
    }

    private func receiveDecryptedFrame(label: String) async throws -> SMBReceivedFrame {
        let header = try await receiveExactly(4)
        let length = try DirectTCPFraming.length(from: header)
        debugDump("\(label) direct-TCP header length=\(length)", header)
        let body = try await receiveExactly(length)
        debugDump(label, body)
        let decryptedFromTransform = body.starts(with: SMB3TransformHeader.protocolId)
        let packet = decryptedFromTransform ? try decryptTransform(body) : body
        await recordCreditGrant(packet, label: label)
        return SMBReceivedFrame(bytes: packet, decryptedFromTransform: decryptedFromTransform)
    }

    private func startReceiveLoopIfNeeded() {
        guard !receiveLoopRunning else { return }
        receiveLoopRunning = true
        Task { await self.receiveLoop() }
    }

    private func receiveLoop() async {
        while !sentResponseMessageIds.isEmpty {
            do {
                try Task.checkCancellation()
                let frame = try await receiveDecryptedFrame(label: "SMB response")
                try dispatchReceivedPacket(frame)
            } catch {
                failWire(error: error)
                receiveLoopRunning = false
                return
            }
        }
        receiveLoopRunning = false
    }

    private func dispatchReceivedPacket(_ frame: SMBReceivedFrame) throws {
        let packet = frame.bytes
        let header = try SMB2Header.decode(packet)
        SMBPerfLog.line("[wire] recv message_id=\(header.messageId) command=\(header.command) status=0x\(String(format: "%08x", header.status))\(header.status == SMB2Status.pending ? " STATUS_PENDING" : "")")
        // Server-initiated notifications (oplock/lease break) arrive with MessageId
        // 0xFFFFFFFFFFFFFFFF and never correspond to a request. This client never requests
        // oplocks or leases (CREATE RequestedOplockLevel is always NONE), so drop them
        // instead of queueing them as orphan responses forever.
        if header.command == SMB2Commands.oplockBreak || header.messageId == UInt64.max {
            debugLine("ignoring unsolicited server notification (command \(header.command), messageId \(header.messageId))")
            return
        }
        guard var pending = pendingResponses[header.messageId] else {
            if sentResponseMessageIds.contains(header.messageId) {
                // A cancelled request still owns its wire response until the final frame.
                if try SMB2AsyncInterim.shouldDiscard(packet) {
                    debugLine("ignoring interim response for cancelled message id \(header.messageId)")
                    return
                }
                sentResponseMessageIds.remove(header.messageId)
                debugLine("completed cancelled SMB response message id \(header.messageId)")
                return
            }
            // Bound the orphan queue: spurious/duplicate server responses whose messageId is
            // never claimed by markRequestSent would otherwise accumulate for the whole
            // session lifetime (issues/012). Dropping the oldest is safe — a legitimate
            // pre-send response arrives within the current in-flight window.
            if orphanResponses.count >= Self.maxOrphanResponses,
               let oldestId = orphanResponses.keys.min() {
                orphanResponses.removeValue(forKey: oldestId)
                debugLine("SMB orphan response queue full; dropped message id \(oldestId)")
            }
            orphanResponses[header.messageId] = frame
            debugLine("SMB response queued for future message id \(header.messageId)")
            return
        }
        // SESSION_SETUP/legacy test and server responses may carry zero session/tree
        // before the authenticated context is established; once populated, both are
        // part of the correlation key.
        guard header.command == pending.expectedCommand,
              pending.expectedSessionId == 0 || header.sessionId == 0 || header.sessionId == pending.expectedSessionId,
              pending.expectedTreeId == 0 || header.treeId == 0 || header.treeId == pending.expectedTreeId else {
            throw SMBCodecError.invalidValue("SMB response correlation mismatch command=\(header.command)/\(pending.expectedCommand) session=\(header.sessionId)/\(pending.expectedSessionId) tree=\(header.treeId)/\(pending.expectedTreeId)")
        }
        if try SMB2AsyncInterim.shouldDiscard(packet) {
            pending.pendingCount += 1
            if !pending.longPoll && pending.pendingCount > SMB2AsyncInterim.maxPendingResponses {
                pendingResponses.removeValue(forKey: header.messageId)
                if !pending.continuationResumed {
                    pending.continuationResumed = true
                    pending.continuation.resume(throwing: SMBCodecError.invalidValue("too many interim SMB2 STATUS_PENDING responses"))
                }
                return
            }
            pendingResponses[header.messageId] = pending
            debugLine("\(pending.label) ignored interim STATUS_PENDING async response")
            return
        }
        pendingResponses.removeValue(forKey: header.messageId)
        sentResponseMessageIds.remove(header.messageId)
        if !pending.continuationResumed {
            pending.continuationResumed = true
            pending.continuation.resume(returning: frame)
        }
    }

    private func markSendStarted(messageId: UInt64) -> Bool {
        guard var pending = pendingResponses[messageId] else {
            return false
        }
        pending.sendStarted = true
        pendingResponses[messageId] = pending
        return true
    }

    @discardableResult
    private func markRequestSent(messageId: UInt64) -> Bool {
        guard let pending = pendingResponses[messageId] else {
            return false
        }
        SMBPerfLog.line("[wire] sent message_id=\(messageId)")
        sentResponseMessageIds.insert(messageId)
        if pending.cancellationRequested {
            pendingResponses.removeValue(forKey: messageId)
        }
        if let orphan = orphanResponses.removeValue(forKey: messageId) {
            do {
                try dispatchReceivedPacket(orphan)
            } catch {
                failPendingResponse(messageId: messageId, error: error)
                return false
            }
        }
        startReceiveLoopIfNeeded()
        // An orphan can be the final response. In that case dispatchReceivedPacket
        // already consumed it, so there is no wire request left to cancel.
        return pending.cancellationRequested && sentResponseMessageIds.contains(messageId)
    }

    private func failPendingResponse(messageId: UInt64, error: Error) {
        guard var pending = pendingResponses[messageId] else { return }
        if pending.sendStarted {
            if error is CancellationError {
                pending.cancellationRequested = true
                pendingResponses[messageId] = pending
            } else {
                pendingResponses.removeValue(forKey: messageId)
            }
        } else {
            pendingResponses.removeValue(forKey: messageId)
            pending.sendTask?.cancel()
        }
        // Cancel releases pending state, but the wire response is unfinished — retain
        // sentResponseMessageIds until its final response so credit grants remain observable.
        if !pending.continuationResumed {
            pending.continuationResumed = true
            pending.continuation.resume(throwing: error)
            if pending.sendStarted, pending.cancellationRequested {
                pendingResponses[messageId] = pending
            }
        }
    }

    private func cancelInFlightRequest(messageId: UInt64) -> Bool {
        let wasSent = sentResponseMessageIds.contains(messageId)
        failPendingResponse(messageId: messageId, error: CancellationError())
        return wasSent
    }

    private func failAllPendingResponses(error: Error) {
        let pending = pendingResponses
        if SMBPerfLog.effectiveIsEnabled {
            let resumed = pending.values.filter(\.continuationResumed).count
            let details = pending.sorted { $0.key < $1.key }.prefix(16).map {
                "\($0.key):\($0.value.expectedCommand):\($0.value.continuationResumed ? 1 : 0)"
            }
            let remaining = pending.count - details.count
            let detail = details.joined(separator: ",") + (remaining > 0 ? ",(+\(remaining) more)" : "")
            SMBPerfLog.line("[wire] victim count=\(pending.count) resumed=\(resumed) pending=\(pending.count - resumed) detail=\(detail)")
        }
        pendingResponses.removeAll()
        sentResponseMessageIds.removeAll()
        orphanResponses.removeAll()
        for var waiter in pending.values {
            // A cancellation tombstone may have already resumed its continuation;
            // wire failure must not resume it a second time.
            if waiter.continuationResumed { continue }
            waiter.continuationResumed = true
            // failAllPendingResponses is only reached after the receive side has
            // declared the shared wire dead. Cancelling a send that already started
            // is therefore safe: the transport/socket is being torn down as a unit,
            // and it prevents a blocked send task from surviving session failure.
            waiter.sendTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
        // Credit waiters are only ever resumed by grants from received responses; once the
        // receive path is dead they must be drained too (issues/010 §B invariant: every
        // session-owned continuation is resumed by some terminal event).
        let creditWindow = creditWindow
        Task { await creditWindow.failAllWaiters(error) }
    }

    private func failWire(error: Error) {
        let firstFault = wireFailure == nil
        let failure = wireFailure ?? error
        wireFailure = failure
        if firstFault {
            SMBPerfLog.line("[wire] first_fault error=\(Self.diagnosticError(error))")
        }
        failAllPendingResponses(error: failure)
    }

    private func reserveCredit(_ packet: [UInt8]) async throws -> UInt16 {
        if let wireFailure {
            throw wireFailure
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
        if SMBPerfLog.effectiveIsEnabled {
            let available = await creditWindow.balance
            if available < UInt32(effectiveCharge) {
                SMBPerfLog.line("[wire] credit_wait message_id=\(header.messageId) command=\(header.command) charge=\(effectiveCharge) available=\(available)")
            }
        }
        let balance = try await creditWindow.reserve(charge: effectiveCharge)
        debugLine("SMB credit charge=\(effectiveCharge) balance=\(balance)")
        return effectiveCharge
    }

    private func applyCreditRequest(to packet: inout [UInt8]) async {
        let balance = await creditWindow.balance
        SMB2Credit.patchCreditRequest(into: &packet, balance: balance, target: SMB2Credit.targetWindowCredits)
    }

    private func refundCredit(charge: UInt16) async {
        let balance = await creditWindow.refund(charge: charge)
        debugLine("SMB credit refund=\(charge) balance=\(balance)")
    }

    private func recordCreditGrant(_ packet: [UInt8], label: String) async {
        guard let header = try? SMB2Header.decode(packet) else { return }
        let balance = await creditWindow.grant(header.credits)
        debugLine("\(label) credit grant=\(header.credits) balance=\(balance)")
    }

    private func decryptTransform(_ packet: [UInt8]) throws -> [UInt8] {
        guard let decryptionKey else { throw SMBCodecError.invalidValue("missing SMB decryption key") }
        let header = try SMB3TransformHeader.decode(packet)
        guard header.flags == SMB3TransformHeader.encryptedFlag else {
            throw SMBCodecError.invalidValue("unsupported SMB3 transform flags")
        }
        guard header.sessionId == sessionId else { throw SMBCodecError.invalidValue("SMB3 transform session id mismatch") }
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
        return plaintext
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
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        let negotiated = SMBTransferLimits.negotiatedChunkSize(
            localLimit: SMBClientSession.localWriteChunkLimit,
            negotiatedLimit: maxWriteSize,
            transformOverhead: transformOverhead,
        )
        return Int(clamping: await creditCappedLength(UInt32(min(negotiated, Int(clamping: UInt32.max)))))
    }

    private func creditAwareReadChunkSize() async -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        let negotiated = SMBTransferLimits.negotiatedChunkSize(
            localLimit: Self.localReadChunkLimit,
            negotiatedLimit: maxReadSize,
            transformOverhead: transformOverhead,
        )
        return Int(clamping: await creditCappedLength(UInt32(min(negotiated, Int(clamping: UInt32.max)))))
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
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        let traceWire = ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE"] == "1"
        FileHandle.standardError.write(Data("\(label) (\(bytes.count) bytes): \(SMBDebug.packetSummary(bytes, traceWire: traceWire))\n".utf8))
    }

    private func debugLine(_ message: String) {
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}

enum SMB2Status {
    static let success: UInt32 = 0x0000_0000
    static let pending: UInt32 = 0x0000_0103
    static let notifyEnumDir: UInt32 = 0x0000_010c
    static let bufferOverflow: UInt32 = 0x8000_0005
    static let noMoreFiles: UInt32 = 0x8000_0006
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

    static func shouldDiscard(_ packet: [UInt8]) throws -> Bool {
        let header = try SMB2Header.decode(packet)
        guard header.status == SMB2Status.pending else { return false }
        guard (header.flags & SMB2Flags.asyncCommand) != 0 else {
            throw SMBCodecError.invalidValue("SMB2 STATUS_PENDING response missing ASYNC_COMMAND flag")
        }
        return true
    }
}
