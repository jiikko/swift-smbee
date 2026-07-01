import Foundation
// swiftlint:disable file_length type_body_length

public struct SMBDirectoryEntry: Equatable, Sendable {
    public var name: String
    public var fileSize: UInt64
    public var isDirectory: Bool
    public var attributes: UInt32
    public var fileId: UInt64?

    public var isReparsePoint: Bool {
        (attributes & SMBFileAttributes.reparsePoint) != 0
    }

    public init(name: String, fileSize: UInt64, isDirectory: Bool, attributes: UInt32 = 0, fileId: UInt64? = nil) {
        self.name = name
        self.fileSize = fileSize
        self.isDirectory = isDirectory
        self.attributes = attributes
        self.fileId = fileId
    }
}

public struct SMBFileStat: Equatable, Sendable {
    public var size: UInt64
    public var creationTime: Date?
    public var lastAccessTime: Date?
    public var modifiedTime: Date?
    public var changeTime: Date?
    public var isDirectory: Bool
    public var attributes: UInt32

    public var isReparsePoint: Bool {
        (attributes & SMBFileAttributes.reparsePoint) != 0
    }

    public init(
        size: UInt64,
        modifiedTime: Date?,
        isDirectory: Bool,
        attributes: UInt32 = 0,
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        changeTime: Date? = nil
    ) {
        self.size = size
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.modifiedTime = modifiedTime
        self.changeTime = changeTime
        self.isDirectory = isDirectory
        self.attributes = attributes
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
        let usableNegotiatedLimit = max(0, Int(negotiatedLimit) - transformOverhead)
        return max(1, min(localLimit, usableNegotiatedLimit))
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

public actor SMBClientSession {
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
        await session.disconnect(treeId: treeId)
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
            try? await session.close(treeId: treeId, fileId: fileId)
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func stat(path: String) async throws -> SMBFileStat {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            try? await session.close(treeId: treeId, fileId: fileId)
            return stat
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func read(path: String, range: SMBReadRange? = nil) async throws -> [UInt8] {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, path: path, directory: false)
        do {
            let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
            let (start, requested) = try readBounds(stat: stat, range: range)
            let data = try await SMBClient.readAll(session: session, treeId: treeId, fileId: fileId, offset: start, length: requested)
            guard UInt64(data.count) == requested else {
                throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(data.count)")
            }
            try? await session.close(treeId: treeId, fileId: fileId)
            return data
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func withReadStream(
        path: String,
        range: SMBReadRange? = nil,
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
                onChunk: onChunk
            )
            try? await session.close(treeId: treeId, fileId: fileId)
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            if progress.startedYielding, error.isSMBConnectionLoss {
                throw SMBError.connectionLost(operation: "READ")
            }
            throw error
        }
    }

    public func makeDirectory(path: String) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
        try await session.close(treeId: treeId, fileId: fileId)
    }

    public func upload(path: String, data: [UInt8], overwrite: Bool = true) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
        do {
            try await session.write(treeId: treeId, fileId: fileId, data: data)
            try await session.flush(treeId: treeId, fileId: fileId)
            try? await session.close(treeId: treeId, fileId: fileId)
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func copy(fromPath: String, toPath: String, overwrite: Bool = false) async throws {
        try ensureOpen()
        try await session.copyFile(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
    }

    public func copyDirectory(fromPath: String, toPath: String, overwrite: Bool = false) async throws {
        try ensureOpen()
        try await session.copyDirectory(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
    }

    public func rename(fromPath: String, toPath: String, replaceIfExists: Bool = false) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .rename(path: fromPath))
        do {
            try await session.rename(treeId: treeId, fileId: fileId, newPath: toPath, replaceIfExists: replaceIfExists)
            try? await session.close(treeId: treeId, fileId: fileId)
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    public func delete(path: String, directory: Bool = false, recursive: Bool = false) async throws {
        try ensureOpen()
        if recursive {
            try await session.deleteRecursively(treeId: treeId, path: path, directory: directory)
            return
        }
        try await session.deleteNonRecursive(treeId: treeId, path: path, directory: directory)
    }

    public func updateMetadata(path: String, update: SMBFileMetadataUpdate, directory: Bool = false) async throws {
        try ensureOpen()
        let fileId = try await session.create(treeId: treeId, request: .metadata(path: path, directory: directory))
        do {
            try await session.setBasicInfo(treeId: treeId, fileId: fileId, update: update)
            try? await session.close(treeId: treeId, fileId: fileId)
        } catch {
            try? await session.close(treeId: treeId, fileId: fileId)
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

public enum SMBClient {
    private static let localWriteChunkLimit = 64 * 1024

    private static func withSession<T>(
        host: String,
        port: UInt16,
        share: String,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() },
        idempotent: Bool,
        operationName: String,
        operation: (SMBSession, UInt32) async throws -> T
    ) async throws -> T {
        var retryConnectionLoss = idempotent
        while true {
            let transport = makeTransport()
            let session = SMBSession(host: host, port: port, credential: credential, transport: transport)
            do {
                try await session.connect()
                let treeId = try await session.treeConnect(share: share)
                let result = try await operation(session, treeId)
                await session.closeTransport()
                return result
            } catch {
                await session.closeTransport()
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

    public static func connect(
        host: String,
        port: UInt16 = 445,
        share: String,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> SMBClientSession {
        let session = SMBSession(host: host, port: port, credential: credential, transport: makeTransport())
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: share)
            return SMBClientSession(session: session, treeId: treeId)
        } catch {
            await session.closeTransport()
            throw error
        }
    }

    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> [SMBShareInfo] {
        let session = SMBSession(host: host, port: port, credential: credential, transport: makeTransport())
        do {
            try await session.connect()
            let treeId = try await session.treeConnect(share: "IPC$")
            let shares = try await session.listShares(treeId: treeId)
            await session.disconnect(treeId: treeId)
            return shares
        } catch {
            await session.closeTransport()
            throw error
        }
    }

    public static func list(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> [SMBDirectoryEntry] {
        let collector = SMBDirectoryEntryCollector()
        try await withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            makeTransport: makeTransport
        ) { entry in
            collector.append(entry)
        }
        return collector.entries
    }

    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() },
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: true, operationName: "LIST") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: true)
            do {
                try await session.queryDirectory(treeId: treeId, fileId: fileId, onEntry: onEntry)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func stat(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> SMBFileStat {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: true, operationName: "STAT") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
                return stat
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func read(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> [UInt8] {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: true, operationName: "READ") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                let start = range?.offset ?? 0
                guard start <= stat.size else {
                    throw SMBCodecError.invalidValue("read range starts past end of file")
                }
                let available = stat.size - start
                let requested = range.map { min($0.length, available) } ?? available
                let data = try await readAll(session: session, treeId: treeId, fileId: fileId, offset: start, length: requested)
                guard UInt64(data.count) == requested else {
                    throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(data.count)")
                }
                try? await session.close(treeId: treeId, fileId: fileId)
                return data
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
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
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() },
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        let progress = SMBReadStreamProgress()
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: true, operationName: "READ") { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                let start = range?.offset ?? 0
                guard start <= stat.size else {
                    throw SMBCodecError.invalidValue("read range starts past end of file")
                }
                let available = stat.size - start
                let requested = range.map { min($0.length, available) } ?? available
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
                    cursor = advanced.cursor
                    remaining = advanced.remaining
                }
                let received = progress.received
                guard received == requested else {
                    throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(received)")
                }
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                if progress.startedYielding, error.isSMBConnectionLoss {
                    throw SMBError.connectionLost(operation: "READ")
                }
                throw error
            }
        }
    }

    public static func download(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        let fileManager = FileManager.default
        let destination = localFile.standardizedFileURL
        let directory = destination.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".\(destination.lastPathComponent).smbee-\(UUID().uuidString).tmp")

        guard overwrite || !fileManager.fileExists(atPath: destination.path) else {
            throw SMBCodecError.invalidValue("local destination already exists")
        }
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        fileManager.createFile(atPath: temporary.path, contents: nil)
        let handle = try FileHandle(forWritingTo: temporary)
        do {
            try await withReadStream(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                makeTransport: makeTransport
            ) { chunk in
                try handle.write(contentsOf: Data(chunk))
            }
            try handle.close()
            if overwrite, fileManager.fileExists(atPath: destination.path) {
                _ = try fileManager.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: destination)
            }
        } catch {
            try? handle.close()
            try? fileManager.removeItem(at: temporary)
            throw error
        }
    }

    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        credential: SMBCredential,
        makeTransport: @Sendable @escaping () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: localDirectory, withIntermediateDirectories: true)
        let entries = try await list(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            makeTransport: makeTransport
        )
        for entry in entries {
            try Task.checkCancellation()
            guard !entry.isReparsePoint else { continue }
            let remoteChild = joinSMBPath(path, entry.name)
            let localChild = localDirectory.appendingPathComponent(entry.name)
            if entry.isDirectory {
                try await downloadDirectory(
                    host: host,
                    port: port,
                    share: share,
                    path: remoteChild,
                    localDirectory: localChild,
                    overwrite: overwrite,
                    credential: credential,
                    makeTransport: makeTransport
                )
            } else {
                try await download(
                    host: host,
                    port: port,
                    share: share,
                    path: remoteChild,
                    localFile: localChild,
                    overwrite: overwrite,
                    credential: credential,
                    makeTransport: makeTransport
                )
            }
        }
    }

    fileprivate static func readAll(session: SMBSession, treeId: UInt32, fileId: [UInt8], offset: UInt64, length: UInt64) async throws -> [UInt8] {
        let result = SMBReadAccumulator()
        var cursor = offset
        var remaining = length
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
            cursor = advanced.cursor
            remaining = advanced.remaining
        }
        return result.bytes
    }

    fileprivate static func streamRead(
        session: SMBSession,
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt64,
        progress: SMBReadStreamProgress,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        var cursor = offset
        var remaining = length
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
            cursor = advanced.cursor
            remaining = advanced.remaining
        }
        let received = progress.received
        guard received == length else {
            throw SMBCodecError.invalidValue("short SMB read: expected \(length) bytes, got \(received)")
        }
    }

    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "MKDIR") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
            try await session.close(treeId: treeId, fileId: fileId)
        }
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "UPLOAD") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
            do {
                try await session.write(treeId: treeId, fileId: fileId, data: data)
                try await session.flush(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        credential: SMBCredential,
        makeTransport: @Sendable @escaping () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        if !path.trimmingCharacters(in: CharacterSet(charactersIn: "\\/")).isEmpty {
            try await createDirectoryIfNeeded(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                makeTransport: makeTransport
            )
        }
        let fileManager = FileManager.default
        let contents = try fileManager.contentsOfDirectory(
            at: localDirectory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        )
        for localChild in contents {
            try Task.checkCancellation()
            let resourceValues = try localChild.resourceValues(forKeys: [.isDirectoryKey])
            let remoteChild = joinSMBPath(path, localChild.lastPathComponent)
            if resourceValues.isDirectory == true {
                try await uploadDirectory(
                    host: host,
                    port: port,
                    share: share,
                    path: remoteChild,
                    localDirectory: localChild,
                    overwrite: overwrite,
                    credential: credential,
                    makeTransport: makeTransport
                )
            } else {
                try await upload(
                    host: host,
                    port: port,
                    share: share,
                    path: remoteChild,
                    localFile: localChild,
                    overwrite: overwrite,
                    credential: credential,
                    makeTransport: makeTransport
                )
            }
        }
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "UPLOAD") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
            let handle = try FileHandle(forReadingFrom: localFile)
            defer { try? handle.close() }
            do {
                try await session.write(treeId: treeId, fileId: fileId) { maxLength in
                    let length = min(maxLength, localWriteChunkLimit)
                    let data = try handle.read(upToCount: length) ?? Data()
                    return Array(data)
                }
                try await session.flush(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func copy(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "COPY") { session, treeId in
            try await session.copyFile(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
        }
    }

    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "COPY") { session, treeId in
            try await session.copyDirectory(treeId: treeId, fromPath: fromPath, toPath: toPath, overwrite: overwrite)
        }
    }

    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        update: SMBFileMetadataUpdate,
        directory: Bool = false,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "SET_METADATA") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .metadata(path: path, directory: directory))
            do {
                try await session.setBasicInfo(treeId: treeId, fileId: fileId, update: update)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
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
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "RENAME") { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .rename(path: fromPath))
            do {
                try await session.rename(treeId: treeId, fileId: fileId, newPath: toPath, replaceIfExists: replaceIfExists)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func delete(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, makeTransport: makeTransport, idempotent: false, operationName: "DELETE") { session, treeId in
            if recursive {
                try await session.deleteRecursively(treeId: treeId, path: path, directory: directory)
                return
            }
            try await session.deleteNonRecursive(treeId: treeId, path: path, directory: directory)
        }
    }

    private static func createDirectoryIfNeeded(
        host: String,
        port: UInt16,
        share: String,
        path: String,
        credential: SMBCredential,
        makeTransport: @Sendable () -> SMBTransport
    ) async throws {
        do {
            try await makeDirectory(
                host: host,
                port: port,
                share: share,
                path: path,
                credential: credential,
                makeTransport: makeTransport
            )
        } catch SMBError.nameCollision {
            return
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
        case .connectionClosed, .socketFailure:
            return true
        case .invalidAddress:
            return false
        }
    }
}

/// Wire transaction は直列化する。
///
/// この actor は mutable wire state (messageId / sessionId / transformNonce / 鍵 / 交渉値) を隔離する。
/// actor reentrancy により `sendSigned` → `receive` 間で別の wire 操作が入り得るため、各 request/response
/// pair は `SMBWireTransactionGate` で直列化する。これにより同一 `SMBSession` への並行呼び出しでも
/// 応答取り違えは起きないが、SMB2 本来の multi-credit / multi-flight 並行化はまだ行わない。
///
/// 真の multi-flight が必要になったら MS-SMB2 の messageId/credit ベース応答多重分離へ置き換える
/// (背景と対応案は issues/done/002-design-smbsession-concurrent-multiflight.md)。
actor SMBSession {
    private let host: String
    private let port: UInt16
    private let credential: SMBCredential
    private let transport: SMBTransport
    private let wireTransactionGate = SMBWireTransactionGate()
    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var signingKey: [UInt8]?
    private var encryptionKey: [UInt8]?
    private var decryptionKey: [UInt8]?
    private var signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC
    private var encryptionAlgorithm: SMBSessionEncryptionAlgorithm = .aes128CCM
    private var transformNonceCounter: UInt64 = 0
    private var maxReadSize: UInt32 = UInt32.max
    private var maxWriteSize: UInt32 = UInt32.max

    init(
        host: String,
        port: UInt16,
        credential: SMBCredential,
        transport: SMBTransport,
        signingKey: [UInt8]? = nil,
        signingAlgorithm: SMBSessionSigningAlgorithm = .aesCMAC
    ) {
        self.host = host
        self.port = port
        self.credential = credential
        self.transport = transport
        self.signingKey = signingKey
        self.signingAlgorithm = signingAlgorithm
    }

    func connect() async throws {
        try Task.checkCancellation()
        try await transport.connect(host: host, port: port)
        let negotiate = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(),
            messageId: nextMessageId(),
            offeredDialects: SMBNegotiateCodec.authenticatedDialects
        )
        var preauthMessages = [negotiate]
        debugDump("NEGOTIATE request", negotiate)
        let negotiateResponse = try await unsignedWireTransaction(packet: negotiate, responseLabel: "NEGOTIATE response")
        preauthMessages.append(negotiateResponse)
        let result = try SMBNegotiateCodec.decodeResponse(negotiateResponse)
        maxReadSize = result.maxReadSize
        maxWriteSize = result.maxWriteSize
        guard result.dialect == SMBNegotiateConstants.dialect311
            || result.dialect == SMBNegotiateConstants.dialect302
            || result.dialect == SMBNegotiateConstants.dialect300
        else {
            throw SMBCodecError.invalidValue("authenticated path currently supports SMB 3.0.x and 3.1.1")
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

        let type1Message = NTLM.makeType1(domain: credential.domain)
        let type1 = SPNEGO.wrapNegTokenInit(type1Message)
        let challengePacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: 0,
            securityBlob: type1,
            signed: false
        )
        debugLine("SESSION_SETUP#1 request length=\(challengePacket.count)")
        preauthMessages.append(challengePacket)
        let challengeResponse = try await unsignedWireTransaction(packet: challengePacket, responseLabel: "SESSION_SETUP#1 response")
        preauthMessages.append(challengeResponse)
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
        let mechListMIC = NTLM.makeMechListMIC(exportedSessionKey: authenticate.exportedSessionKey)
        let authBlob = SPNEGO.wrapNegTokenResp(authenticate.message, mechListMIC: mechListMIC)
        let authPacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            securityBlob: authBlob,
            signed: false
        )
        debugLine("SESSION_SETUP#2 request length=\(authPacket.count)")
        preauthMessages.append(authPacket)
        // MS-SMB2 §3.2.5.3.1: preauth integrity hash for key derivation covers messages
        // up to the final SESSION_SETUP *request*. The terminal STATUS_SUCCESS response is
        // NOT folded into the hash — including it derives a signing/encryption key that
        // differs from the server's, so every signed/encrypted 3.1.1 op fails verification.
        let authResponse = try await unsignedWireTransaction(packet: authPacket, responseLabel: "SESSION_SETUP#2 response")
        let authHeader = try SMB2Header.decode(authResponse)
        try SMBErrorMapper.throwIfFailure(status: authHeader.status, operation: "SESSION_SETUP")
        sessionId = authHeader.sessionId
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

    func deleteNonRecursive(treeId: UInt32, path: String, directory: Bool) async throws {
        do {
            let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: directory))
            try await close(treeId: treeId, fileId: fileId)
        } catch SMBError.fileIsADirectory where !directory {
            let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: true))
            try await close(treeId: treeId, fileId: fileId)
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
        while true {
            let entries = try await queryDirectoryPage(treeId: treeId, fileId: fileId, restartScan: restartScan)
            restartScan = false
            guard let entries else { return }
            for entry in entries {
                try Task.checkCancellation()
                try await onEntry(entry)
            }
        }
    }

    private func queryDirectoryPage(treeId: UInt32, fileId: [UInt8], restartScan: Bool) async throws -> [SMBDirectoryEntry]? {
        try Task.checkCancellation()
        let packet = try SMB2QueryDirectory.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            restartScan: restartScan
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
        return try SMB2QueryInfo.decodeNetworkOpenInformation(response)
    }

    func readChunk(treeId: UInt32, fileId: [UInt8], offset: UInt64, length: UInt64) async throws -> [UInt8] {
        guard length > 0 else { return [] }
        try Task.checkCancellation()
        let requestLength = UInt32(min(UInt64(negotiatedReadChunkSize()), length))
        let packet = try SMB2Read.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            length: requestLength
        )
        debugDump("READ request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "READ response")
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.endOfFile {
            return []
        }
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "READ")
        let data = try SMB2Read.decodeResponse(response)
        guard data.count <= Int(requestLength) else {
            throw SMBCodecError.invalidValue("SMB read returned more data than requested")
        }
        try Task.checkCancellation()
        return data
    }

    func write(treeId: UInt32, fileId: [UInt8], data: [UInt8]) async throws {
        let chunkSize = negotiatedWriteChunkSize()
        var cursor = 0
        while let range = try SMBChunkedTransfer.nextWriteRange(cursor: cursor, dataCount: data.count, chunkSize: chunkSize) {
            try Task.checkCancellation()
            let chunk = Array(data[range])
            try await writeChunk(treeId: treeId, fileId: fileId, offset: UInt64(cursor), data: chunk)
            cursor = range.upperBound
        }
    }

    func write(treeId: UInt32, fileId: [UInt8], nextChunk: (Int) throws -> [UInt8]) async throws {
        let chunkSize = negotiatedWriteChunkSize()
        var offset: UInt64 = 0
        while true {
            try Task.checkCancellation()
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
                try? await close(treeId: treeId, fileId: destinationFileId)
                try? await close(treeId: treeId, fileId: sourceFileId)
            } catch {
                try? await close(treeId: treeId, fileId: destinationFileId)
                throw error
            }
        } catch {
            try? await close(treeId: treeId, fileId: sourceFileId)
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

    func copyDirectory(treeId: UInt32, fromPath: String, toPath: String, overwrite: Bool) async throws {
        try Task.checkCancellation()
        let sourceFileId = try await create(treeId: treeId, path: fromPath, directory: true)
        do {
            let destinationFileId = try await create(treeId: treeId, request: .makeDirectory(path: toPath))
            try await close(treeId: treeId, fileId: destinationFileId)
        } catch SMBError.nameCollision where overwrite {
            // Existing destination directories are reused only when overwrite is explicit.
        } catch {
            try? await close(treeId: treeId, fileId: sourceFileId)
            throw error
        }

        do {
            try await queryDirectory(treeId: treeId, fileId: sourceFileId) { entry in
                try Task.checkCancellation()
                let sourceChild = self.joinSMBPath(fromPath, entry.name)
                let destinationChild = self.joinSMBPath(toPath, entry.name)
                if entry.isDirectory && !entry.isReparsePoint {
                    try await self.copyDirectory(treeId: treeId, fromPath: sourceChild, toPath: destinationChild, overwrite: overwrite)
                } else {
                    try await self.copyFile(treeId: treeId, fromPath: sourceChild, toPath: destinationChild, overwrite: overwrite)
                }
            }
            try? await close(treeId: treeId, fileId: sourceFileId)
        } catch {
            try? await close(treeId: treeId, fileId: sourceFileId)
            throw error
        }
    }

    private func writeChunk(treeId: UInt32, fileId: [UInt8], offset: UInt64, data: [UInt8]) async throws {
        let packet = try SMB2Write.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            offset: offset,
            data: data
        )
        debugDump("WRITE request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "WRITE response")
        let count = try SMB2Write.decodeResponseCount(response)
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
        while !(try DCERPC.responseHasLastFragment(output)) {
            try Task.checkCancellation()
            let chunk = try await readChunk(treeId: treeId, fileId: fileId, offset: 0, length: UInt64(negotiatedReadChunkSize()))
            guard !chunk.isEmpty else {
                throw SMBCodecError.invalidValue("short DCE/RPC pipe response")
            }
            output.append(contentsOf: chunk)
        }
        return output
    }

    func flush(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Flush.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("FLUSH request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "FLUSH response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "FLUSH")
    }

    func deleteRecursively(treeId: UInt32, path: String, directory: Bool) async throws {
        try Task.checkCancellation()
        if directory {
            let fileId = try await create(treeId: treeId, path: path, directory: true)
            do {
                try await queryDirectory(treeId: treeId, fileId: fileId) { entry in
                    try Task.checkCancellation()
                    guard !entry.isReparsePoint else { return }
                    try await self.deleteRecursively(treeId: treeId, path: self.joinSMBPath(path, entry.name), directory: entry.isDirectory)
                }
                try? await close(treeId: treeId, fileId: fileId)
            } catch {
                try? await close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
        let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: directory))
        try await close(treeId: treeId, fileId: fileId)
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
            try? await close(treeId: treeId, fileId: fileId)
            return shares
        } catch {
            try? await close(treeId: treeId, fileId: fileId)
            throw error
        }
    }

    func close(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Close.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("CLOSE request", packet)
        _ = try await signedWireTransaction(packet: packet, responseLabel: "CLOSE response", verifySignature: false)
    }

    func treeDisconnect(treeId: UInt32) async throws {
        let packet = try SMB2TreeDisconnect.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId)
        debugDump("TREE_DISCONNECT request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "TREE_DISCONNECT response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "TREE_DISCONNECT")
    }

    func logoff() async throws {
        let packet = try SMB2Logoff.encodeRequest(messageId: nextMessageId(), sessionId: sessionId)
        debugDump("LOGOFF request", packet)
        let response = try await signedWireTransaction(packet: packet, responseLabel: "LOGOFF response")
        let header = try SMB2Header.decode(response)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "LOGOFF")
    }

    func disconnect(treeId: UInt32) async {
        try? await treeDisconnect(treeId: treeId)
        try? await logoff()
        closeTransport()
    }

    func closeTransport() {
        transport.close()
    }

    private func unsignedWireTransaction(packet: [UInt8], responseLabel: String) async throws -> [UInt8] {
        await wireTransactionGate.enter()
        defer { wireTransactionGate.leave() }
        try await sendUnsigned(packet)
        return try await receive(label: responseLabel)
    }

    private func signedWireTransaction(packet: [UInt8], responseLabel: String, verifySignature: Bool = true) async throws -> [UInt8] {
        await wireTransactionGate.enter()
        defer { wireTransactionGate.leave() }
        try await sendSigned(packet)
        let response = try await receive(label: responseLabel)
        if verifySignature {
            try verifySigned(response)
        }
        return response
    }

    private func sendUnsigned(_ packet: [UInt8]) async throws {
        try Task.checkCancellation()
        try await transport.send(DirectTCPFraming.frame(packet))
        try Task.checkCancellation()
    }

    private func sendSigned(_ packet: [UInt8]) async throws {
        try Task.checkCancellation()
        if encryptionKey != nil {
            try await sendEncrypted(packet)
            return
        }
        guard let signingKey else { throw SMBCodecError.invalidValue("missing SMB signing key") }
        var signed = packet
        signed[16] |= UInt8(SMB2Flags.signed & 0xff)
        for index in 48..<64 { signed[index] = 0 }
        let signature = try SMBSessionSigning.signature(
            algorithm: signingAlgorithm,
            key: signingKey,
            packet: signed,
            sender: .client
        )
        signed.replaceSubrange(48..<64, with: signature)
        try await transport.send(DirectTCPFraming.frame(signed))
        try Task.checkCancellation()
    }

    private func sendEncrypted(_ packet: [UInt8]) async throws {
        guard let encryptionKey else { throw SMBCodecError.invalidValue("missing SMB encryption key") }
        let nonceLength = encryptionAlgorithm == .aes128GCM ? 12 : 11
        let nonce = nextTransformNonce(length: nonceLength)
        let nonce16 = nonce + Array(repeating: UInt8(0), count: 16 - nonceLength)
        let flags: UInt16 = encryptionAlgorithm == .aes128GCM ? SMB3TransformHeader.aes128GCM : SMB3TransformHeader.aes128CCM
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce16,
            originalMessageSize: UInt32(packet.count),
            flags: flags,
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
        try await transport.send(DirectTCPFraming.frame(try header.encode() + sealed.ciphertext))
        try Task.checkCancellation()
    }

    private func verifySigned(_ packet: [UInt8]) throws {
        if packet.starts(with: SMB3TransformHeader.protocolId) { return }
        guard let signingKey else { return }
        let header = try SMB2Header.decode(packet)
        guard (header.flags & SMB2Flags.signed) != 0 else { return }
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

    private func receive(label: String) async throws -> [UInt8] {
        for pendingCount in 0...SMB2AsyncInterim.maxPendingResponses {
            try Task.checkCancellation()
            let packet = try await receiveDecryptedFrame(label: label)
            guard try SMB2AsyncInterim.shouldDiscard(packet) else {
                return packet
            }
            if pendingCount == SMB2AsyncInterim.maxPendingResponses {
                break
            }
            debugLine("\(label) ignored interim STATUS_PENDING async response")
        }
        throw SMBCodecError.invalidValue("too many interim SMB2 STATUS_PENDING responses")
    }

    private func receiveDecryptedFrame(label: String) async throws -> [UInt8] {
        let header = try await receiveExactly(4)
        let length = try DirectTCPFraming.length(from: header)
        debugDump("\(label) direct-TCP header length=\(length)", header)
        let body = try await receiveExactly(length)
        debugDump(label, body)
        if body.starts(with: SMB3TransformHeader.protocolId) {
            return try decryptTransform(body)
        }
        return body
    }

    private func decryptTransform(_ packet: [UInt8]) throws -> [UInt8] {
        guard let decryptionKey else { throw SMBCodecError.invalidValue("missing SMB decryption key") }
        let header = try SMB3TransformHeader.decode(packet)
        let algorithm: SMBSessionEncryptionAlgorithm
        switch header.flags {
        case SMB3TransformHeader.aes128CCM:
            algorithm = .aes128CCM
        case SMB3TransformHeader.aes128GCM:
            algorithm = .aes128GCM
        default:
            throw SMBCodecError.invalidValue("unsupported SMB3 encryption algorithm")
        }
        guard header.sessionId == sessionId else { throw SMBCodecError.invalidValue("SMB3 transform session id mismatch") }
        let ciphertext = Array(packet.dropFirst(SMB3TransformHeader.encodedSize))
        guard ciphertext.count == Int(header.originalMessageSize) else {
            throw SMBCodecError.invalidValue("SMB3 transform original message size mismatch")
        }
        let plaintext: [UInt8]
        switch algorithm {
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

    private func nextMessageId() -> UInt64 {
        defer { messageId += 1 }
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
            UInt8(value & 0xff),
        ]
        return bytes + Array(repeating: 0, count: length - bytes.count)
    }

    private func negotiatedWriteChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: maxWriteSize, transformOverhead: transformOverhead)
    }

    private func negotiatedReadChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: maxReadSize, transformOverhead: transformOverhead)
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
    static let bufferOverflow: UInt32 = 0x8000_0005
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let invalidParameter: UInt32 = 0xc000_000d
    static let invalidDeviceRequest: UInt32 = 0xc000_0010
    static let endOfFile: UInt32 = 0xc000_0011
    static let moreProcessingRequired: UInt32 = 0xc000_0016
    static let accessDenied: UInt32 = 0xc000_0022
    static let objectNameInvalid: UInt32 = 0xc000_0033
    static let objectNameNotFound: UInt32 = 0xc000_0034
    static let objectNameCollision: UInt32 = 0xc000_0035
    static let objectPathNotFound: UInt32 = 0xc000_003a
    static let sharingViolation: UInt32 = 0xc000_0043
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
        SMB2Status.invalidDeviceRequest,
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
