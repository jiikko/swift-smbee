import Foundation

/// A connection-level failure reported by an `SMBTransport` or an operation deadline.
public enum SMBTransportError: Error, Equatable, Sendable {
    case connectionClosed
    case invalidAddress
    case socketFailure(String)
    case timedOut
}

public protocol SMBTransport: Sendable {
    func connect(host: String, port: UInt16) async throws
    func send(_ bytes: [UInt8]) async throws
    func send(_ segments: [[UInt8]]) async throws
    func receive(maxLength: Int) async throws -> [UInt8]
    func close()
}

public extension SMBTransport {
    /// Sends one logical byte stream assembled from multiple buffers. Transports can
    /// override this to use vectored I/O; the default preserves source compatibility.
    func send(_ segments: [[UInt8]]) async throws {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(segments.reduce(0) { $0 + $1.count })
        for segment in segments {
            bytes.append(contentsOf: segment)
        }
        try await send(bytes)
    }
}

public final class InMemoryTransport: SMBTransport, @unchecked Sendable {
    // `SMBTransport` is Sendable and the multi-flight session can call send/receive
    // from separate tasks. Keep this test transport honest too: callers commonly
    // inspect `outbound` while a response loop is still running.
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var outboundStorage: [UInt8] = []

    public var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    public init(inbound: [UInt8] = []) {
        self.inbound = inbound
    }

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    public func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        lock.withLock {
            outboundStorage.append(contentsOf: bytes)
        }
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let chunk = lock.withLock { () -> [UInt8] in
            if inbound.isEmpty {
                return []
            }
            let count = min(maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            return chunk
        }
        try Task.checkCancellation()
        return chunk
    }

    public func close() {}
}
