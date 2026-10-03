import Foundation

/// A connection-level failure reported by an `SMBTransport` or an operation deadline.
public enum SMBTransportError: Error, Equatable, Sendable {
    case connectionClosed
    case invalidAddress
    case socketFailure(String)
    case timedOut
}

public protocol SMBTransport: Sendable {
    /// Opens this transport's one connection lifetime. Implementations must cooperate with
    /// `close()` so a concurrent connect does not publish a connection after terminal close.
    func connect(host: String, port: UInt16) async throws

    /// Sends one logical byte stream. Concurrent invocations are allowed, but the bytes
    /// from each invocation must not be interleaved with another invocation. The order in
    /// which concurrent invocations become visible is unspecified.
    func send(_ bytes: [UInt8]) async throws

    /// Sends the concatenation of all segments as one logical byte stream. It has the same
    /// non-interleaving and unspecified concurrent-order contract as `send(_:)`.
    func send(_ segments: [[UInt8]]) async throws
    func receive(maxLength: Int) async throws -> [UInt8]

    /// Terminal and idempotent. Closing must make already-issued connect, send, and receive
    /// operations return without depending on a peer response, and future I/O must fail.
    func close()
}

public extension SMBTransport {
    /// Sends one logical byte stream assembled from multiple buffers. Transports can
    /// override this to use vectored I/O; the default preserves the contract by joining
    /// the segments before making one bytes-send invocation.
    func send(_ segments: [[UInt8]]) async throws {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(segments.reduce(0) { $0 + $1.count })
        for segment in segments {
            bytes.append(contentsOf: segment)
        }
        try await send(bytes)
    }
}

/// Linearizes one connection candidate's publication against terminal close.
/// Transports that create a resource before awaiting readiness can publish it here;
/// a close that wins first rejects and leaves cleanup of the candidate to its creator.
final class SMBTransportConnectionSlot<Value>: @unchecked Sendable {
    private enum State {
        case open
        case installed(Value)
        case closed
    }

    private let lock = NSLock()
    private var state = State.open

    var value: Value? {
        lock.withLock {
            guard case .installed(let value) = state else { return nil }
            return value
        }
    }

    @discardableResult
    func install(_ value: Value) -> Bool {
        lock.withLock {
            guard case .open = state else { return false }
            state = .installed(value)
            return true
        }
    }

    /// Returns the published value once. A later candidate can no longer be installed.
    func close() -> Value? {
        lock.withLock {
            guard case .closed = state else {
                let value: Value?
                if case .installed(let installed) = state {
                    value = installed
                } else {
                    value = nil
                }
                state = .closed
                return value
            }
            return nil
        }
    }
}

/// Receive behavior for the in-memory test transport. The default releases one preloaded
/// response frame after each successful full send and then waits for close, matching a live
/// connection without synthetic future-response preload. Select `eofWhenDrained` explicitly
/// in tests that need to exercise peer EOF.
public enum InMemoryTransportMode: Sendable {
    case eofWhenDrained
    case waitUntilClosed
    case sendGatedWaitUntilClosed
}

struct SMBWireRequestIdentity: Hashable, Sendable {
    let messageId: UInt64
    let command: UInt16
}

struct SMBWireRequestDescriptor: Sendable {
    let identity: SMBWireRequestIdentity
    let sessionId: UInt64
    let treeId: UInt32
    let controlCode: UInt32?

    init(packet: [UInt8]) throws {
        let header = try SMB2Header.decode(packet)
        identity = SMBWireRequestIdentity(messageId: header.messageId, command: header.command)
        sessionId = header.sessionId
        treeId = header.treeId
        if header.command == SMB2Commands.ioctl && packet.count >= SMB2Header.encodedSize + 8 {
            let offset = SMB2Header.encodedSize + 4
            controlCode = UInt32(packet[offset])
                | (UInt32(packet[offset + 1]) << 8)
                | (UInt32(packet[offset + 2]) << 16)
                | (UInt32(packet[offset + 3]) << 24)
        } else {
            controlCode = nil
        }
    }
}

typealias SMBWireRequestDecoder = @Sendable ([UInt8]) throws -> SMBWireRequestDescriptor

public final class InMemoryTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        let id: UUID
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    // `SMBTransport` is Sendable and the multi-flight session can call send/receive
    // from separate tasks. Keep this test transport honest too: callers commonly
    // inspect `outbound` while a response loop is still running.
    private let lock = NSLock()
    private let mode: InMemoryTransportMode
    private var inbound: [UInt8]
    private var responsesByRequest: [SMBWireRequestIdentity: [[UInt8]]] = [:]
    private var responsePreparationError: Error?
    private var allowedUnansweredRequests: Set<SMBWireRequestIdentity>
    private let responseIdentityOverrides: [SMBWireRequestIdentity]?
    private let requestDecoder: SMBWireRequestDecoder?
    private var sentRequestIds: Set<UInt64> = []
    private var releasedFrames: [[UInt8]] = []
    private var nextReleasedFrameIndex = 0
    private var currentFrame: [UInt8] = []
    private var currentFrameOffset = 0
    private var pendingReceive: PendingReceive?
    private var isClosed = false
    private var outboundStorage: [UInt8] = []

    public var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    var hasPendingReceiveForTesting: Bool {
        lock.withLock { pendingReceive != nil }
    }

    public convenience init(inbound: [UInt8] = [], mode: InMemoryTransportMode = .sendGatedWaitUntilClosed) {
        self.init(
            inbound: inbound,
            mode: mode,
            responseIdentityOverrides: nil,
            allowedUnansweredRequests: [],
            requestDecoder: nil
        )
    }

    init(
        inbound: [UInt8],
        mode: InMemoryTransportMode,
        responseIdentityOverrides: [SMBWireRequestIdentity]?,
        allowedUnansweredRequests: Set<SMBWireRequestIdentity>,
        requestDecoder: SMBWireRequestDecoder?
    ) {
        self.inbound = inbound
        self.mode = mode
        self.responseIdentityOverrides = responseIdentityOverrides
        self.allowedUnansweredRequests = allowedUnansweredRequests
        self.requestDecoder = requestDecoder
        if case .sendGatedWaitUntilClosed = mode {
            do {
                let frames = try Self.unframe(inbound)
                if let responseIdentityOverrides, responseIdentityOverrides.count != frames.count {
                    throw SMBCodecError.invalidValue("response identity override count does not match inbound frames")
                }
                for (index, frame) in frames.enumerated() {
                    let identity: SMBWireRequestIdentity
                    if let responseIdentityOverrides {
                        identity = responseIdentityOverrides[index]
                    } else {
                        identity = try Self.responseIdentity(frame)
                    }
                    responsesByRequest[identity, default: []].append(frame)
                }
            } catch {
                responsePreparationError = error
            }
        }
    }

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        guard !lock.withLock({ isClosed }) else { throw SMBTransportError.connectionClosed }
    }

    public func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let descriptor: SMBWireRequestDescriptor?
        if case .sendGatedWaitUntilClosed = mode {
            descriptor = try Self.requestDescriptor(bytes, decoder: requestDecoder)
        } else {
            descriptor = nil
        }
        let shouldWake = try lock.withLock { () throws -> Bool in
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            guard case .sendGatedWaitUntilClosed = mode else {
                outboundStorage.append(contentsOf: bytes)
                return false
            }
            if let responsePreparationError { throw responsePreparationError }
            guard let descriptor else { throw SMBCodecError.invalidValue("missing decoded SMB request") }
            let identity = descriptor.identity
            if identity.command == SMB2Commands.cancel {
                guard sentRequestIds.contains(identity.messageId) else {
                    throw SMBCodecError.invalidValue("CANCEL does not identify a previously sent request")
                }
                outboundStorage.append(contentsOf: bytes)
                return false
            }
            guard !sentRequestIds.contains(identity.messageId) else {
                throw SMBCodecError.invalidValue("duplicate SMB request MessageId \(identity.messageId)")
            }
            guard let frames = responsesByRequest.removeValue(forKey: identity) else {
                if allowedUnansweredRequests.contains(identity) {
                    sentRequestIds.insert(identity.messageId)
                    outboundStorage.append(contentsOf: bytes)
                    return false
                }
                throw SMBCodecError.invalidValue(
                    "unexpected SMB request command=\(identity.command) messageId=\(identity.messageId)"
                )
            }
            sentRequestIds.insert(identity.messageId)
            outboundStorage.append(contentsOf: bytes)
            releasedFrames.append(contentsOf: frames)
            return !frames.isEmpty
        }
        if shouldWake { resumePendingReceiveIfReady() }
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<[UInt8], Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    if isClosed { return .failure(SMBTransportError.connectionClosed) }
                    if let chunk = takeAvailableChunk(maxLength: maxLength) { return .success(chunk) }
                    if case .eofWhenDrained = mode, inbound.isEmpty { return .success([]) }
                    guard pendingReceive == nil else {
                        return .failure(SMBCodecError.invalidValue("concurrent receive on in-memory transport"))
                    }
                    pendingReceive = PendingReceive(id: id, maxLength: maxLength, continuation: continuation)
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            self.cancelPendingReceive(id: id)
        }
    }

    public func close() {
        let waiter = lock.withLock { () -> PendingReceive? in
            isClosed = true
            defer { pendingReceive = nil }
            return pendingReceive
        }
        waiter?.continuation.resume(throwing: SMBTransportError.connectionClosed)
    }

    private func resumePendingReceiveIfReady() {
        let result: (PendingReceive, Result<[UInt8], Error>)? = lock.withLock {
            guard let waiter = pendingReceive,
                  let chunk = takeAvailableChunk(maxLength: waiter.maxLength) else { return nil }
            pendingReceive = nil
            return (waiter, .success(chunk))
        }
        if let (waiter, result) = result { waiter.continuation.resume(with: result) }
    }

    private func takeAvailableChunk(maxLength: Int) -> [UInt8]? {
        switch mode {
        case .eofWhenDrained, .waitUntilClosed:
            guard !inbound.isEmpty else { return nil }
            let count = min(maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            return chunk
        case .sendGatedWaitUntilClosed:
            if currentFrameOffset >= currentFrame.count {
                guard nextReleasedFrameIndex < releasedFrames.count else { return nil }
                currentFrame = releasedFrames[nextReleasedFrameIndex]
                nextReleasedFrameIndex += 1
                currentFrameOffset = 0
            }
            let count = min(maxLength, currentFrame.count - currentFrameOffset)
            let chunk = Array(currentFrame[currentFrameOffset..<(currentFrameOffset + count)])
            currentFrameOffset += count
            return chunk
        }
    }

    private func cancelPendingReceive(id: UUID) {
        let waiter = lock.withLock { () -> PendingReceive? in
            guard pendingReceive?.id == id else { return nil }
            defer { pendingReceive = nil }
            return pendingReceive
        }
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private static func unframe(_ bytes: [UInt8]) throws -> [[UInt8]] {
        var frames: [[UInt8]] = []
        var offset = 0
        while offset < bytes.count {
            guard offset + 4 <= bytes.count, bytes[offset] == 0 else { throw SMBCodecError.truncated }
            let length = (Int(bytes[offset + 1]) << 16) | (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
            let end = offset + 4 + length
            guard end <= bytes.count else { throw SMBCodecError.truncated }
            frames.append(Array(bytes[offset..<end]))
            offset = end
        }
        return frames
    }

    private static func responseIdentity(_ frame: [UInt8]) throws -> SMBWireRequestIdentity {
        guard frame.count >= 4 else { throw SMBCodecError.truncated }
        let descriptor = try SMBWireRequestDescriptor(packet: Array(frame.dropFirst(4)))
        return descriptor.identity
    }

    private static func requestDescriptor(
        _ framedBytes: [UInt8],
        decoder: SMBWireRequestDecoder?
    ) throws -> SMBWireRequestDescriptor {
        guard framedBytes.count >= 4 else { throw SMBCodecError.truncated }
        let length = (Int(framedBytes[1]) << 16) | (Int(framedBytes[2]) << 8) | Int(framedBytes[3])
        guard framedBytes[0] == 0, framedBytes.count == length + 4 else { throw SMBCodecError.truncated }
        let packet = Array(framedBytes.dropFirst(4))
        if let decoder { return try decoder(packet) }
        guard !packet.starts(with: SMB3TransformHeader.protocolId) else {
            throw SMBCodecError.invalidValue("encrypted SMB request requires a request decoder")
        }
        return try SMBWireRequestDescriptor(packet: packet)
    }
}
