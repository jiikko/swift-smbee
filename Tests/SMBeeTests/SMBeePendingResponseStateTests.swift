import Foundation
import XCTest
@testable import SMBee

private let m2PollLimit = 50_000

private struct M2WaitError: Error, CustomStringConvertible {
    let label: String

    var description: String {
        "condition '\(label)' did not become true"
    }
}

private final class M2ResultBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Result<Value, Error>?

    var result: Result<Value, Error>? {
        lock.withLock { storage }
    }

    func store(_ result: Result<Value, Error>) {
        lock.withLock {
            if storage == nil {
                storage = result
            }
        }
    }
}

private func m2Start<Value: Sendable>(
    _ operation: @escaping @Sendable () async throws -> Value
) -> (Task<Void, Never>, M2ResultBox<Value>) {
    let result = M2ResultBox<Value>()
    let task = Task { @Sendable in
        do {
            result.store(.success(try await operation()))
        } catch {
            result.store(.failure(error))
        }
    }
    return (task, result)
}

private func m2WaitUntil(
    _ label: String,
    _ condition: @escaping @Sendable () -> Bool
) async throws {
    for _ in 0..<m2PollLimit {
        if condition() {
            return
        }
        try Task.checkCancellation()
        await Task.yield()
    }
    throw M2WaitError(label: label)
}

private func m2WaitForResult<Value: Sendable>(
    _ label: String,
    _ result: M2ResultBox<Value>
) async throws -> Result<Value, Error> {
    for _ in 0..<m2PollLimit {
        if let value = result.result {
            return value
        }
        try Task.checkCancellation()
        await Task.yield()
    }
    throw M2WaitError(label: label)
}

private func m2Unframed(_ bytes: [UInt8]) throws -> [[UInt8]] {
    var frames: [[UInt8]] = []
    var cursor = 0
    while cursor < bytes.count {
        guard cursor + 4 <= bytes.count else { throw SMBCodecError.truncated }
        let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<(cursor + 4)]))
        let start = cursor + 4
        let end = start + length
        guard end <= bytes.count else { throw SMBCodecError.truncated }
        frames.append(Array(bytes[start..<end]))
        cursor = end
    }
    return frames
}

private final class M2ReceiveTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private let lock = NSLock()
    private var outboundStorage: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var receiveStartedStorage = false
    private var isClosed = false

    var outbound: [UInt8] {
        lock.withLock { outboundStorage }
    }

    var didStartReceive: Bool {
        lock.withLock { receiveStartedStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        lock.withLock { isClosed = false }
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let closed = lock.withLock {
            if isClosed {
                return true
            }
            outboundStorage.append(contentsOf: bytes)
            return false
        }
        if closed {
            throw SMBTransportError.connectionClosed
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        _ = maxLength
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                let action: Result<[UInt8], Error>?

                lock.lock()
                receiveStartedStorage = true
                if isClosed {
                    action = .failure(SMBTransportError.connectionClosed)
                } else if Task.isCancelled {
                    action = .failure(CancellationError())
                } else {
                    pendingReceive = PendingReceive(continuation: continuation)
                    action = nil
                }
                lock.unlock()

                if let action {
                    continuation.resume(with: action)
                }
            }
        } onCancel: {
            self.cancelPendingReceive()
        }
    }

    func close() {
        let pendingReceive = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            isClosed = true
            defer { self.pendingReceive = nil }
            return self.pendingReceive?.continuation
        }
        pendingReceive?.resume(throwing: SMBTransportError.connectionClosed)
    }

    private func cancelPendingReceive() {
        let pendingReceive = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            let continuation = self.pendingReceive?.continuation
            self.pendingReceive = nil
            return continuation
        }
        pendingReceive?.resume(throwing: CancellationError())
    }
}

private final class M2BlockingSendTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var firstSend = true
    private var blockedSendContinuation: CheckedContinuation<Void, Error>?
    private var sendStartedStorage = false
    private var sendCancellationObservedStorage = false

    var didStartFirstSend: Bool {
        lock.withLock { sendStartedStorage }
    }

    var didObserveSendCancellation: Bool {
        lock.withLock { sendCancellationObservedStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let shouldBlock = lock.withLock { () -> Bool in
            sendStartedStorage = true
            let isFirstSend = firstSend
            firstSend = false
            return isFirstSend
        }

        if shouldBlock {
            try await withCheckedThrowingContinuation { continuation in
                lock.withLock {
                    blockedSendContinuation = continuation
                }
            }
            if Task.isCancelled {
                lock.withLock { sendCancellationObservedStorage = true }
                throw CancellationError()
            }
        }

        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        _ = maxLength
        throw SMBTransportError.connectionClosed
    }

    func close() {}

    func releaseBlockedSend() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            let continuation = blockedSendContinuation
            blockedSendContinuation = nil
            return continuation
        }
        continuation?.resume()
    }
}

private func m2Session(_ transport: SMBTransport, initialCredits: UInt32 = 1) -> SMBSession {
    SMBSession(
        host: "server",
        port: 445,
        credential: SMBCredential(username: "user", password: "pass"),
        transport: transport,
        initialCredits: initialCredits
    )
}

private func m2FileId() -> [UInt8] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ]
}

private func m2AssertCancellation<Value>(_ result: Result<Value, Error>, file: StaticString = #filePath, line: UInt = #line) {
    switch result {
    case .success:
        XCTFail("cancelled operation unexpectedly completed", file: file, line: line)
    case .failure(let error):
        XCTAssertTrue(error is CancellationError, "expected CancellationError, got \(error)", file: file, line: line)
    }
}

final class SMBeePendingResponseStateTests: XCTestCase {
    func testClosingAfterSentCancellationDoesNotResumeTombstoneTwice() async throws {
        let transport = M2ReceiveTransport()
        let session = m2Session(transport)
        let (task, result) = m2Start {
            try await session.readChunk(treeId: 0x3344, fileId: m2FileId(), offset: 0, length: 3)
        }
        defer {
            task.cancel()
            transport.close()
        }

        try await m2WaitUntil("sent READ frame") {
            ((try? m2Unframed(transport.outbound).count) ?? 0) >= 1
        }
        try await m2WaitUntil("receive loop after sent READ") {
            transport.didStartReceive
        }
        task.cancel()
        try await m2WaitUntil("sent READ and CANCEL frames") {
            ((try? m2Unframed(transport.outbound).count) ?? 0) >= 2
        }
        m2AssertCancellation(try await m2WaitForResult("cancelled READ", result))

        await session.closeTransport(cause: "m2_tombstone_double_resume")
    }

    func testClosingCancelsBlockedSendOwnedByCancelledTombstone() async throws {
        let transport = M2BlockingSendTransport()
        let session = m2Session(transport)
        let (task, result) = m2Start {
            try await session.readChunk(treeId: 0x3344, fileId: m2FileId(), offset: 0, length: 3)
        }
        defer {
            task.cancel()
            transport.releaseBlockedSend()
        }

        try await m2WaitUntil("blocked first send") {
            transport.didStartFirstSend
        }
        task.cancel()
        m2AssertCancellation(try await m2WaitForResult("cancelled blocked READ", result))

        await session.closeTransport(cause: "m2_cancel_blocked_send")
        transport.releaseBlockedSend()
        try await m2WaitUntil("blocked send observes cancellation") {
            transport.didObserveSendCancellation
        }
    }
}
