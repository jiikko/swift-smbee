import XCTest
@testable import SMBee

final class SMBWireDiagnosticsTests: XCTestCase {
    func testFirstFaultIsLoggedOnce() async {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let session = SMBSession(
            host: "test", port: 445,
            credential: SMBCredential(username: "", password: ""),
            transport: InMemoryTransport()
        )
        await session.failWireForTesting(error: SMBTransportError.socketFailure("first"))
        await session.failWireForTesting(error: SMBTransportError.timedOut)
        let faults = capture.messages.filter { $0.hasPrefix("[wire] first_fault") }
        XCTAssertEqual(faults.count, 1)
        XCTAssertTrue(faults[0].contains("SMBTransportError"))
    }

    func testCloseCauseAndVictimSnapshotAreLogged() async {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let session = SMBSession(
            host: "test", port: 445,
            credential: SMBCredential(username: "", password: ""),
            transport: InMemoryTransport()
        )
        let first = Task { try await session.parkPendingForTesting(messageId: 1, command: 8) }
        let second = Task { try await session.parkPendingForTesting(messageId: 2, command: 9) }
        for _ in 0..<100 {
            if await session.pendingCountForTesting() == 2 { break }
            try? await Task.sleep(for: .milliseconds(1))
        }
        let pendingCount = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCount, 2)
        await session.closeTransport(cause: "unit_test", diagnosticError: SMBTransportError.timedOut)
        _ = try? await first.value
        _ = try? await second.value

        XCTAssertTrue(capture.messages.contains { $0.contains("[wire] close_transport cause=unit_test") })
        XCTAssertTrue(capture.messages.contains { $0.contains("[wire] victim count=2") })
    }

    func testBestEffortCloseTimeoutClosesTransportAndFailsConcurrentPendingOperations() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }

        let transport = CloseSilentTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            cleanupTimeout: .milliseconds(25)
        )
        let first = Task { try await session.parkPendingForTesting(messageId: 1, command: 8) }
        let second = Task { try await session.parkPendingForTesting(messageId: 2, command: 9) }
        await session.waitForPendingCountForTesting(atLeast: 2)

        await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 1, count: 16))

        XCTAssertTrue(transport.commands.contains(SMB2Commands.close))
        do {
            _ = try await awaitWithTimeout("first pending close victim") { try await first.value }
            XCTFail("first pending operation unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("second pending close victim") { try await second.value }
            XCTFail("second pending operation unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        let pendingCountAfterClose = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCountAfterClose, 0)

        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] cleanup_close_failed") && $0.contains("timeout=true")
        })
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] close_transport cause=best_effort_close")
        })
    }
}

private final class SMBWireLogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        lock.withLock { storage.append(message) }
    }
}

private final class CloseSilentTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let receiveState = CloseSilentReceiveState()
    private var commandStorage: [UInt16] = []

    var commands: [UInt16] {
        lock.withLock { commandStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let header = try SMB2Header.decode(Array(bytes.dropFirst(4)))
        lock.withLock { commandStorage.append(header.command) }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        return try await withTaskCancellationHandler {
            try await receiveState.wait()
        } onCancel: {
            receiveState.cancel()
        }
    }

    func close() {
        receiveState.cancel()
    }
}

private final class CloseSilentReceiveState: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[UInt8], Error>?
    private var isCancelled = false

    func wait() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            let continuationToResume: CheckedContinuation<[UInt8], Error>?
            lock.lock()
            if isCancelled {
                continuationToResume = continuation
            } else {
                self.continuation = continuation
                continuationToResume = nil
            }
            lock.unlock()
            continuationToResume?.resume(throwing: CancellationError())
        }
    }

    func cancel() {
        let continuationToResume: CheckedContinuation<[UInt8], Error>?
        lock.lock()
        isCancelled = true
        continuationToResume = continuation
        continuation = nil
        lock.unlock()
        continuationToResume?.resume(throwing: CancellationError())
    }
}

private struct SMBWireDiagnosticsTimeout: Error {
    let label: String
}

private final class SMBWireDiagnosticsResumeOnceBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    private var result: Result<T, Error>?
    private var completed = false

    func install(_ continuation: CheckedContinuation<T, Error>) {
        let resultToResume: Result<T, Error>?
        lock.lock()
        if let result {
            resultToResume = result
        } else {
            self.continuation = continuation
            resultToResume = nil
        }
        lock.unlock()
        if let resultToResume {
            continuation.resume(with: resultToResume)
        }
    }

    func resume(_ result: Result<T, Error>) {
        let continuationToResume: CheckedContinuation<T, Error>?
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        self.result = result
        continuationToResume = continuation
        continuation = nil
        lock.unlock()
        continuationToResume?.resume(with: result)
    }
}

private func awaitWithTimeout<T: Sendable>(
    _ label: String,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let box = SMBWireDiagnosticsResumeOnceBox<T>()
    let operationTask = Task {
        do {
            box.resume(.success(try await operation()))
        } catch {
            box.resume(.failure(error))
        }
    }
    let timeoutTask = Task {
        try? await Task.sleep(for: .seconds(2))
        operationTask.cancel()
        box.resume(.failure(SMBWireDiagnosticsTimeout(label: label)))
    }
    defer { timeoutTask.cancel() }
    return try await withCheckedThrowingContinuation { continuation in
        box.install(continuation)
    }
}
