import Foundation
import XCTest
@testable import SMBee

final class SMBOperationDeadlineTests: XCTestCase {
    func testClientSessionStreamDeadlineWaitsForCloseCompletion() async throws {
        let fileId = deadlineFileId
        let transport = try makeDeadlineTransport([
            deadlineCreateResponse(fileId: fileId, messageId: 0),
            deadlineQueryInfoResponse(size: 4, messageId: 1),
            deadlineReadResponse(Array("data".utf8), messageId: 2),
            deadlineStatusResponse(command: SMB2Commands.close, messageId: 3)
        ])
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport
        )
        let client = SMBClientSession(session: session, treeId: deadlineTreeId)
        let clock = SMBDeadlineManualSleeper()
        let chunkGate = SMBDeadlineAsyncGate()
        let operation = Task {
            try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await clock.sleep(for: $0) }, operation: {
                try await client.withReadStream(path: "file.bin", operationTimeout: .seconds(30)) { _ in
                    try await chunkGate.suspend()
                }
            })
        }

        guard await waitForDeadlineGate(chunkGate, operation: operation, clock: clock, label: "stream callback") else {
            return
        }
        guard await waitForDeadlineTimer(clock, operation: operation, gates: [chunkGate], label: "stream timer") else {
            return
        }
        clock.fireNext()
        await assertDeadlineExpired(operation, clock: clock, gates: [chunkGate], label: "session stream")

        let commands = try deadlineCommands(transport.outbound)
        XCTAssertEqual(commands.filter { $0 == SMB2Commands.close }.count, 1)
        let pendingCount = await session.pendingCountForTesting()
        let tombstoneCount = await session.cleanupTombstoneCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertEqual(tombstoneCount, 0, "the CLOSE response should be drained before the operation returns")
        XCTAssertEqual(ledgerCount, 0)
        XCTAssertEqual(transport.closeCount, 0, "a persistent session remains available after CLOSE succeeds")
        clock.reset()
        chunkGate.reset()

        let oneShotTransport = try makeResumeTransport(readBytes: Array("data".utf8), fileSize: 4)
        let oneShotClock = SMBDeadlineManualSleeper()
        let oneShotGate = SMBDeadlineAsyncGate()
        let previousFactory = SMBTransportTestOverride.factory
        SMBTransportTestOverride.factory = { oneShotTransport }
        defer { SMBTransportTestOverride.factory = previousFactory }
        let oneShotOperation = Task {
            try await SMBOperationDeadline.$sleeperForTesting.withValue(
                { try await oneShotClock.sleep(for: $0) },
                operation: {
                    try await SMBee.withReadStream(
                        host: "server",
                        credential: .anonymous,
                        share: "share",
                        path: "file.bin",
                        operationTimeout: .seconds(30),
                        onChunk: { _ in try await oneShotGate.suspend() }
                    )
                }
            )
        }
        guard await waitForDeadlineGate(oneShotGate, operation: oneShotOperation, clock: oneShotClock, label: "one-shot stream callback") else {
            return
        }
        guard await waitForDeadlineTimer(oneShotClock, operation: oneShotOperation, gates: [oneShotGate], label: "one-shot stream timer") else {
            return
        }
        oneShotClock.fireNext()
        await assertDeadlineExpired(oneShotOperation, clock: oneShotClock, gates: [oneShotGate], label: "one-shot stream")
        let oneShotCommands = try deadlineCommands(oneShotTransport.outbound)
        XCTAssertEqual(oneShotCommands.filter { $0 == SMB2Commands.close }.count, 1)
        XCTAssertEqual(oneShotTransport.closeCount, 1, "the one-shot transport closes only after handle cleanup")
        XCTAssertFalse(oneShotCommands.contains(SMB2Commands.treeDisconnect))
        oneShotClock.reset()
        oneShotGate.reset()
    }

    func testClientSessionDownloadDeadlineCleansTemporaryAfterClose() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-deadline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("download.bin")
        let fileId = deadlineFileId
        let transport = try makeDeadlineTransport([
            deadlineCreateResponse(fileId: fileId, messageId: 0),
            deadlineQueryInfoResponse(size: 4, messageId: 1),
            deadlineReadResponse(Array("data".utf8), messageId: 2),
            deadlineStatusResponse(command: SMB2Commands.close, messageId: 3)
        ])
        let session = SMBSession(host: "server", port: 445, credential: .anonymous, transport: transport)
        let client = SMBClientSession(session: session, treeId: deadlineTreeId)
        let clock = SMBDeadlineManualSleeper()
        let installGate = SMBDeadlineAsyncGate()
        let operation = Task {
            try await SMBDownloadTestSeams.$beforeDestinationInstall.withValue({ try await installGate.suspend() }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await clock.sleep(for: $0) }, operation: {
                    try await client.download(path: "file.bin", localFile: destination, operationTimeout: .seconds(30))
                })
            })
        }

        guard await waitForDeadlineGate(installGate, operation: operation, clock: clock, label: "download install") else {
            return
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        let stagedBeforeTimeout = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(stagedBeforeTimeout.count, 1, "the download should have a temporary file before install")
        guard await waitForDeadlineTimer(clock, operation: operation, gates: [installGate], label: "download timer") else {
            return
        }
        clock.fireNext()
        await assertDeadlineExpired(operation, clock: clock, gates: [installGate], label: "session download")

        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        XCTAssertEqual(try deadlineCommands(transport.outbound).filter { $0 == SMB2Commands.close }.count, 1)
        let pendingCount = await session.pendingCountForTesting()
        let tombstoneCount = await session.cleanupTombstoneCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertEqual(tombstoneCount, 0)
        XCTAssertEqual(ledgerCount, 0)
        XCTAssertEqual(transport.closeCount, 0)
        clock.reset()
        installGate.reset()
    }

    func testProviderOverloadsIncludeCredentialResolutionInDeadline() async throws {
        let streamClock = SMBDeadlineManualSleeper()
        let streamGate = SMBDeadlineAsyncGate()
        let streamTransportCount = SMBDeadlineCounter()
        let stream = Task {
            try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await streamClock.sleep(for: $0) }, operation: {
                try await SMBClient.withReadStream(
                    host: "server",
                    share: "share",
                    path: "file.bin",
                    credentialProvider: {
                        try await streamGate.suspend()
                        return .anonymous
                    },
                    operationTimeout: .seconds(30),
                    makeTransport: {
                        streamTransportCount.increment()
                        return SMBDeadlineTransport(inbound: [])
                    },
                    onChunk: { _ in }
                )
            })
        }
        guard await waitForDeadlineGate(streamGate, operation: stream, clock: streamClock, label: "stream provider") else {
            return
        }
        guard await waitForDeadlineTimer(streamClock, operation: stream, gates: [streamGate], label: "stream provider timer") else {
            return
        }
        streamClock.fireNext()
        await assertDeadlineExpired(stream, clock: streamClock, gates: [streamGate], label: "stream provider")
        XCTAssertEqual(streamTransportCount.value, 0)
        streamClock.reset()
        streamGate.reset()

        let downloadClock = SMBDeadlineManualSleeper()
        let downloadGate = SMBDeadlineAsyncGate()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-provider-\(UUID().uuidString)")
        let destination = directory.appendingPathComponent("download.bin")
        let download = Task {
            try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await downloadClock.sleep(for: $0) }, operation: {
                try await SMBee.download(
                    host: "server",
                    credentialProvider: {
                        try await downloadGate.suspend()
                        return .anonymous
                    },
                    share: "share",
                    path: "file.bin",
                    localFile: destination,
                    operationTimeout: .seconds(30)
                )
            })
        }
        guard await waitForDeadlineGate(downloadGate, operation: download, clock: downloadClock, label: "download provider") else {
            return
        }
        guard await waitForDeadlineTimer(downloadClock, operation: download, gates: [downloadGate], label: "download provider timer") else {
            return
        }
        downloadClock.fireNext()
        await assertDeadlineExpired(download, clock: downloadClock, gates: [downloadGate], label: "download provider")
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        downloadClock.reset()
        downloadGate.reset()
    }

    func testResumeDownloadCoversPrefixComparisonAndUsesTwoOneShotConnections() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-resume-deadline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let successfulDestination = directory.appendingPathComponent("complete.bin")
        try Data("hello ".utf8).write(to: successfulDestination)
        let successfulTransports = try [
            makeResumeTransport(readBytes: Array("hello ".utf8)),
            makeResumeTransport(readBytes: Array("world".utf8))
        ]
        let successfulFactory = SMBDeadlineTransportSequence(successfulTransports)
        let successfulClock = SMBDeadlineManualSleeper()
        let previousFactory = SMBTransportTestOverride.factory
        SMBTransportTestOverride.factory = { successfulFactory.make() }
        defer { SMBTransportTestOverride.factory = previousFactory }
        try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await successfulClock.sleep(for: $0) }, operation: {
            try await SMBee.download(
                host: "server",
                credential: .anonymous,
                share: "share",
                path: "remote.bin",
                localFile: successfulDestination,
                overwrite: false,
                resume: true,
                operationTimeout: .seconds(30)
            )
        })
        XCTAssertEqual(try Data(contentsOf: successfulDestination), Data("hello world".utf8))
        XCTAssertEqual(successfulFactory.makeCount, 2, "resume prefix validation and append use separate one-shot sessions")
        successfulClock.reset()

        let timedDestination = directory.appendingPathComponent("timed.bin")
        try Data("hello ".utf8).write(to: timedDestination)
        let prefixTransport = try makeResumeTransport(readBytes: Array("hello ".utf8))
        let unusedAppendTransport = try makeResumeTransport(readBytes: Array("world".utf8))
        let timedFactory = SMBDeadlineTransportSequence([prefixTransport, unusedAppendTransport])
        let clock = SMBDeadlineManualSleeper()
        let comparisonGate = SMBDeadlineAsyncGate()
        let operation = Task {
            try await SMBDownloadTestSeams.$beforeResumePrefixComparison.withValue({ try await comparisonGate.suspend() }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await clock.sleep(for: $0) }, operation: {
                    try await SMBClient.download(
                        host: "server",
                        share: "share",
                        path: "remote.bin",
                        localFile: timedDestination,
                        overwrite: false,
                        resume: true,
                        credential: .anonymous,
                        operationTimeout: .seconds(30),
                        makeTransport: { timedFactory.make() }
                    )
                })
            })
        }
        guard await waitForDeadlineGate(comparisonGate, operation: operation, clock: clock, label: "resume comparison") else {
            return
        }
        guard await waitForDeadlineTimer(clock, operation: operation, gates: [comparisonGate], label: "resume comparison timer") else {
            return
        }
        clock.fireNext()
        await assertDeadlineExpired(operation, clock: clock, gates: [comparisonGate], label: "resume validation")

        XCTAssertEqual(timedFactory.makeCount, 1, "the deadline should expire before the second one-shot connection")
        XCTAssertEqual(try Data(contentsOf: timedDestination), Data("hello ".utf8), "resume validation must not append before it succeeds")
        let firstConnectionCommands = try deadlineCommands(prefixTransport.outbound)
        XCTAssertEqual(
            Array(firstConnectionCommands.suffix(3)),
            [SMB2Commands.close, SMB2Commands.treeDisconnect, SMB2Commands.logoff],
            "CLOSE must finish before one-shot session teardown begins"
        )
        XCTAssertEqual(prefixTransport.closeCount, 1)
        clock.reset()
        comparisonGate.reset()
    }
}

private let deadlineTreeId: UInt32 = 0x3344
private let deadlineFileId = Array(UInt8(0x51)...UInt8(0x60))

private func makeDeadlineTransport(_ packets: [[UInt8]]) throws -> SMBDeadlineTransport {
    SMBDeadlineTransport(inbound: try SMBIssue102WireFixtures.framed(packets))
}

private func makeResumeTransport(readBytes: [UInt8], fileSize: UInt64 = 11) throws -> SMBDeadlineTransport {
    let sessionPackets = try SMBIssue102WireFixtures.anonymousSessionResponses()
    let fileOperations = [
        try deadlineCreateResponse(fileId: deadlineFileId, messageId: 4),
        try deadlineQueryInfoResponse(size: fileSize, messageId: 5),
        try deadlineReadResponse(readBytes, messageId: 6),
        try deadlineStatusResponse(command: SMB2Commands.close, messageId: 7, sessionId: 0x1122_3344_5566_7788),
        try deadlineStatusResponse(command: SMB2Commands.treeDisconnect, messageId: 8, sessionId: 0x1122_3344_5566_7788),
        try SMB2Header(command: SMB2Commands.logoff, messageId: 9, sessionId: 0x1122_3344_5566_7788).encode()
    ]
    return SMBDeadlineTransport(inbound: try SMBIssue102WireFixtures.framed(sessionPackets + fileOperations))
}

private func deadlineCreateResponse(fileId: [UInt8], messageId: UInt64) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.create, messageId: messageId, treeId: deadlineTreeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
    writeUInt16LE(89, to: &response, at: 64)
    response.replaceSubrange(128..<144, with: fileId)
    return response
}

private func deadlineQueryInfoResponse(size: UInt64, messageId: UInt64) throws -> [UInt8] {
    var payload = Array(repeating: UInt8(0), count: 56)
    writeUInt64LE(size, to: &payload, at: 40)
    var response = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: deadlineTreeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    writeUInt16LE(9, to: &response, at: 64)
    writeUInt16LE(72, to: &response, at: 66)
    writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
    response.append(contentsOf: payload)
    return response
}

private func deadlineReadResponse(_ payload: [UInt8], messageId: UInt64) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.read, messageId: messageId, treeId: deadlineTreeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
    writeUInt16LE(17, to: &response, at: 64)
    response[66] = 80
    writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
    response.append(contentsOf: payload)
    return response
}

private func deadlineStatusResponse(command: UInt16, messageId: UInt64, sessionId: UInt64 = 0) throws -> [UInt8] {
    try SMB2Header(
        command: command,
        messageId: messageId,
        treeId: command == SMB2Commands.logoff ? 0 : deadlineTreeId,
        sessionId: sessionId
    ).encode()
}

private func deadlineCommands(_ bytes: [UInt8]) throws -> [UInt16] {
    try deadlineUnframe(bytes).map { try SMB2Header.decode($0).command }
}

private func deadlineUnframe(_ bytes: [UInt8]) throws -> [[UInt8]] {
    var packets: [[UInt8]] = []
    var cursor = 0
    while cursor < bytes.count {
        let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<cursor + 4]))
        let start = cursor + 4
        let end = start + length
        packets.append(Array(bytes[start..<end]))
        cursor = end
    }
    return packets
}

private final class SMBDeadlineTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var outboundStorage: [UInt8] = []
    private var closeCountStorage = 0

    init(inbound: [UInt8]) {
        self.inbound = inbound
    }

    var outbound: [UInt8] { lock.withLock { outboundStorage } }
    var closeCount: Int { lock.withLock { closeCountStorage } }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        lock.withLock { outboundStorage.append(contentsOf: bytes) }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let bytes = lock.withLock { () -> [UInt8] in
            let count = min(maxLength, inbound.count)
            let result = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            return result
        }
        try Task.checkCancellation()
        return bytes
    }

    func close() {
        lock.withLock { closeCountStorage += 1 }
    }
}

private final class SMBDeadlineTransportSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [SMBDeadlineTransport]
    private var makeCountStorage = 0

    init(_ transports: [SMBDeadlineTransport]) {
        self.transports = transports
    }

    var makeCount: Int { lock.withLock { makeCountStorage } }

    func make() -> SMBTransport {
        lock.withLock {
            makeCountStorage += 1
            return transports.removeFirst()
        }
    }
}

private final class SMBDeadlineCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    var value: Int { lock.withLock { storage } }

    func increment() {
        lock.withLock { storage += 1 }
    }
}

private final class SMBDeadlineManualSleeper: @unchecked Sendable {
    private struct TimerWaiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var timers: [TimerWaiter] = []
    private var callCount = 0
    private let callsChanged = SMBDeadlineTestEvent()

    func sleep(for duration: Duration) async throws {
        _ = duration
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let cancelled = lock.withLock { () -> Bool in
                    guard !Task.isCancelled else { return true }
                    callCount += 1
                    timers.append(TimerWaiter(id: id, continuation: continuation))
                    return false
                }
                if cancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    callsChanged.signal()
                }
            }
        } onCancel: {
            self.cancelTimer(id: id)
        }
    }

    func waitForCallCount(_ target: Int) async throws {
        try await callsChanged.wait(until: target)
    }

    func fireNext() {
        let waiter = lock.withLock { timers.isEmpty ? nil : timers.removeFirst() }
        waiter?.continuation.resume()
    }

    func reset() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            let pending = timers.map(\.continuation)
            timers.removeAll()
            callCount = 0
            return pending
        }
        pending.forEach { $0.resume(throwing: CancellationError()) }
        callsChanged.reset()
    }

    private func cancelTimer(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = timers.firstIndex(where: { $0.id == id }) else { return nil }
            return timers.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class SMBDeadlineAsyncGate: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var waiters: [Waiter] = []
    private var released = false
    private let entered = SMBDeadlineTestEvent()

    func suspend() async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let resumeNow = lock.withLock { () -> Bool in
                    guard !released else { return true }
                    waiters.append(Waiter(id: id, continuation: continuation))
                    return false
                }
                entered.signal()
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            self.cancelWaiter(id: id)
        }
    }

    func waitUntilEntered() async throws {
        try await entered.wait(until: 1)
    }

    func release() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            released = true
            let pending = waiters.map(\.continuation)
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume() }
    }

    func reset() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            released = false
            let pending = waiters.map(\.continuation)
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume(throwing: CancellationError()) }
        entered.reset()
    }

    private func cancelWaiter(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class SMBDeadlineTestEvent: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var count = 0
    private var waiters: [Waiter] = []

    func signal() {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            count += 1
            let ready = waiters.filter { count >= $0.target }.map(\.continuation)
            waiters.removeAll { count >= $0.target }
            return ready
        }
        ready.forEach { $0.resume() }
    }

    func wait(until target: Int) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> Int in
                    guard !Task.isCancelled else { return -1 }
                    guard count < target else { return 1 }
                    waiters.append(Waiter(id: id, target: target, continuation: continuation))
                    return 0
                }
                if state < 0 { continuation.resume(throwing: CancellationError()) }
                if state > 0 { continuation.resume() }
            }
        } onCancel: {
            self.cancelWaiter(id: id)
        }
    }

    func reset() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            count = 0
            let pending = waiters.map(\.continuation)
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume(throwing: CancellationError()) }
    }

    private func cancelWaiter(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private struct SMBDeadlineHangGuardError: Error, CustomStringConvertible {
    let label: String
    var description: String { "Test event did not arrive: \(label)" }
}

private final class SMBDeadlineResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    private var result: Result<T, Error>?
    private var completed = false

    func install(_ continuation: CheckedContinuation<T, Error>) {
        let result = lock.withLock { () -> Result<T, Error>? in
            if completed, let result {
                self.result = nil
                return result
            }
            self.continuation = continuation
            return nil
        }
        if let result { continuation.resume(with: result) }
    }

    func resume(_ result: Result<T, Error>) {
        let continuation = lock.withLock { () -> CheckedContinuation<T, Error>? in
            guard !completed else { return nil }
            completed = true
            if let continuation = self.continuation {
                self.continuation = nil
                return continuation
            }
            self.result = result
            return nil
        }
        continuation?.resume(with: result)
    }
}

private func awaitWithDeadlineHangGuard<T: Sendable>(
    _ label: String,
    timeout: Duration = .seconds(3),
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let box = SMBDeadlineResumeOnce<T>()
    let operationTask = Task {
        do {
            box.resume(.success(try await operation()))
        } catch {
            box.resume(.failure(error))
        }
    }
    let guardTask = Task {
        try? await Task.sleep(for: timeout)
        operationTask.cancel()
        box.resume(.failure(SMBDeadlineHangGuardError(label: label)))
    }
    do {
        let value = try await withCheckedThrowingContinuation { continuation in
            box.install(continuation)
        }
        guardTask.cancel()
        await guardTask.value
        return value
    } catch {
        guardTask.cancel()
        await guardTask.value
        throw error
    }
}

private func waitForDeadlineGate(
    _ gate: SMBDeadlineAsyncGate,
    operation: Task<Void, Error>,
    clock: SMBDeadlineManualSleeper,
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) event") { try await gate.waitUntilEntered() }
        return true
    } catch {
        await failAndDrainDeadlineOperation(operation, gates: [gate], clock: clock, label: label, error: error)
        return false
    }
}

private func waitForDeadlineTimer(
    _ clock: SMBDeadlineManualSleeper,
    operation: Task<Void, Error>,
    gates: [SMBDeadlineAsyncGate],
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) registration") { try await clock.waitForCallCount(1) }
        return true
    } catch {
        await failAndDrainDeadlineOperation(operation, gates: gates, clock: clock, label: label, error: error)
        return false
    }
}

private func assertDeadlineExpired(
    _ operation: Task<Void, Error>,
    clock: SMBDeadlineManualSleeper,
    gates: [SMBDeadlineAsyncGate],
    label: String
) async {
    do {
        try await awaitWithDeadlineHangGuard("\(label) completion") { try await operation.value }
        XCTFail("\(label) unexpectedly completed")
    } catch SMBTransportError.timedOut {
        return
    } catch {
        await failAndDrainDeadlineOperation(operation, gates: gates, clock: clock, label: label, error: error)
        XCTFail("\(label) returned the wrong error: \(error)")
    }
}

private func failAndDrainDeadlineOperation(
    _ operation: Task<Void, Error>,
    gates: [SMBDeadlineAsyncGate],
    clock: SMBDeadlineManualSleeper,
    label: String,
    error: Error
) async {
    XCTFail("\(label): \(error)")
    operation.cancel()
    gates.forEach { $0.release() }
    clock.reset()
    _ = try? await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
    gates.forEach { $0.reset() }
}
