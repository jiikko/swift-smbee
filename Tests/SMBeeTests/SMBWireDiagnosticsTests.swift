import XCTest
@testable import SMBee

final class SMBWireDiagnosticsTests: XCTestCase {
    func testCreditWindowLogsActualWaitAndGrant() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "credit-test")

        let reserve = Task {
            try await window.reserve(charge: 2, messageId: 42, command: SMB2Commands.read)
        }
        while await window.pendingWaiterCount == 0 {
            await Task.yield()
        }

        let waits = capture.messages.filter { $0.hasPrefix("[wire] credit_wait ") }
        XCTAssertEqual(waits.count, 1)
        XCTAssertTrue(waits[0].contains(
            "session=credit-test message_id=42 command=8 charge=2 available=0 waiters=1"
        ))
        XCTAssertNotNil(Self.uint64Field("ts_ns", in: waits[0]))
        _ = await window.grant(2)
        _ = try await reserve.value

        let grants = capture.messages.filter {
            $0.hasPrefix(
                "[wire] credit_granted session=credit-test message_id=42 command=8 charge=2 waited_ms="
            )
        }
        XCTAssertEqual(grants.count, 1)
        XCTAssertNotNil(Self.doubleField("waited_ms", in: grants[0]))
        XCTAssertNotNil(Self.uint64Field("ts_ns", in: grants[0]))
    }

    func testCreditWindowPreservesFIFOHeadOfLineBlocking() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "hol-test")

        let large = Task {
            try await window.reserve(
                charge: 16,
                messageId: 100,
                command: SMB2Commands.read
            )
        }
        defer { large.cancel() }
        try await Self.waitForWaiterCount(1, in: window)

        var small: [Task<UInt32, Error>] = []
        defer { small.forEach { $0.cancel() } }
        for messageId in UInt64(101)...UInt64(104) {
            small.append(Task {
                try await window.reserve(
                    charge: 1,
                    messageId: messageId,
                    command: SMB2Commands.read
                )
            })
            try await Self.waitForWaiterCount(Int(messageId - 99), in: window)
        }

        let partialBalance = await window.grant(1)
        let waitersAfterPartialGrant = await window.pendingWaiterCount
        let balanceAfterPartialGrant = await window.balance
        XCTAssertEqual(partialBalance, 1)
        XCTAssertEqual(waitersAfterPartialGrant, 5)
        XCTAssertEqual(balanceAfterPartialGrant, 1)

        let headBalance = await window.grant(15)
        let waitersAfterHeadGrant = await window.pendingWaiterCount
        let largeBalance = try await awaitWithTimeout("large HoL waiter released") {
            try await large.value
        }
        XCTAssertEqual(headBalance, 0)
        XCTAssertEqual(waitersAfterHeadGrant, 4)
        XCTAssertEqual(largeBalance, 0)

        let finalBalance = await window.grant(4)
        let finalWaiterCount = await window.pendingWaiterCount
        XCTAssertEqual(finalBalance, 0)
        XCTAssertEqual(finalWaiterCount, 0)
        var smallBalances: [UInt32] = []
        for (index, task) in small.enumerated() {
            smallBalances.append(try await awaitWithTimeout("small waiter \(index) released") {
                try await task.value
            })
        }
        XCTAssertEqual(smallBalances, [3, 2, 1, 0])

        let grantedMessageIds = capture.messages
            .filter { $0.hasPrefix("[wire] credit_granted ") }
            .compactMap { Self.uint64Field("message_id", in: $0) }
        XCTAssertEqual(grantedMessageIds, [100, 101, 102, 103, 104])
    }

    func testCreditWindowDoesNotLogWhenReserveDoesNotWait() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let window = SMB2CreditWindow(initialCredits: 2, diagnosticSessionId: "credit-test")

        _ = try await window.reserve(charge: 2)

        XCTAssertFalse(capture.messages.contains {
            $0.hasPrefix("[wire] credit_wait ") || $0.hasPrefix("[wire] credit_granted ")
        })
    }

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

    func testWireEventsCarryDistinctSessionIdentifiers() async {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let firstSession = SMBSession(
            host: "test", port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        let secondSession = SMBSession(
            host: "test", port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )

        await firstSession.failWireForTesting(error: SMBTransportError.timedOut)
        await secondSession.failWireForTesting(error: SMBTransportError.timedOut)

        let wireEvents = capture.messages.filter { $0.hasPrefix("[wire] ") }
        XCTAssertFalse(wireEvents.isEmpty)
        XCTAssertTrue(wireEvents.allSatisfy { event in
            event.split(separator: " ").dropFirst(2).first?.hasPrefix("session=") == true
        })
        let sessionIds = wireEvents.compactMap { event in
            event.split(separator: " ").first { $0.hasPrefix("session=") }
        }
        XCTAssertEqual(Set(sessionIds).count, 2)
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

        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] close_transport session=") && $0.contains("cause=unit_test")
        })
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] victim session=") && $0.contains("count=2")
        })
    }

    func testRequestAfterWireFailureTearsDownTransportBeforeThrowing() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let session = SMBSession(
            host: "test", port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        // The receive side can declare the wire dead without closing the transport yet
        // (issue 077 review: the pre-registration fast path must not skip teardown).
        await session.failWireForTesting(error: SMBTransportError.timedOut)

        do {
            try await awaitWithTimeout("ECHO after wire failure") { try await session.echo() }
            XCTFail("ECHO unexpectedly completed after wire failure")
        } catch SMBTransportError.timedOut {
        }
        let pendingCount = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] close_transport session=") &&
                $0.contains("cause=request_after_wire_failure")
        })
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
            $0.contains("[wire] close_transport session=") && $0.contains("cause=best_effort_close")
        })
    }

    func testBestEffortCloseTimeoutFailsWireReadsAndCreditWaiter() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }

        let transport = CommandAwareCloseTimeoutTransport()
        defer { transport.close() }
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeout: .seconds(2)
        )

        try await awaitWithTimeout("echo round trip") {
            try await session.echo()
        }
        let balanceAfterEcho = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterEcho, 4)

        let victimFileId = [UInt8](repeating: 1, count: 16)
        let closeFileId = [UInt8](repeating: 2, count: 16)
        let firstRead = Task {
            try await session.readChunk(treeId: 1, fileId: victimFileId, offset: 0, length: 1)
        }
        defer { firstRead.cancel() }
        let secondRead = Task {
            try await session.readChunk(treeId: 1, fileId: victimFileId, offset: 1, length: 1)
        }
        defer { secondRead.cancel() }
        let writeChunk = Task {
            try await session.write(treeId: 1, fileId: victimFileId, data: [0xa5])
        }
        defer { writeChunk.cancel() }
        try await awaitWithTimeout("two READ requests sent") {
            try await transport.waitUntilSent(command: SMB2Commands.read, count: 2)
        }
        try await awaitWithTimeout("WRITE request sent") {
            try await transport.waitUntilSent(command: SMB2Commands.write, count: 1)
        }
        try await awaitWithTimeout("READ and WRITE responses pending") {
            while await session.pendingCountForTesting() < 3 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let pendingWireVictims = await session.pendingCountForTesting()
        XCTAssertGreaterThanOrEqual(pendingWireVictims, 3)
        let balanceAfterWireVictims = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterWireVictims, 1)

        let creditWaiter = Task {
            try await session.parkCreditWaiterForTesting(charge: 2)
        }
        defer { creditWaiter.cancel() }
        try await awaitWithTimeout("credit waiter parked") {
            while await session.creditWaiterCountForTesting() < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }

        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: closeFileId)
        }
        defer { closeTask.cancel() }
        try await awaitWithTimeout("CLOSE request sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        let exhaustedBalance = await session.creditBalanceForTesting()
        XCTAssertEqual(exhaustedBalance, 0)

        let queryDirectoryWaiter = Task {
            try await session.queryDirectory(treeId: 1, fileId: victimFileId)
        }
        defer { queryDirectoryWaiter.cancel() }
        try await awaitWithTimeout("QUERY_DIRECTORY credit waiter parked") {
            while await session.creditWaiterCountForTesting() < 2 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] credit_wait session=") &&
                $0.contains("charge=1 available=0 waiters=2")
        })

        try await awaitWithTimeout("best-effort CLOSE timeout", timeout: .seconds(4)) {
            await closeTask.value
        }

        do {
            _ = try await awaitWithTimeout("first READ close victim") { try await firstRead.value }
            XCTFail("first READ unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("second READ close victim") { try await secondRead.value }
            XCTFail("second READ unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await awaitWithTimeout("WRITE close victim") { try await writeChunk.value }
            XCTFail("WRITE unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("credit waiter close victim") { try await creditWaiter.value }
            XCTFail("credit waiter unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("QUERY_DIRECTORY close victim") {
                try await queryDirectoryWaiter.value
            }
            XCTFail("QUERY_DIRECTORY unexpectedly completed")
        } catch SMBTransportError.connectionClosed {
        }

        let finalPendingCount = await session.pendingCountForTesting()
        let finalCreditWaiterCount = await session.creditWaiterCountForTesting()
        XCTAssertEqual(finalPendingCount, 0)
        XCTAssertEqual(finalCreditWaiterCount, 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.close), 1)
        XCTAssertEqual(transport.commandCount(SMB2Commands.queryDirectory), 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.read), 2)
        XCTAssertEqual(transport.commandCount(SMB2Commands.write), 1)
        let wireVictimCommands: Set<UInt16> = [SMB2Commands.read, SMB2Commands.write]
        XCTAssertEqual(transport.heldResponseCount(for: wireVictimCommands), 3)
        XCTAssertEqual(transport.deliveredResponseCount(for: wireVictimCommands), 0)
        XCTAssertEqual(transport.closeCallCount, 1)
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] cleanup_close_failed") && $0.contains("timeout=true")
        })
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] close_transport session=") && $0.contains("cause=best_effort_close")
        })
    }

    private static func waitForWaiterCount(
        _ expectedCount: Int,
        in window: SMB2CreditWindow
    ) async throws {
        try await awaitWithTimeout("credit waiter count \(expectedCount)") {
            while await window.pendingWaiterCount != expectedCount {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
    }

    private static func uint64Field(_ name: String, in message: String) -> UInt64? {
        field(name, in: message).flatMap(UInt64.init)
    }

    private static func doubleField(_ name: String, in message: String) -> Double? {
        field(name, in: message).flatMap(Double.init)
    }

    private static func field(_ name: String, in message: String) -> String? {
        let prefix = "\(name)="
        return message.split(separator: " ")
            .first { $0.hasPrefix(prefix) }
            .map { String($0.dropFirst(prefix.count)) }
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

private final class CommandAwareCloseTimeoutTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private struct SentWaiter {
        let id: UInt64
        let command: UInt16
        let count: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var inbound: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var commandStorage: [UInt16] = []
    private var heldResponses: [(command: UInt16, frame: [UInt8])] = []
    private var deliveredResponseCommands: [UInt16] = []
    private var sentWaiters: [SentWaiter] = []
    private var nextWaiterId: UInt64 = 0
    private var isClosed = false
    private var closeCallCountStorage = 0

    func heldResponseCount(for commands: Set<UInt16>) -> Int {
        lock.withLock { heldResponses.filter { commands.contains($0.command) }.count }
    }

    func deliveredResponseCount(for commands: Set<UInt16>) -> Int {
        lock.withLock { deliveredResponseCommands.filter { commands.contains($0) }.count }
    }

    var closeCallCount: Int {
        lock.withLock { closeCallCountStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let header = try SMB2Header.decode(Array(bytes.dropFirst(4)))
        let deliveredResponse: [UInt8]?
        let heldResponse: [UInt8]?
        if header.command == SMB2Commands.echo {
            var packet = try SMB2Header(
                command: SMB2Commands.echo,
                credits: 1,
                messageId: header.messageId,
                treeId: header.treeId,
                sessionId: header.sessionId
            ).encode()
            packet.append(contentsOf: [4, 0, 0, 0])
            deliveredResponse = try DirectTCPFraming.frame(packet)
            heldResponse = nil
        } else if header.command == SMB2Commands.read {
            var packet = try SMB2Header(
                command: SMB2Commands.read,
                credits: 1,
                messageId: header.messageId,
                treeId: header.treeId,
                sessionId: header.sessionId
            ).encode()
            packet.append(contentsOf: Array(repeating: UInt8(0), count: 16))
            packet[64] = 17
            packet[65] = 0
            packet[66] = 80
            packet[68] = 1
            packet.append(0)
            deliveredResponse = nil
            heldResponse = try DirectTCPFraming.frame(packet)
        } else if header.command == SMB2Commands.write {
            var packet = try SMB2Header(
                command: SMB2Commands.write,
                credits: 1,
                messageId: header.messageId,
                treeId: header.treeId,
                sessionId: header.sessionId
            ).encode()
            packet.append(contentsOf: Array(repeating: UInt8(0), count: 16))
            packet[64] = 17
            packet[68] = 1
            deliveredResponse = nil
            heldResponse = try DirectTCPFraming.frame(packet)
        } else {
            deliveredResponse = nil
            heldResponse = nil
        }

        let state = lock.withLock { () -> (sent: Bool, waiters: [SentWaiter], receive: (PendingReceive, [UInt8])?) in
            guard !isClosed else { return (false, [], nil) }
            commandStorage.append(header.command)
            if let deliveredResponse {
                inbound.append(contentsOf: deliveredResponse)
                deliveredResponseCommands.append(header.command)
            }
            if let heldResponse {
                heldResponses.append((command: header.command, frame: heldResponse))
            }
            return (true, removeReadySentWaitersLocked(), takeReceiveDeliveryLocked())
        }
        guard state.sent else { throw SMBTransportError.connectionClosed }

        for waiter in state.waiters {
            waiter.continuation.resume()
        }
        if let (pending, chunk) = state.receive {
            pending.continuation.resume(returning: chunk)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<[UInt8], Error>?
                lock.lock()
                if isClosed {
                    immediate = .failure(SMBTransportError.connectionClosed)
                } else if Task.isCancelled {
                    immediate = .failure(CancellationError())
                } else if inbound.isEmpty {
                    pendingReceive = PendingReceive(maxLength: maxLength, continuation: continuation)
                    immediate = nil
                } else {
                    let count = min(maxLength, inbound.count)
                    let chunk = Array(inbound.prefix(count))
                    inbound.removeFirst(count)
                    immediate = .success(chunk)
                }
                lock.unlock()
                if let immediate {
                    continuation.resume(with: immediate)
                }
            }
        } onCancel: {
            self.cancelPendingReceive()
        }
    }

    func close() {
        let receive: PendingReceive?
        let waiters: [SentWaiter]
        lock.lock()
        closeCallCountStorage += 1
        guard !isClosed else {
            lock.unlock()
            return
        }
        isClosed = true
        receive = pendingReceive
        pendingReceive = nil
        waiters = sentWaiters
        sentWaiters.removeAll()
        lock.unlock()

        receive?.continuation.resume(throwing: SMBTransportError.connectionClosed)
        for waiter in waiters {
            waiter.continuation.resume(throwing: SMBTransportError.connectionClosed)
        }
    }

    func waitUntilSent(command: UInt16, count: Int) async throws {
        let waiterId = lock.withLock { () -> UInt64 in
            defer { nextWaiterId += 1 }
            return nextWaiterId
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<Void, Error>?
                lock.lock()
                if commandStorage.filter({ $0 == command }).count >= count {
                    immediate = .success(())
                } else if isClosed {
                    immediate = .failure(SMBTransportError.connectionClosed)
                } else if Task.isCancelled {
                    immediate = .failure(CancellationError())
                } else {
                    sentWaiters.append(SentWaiter(
                        id: waiterId,
                        command: command,
                        count: count,
                        continuation: continuation
                    ))
                    immediate = nil
                }
                lock.unlock()
                if let immediate {
                    continuation.resume(with: immediate)
                }
            }
        } onCancel: {
            self.cancelSentWaiter(id: waiterId)
        }
    }

    func commandCount(_ command: UInt16) -> Int {
        lock.withLock { commandStorage.filter { $0 == command }.count }
    }

    private func removeReadySentWaitersLocked() -> [SentWaiter] {
        var ready: [SentWaiter] = []
        sentWaiters.removeAll { waiter in
            if commandStorage.filter({ $0 == waiter.command }).count >= waiter.count {
                ready.append(waiter)
                return true
            }
            return false
        }
        return ready
    }

    private func takeReceiveDeliveryLocked() -> (PendingReceive, [UInt8])? {
        guard let pendingReceive, !inbound.isEmpty else { return nil }
        let count = min(pendingReceive.maxLength, inbound.count)
        let chunk = Array(inbound.prefix(count))
        inbound.removeFirst(count)
        self.pendingReceive = nil
        return (pendingReceive, chunk)
    }

    private func cancelPendingReceive() {
        let receive = lock.withLock { () -> PendingReceive? in
            defer { pendingReceive = nil }
            return pendingReceive
        }
        receive?.continuation.resume(throwing: CancellationError())
    }

    private func cancelSentWaiter(id: UInt64) {
        let waiter = lock.withLock { () -> SentWaiter? in
            guard let index = sentWaiters.firstIndex(where: { $0.id == id }) else { return nil }
            return sentWaiters.remove(at: index)
        }
        waiter?.continuation.resume(throwing: CancellationError())
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
    timeout: Duration = .seconds(2),
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
        try? await Task.sleep(for: timeout)
        operationTask.cancel()
        box.resume(.failure(SMBWireDiagnosticsTimeout(label: label)))
    }
    defer { timeoutTask.cancel() }
    return try await withCheckedThrowingContinuation { continuation in
        box.install(continuation)
    }
}
