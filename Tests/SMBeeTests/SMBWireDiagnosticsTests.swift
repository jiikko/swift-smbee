import XCTest
@testable import SMBee

final class SMBWireDiagnosticsTests: XCTestCase {
    func testTestingWaitersReleaseOnCancellationAndTerminalTransitions() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: CommandAwareCloseTimeoutTransport(),
            initialCredits: 1
        )
        let cancelledSessionWaiter = Task {
            await session.waitForPendingCountForTesting(atLeast: Int.max)
        }
        try await awaitWithTimeout("session cancellation waiter registered") {
            while await session.testingCountWaiterCountForTesting() != 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        cancelledSessionWaiter.cancel()
        try await awaitWithTimeout("cancelled session observer released") {
            await cancelledSessionWaiter.value
        }
        let sessionWaiterCountAfterCancel = await session.testingCountWaiterCountForTesting()
        XCTAssertEqual(sessionWaiterCountAfterCancel, 0)

        let sessionWaiters = [
            Task { await session.waitForPendingCountForTesting(atLeast: Int.max) },
            Task { await session.waitForRequestSentCountForTesting(atLeast: Int.max) },
            Task { await session.waitForRequestSentWaiterRegistrationCountForTesting(atLeast: Int.max) },
            Task { await session.waitForCleanupLedgerCountForTesting(Int.max) },
            Task { await session.waitForReceivedPacketDispatchCountForTesting(atLeast: Int.max) }
        ]
        try await awaitWithTimeout("session observers registered") {
            while await session.testingCountWaiterCountForTesting() != sessionWaiters.count {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        await session.closeTransport(cause: "test_waiter_teardown")
        for waiter in sessionWaiters {
            try await awaitWithTimeout("session observer released by close") {
                await waiter.value
            }
        }
        let sessionWaiterCountAfterClose = await session.testingCountWaiterCountForTesting()
        XCTAssertEqual(sessionWaiterCountAfterClose, 0)

        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "waiter-test")
        let cancelledCreditObserver = Task {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }
        try await awaitWithTimeout("credit cancellation observer registered") {
            while await window.pendingWaiterCountObserverCountForTesting != 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        cancelledCreditObserver.cancel()
        try await awaitWithTimeout("cancelled credit observer released") {
            await cancelledCreditObserver.value
        }
        let observerCountAfterCancel = await window.pendingWaiterCountObserverCountForTesting
        XCTAssertEqual(observerCountAfterCancel, 0)

        let resetObserver = Task { await window.waitForPendingWaiterCount(atLeast: 1) }
        try await awaitWithTimeout("reset observer registered") {
            while await window.pendingWaiterCountObserverCountForTesting != 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        await window.reset(initialCredits: 0)
        try await awaitWithTimeout("credit observer released by reset") { await resetObserver.value }
        let observerCountAfterReset = await window.pendingWaiterCountObserverCountForTesting
        XCTAssertEqual(observerCountAfterReset, 0)

        let failedObserver = Task { await window.waitForPendingWaiterCount(atLeast: 1) }
        try await awaitWithTimeout("failure observer registered") {
            while await window.pendingWaiterCountObserverCountForTesting != 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        await window.failAllWaiters(SMBTransportError.connectionClosed)
        try await awaitWithTimeout("credit observer released by failure") { await failedObserver.value }
        let observerCountAfterFailure = await window.pendingWaiterCountObserverCountForTesting
        XCTAssertEqual(observerCountAfterFailure, 0)
    }

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
        try await awaitWithTimeout("credit waiter parked") {
            await window.waitForPendingWaiterCount(atLeast: 1)
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

    func testCloseCauseAndVictimSnapshotAreLogged() async throws {
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
        try await awaitWithTimeout("two pending records registered") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }
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

    func testBestEffortCloseTimeoutLeavesUnrelatedPendingOperationsAliveUntilWireClose() async throws {
        // This used to pin the issue 065 contract that the first cleanup deadline tears
        // down the whole session. The 069 contract keeps these unrelated requests live.
        let clock = ManualSMBSleeper()
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
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let first = Task { try await session.parkPendingForTesting(messageId: 1, command: 8) }
        let second = Task { try await session.parkPendingForTesting(messageId: 2, command: 9) }
        try await awaitWithTimeout("pending records registered") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }

        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 1, count: 16)) }
        try await awaitWithTimeout("CLOSE send") { await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("cleanup timeout returns") { await closeTask.value }
        XCTAssertTrue(transport.commands.contains(SMB2Commands.close))
        XCTAssertEqual(transport.closeCallCount, 0)
        let pendingAfterTimeout = await session.pendingCountForTesting()
        let tombstonesAfterTimeout = await session.cleanupTombstoneCountForTesting()
        let ledgerAfterTimeout = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingAfterTimeout, 2)
        XCTAssertEqual(tombstonesAfterTimeout, 1)
        XCTAssertEqual(ledgerAfterTimeout, 1)
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] cleanup_close_failed") && $0.contains("timeout=true")
        })

        // The former invariant explicitly failed these waiters at cleanup timeout. They now
        // remain pending until a real wire fault or explicit session close occurs.
        await session.closeTransport(cause: "test_cleanup")
        do {
            _ = try await awaitWithTimeout("first pending close victim") { try await first.value }
            XCTFail("first pending operation should fail after explicit transport close")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("second pending close victim") { try await second.value }
            XCTFail("second pending operation should fail after explicit transport close")
        } catch SMBTransportError.connectionClosed {
        }
        let pendingCountAfterClose = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCountAfterClose, 0)
    }

    func testBestEffortCloseTimeoutAllowsReadToDrainAndClearsLedger() async throws {
        // The old test verified that a CLOSE timeout failed READ/WRITE requests and credit
        // waiters. Keep the coverage target while fixing the new behavior: late responses drain.
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 3,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_cleanup_late_close") } }
        let read = Task { try await session.readChunk(treeId: 1, fileId: [UInt8](repeating: 1, count: 16), offset: 0, length: 1) }
        try await awaitWithTimeout("READ sent") { try await transport.waitUntilSent(SMB2Commands.read, count: 1) }
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 2, count: 16))
        }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("best-effort CLOSE timeout returns") { await closeTask.value }

        XCTAssertEqual(transport.closeCallCount, 0)
        let pendingAfterTimeout = await session.pendingCountForTesting()
        let tombstonesAfterTimeout = await session.cleanupTombstoneCountForTesting()
        let cleanupState = await session.cleanupAttemptStateForTesting(fileId: [UInt8](repeating: 2, count: 16))
        XCTAssertEqual(pendingAfterTimeout, 1)
        XCTAssertEqual(tombstonesAfterTimeout, 1)
        XCTAssertTrue(cleanupState?.hasPrefix("draining:") == true)

        transport.releaseNextResponse(command: SMB2Commands.read)
        transport.releaseNextResponse(command: SMB2Commands.close)
        let readBytes = try await awaitWithTimeout("late READ response") { try await read.value }
        XCTAssertEqual(readBytes, [0])
        try await awaitWithTimeout("cleanup ledger drained") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        let finalWirePendingCount = await session.wirePendingRecordCountForTesting()
        let orphanCount = await session.orphanResponseCountForTesting()
        XCTAssertEqual(finalWirePendingCount, 0)
        XCTAssertEqual(orphanCount, 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.close), 1)
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testDrainingCleanupRejectsReadUsingSameFileId() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport(heldCommands: [SMB2Commands.close])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_draining_file_id_admission") } }
        let fileId = [UInt8](repeating: 0x2a, count: 16)
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("cleanup caller timeout") { await closeTask.value }
        let cleanupState = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertTrue(cleanupState?.hasPrefix("draining:") == true)

        do {
            _ = try await awaitWithTimeout("same FileId READ admission") {
                try await session.readChunk(treeId: 1, fileId: fileId, offset: 0, length: 1)
            }
            XCTFail("READ reused a FileId while its CLOSE response was unresolved")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unresolved after CLOSE"))
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.read), 0)
        XCTAssertEqual(transport.closeCallCount, 0)

        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("late CLOSE resolves ledger") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testCleanupTimeoutPreservesReadsWriteAndParkedQueryUntilWireFault() async throws {
        let clock = ManualSMBSleeper()
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let transport = CommandAwareCloseTimeoutTransport(
            heldCommands: [SMB2Commands.read, SMB2Commands.write, SMB2Commands.close]
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_close_timeout_preserves_operations") } }
        let victimFileId = [UInt8](repeating: 0x31, count: 16)
        let closeFileId = [UInt8](repeating: 0x32, count: 16)
        let firstRead = Task {
            try await session.readChunk(treeId: 1, fileId: victimFileId, offset: 0, length: 1)
        }
        let secondRead = Task {
            try await session.readChunk(treeId: 1, fileId: victimFileId, offset: 1, length: 1)
        }
        let write = Task {
            try await session.write(treeId: 1, fileId: victimFileId, data: [0xa5])
        }
        try await awaitWithTimeout("two READ requests sent") {
            try await transport.waitUntilSent(command: SMB2Commands.read, count: 2)
        }
        try await awaitWithTimeout("WRITE request sent") {
            try await transport.waitUntilSent(command: SMB2Commands.write, count: 1)
        }
        try await Self.waitForRequestSentCount(3, in: session)
        try await awaitWithTimeout("three READ and WRITE records registered") {
            await session.waitForPendingCountForTesting(atLeast: 3)
        }

        let sentBeforeClose = await session.requestSentCountForTesting()
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: closeFileId) }
        try await awaitWithTimeout("CLOSE request sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(sentBeforeClose + 1, in: session)
        try await awaitWithTimeout("CLOSE receive loop blocked") {
            await transport.waitUntilReceiveIsBlocked()
        }
        let creditWaiter = Task { try await session.parkCreditWaiterForTesting(charge: 2) }
        try await awaitWithTimeout("first credit waiter parked") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        let queryDirectory = Task {
            try await session.queryDirectory(treeId: 1, fileId: victimFileId) { _ in }
        }
        try await awaitWithTimeout("QUERY_DIRECTORY credit waiter parked") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 2)
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.queryDirectory), 0)
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] credit_wait session=") &&
                $0.contains("command=14 charge=1 available=0 waiters=2")
        })

        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("cleanup timeout returns") { await closeTask.value }
        XCTAssertEqual(transport.closeCallCount, 0)
        let tombstoneCountDuringDrain = await session.cleanupTombstoneCountForTesting()
        let pendingCountDuringDrain = await session.pendingCountForTesting()
        let creditWaiterCountDuringDrain = await session.creditWaiterCountForTesting()
        XCTAssertEqual(tombstoneCountDuringDrain, 1)
        XCTAssertEqual(pendingCountDuringDrain, 4)
        XCTAssertEqual(creditWaiterCountDuringDrain, 2)
        XCTAssertEqual(transport.commandCount(SMB2Commands.queryDirectory), 0)
        XCTAssertTrue(capture.messages.contains {
            $0.contains("[wire] cleanup_close_failed") && $0.contains("timeout=true")
        })

        transport.failReceive(with: SMBTransportError.connectionClosed)
        do {
            _ = try await awaitWithTimeout("first READ fails on wire fault") { try await firstRead.value }
            XCTFail("first READ should fail after the receive loop dies")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("second READ fails on wire fault") { try await secondRead.value }
            XCTFail("second READ should fail after the receive loop dies")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await awaitWithTimeout("WRITE fails on wire fault") { try await write.value }
            XCTFail("WRITE should fail after the receive loop dies")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("credit waiter fails on wire fault") { try await creditWaiter.value }
            XCTFail("credit waiter should fail after the receive loop dies")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await awaitWithTimeout("QUERY_DIRECTORY fails on wire fault") { try await queryDirectory.value }
            XCTFail("QUERY_DIRECTORY should fail after the receive loop dies")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.read), 2)
        XCTAssertEqual(transport.commandCount(SMB2Commands.write), 1)
        XCTAssertEqual(transport.commandCount(SMB2Commands.close), 1)
        XCTAssertEqual(transport.commandCount(SMB2Commands.queryDirectory), 0)
        XCTAssertEqual(transport.heldResponseCount(for: [SMB2Commands.read, SMB2Commands.write]), 3)
        XCTAssertEqual(transport.closeCallCount, 1)
        let pendingCountAfterWireFault = await session.pendingCountForTesting()
        let creditWaiterCountAfterWireFault = await session.creditWaiterCountForTesting()
        XCTAssertEqual(pendingCountAfterWireFault, 0)
        XCTAssertEqual(creditWaiterCountAfterWireFault, 0)
    }

    func testBestEffortCloseTimeoutThenReceiveFailureClosesAllWaitersOnce() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let read = Task { try await session.readChunk(treeId: 1, fileId: [UInt8](repeating: 1, count: 16), offset: 0, length: 1) }
        try await awaitWithTimeout("READ sent") { try await transport.waitUntilSent(SMB2Commands.read, count: 1) }
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 2, count: 16))
        }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        let creditWaiter = Task { try await session.parkCreditWaiterForTesting(charge: 1) }
        try await awaitWithTimeout("credit waiter parked") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("best-effort CLOSE timeout returns") { await closeTask.value }
        XCTAssertEqual(transport.closeCallCount, 0)

        transport.failReceive(with: SMBTransportError.connectionClosed)
        do {
            _ = try await awaitWithTimeout("READ gets transport failure") { try await read.value }
            XCTFail("READ should fail after receive dies")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await awaitWithTimeout("credit waiter gets transport failure") { try await creditWaiter.value }
            XCTFail("credit waiter should fail after receive dies")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let pendingAfterFailure = await session.pendingCountForTesting()
        let creditWaitersAfterFailure = await session.creditWaiterCountForTesting()
        XCTAssertEqual(pendingAfterFailure, 0)
        XCTAssertEqual(creditWaitersAfterFailure, 0)
    }

    func testCleanupCloseDeadlineWhileSendingIsWireFault() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        transport.blockSends(for: [SMB2Commands.close])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 3, count: 16))
        }
        try await awaitWithTimeout("CLOSE send started") {
            await transport.waitUntilBlockedSendCount(1)
        }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("sending timeout closes session") { await closeTask.value }
        XCTAssertEqual(transport.closeCallCount, 1)
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        let ledgerCountAfterSendTimeout = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(ledgerCountAfterSendTimeout, 0)
    }

    func testCleanupDeadlineAdvancesOnlyAfterProductionSentTransition() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        transport.blockSends(for: [SMB2Commands.close])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        defer { Task { await session.closeTransport(cause: "test_sent_transition_barrier") } }
        let sentTransition = Task {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("sent-state waiter registered") {
            await session.waitForRequestSentWaiterRegistrationCountForTesting(atLeast: 1)
        }
        let fileId = [UInt8](repeating: 0x43, count: 16)
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE transport send blocked") {
            await transport.waitUntilBlockedSendCount(1)
        }
        try await awaitWithTimeout("cleanup timeout registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        transport.releaseBlockedSends(for: SMB2Commands.close)
        try await awaitWithTimeout("production markRequestSent completed") {
            await sentTransition.value
        }
        let stateAfterMarkRequestSent = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertTrue(stateAfterMarkRequestSent?.hasPrefix("draining:") == true)

        clock.fireNext()
        try await awaitWithTimeout("cleanup timeout returns after sent state") { await closeTask.value }
        let tombstoneCount = await session.cleanupTombstoneCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(tombstoneCount, 1)
        XCTAssertEqual(ledgerCount, 1)
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testCleanupCloseDeadlineBeforeSendRetiresOnlyThatFileId() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let fileId = [UInt8](repeating: 4, count: 16)
        let closeTask = Task { try await session.closeCreatedHandle(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        do {
            try await awaitWithTimeout("pre-send CLOSE timeout") { try await closeTask.value }
            XCTFail("CLOSE should time out before send")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.close), 0)
        XCTAssertEqual(transport.closeCallCount, 0)
        let state = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(state, "retiredUnknown")
        let creditWaiterCountAfterPreSendTimeout = await session.creditWaiterCountForTesting()
        XCTAssertEqual(creditWaiterCountAfterPreSendTimeout, 0)
    }

    func testCleanupLedgerLimitCountsSendingAttemptsAndClosesAt65() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        transport.blockSends(for: [SMB2Commands.close])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 128,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        defer { Task { await session.closeTransport(cause: "test_cleanup_ledger_bound") } }
        let attempts = (0..<64).map { index in
            Task {
                await session.bestEffortClose(
                    treeId: 1,
                    fileId: [UInt8](repeating: UInt8(index), count: 16)
                )
            }
        }
        try await awaitWithTimeout("64 CLOSE sends blocked") {
            await transport.waitUntilBlockedSendCount(64)
        }
        try await awaitWithTimeout("64 cleanup timers registered") {
            await clock.waitUntilCallCount(atLeast: 64)
        }
        let reservedAttempts = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(reservedAttempts, 64)

        let overflow = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 0xfe, count: 16))
        }
        try await awaitWithTimeout("65th attempt tears down") { await overflow.value }
        for attempt in attempts {
            try await awaitWithTimeout("reserved CLOSE drained by teardown") { await attempt.value }
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.close), 64)
        XCTAssertEqual(transport.closeCallCount, 1)
    }

    func testCleanupDrainLimitClosesSessionAndFailsCreditWaiter() async throws {
        let cleanupClock = ManualSMBSleeper()
        let drainClock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            cleanupTimeout: .seconds(5),
            requestTimeout: .seconds(30),
            requestTimeoutSleeper: { try await drainClock.sleep(for: $0) },
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_cleanup_drain_bound") } }
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 5, count: 16))
        }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        let creditWaiter = Task { try await session.parkCreditWaiterForTesting(charge: 1) }
        try await awaitWithTimeout("credit waiter parks") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("cleanup timer registered") {
            await cleanupClock.waitUntilCallCount(atLeast: 1)
        }
        cleanupClock.fireNext()
        try await awaitWithTimeout("cleanup deadline resumes caller") { await closeTask.value }
        try await awaitWithTimeout("drain timer registered") {
            await drainClock.waitUntilCallCount(atLeast: 1)
        }
        XCTAssertEqual(transport.closeCallCount, 0)
        let creditWaitersDuringDrain = await session.creditWaiterCountForTesting()
        XCTAssertEqual(creditWaitersDuringDrain, 1)

        drainClock.fireNext()
        do {
            _ = try await awaitWithTimeout("drain timeout fails credit waiter") { try await creditWaiter.value }
            XCTFail("credit waiter should fail after drain bound")
        } catch SMBTransportError.connectionClosed {
        }
        try await awaitWithTimeout("cleanup ledger cleared") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let creditWaitersAfterDrain = await session.creditWaiterCountForTesting()
        XCTAssertEqual(creditWaitersAfterDrain, 0)
    }

    func testCloseCreatedHandleThrowsServerStatusAndSessionRemainsUsable() async throws {
        let transport = CommandAwareCloseTimeoutTransport(closeStatus: SMB2Status.accessDenied)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_cleanup_file_id_admission") } }
        let fileId = [UInt8](repeating: 6, count: 16)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { try await session.closeCreatedHandle(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        transport.releaseNextResponse(command: SMB2Commands.close)
        do {
            try await awaitWithTimeout("CLOSE status returned") { try await closeTask.value }
            XCTFail("closeCreatedHandle should report the server error")
        } catch let error as SMBError {
            XCTAssertEqual(error, .accessDenied(status: SMB2Status.accessDenied, operation: "CLOSE"))
        }
        let state = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(state, "retiredUnknown")

        do {
            _ = try await awaitWithTimeout("retired FileId read rejected") {
                try await session.readChunk(treeId: 1, fileId: fileId, offset: 0, length: 1)
            }
            XCTFail("retired FileId must be rejected before another wire operation")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unresolved after CLOSE"))
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.read), 0)
        try await awaitWithTimeout("ECHO proves transport remains usable") { try await session.echo() }
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testStatusCancelledCloseRetiresFileIdWithoutClosingSharedSession() async throws {
        let transport = CommandAwareCloseTimeoutTransport(closeStatus: SMB2Status.cancelled)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let fileId = [UInt8](repeating: 7, count: 16)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { try await session.closeCreatedHandle(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        transport.releaseNextResponse(command: SMB2Commands.close)
        do {
            try await awaitWithTimeout("STATUS_CANCELLED returned") { try await closeTask.value }
            XCTFail("STATUS_CANCELLED must be thrown")
        } catch is CancellationError {
        }
        let state = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(state, "retiredUnknown")
        try await awaitWithTimeout("ECHO after STATUS_CANCELLED") { try await session.echo() }
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testBestEffortCloseFailureStatusIsSwallowedAndSessionRemainsUsable() async throws {
        let transport = CommandAwareCloseTimeoutTransport(closeStatus: SMB2Status.accessDenied)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let fileId = [UInt8](repeating: 13, count: 16)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("best-effort CLOSE returns on failed status") { await closeTask.value }
        let state = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(state, "retiredUnknown")
        try await awaitWithTimeout("ECHO after best-effort status failure") { try await session.echo() }
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testLateCleanupTombstoneAcceptsUnsignedInterimAndRetainsUntilFinal() async throws {
        let clock = ManualSMBSleeper()
        let signingKey = [UInt8](repeating: 0x31, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(
            unsignedCloseInterim: true,
            signingKey: signingKey,
            closeInterimAsyncId: 0x1122_3344_5566_7788
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let fileId = [UInt8](repeating: 8, count: 16)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("signed CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("signed CLOSE caller timeout") { await closeTask.value }
        let closeMessageId = try XCTUnwrap(transport.messageIds(for: SMB2Commands.close).first)
        await session.requestDidTimeOutForTesting(messageId: closeMessageId, command: SMB2Commands.close)
        let tombstonesBeforeInterim = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstonesBeforeInterim, 1)

        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("unsigned interim dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let asyncIdAfterInterim = await session.pendingAsyncIdForTesting(messageId: closeMessageId)
        XCTAssertEqual(asyncIdAfterInterim, 0x1122_3344_5566_7788)
        let tombstonesAfterInterim = await session.cleanupTombstoneCountForTesting()
        let ledgerAfterInterim = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(tombstonesAfterInterim, 1)
        XCTAssertEqual(ledgerAfterInterim, 1)
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("final dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 2)
        }
        try await awaitWithTimeout("cleanup ledger cleared") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        let tombstonesAfterFinal = await session.cleanupTombstoneCountForTesting()
        let orphanCountAfterFinal = await session.orphanResponseCountForTesting()
        XCTAssertEqual(tombstonesAfterFinal, 0)
        XCTAssertEqual(orphanCountAfterFinal, 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testLateCleanupTombstoneRejectsInvalidSignature() async throws {
        let clock = ManualSMBSleeper()
        let signingKey = [UInt8](repeating: 0x42, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(
            corruptCloseSignature: true,
            signingKey: signingKey
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 9, count: 16))
        }
        try await awaitWithTimeout("signed CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("signed CLOSE caller timeout") { await closeTask.value }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("cleanup ledger cleared after invalid signature") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
    }

    func testLateCleanupTombstoneRejectsTreeIdMismatch() async throws {
        let clock = ManualSMBSleeper()
        let signingKey = [UInt8](repeating: 0x53, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(
            closeTreeIdOverride: 99,
            signingKey: signingKey
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 10, count: 16))
        }
        try await awaitWithTimeout("signed CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("signed CLOSE caller timeout") { await closeTask.value }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("cleanup ledger cleared after tree mismatch") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
    }

    func testOrphanCleanupDispatchFailureClosesTransportAndClearsLedger() async throws {
        let signingKey = [UInt8](repeating: 0x63, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(signingKey: signingKey)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true
        )
        defer { Task { await session.closeTransport(cause: "test_orphan_cleanup_dispatch") } }
        let messageId: UInt64 = 41
        let sessionId: UInt64 = 0x1111_2222_3333_4444
        let fileId = [UInt8](repeating: 0x41, count: 16)
        let pending = Task {
            try await session.parkCleanupPendingForTesting(
                messageId: messageId,
                sessionId: sessionId,
                treeId: 1,
                fileId: fileId
            )
        }
        try await awaitWithTimeout("cleanup pending record registered") {
            await session.waitForCleanupLedgerCountForTesting(1)
        }
        let invalidSignatureResponse = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.close,
            flags: SMB2Flags.signed,
            messageId: messageId,
            treeId: 1,
            sessionId: sessionId
        ).encode()

        try await session.queueOrphanAndMarkRequestSentForTesting(invalidSignatureResponse)
        do {
            try await awaitWithTimeout("orphan cleanup pending fails on wire fault") {
                try await pending.value
            }
            XCTFail("orphan cleanup dispatch failure did not terminate the pending CLOSE")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let pendingCount = await session.wirePendingRecordCountForTesting()
        let orphanCount = await session.orphanResponseCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertEqual(orphanCount, 0)
        XCTAssertEqual(ledgerCount, 0)
    }

    func testCleanupSyncResponseRejectsZeroSessionId() async throws {
        try await assertCleanupSyncResponseIsWireFault(
            transport: CommandAwareCloseTimeoutTransport(
                closeSessionIdOverride: 0,
                signingKey: [UInt8](repeating: 0x64, count: 16)
            ),
            signingKey: [UInt8](repeating: 0x64, count: 16),
            label: "zero SessionId"
        )
    }

    func testCleanupSyncResponseRejectsZeroTreeId() async throws {
        try await assertCleanupSyncResponseIsWireFault(
            transport: CommandAwareCloseTimeoutTransport(
                closeTreeIdOverride: 0,
                signingKey: [UInt8](repeating: 0x65, count: 16)
            ),
            signingKey: [UInt8](repeating: 0x65, count: 16),
            label: "zero TreeId"
        )
    }

    func testCleanupSyncResponseAcceptsMatchingZeroTreeId() async throws {
        let signingKey = [UInt8](repeating: 0x65, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(signingKey: signingKey)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            initialCredits: 2
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeTask = Task {
            await session.bestEffortClose(treeId: 0, fileId: [UInt8](repeating: 0x65, count: 16))
        }
        try await awaitWithTimeout("zero-TreeId CLOSE sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("zero-TreeId receive loop blocked") {
            await transport.waitUntilReceiveIsBlocked()
        }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("matching zero-TreeId response accepted") { await closeTask.value }
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(ledgerCount, 0)
        XCTAssertEqual(transport.closeCallCount, 0)
        await session.closeTransport(cause: "test_zero_tree_cleanup")
    }

    func testCleanupUnsignedInterimAsyncIdMismatchWithSignedFinalIsWireFault() async throws {
        let clock = ManualSMBSleeper()
        let signingKey = [UInt8](repeating: 0x66, count: 16)
        let interimAsyncId: UInt64 = 0x8877_6655_4433_2211
        let finalAsyncId: UInt64 = 0x8877_6655_4433_2212
        let transport = CommandAwareCloseTimeoutTransport(
            heldCommands: [SMB2Commands.close],
            unsignedCloseInterim: true,
            signingKey: signingKey,
            closeInterimAsyncId: interimAsyncId,
            closeFinalAsyncIdOverride: finalAsyncId
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_bad_cleanup_interim_cleanup") } }
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 0x66, count: 16))
        }
        try await awaitWithTimeout("signed CLOSE sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("cleanup caller timeout") { await closeTask.value }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("unsigned interim dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let storedAsyncId = await session.pendingAsyncIdForTesting(
            messageId: try XCTUnwrap(transport.messageIds(for: SMB2Commands.close).first)
        )
        XCTAssertEqual(storedAsyncId, interimAsyncId)
        let tombstoneCountAfterInterim = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstoneCountAfterInterim, 1)

        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("mismatched signed final dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 2)
        }
        try await awaitWithTimeout("AsyncId mismatch closes cleanup ledger") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        XCTAssertEqual(dispatchCount, 2)
    }

    func testCleanupCallerCancellationAfterResponseDispatchKeepsSuccessfulResult() async throws {
        let signingKey = [UInt8](repeating: 0x67, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(
            heldCommands: [SMB2Commands.close],
            signingKey: signingKey
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            initialCredits: 2
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_post_dispatch_cancel") } }
        let closeTask = Task {
            try await session.closeCreatedHandle(treeId: 1, fileId: [UInt8](repeating: 0x67, count: 16))
        }
        try await awaitWithTimeout("CLOSE sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        var finalResponse = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.close,
            credits: 1,
            flags: SMB2Flags.signed,
            messageId: try XCTUnwrap(transport.messageIds(for: SMB2Commands.close).first),
            treeId: 1,
            sessionId: 0x1111_2222_3333_4444
        ).encode()
        finalResponse.append(contentsOf: [60, 0] + Array(repeating: UInt8(0), count: 58))
        let signature = try SMBSessionSigning.signature(
            algorithm: .aesCMAC,
            key: signingKey,
            packet: finalResponse,
            sender: .server
        )
        finalResponse.replaceSubrange(48..<64, with: signature)
        try await session.dispatchReceivedPacketThenCancelForTesting(finalResponse) {
            closeTask.cancel()
        }
        try await awaitWithTimeout("successful CLOSE result survives later cancel") {
            try await closeTask.value
        }
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        let ledgerCountAfterResponse = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(ledgerCountAfterResponse, 0)
        XCTAssertEqual(transport.closeCallCount, 0)
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        XCTAssertEqual(dispatchCount, 1)
    }

    func testCleanupCallerCancellationDoesNotSendCancelAndResponseWins() async throws {
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { try await session.closeCreatedHandle(treeId: 1, fileId: [UInt8](repeating: 11, count: 16)) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        closeTask.cancel()
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("CLOSE response wins over caller cancellation") { try await closeTask.value }
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        let ledgerCountAfterResponse = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(ledgerCountAfterResponse, 0)
        XCTAssertEqual(transport.closeCallCount, 0)
    }

    func testCleanupCallerCancellationBeforeResponseKeepsLateResponseCorrelated() async throws {
        let clock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeSentCount = await session.requestSentCountForTesting()
        let closeTask = Task { try await session.closeCreatedHandle(treeId: 1, fileId: [UInt8](repeating: 12, count: 16)) }
        try await awaitWithTimeout("CLOSE sent") { try await transport.waitUntilSent(SMB2Commands.close, count: 1) }
        try await Self.waitForRequestSentCount(closeSentCount + 1, in: session)
        try await awaitWithTimeout("receive loop blocked") { await transport.waitUntilReceiveIsBlocked() }
        closeTask.cancel()
        try await awaitWithTimeout("cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        do {
            try await awaitWithTimeout("cancelled caller waits to cleanup deadline") { try await closeTask.value }
            XCTFail("CLOSE should time out")
        } catch SMBTransportError.timedOut {
        }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("cleanup ledger cleared after late response") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        let orphanCountAfterLateResponse = await session.orphanResponseCountForTesting()
        XCTAssertEqual(orphanCountAfterLateResponse, 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.cancel), 0)
        XCTAssertEqual(transport.closeCallCount, 0)
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

    private static func waitForRequestSentCount(_ count: Int, in session: SMBSession) async throws {
        try await awaitWithTimeout("production markRequestSent count \(count)") {
            await session.waitForRequestSentCountForTesting(atLeast: count)
        }
    }

    private func assertCleanupSyncResponseIsWireFault(
        transport: CommandAwareCloseTimeoutTransport,
        signingKey: [UInt8],
        label: String
    ) async throws {
        let clock = ManualSMBSleeper()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            signingRequired: true,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        defer { Task { await session.closeTransport(cause: "test_cleanup_correlation") } }
        let closeTask = Task {
            await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 0x68, count: 16))
        }
        try await awaitWithTimeout("\(label) CLOSE sent") {
            try await transport.waitUntilSent(command: SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("\(label) receive loop blocked") {
            await transport.waitUntilReceiveIsBlocked()
        }
        try await awaitWithTimeout("\(label) cleanup timer registered") {
            await clock.waitUntilCallCount(atLeast: 1)
        }
        clock.fireNext()
        try await awaitWithTimeout("\(label) cleanup caller timeout") { await closeTask.value }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("\(label) response dispatch") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("\(label) wire fault clears cleanup ledger") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1, "\(label) must close the transport")
        let pendingCount = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingCount, 0)
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
    private struct CommandWaiter {
        let command: UInt16
        let count: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private let lock = NSLock()
    private let receiveState = CloseSilentReceiveState()
    private var commandStorage: [UInt16] = []
    private var commandWaiters: [CommandWaiter] = []
    private var closeCountStorage = 0

    var commands: [UInt16] {
        lock.withLock { commandStorage }
    }

    var closeCallCount: Int {
        lock.withLock { closeCountStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let header = try SMB2Header.decode(Array(bytes.dropFirst(4)))
        let ready = lock.withLock { () -> [CommandWaiter] in
            commandStorage.append(header.command)
            var ready: [CommandWaiter] = []
            commandWaiters.removeAll { waiter in
                if commandStorage.filter({ $0 == waiter.command }).count >= waiter.count {
                    ready.append(waiter)
                    return true
                }
                return false
            }
            return ready
        }
        for waiter in ready { waiter.continuation.resume() }
    }

    func waitUntilSent(_ command: UInt16, count: Int) async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if commandStorage.filter({ $0 == command }).count >= count {
                lock.unlock()
                continuation.resume()
            } else {
                commandWaiters.append(CommandWaiter(command: command, count: count, continuation: continuation))
                lock.unlock()
            }
        }
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
        lock.withLock { closeCountStorage += 1 }
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

final class ManualSMBSleeper: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var callCountStorage = 0
    private var waiters: [Waiter] = []
    private var countWaiters: [(Int, CheckedContinuation<Void, Never>)] = []

    func sleep(for duration: Duration) async throws {
        _ = duration
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let countWaitersToResume: [CheckedContinuation<Void, Never>]
                let cancelled: Bool
                lock.lock()
                callCountStorage += 1
                cancelled = Task.isCancelled
                if !cancelled {
                    waiters.append(Waiter(id: id, continuation: continuation))
                }
                countWaitersToResume = takeReadyCountWaitersLocked()
                lock.unlock()
                for waiter in countWaitersToResume { waiter.resume() }
                if cancelled { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            self.cancel(id: id)
        }
    }

    func waitUntilCallCount(atLeast count: Int) async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if callCountStorage >= count {
                lock.unlock()
                continuation.resume()
            } else {
                countWaiters.append((count, continuation))
                lock.unlock()
            }
        }
    }

    func fireNext() {
        let waiter = lock.withLock { waiters.isEmpty ? nil : waiters.removeFirst() }
        waiter?.continuation.resume()
    }

    private func cancel(id: UUID) {
        let waiter = lock.withLock { () -> Waiter? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index)
        }
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func takeReadyCountWaitersLocked() -> [CheckedContinuation<Void, Never>] {
        var ready: [CheckedContinuation<Void, Never>] = []
        countWaiters.removeAll { target, continuation in
            if callCountStorage >= target {
                ready.append(continuation)
                return true
            }
            return false
        }
        return ready
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

    private struct PendingSend {
        let id: UInt64
        let command: UInt16
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var inbound: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var receiveFailure: Error?
    private var receiveStateWaiters: [CheckedContinuation<Void, Never>] = []
    private var commandStorage: [UInt16] = []
    private var messageIdStorage: [(command: UInt16, messageId: UInt64)] = []
    private var heldResponses: [(command: UInt16, frame: [UInt8])] = []
    private var sentWaiters: [SentWaiter] = []
    private var blockedSendCommands: Set<UInt16> = []
    private var pendingSends: [PendingSend] = []
    private var blockedSendCountWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var nextWaiterId: UInt64 = 0
    private var nextSendId: UInt64 = 0
    private var isClosed = false
    private var closeCallCountStorage = 0
    private let heldCommands: Set<UInt16>
    private let closeStatus: UInt32
    private let closeTreeIdOverride: UInt32?
    private let closeSessionIdOverride: UInt64?
    private let corruptCloseSignature: Bool
    private let unsignedCloseInterim: Bool
    private let signingKey: [UInt8]?
    private let closeInterimAsyncId: UInt64?
    private let closeFinalAsyncIdOverride: UInt64?

    init(
        heldCommands: Set<UInt16> = [SMB2Commands.read, SMB2Commands.close],
        closeStatus: UInt32 = SMB2Status.success,
        closeTreeIdOverride: UInt32? = nil,
        closeSessionIdOverride: UInt64? = nil,
        corruptCloseSignature: Bool = false,
        unsignedCloseInterim: Bool = false,
        signingKey: [UInt8]? = nil,
        closeInterimAsyncId: UInt64? = nil,
        closeFinalAsyncIdOverride: UInt64? = nil
    ) {
        self.heldCommands = heldCommands
        self.closeStatus = closeStatus
        self.closeTreeIdOverride = closeTreeIdOverride
        self.closeSessionIdOverride = closeSessionIdOverride
        self.corruptCloseSignature = corruptCloseSignature
        self.unsignedCloseInterim = unsignedCloseInterim
        self.signingKey = signingKey
        self.closeInterimAsyncId = closeInterimAsyncId
        self.closeFinalAsyncIdOverride = closeFinalAsyncIdOverride
    }

    var closeCallCount: Int {
        lock.withLock { closeCallCountStorage }
    }

    func blockSends(for commands: Set<UInt16>) {
        lock.withLock { blockedSendCommands.formUnion(commands) }
    }

    func messageIds(for command: UInt16) -> [UInt64] {
        lock.withLock { messageIdStorage.filter { $0.command == command }.map(\.messageId) }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let header = try SMB2Header.decode(Array(bytes.dropFirst(4)))
        let sendId = lock.withLock { () -> UInt64 in
            defer { nextSendId += 1 }
            return nextSendId
        }
        let state = lock.withLock { () -> (sent: Bool, blocked: Bool, waiters: [SentWaiter]) in
            guard !isClosed else { return (false, false, []) }
            commandStorage.append(header.command)
            messageIdStorage.append((header.command, header.messageId))
            return (true, blockedSendCommands.contains(header.command), removeReadySentWaitersLocked())
        }
        guard state.sent else { throw SMBTransportError.connectionClosed }
        for waiter in state.waiters {
            waiter.continuation.resume()
        }

        if state.blocked {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let immediate: Result<Void, Error>?
                    let countWaiters: [CheckedContinuation<Void, Never>]
                    lock.lock()
                    if isClosed {
                        immediate = .failure(SMBTransportError.connectionClosed)
                    } else if Task.isCancelled {
                        immediate = .failure(CancellationError())
                    } else {
                        pendingSends.append(PendingSend(id: sendId, command: header.command, continuation: continuation))
                        immediate = nil
                    }
                    countWaiters = takeReadyBlockedSendCountWaitersLocked()
                    lock.unlock()
                    for waiter in countWaiters { waiter.resume() }
                    if let immediate { continuation.resume(with: immediate) }
                }
            } onCancel: {
                self.cancelPendingSend(id: sendId)
            }
        }

        let responses = try responseFrames(for: header)
        let receiveDelivery = lock.withLock { () -> (PendingReceive, [UInt8])? in
            guard !isClosed else { return nil }
            for response in responses {
                if heldCommands.contains(header.command) {
                    heldResponses.append((command: header.command, frame: response))
                } else {
                    inbound.append(contentsOf: response)
                }
            }
            return takeReceiveDeliveryLocked()
        }
        if let (pending, chunk) = receiveDelivery {
            pending.continuation.resume(returning: chunk)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<[UInt8], Error>?
                let stateWaiters: [CheckedContinuation<Void, Never>]
                lock.lock()
                if isClosed {
                    immediate = .failure(SMBTransportError.connectionClosed)
                } else if Task.isCancelled {
                    immediate = .failure(CancellationError())
                } else if let receiveFailure {
                    self.receiveFailure = nil
                    immediate = .failure(receiveFailure)
                } else if inbound.isEmpty {
                    pendingReceive = PendingReceive(maxLength: maxLength, continuation: continuation)
                    immediate = nil
                } else {
                    let count = min(maxLength, inbound.count)
                    let chunk = Array(inbound.prefix(count))
                    inbound.removeFirst(count)
                    immediate = .success(chunk)
                }
                stateWaiters = pendingReceive == nil ? [] : takeReceiveStateWaitersLocked()
                lock.unlock()
                for waiter in stateWaiters { waiter.resume() }
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
        let sends: [PendingSend]
        let blockedSendObservers: [CheckedContinuation<Void, Never>]
        let receiveObservers: [CheckedContinuation<Void, Never>]
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
        sends = pendingSends
        pendingSends.removeAll()
        blockedSendObservers = blockedSendCountWaiters.map(\.1)
        blockedSendCountWaiters.removeAll()
        receiveObservers = receiveStateWaiters
        receiveStateWaiters.removeAll()
        lock.unlock()

        receive?.continuation.resume(throwing: SMBTransportError.connectionClosed)
        for waiter in waiters {
            waiter.continuation.resume(throwing: SMBTransportError.connectionClosed)
        }
        for send in sends { send.continuation.resume(throwing: SMBTransportError.connectionClosed) }
        for waiter in blockedSendObservers { waiter.resume() }
        for waiter in receiveObservers { waiter.resume() }
    }

    func waitUntilReceiveIsBlocked() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if pendingReceive != nil {
                lock.unlock()
                continuation.resume()
            } else {
                receiveStateWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func failReceive(with error: Error) {
        let receive: PendingReceive?
        lock.lock()
        receive = pendingReceive
        pendingReceive = nil
        if receive == nil { receiveFailure = error }
        lock.unlock()
        receive?.continuation.resume(throwing: error)
    }

    func releaseNextResponse(command: UInt16) {
        let delivery = lock.withLock { () -> (PendingReceive, [UInt8])? in
            guard let index = heldResponses.firstIndex(where: { $0.command == command }) else { return nil }
            let response = heldResponses.remove(at: index)
            inbound.append(contentsOf: response.frame)
            return takeReceiveDeliveryLocked()
        }
        if let (pending, chunk) = delivery {
            pending.continuation.resume(returning: chunk)
        }
    }

    func waitUntilBlockedSendCount(_ count: Int) async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if pendingSends.count >= count || isClosed {
                lock.unlock()
                continuation.resume()
            } else {
                blockedSendCountWaiters.append((count, continuation))
                lock.unlock()
            }
        }
    }

    func releaseBlockedSends(for command: UInt16) {
        let sends: [CheckedContinuation<Void, Error>]
        let observers: [CheckedContinuation<Void, Never>]
        lock.lock()
        blockedSendCommands.remove(command)
        sends = pendingSends.filter { $0.command == command }.map(\.continuation)
        pendingSends.removeAll { $0.command == command }
        observers = takeReadyBlockedSendCountWaitersLocked()
        lock.unlock()
        for send in sends { send.resume() }
        for observer in observers { observer.resume() }
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

    func heldResponseCount(for commands: Set<UInt16>) -> Int {
        lock.withLock { heldResponses.filter { commands.contains($0.command) }.count }
    }

    func waitUntilSent(_ command: UInt16, count: Int) async throws {
        try await waitUntilSent(command: command, count: count)
    }

    private func responseFrames(for request: SMB2Header) throws -> [[UInt8]] {
        switch request.command {
        case SMB2Commands.echo:
            return [try responseFrame(
                command: request.command,
                messageId: request.messageId,
                sessionId: request.sessionId,
                treeId: request.treeId,
                status: SMB2Status.success,
                body: [4, 0, 0, 0]
            )]
        case SMB2Commands.read:
            var body = Array(repeating: UInt8(0), count: 16)
            body[0] = 17
            body[2] = 80
            body[4] = 1
            return [try responseFrame(
                command: request.command,
                messageId: request.messageId,
                sessionId: request.sessionId,
                treeId: request.treeId,
                status: SMB2Status.success,
                body: body + [0]
            )]
        case SMB2Commands.write:
            var body = Array(repeating: UInt8(0), count: 16)
            body[0] = 17
            body[4] = 1
            return [try responseFrame(
                command: request.command,
                messageId: request.messageId,
                sessionId: request.sessionId,
                treeId: request.treeId,
                status: SMB2Status.success,
                body: body
            )]
        case SMB2Commands.close:
            var frames: [[UInt8]] = []
            let responseSessionId = closeSessionIdOverride ?? request.sessionId
            if let closeInterimAsyncId {
                frames.append(try responseFrame(
                    command: request.command,
                    messageId: request.messageId,
                    sessionId: responseSessionId,
                    treeId: request.treeId,
                    status: SMB2Status.pending,
                    body: [],
                    asyncId: closeInterimAsyncId
                ))
            }
            let body = [60, 0] + Array(repeating: UInt8(0), count: 58)
            frames.append(try responseFrame(
                command: request.command,
                messageId: request.messageId,
                sessionId: responseSessionId,
                treeId: closeTreeIdOverride ?? request.treeId,
                status: closeStatus,
                body: body,
                asyncId: closeFinalAsyncIdOverride ?? closeInterimAsyncId
            ))
            return frames
        default:
            return []
        }
    }

    private func responseFrame(
        command: UInt16,
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        status: UInt32,
        body: [UInt8],
        asyncId: UInt64? = nil
    ) throws -> [UInt8] {
        let shouldSign = signingKey != nil && !(command == SMB2Commands.close && status == SMB2Status.pending && unsignedCloseInterim)
        let flags: UInt32 = shouldSign ? SMB2Flags.signed : 0
        var packet: [UInt8]
        if let asyncId {
            packet = try SMB2Header.asyncHeader(
                status: status,
                command: command,
                credits: 1,
                flags: flags,
                messageId: messageId,
                asyncId: asyncId,
                sessionId: sessionId
            ).encode()
        } else {
            packet = try SMB2Header(
                status: status,
                command: command,
                credits: 1,
                flags: flags,
                messageId: messageId,
                treeId: treeId,
                sessionId: sessionId
            ).encode()
        }
        packet.append(contentsOf: body)
        if shouldSign, let signingKey {
            let signature = try SMBSessionSigning.signature(
                algorithm: .aesCMAC,
                key: signingKey,
                packet: packet,
                sender: .server
            )
            packet.replaceSubrange(48..<64, with: signature)
            if command == SMB2Commands.close, status != SMB2Status.pending, corruptCloseSignature {
                packet[48] ^= 0xff
            }
        }
        return try DirectTCPFraming.frame(packet)
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

    private func takeReceiveStateWaitersLocked() -> [CheckedContinuation<Void, Never>] {
        defer { receiveStateWaiters.removeAll() }
        return receiveStateWaiters
    }

    private func takeReadyBlockedSendCountWaitersLocked() -> [CheckedContinuation<Void, Never>] {
        var ready: [CheckedContinuation<Void, Never>] = []
        blockedSendCountWaiters.removeAll { waiter in
            if pendingSends.count >= waiter.0 {
                ready.append(waiter.1)
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

    private func cancelPendingSend(id: UInt64) {
        let send = lock.withLock { () -> PendingSend? in
            guard let index = pendingSends.firstIndex(where: { $0.id == id }) else { return nil }
            return pendingSends.remove(at: index)
        }
        send?.continuation.resume(throwing: CancellationError())
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
