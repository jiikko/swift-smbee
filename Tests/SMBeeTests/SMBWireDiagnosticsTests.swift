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

    func testCloseCancellationDoesNotCreateAFirstWireFault() async throws {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        var response = try SMB2Header(command: SMB2Commands.echo, credits: 1, messageId: 0).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        let transport = InMemoryTransport(inbound: try DirectTCPFraming.frame(response))
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )

        try await session.echo()
        await session.closeTransportAndWait(cause: "test_normal_close")

        let faults = capture.messages.filter { $0.hasPrefix("[wire] first_fault") }
        XCTAssertTrue(faults.isEmpty, "normal close cancellation is not a receive fault")
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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

    func testUnresolvedFileIdRejectsReadAndWriteBeforeCreditReservation() async throws {
        let fileId = [UInt8](repeating: 0x2a, count: 16)
        let transport = CommandAwareCloseTimeoutTransport(heldCommands: [SMB2Commands.close])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            requestTimeout: nil
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        defer {
            transport.releaseNextResponse(command: SMB2Commands.close)
            Task { await session.closeTransportAndWait(cause: "test_file_id_precredit_cleanup") }
        }
        try await awaitWithTimeout("last-credit CLOSE sent") {
            try await transport.waitUntilSent(SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        let balanceAfterClose = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterClose, 0)

        do {
            _ = try await awaitWithTimeout("same FileId READ admission before credits", timeout: .milliseconds(500)) {
                try await session.readChunk(treeId: 1, fileId: fileId, offset: 0, length: 65_537)
            }
            XCTFail("READ should reject the unresolved FileId without waiting for credits")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unresolved after CLOSE"), message)
        } catch {
            XCTFail("READ must reject before registering a credit waiter; got \(error)")
        }
        do {
            try await awaitWithTimeout("same FileId WRITE admission before credits", timeout: .milliseconds(500)) {
                try await session.write(treeId: 1, fileId: fileId, data: [0xa5])
            }
            XCTFail("WRITE should reject the unresolved FileId without waiting for credits")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unresolved after CLOSE"), message)
        } catch {
            XCTFail("WRITE must reject before registering a credit waiter; got \(error)")
        }

        XCTAssertEqual(transport.commandCount(SMB2Commands.read), 0)
        XCTAssertEqual(transport.commandCount(SMB2Commands.write), 0)
        let creditWaitersAfterRejectedRequests = await session.creditWaiterCountForTesting()
        let pendingAfterRejectedRequests = await session.pendingCountForTesting()
        XCTAssertEqual(creditWaitersAfterRejectedRequests, 0)
        XCTAssertEqual(pendingAfterRejectedRequests, 1)

        await session.closeTransportAndWait(cause: "test_file_id_rejected_before_credit_reservation")
        await closeTask.value
        XCTAssertEqual(transport.closeCallCount, 1)
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 64, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await cleanupClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        cleanupClock.fireNext()
        try await awaitWithTimeout("cleanup deadline resumes caller") { await closeTask.value }
        try await awaitWithTimeout("drain timer registered") {
            try await drainClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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

    func testCleanupFinalWinsAgainstQueuedDrainTimeout() async throws {
        let cleanupClock = ManualSMBSleeper()
        let drainClock = ManualSMBSleeper()
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            cleanupTimeout: .seconds(5),
            requestTimeout: .seconds(30),
            requestTimeoutSleeper: { try await drainClock.sleep(for: $0) },
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.setSessionIdForTesting(0x1111_2222_3333_4444)
        let fileId = [UInt8](repeating: 0x5a, count: 16)
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await awaitWithTimeout("CLOSE sent") {
            try await transport.waitUntilSent(SMB2Commands.close, count: 1)
        }
        try await Self.waitForRequestSentCount(1, in: session)
        try await awaitWithTimeout("receive waits for CLOSE response") {
            await transport.waitUntilReceiveIsBlocked()
        }
        try await awaitWithTimeout("cleanup timer registered") {
            try await cleanupClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }
        cleanupClock.fireNext()
        try await awaitWithTimeout("CLOSE caller reaches tombstone") { await closeTask.value }
        try await awaitWithTimeout("drain timer registered") {
            try await drainClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }
        let closeMessageId = try XCTUnwrap(transport.messageIds(for: SMB2Commands.close).first)
        let optionalDrainIdentity = await session.cleanupDrainTimeoutIdentityForTesting(messageId: closeMessageId)
        let drainIdentity = try XCTUnwrap(optionalDrainIdentity)
        await session.fireCleanupDrainTimeoutForTesting(
            messageId: closeMessageId,
            generation: 1,
            identity: UUID()
        )
        let isClosedAfterWrongTimer = await session.isTransportClosedForTesting()
        XCTAssertFalse(isClosedAfterWrongTimer, "an obsolete drain timer identity cannot close a live tombstone")

        let dispatchBase = await session.receivedPacketDispatchCountForTesting()
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("late CLOSE final is dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchBase + 1)
        }
        try await awaitWithTimeout("late final clears cleanup ledger") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }

        await session.fireCleanupDrainTimeoutForTesting(
            messageId: closeMessageId,
            generation: 1,
            identity: drainIdentity
        )
        try await awaitWithTimeout("queued drain callback observes retired record") {
            await session.waitForCleanupDrainTimeoutCallbackCountForTesting(atLeast: 2)
        }
        let isClosed = await session.isTransportClosedForTesting()
        XCTAssertFalse(isClosed, "the queued drain callback after final response is stale")
        XCTAssertEqual(transport.closeCallCount, 0)
        await session.closeTransportAndWait(cause: "test_cleanup_final_drain_race_join")
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        clock.fireNext()
        try await awaitWithTimeout("signed CLOSE caller timeout") { await closeTask.value }
        transport.releaseNextResponse(command: SMB2Commands.close)
        try await awaitWithTimeout("cleanup ledger cleared after tree mismatch") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
    }

    func testCleanupDispatchSignatureFailureClosesTransportAndClearsLedger() async throws {
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

        do {
            _ = try await session.processRawFrameForTesting(invalidSignatureResponse, generation: 1)
            XCTFail("invalid cleanup response signature must be rejected before dispatch")
        } catch SMBCodecError.invalidValue {
        }
        let pendingBeforeClose = await session.wirePendingRecordCountForTesting()
        let ledgerBeforeClose = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingBeforeClose, 1)
        XCTAssertEqual(ledgerBeforeClose, 1)
        await session.closeTransportAndWait(cause: "test_cleanup_signature_failure")
        do {
            try await awaitWithTimeout("cleanup pending fails after terminal close") {
                try await pending.value
            }
            XCTFail("cleanup pending must fail after transport teardown")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let pendingCount = await session.wirePendingRecordCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(pendingCount, 0)
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
        try await awaitWithTimeout("AsyncId mismatch closes cleanup ledger") {
            await session.waitForCleanupLedgerCountForTesting(0)
        }
        XCTAssertEqual(transport.closeCallCount, 1)
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        XCTAssertEqual(dispatchCount, 1, "the invalid final is rejected before the receive transaction commits")
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
        finalResponse = try signedTestPacket(
            finalResponse,
            algorithm: .aesCMAC,
            key: signingKey,
            sender: .server
        )
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
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

final class SMBRequestRetirementPrimitiveTests: XCTestCase {
    func testOneShotCreditRefundTokenCannotBeConsumedTwice() {
        let token = SMBOneShotCreditRefundToken(charge: 3)
        XCTAssertEqual(token.consume(), 3)
        XCTAssertNil(token.consume())
    }

    func testUnsentRetirementShrinksAndRefundsEachCreditOwnerOnce() async throws {
        for retireBeforeSurplusAcknowledgement in [true, false] {
            let window = SMB2CreditWindow(initialCredits: 4, diagnosticSessionId: "retire-test")
            let reservedBalance = try await window.reserve(charge: 4)
            XCTAssertEqual(reservedBalance, 0)

            let surplusEntered = SMBRetirementEvent()
            let residualEntered = SMBRetirementEvent()
            let surplusRelease = SMBRetirementEvent()
            let residualRelease = SMBRetirementEvent()
            let probe = SMBRetirementCreditProbe()
            let record = SMBUnsentRequestRecord(
                identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 1),
                maximumCharge: 4,
                reservedCharge: 4,
                refundCredits: { charge in
                    await probe.started(charge)
                    if charge == 3 {
                        await surplusEntered.signal()
                        await surplusRelease.wait()
                    } else if charge == 1 {
                        await residualEntered.signal()
                        await residualRelease.wait()
                    }
                    _ = await window.refund(charge: charge)
                    await probe.acknowledged(charge)
                }
            )

            let prepared = await record.prepareCredit(actualCharge: 1)
            XCTAssertTrue(prepared)
            try await awaitWithTimeout("surplus refund entered") { await surplusEntered.wait() }
            if !retireBeforeSurplusAcknowledgement {
                await surplusRelease.signal()
                try await awaitWithTimeout("surplus refund acknowledged") {
                    await probe.waitForAcknowledgement(charge: 3, count: 1)
                }
            }

            let firstDecision = await record.retireUnsent()
            guard case .retiredLocally(let receipt) = firstDecision else {
                XCTFail("first retirement should be local")
                return
            }
            let duplicateDecision = await record.retireUnsent()
            guard case .alreadyRetired(let duplicateReceipt) = duplicateDecision else {
                XCTFail("duplicate retirement should reuse the receipt")
                return
            }
            XCTAssertEqual(receipt, duplicateReceipt)
            XCTAssertEqual(receipt.id, duplicateReceipt.id)

            try await awaitWithTimeout("residual refund entered") { await residualEntered.wait() }
            let completedBeforeAcks = receipt.isComplete
            XCTAssertFalse(completedBeforeAcks)

            await surplusRelease.signal()
            await residualRelease.signal()
            try await awaitWithTimeout("retirement receipt closed") { await receipt.wait() }

            let snapshot = await record.snapshot()
            XCTAssertEqual(snapshot.caller, .localRefusal)
            XCTAssertEqual(snapshot.send, .neverSubmitted, "a local retirement has no MID")
            XCTAssertEqual(snapshot.credit, .refunded)
            let finalBalance = await window.balance
            XCTAssertEqual(finalBalance, 4)
            let surplusCalls = await probe.calls(for: 3)
            let residualCalls = await probe.calls(for: 1)
            XCTAssertEqual(surplusCalls, 1, "the surplus refund is one-shot")
            XCTAssertEqual(residualCalls, 1, "the residual refund is one-shot")
        }
    }

    func testRetirementReceiptWaitsForLateCreditReservationAndRefundAcknowledgement() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "late-retire-test")
        let reservationAcquired = SMBRetirementEvent()
        let reservationSettlement = SMBRetirementEvent()
        let cancellationObserved = SMBRetirementCallbackCounter()
        let refundEntered = SMBRetirementEvent()
        let refundAcknowledged = SMBRetirementEvent()
        let refundRelease = SMBRetirementEvent()
        let probe = SMBRetirementCreditProbe()
        await window.setReservationAcquiredHookForTesting { _ in
            await reservationAcquired.signal()
            await reservationSettlement.wait()
            if Task.isCancelled { await cancellationObserved.increment() }
        }
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 2),
            maximumCharge: 4,
            refundCredits: { charge in
                await probe.started(charge)
                await refundEntered.signal()
                await refundRelease.wait()
                _ = await window.refund(charge: charge)
                await probe.acknowledged(charge)
                await refundAcknowledged.signal()
            }
        )
        let reservationStarted = await record.startCreditReservation(window: window, maximumCharge: 4)
        XCTAssertTrue(reservationStarted, "settlement ownership and task creation are one operation")
        try await awaitWithTimeout("credit waiter registered") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }
        _ = await window.grant(4)
        try await awaitWithTimeout("late reservation acquired") { await reservationAcquired.wait() }

        let decision = await record.retireUnsent()
        guard case .retiredLocally(let receipt) = decision else {
            XCTFail("waiting request should retire locally")
            return
        }
        try await awaitWithTimeout("only reservation settlement remains") {
            await record.waitForAcknowledgementCountForTesting(atMost: 1)
        }
        let completeAfterWaiterAck = receipt.isComplete
        XCTAssertFalse(completeAfterWaiterAck, "waiter acknowledgement cannot close a receipt with a possible late grant")

        await reservationSettlement.signal()
        try await awaitWithTimeout("acquired reservation observes retirement cancellation") {
            await cancellationObserved.waitForCount(atLeast: 1)
        }
        try await awaitWithTimeout("late grant refund entered") { await refundEntered.wait() }
        let completeBeforeRefundAck = receipt.isComplete
        XCTAssertFalse(completeBeforeRefundAck, "the receipt waits for the credit-window refund acknowledgement")
        await refundRelease.signal()
        try await awaitWithTimeout("late refund acknowledged") { await refundAcknowledged.wait() }
        try await awaitWithTimeout("late-grant retirement receipt closed") { await receipt.wait() }

        let lateRefundCalls = await probe.calls(for: 4)
        XCTAssertEqual(lateRefundCalls, 1)
        let finalBalance = await window.balance
        XCTAssertEqual(finalBalance, 4)
        let snapshot = await record.snapshot()
        XCTAssertEqual(snapshot.send, .neverSubmitted)
        XCTAssertEqual(snapshot.credit, .refunded)
    }

    func testCreditReservationIsStartedAndOwnedAtomically() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "retire-before-attach-test")
        let reservationAcquired = SMBRetirementEvent()
        let reservationRelease = SMBRetirementEvent()
        let cancellationObserved = SMBRetirementCallbackCounter()
        let refundEntered = SMBRetirementEvent()
        let refundRelease = SMBRetirementEvent()
        let probe = SMBRetirementCreditProbe()
        await window.setReservationAcquiredHookForTesting { _ in
            await reservationAcquired.signal()
            await reservationRelease.wait()
            if Task.isCancelled { await cancellationObserved.increment() }
        }
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 20),
            maximumCharge: 4,
            refundCredits: { charge in
                await probe.started(charge)
                await refundEntered.signal()
                await refundRelease.wait()
                _ = await window.refund(charge: charge)
                await probe.acknowledged(charge)
            }
        )
        let firstStarted = await record.startCreditReservation(window: window, maximumCharge: 4)
        XCTAssertTrue(firstStarted)
        let secondStarted = await record.startCreditReservation(window: window, maximumCharge: 4)
        XCTAssertFalse(secondStarted, "a second call cannot create or attach a second reserve task")
        try await awaitWithTimeout("credit waiter registered") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }
        _ = await window.grant(4)
        try await awaitWithTimeout("reservation succeeded") { await reservationAcquired.wait() }
        let waiterCountAfterGrant = await window.pendingWaiterCount
        XCTAssertEqual(waiterCountAfterGrant, 0)

        let retirement = await record.retireUnsent()
        guard case .retiredLocally(let receipt) = retirement else {
            XCTFail("uncommitted request should retire locally")
            return
        }
        XCTAssertFalse(receipt.isComplete)
        try await awaitWithTimeout("only reservation settlement remains") {
            await record.waitForAcknowledgementCountForTesting(atMost: 1)
        }
        XCTAssertFalse(receipt.isComplete, "retirement must continue to own the successful reservation result")

        await reservationRelease.signal()
        try await awaitWithTimeout("acquired reservation observes retirement cancellation") {
            await cancellationObserved.waitForCount(atLeast: 1)
        }
        try await awaitWithTimeout("late-grant refund entered") { await refundEntered.wait() }
        let balanceBeforeRefundAck = await window.balance
        XCTAssertEqual(balanceBeforeRefundAck, 0)
        XCTAssertFalse(receipt.isComplete, "receipt remains open until the late-grant refund is acknowledged")
        await refundRelease.signal()
        try await awaitWithTimeout("late-grant refund acknowledged") {
            await probe.waitForAcknowledgement(charge: 4, count: 1)
        }
        try await awaitWithTimeout("atomic-reservation retirement receipt completed") { await receipt.wait() }

        let finalBalance = await window.balance
        let refundCalls = await probe.calls(for: 4)
        XCTAssertEqual(finalBalance, 4)
        XCTAssertEqual(refundCalls, 1)
    }

    func testRetirementAckOwnersKeepRecordAliveUntilReceiptCompletes() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "record-lifetime-test")
        let reservationHeld = SMBRetirementEvent()
        let reservationRelease = SMBRetirementEvent()
        let refundEntered = SMBRetirementEvent()
        let refundRelease = SMBRetirementEvent()
        let probe = SMBRetirementCreditProbe()
        let deinitialized = SMBRequestRecordLifetimeProbe()
        await window.setReservationAcquiredHookForTesting { _ in
            await reservationHeld.signal()
            await reservationRelease.wait()
        }
        var record: SMBUnsentRequestRecord? = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 21),
            maximumCharge: 1,
            refundCredits: { charge in
                await probe.started(charge)
                await refundEntered.signal()
                await refundRelease.wait()
                await probe.acknowledged(charge)
            },
            onDeinit: { deinitialized.signal() }
        )
        let weakRecord = SMBWeakRequestRecordBox(record!)
        let reservationStarted = await record!.startCreditReservation(window: window, maximumCharge: 1)
        XCTAssertTrue(reservationStarted)
        try await awaitWithTimeout("reservation waiter registered") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }
        _ = await window.grant(1)
        try await awaitWithTimeout("reservation acquired and held by credit-window test hook") {
            await reservationHeld.wait()
        }
        let decision = await record!.retireUnsent()
        guard case .retiredLocally(let receipt) = decision else {
            XCTFail("record should retire locally")
            return
        }

        record = nil
        XCTAssertNotNil(weakRecord.value, "the settlement owner retains the record while its gate is closed")
        XCTAssertFalse(deinitialized.isSignaled)

        await reservationRelease.signal()
        try await awaitWithTimeout("refund acknowledgement is gated") { await refundEntered.wait() }
        XCTAssertNotNil(weakRecord.value, "the refund acknowledgement owner retains the record while its gate is closed")
        XCTAssertFalse(deinitialized.isSignaled)
        XCTAssertFalse(receipt.isComplete)

        await refundRelease.signal()
        try await awaitWithTimeout("lifecycle receipt completed") { await receipt.wait() }
        try await awaitWithTimeout("record released after all owners complete") { await deinitialized.wait() }
        let refundCalls = await probe.calls(for: 1)
        XCTAssertEqual(refundCalls, 1)
        XCTAssertNil(weakRecord.value, "the receipt does not retain the completed record")
    }

    func testRecordKeepsCommitCallerSendAndWireStateIndependent() async {
        let successful = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 3),
            maximumCharge: 2,
            reservedCharge: 2,
            refundCredits: { _ in }
        )
        let committed = await successful.commitSend(messageId: 42)
        XCTAssertTrue(committed)
        let retireDecision = await successful.retireUnsent()
        if case .committedNeedsWireDrain(let identity) = retireDecision {
            let successfulIdentity = await successful.identity
            XCTAssertEqual(identity, successfulIdentity)
        } else {
            XCTFail("committed request must retain wire ownership")
        }
        await successful.markWireStatusPending(asyncId: 99)
        await successful.markWireFinalAccepted()
        await successful.markSendFullySent()
        await successful.markCallerTerminal(.success)
        let successState = await successful.snapshot()
        XCTAssertEqual(successState.caller, .success)
        XCTAssertEqual(successState.send, .fullySent)
        XCTAssertEqual(successState.wire, .finalAccepted)
        XCTAssertEqual(successState.credit, .committed(actualCharge: 2))

        let failed = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 4),
            maximumCharge: 1,
            reservedCharge: 1,
            refundCredits: { _ in }
        )
        let failedCommitted = await failed.commitSend(messageId: 43)
        XCTAssertTrue(failedCommitted)
        await failed.markSendFailed()
        await failed.markCallerTerminal(.transportError)
        await failed.markSessionTerminal()
        let terminalState = await failed.snapshot()
        XCTAssertEqual(terminalState.caller, .transportError)
        XCTAssertEqual(terminalState.send, .failed)
        XCTAssertEqual(terminalState.wire, .sessionTerminal)
        XCTAssertEqual(terminalState.credit, .discardedOnTerminal)
    }

    func testLocalRetirementRequiresNotStartedSendAndPreservesTerminalCallerOutcome() async {
        let fullySent = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 22),
            maximumCharge: 2,
            reservedCharge: 2,
            refundCredits: { _ in }
        )
        let fullSendCommitted = await fullySent.commitSend(messageId: 42)
        XCTAssertTrue(fullSendCommitted)
        await fullySent.markSendFullySent()
        await fullySent.markCallerTerminal(.success)
        let fullSendDecision = await fullySent.retireUnsent()
        guard case .committedNeedsWireDrain(let fullSendIdentity) = fullSendDecision else {
            XCTFail("fully sent request must remain committed for wire drain")
            return
        }
        let expectedFullSendIdentity = await fullySent.identity
        XCTAssertEqual(fullSendIdentity, expectedFullSendIdentity)
        let fullSendSnapshot = await fullySent.snapshot()
        XCTAssertEqual(fullSendSnapshot.caller, .success)
        XCTAssertEqual(fullSendSnapshot.send, .fullySent)
        XCTAssertEqual(fullSendSnapshot.credit, .committed(actualCharge: 2))

        let failedSend = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 23),
            maximumCharge: 1,
            reservedCharge: 1,
            refundCredits: { _ in }
        )
        let failureCommitted = await failedSend.commitSend(messageId: 43)
        XCTAssertTrue(failureCommitted)
        await failedSend.markSendFailed()
        await failedSend.markCallerTerminal(.transportError)
        let failedSendDecision = await failedSend.retireUnsent()
        guard case .committedNeedsWireDrain(let failedSendIdentity) = failedSendDecision else {
            XCTFail("send failure after commit must not be reclassified as unsent")
            return
        }
        let expectedFailedSendIdentity = await failedSend.identity
        XCTAssertEqual(failedSendIdentity, expectedFailedSendIdentity)
        let failedSendSnapshot = await failedSend.snapshot()
        XCTAssertEqual(failedSendSnapshot.caller, .transportError)
        XCTAssertEqual(failedSendSnapshot.send, .failed)
        XCTAssertEqual(failedSendSnapshot.credit, .committed(actualCharge: 1))

        let callerAlreadyCompleted = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 26),
            maximumCharge: 1,
            refundCredits: { _ in }
        )
        await callerAlreadyCompleted.markCallerTerminal(.success)
        let localRetirement = await callerAlreadyCompleted.retireUnsent()
        guard case .retiredLocally = localRetirement else {
            XCTFail("a not-started send remains locally retireable")
            return
        }
        let callerAlreadyCompletedSnapshot = await callerAlreadyCompleted.snapshot()
        XCTAssertEqual(callerAlreadyCompletedSnapshot.caller, .success, "local retirement only changes a pending caller")
    }

    func testCallerCompletionCallbackRunsOnceForEachTerminalState() async throws {
        let terminalStates: [SMBRequestCallerState] = [
            .success,
            .localRefusal,
            .cancelled,
            .timedOut,
            .transportError
        ]

        for (index, terminalState) in terminalStates.enumerated() {
            let callbackCounter = SMBRetirementCallbackCounter()
            let record = SMBUnsentRequestRecord(
                identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: UInt64(30 + index)),
                maximumCharge: 1,
                refundCredits: { _ in },
                completeCaller: { await callbackCounter.increment() }
            )

            let firstTransition = await record.markCallerTerminal(terminalState)
            XCTAssertTrue(firstTransition)
            let repeatedTransition = await record.markCallerTerminal(.transportError)
            XCTAssertFalse(repeatedTransition)
            guard case .retiredLocally(let receipt) = await record.retireUnsent() else {
                XCTFail("not-started send should retire locally after caller completion")
                continue
            }
            guard case .alreadyRetired(let duplicateReceipt) = await record.retireUnsent() else {
                XCTFail("duplicate retire should reuse the same receipt")
                continue
            }
            XCTAssertEqual(receipt, duplicateReceipt)

            try await awaitWithTimeout("caller completion and retirement acknowledgements") {
                await record.waitForAcknowledgementCountForTesting(atMost: 0)
            }
            let callbackCount = await callbackCounter.count
            XCTAssertEqual(callbackCount, 1, "caller terminal state \(terminalState) must claim completion once")
            await receipt.wait()
        }

        let callbackCounter = SMBRetirementCallbackCounter()
        let pendingCaller = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 40),
            maximumCharge: 1,
            refundCredits: { _ in },
            completeCaller: { await callbackCounter.increment() }
        )
        guard case .retiredLocally(let receipt) = await pendingCaller.retireUnsent() else {
            XCTFail("pending caller should complete through local retirement")
            return
        }
        try await awaitWithTimeout("local refusal completion acknowledgement") {
            await pendingCaller.waitForAcknowledgementCountForTesting(atMost: 0)
        }
        let callbackCount = await callbackCounter.count
        XCTAssertEqual(callbackCount, 1, "local refusal claims and invokes caller completion once")
        await receipt.wait()
    }

    func testSessionTerminalCannotBeReopenedByPrepareOrCommit() async {
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 24),
            maximumCharge: 2,
            reservedCharge: 2,
            refundCredits: { _ in }
        )
        await record.markSessionTerminal()
        let preparedAfterTerminal = await record.prepareCredit(actualCharge: 1)
        let committedAfterTerminal = await record.commitSend(messageId: 44)
        XCTAssertFalse(preparedAfterTerminal)
        XCTAssertFalse(committedAfterTerminal)
        let snapshot = await record.snapshot()
        XCTAssertEqual(snapshot.wire, .sessionTerminal)
        XCTAssertEqual(snapshot.send, .notStarted)
        XCTAssertEqual(snapshot.credit, .discardedOnTerminal)
    }

    func testLateReservationAfterSessionTerminalCannotCommit() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "terminal-late-reservation-test")
        let resultReady = SMBRetirementEvent()
        let resultRelease = SMBRetirementEvent()
        await window.setReservationAcquiredHookForTesting { _ in
            await resultReady.signal()
            await resultRelease.wait()
        }
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 25),
            maximumCharge: 2,
            refundCredits: { _ in XCTFail("terminal reservations are discarded, not reattached or refunded") }
        )
        let reservationStarted = await record.startCreditReservation(window: window, maximumCharge: 2)
        XCTAssertTrue(reservationStarted)
        try await awaitWithTimeout("reservation waiter registered") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }
        _ = await window.grant(2)
        try await awaitWithTimeout("reservation acquired before terminal transition") { await resultReady.wait() }

        await record.markSessionTerminal()
        await resultRelease.signal()
        try await awaitWithTimeout("terminal reservation settlement acknowledgement") {
            await record.waitForAcknowledgementCountForTesting(atMost: 0)
        }
        let committedAfterGrant = await record.commitSend(messageId: 45)
        XCTAssertFalse(committedAfterGrant)
        let snapshot = await record.snapshot()
        XCTAssertEqual(snapshot.wire, .sessionTerminal)
        XCTAssertEqual(snapshot.credit, .discardedOnTerminal)
        XCTAssertEqual(snapshot.send, .notStarted)
    }

    func testSessionTerminalCancelsRealCreditWindowWaiter() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "terminal-cancels-waiter-test")
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 27),
            maximumCharge: 1,
            refundCredits: { _ in XCTFail("cancelled waiter cannot produce a grant to refund") }
        )
        let started = await record.startCreditReservation(window: window, charge: 1)
        XCTAssertTrue(started)
        try await awaitWithTimeout("real credit waiter is parked") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }

        await record.markSessionTerminal()
        try await awaitWithTimeout("cancelled credit waiter settlement acknowledgement") {
            await record.waitForAcknowledgementCountForTesting(atMost: 0)
        }
        let waiterCount = await window.pendingWaiterCount
        XCTAssertEqual(waiterCount, 0)
        let state = await record.snapshot()
        XCTAssertEqual(state.credit, .discardedOnTerminal)
        XCTAssertEqual(state.outstandingAcknowledgements, 0)
    }

    func testFailedCreditReservationLeavesCreditWaiting() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "failed-reservation-test")
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 28),
            maximumCharge: 2,
            refundCredits: { _ in XCTFail("a reservation that failed before acquisition has nothing to refund") }
        )
        let started = await record.startCreditReservation(window: window, maximumCharge: 2)
        XCTAssertTrue(started)
        try await awaitWithTimeout("failed reservation waiter registered") {
            await window.waitForPendingWaiterCount(atLeast: 1)
        }

        await window.failAllWaiters(SMBTransportError.connectionClosed)
        try await awaitWithTimeout("failed reservation settled") {
            await record.waitForAcknowledgementCountForTesting(atMost: 0)
        }

        let snapshot = await record.snapshot()
        XCTAssertEqual(snapshot.credit, .waiting, "failure before acquisition cannot claim a refund")
    }

    func testSurplusAndResidualRefundAcknowledgementsIndependentlyGateReceipt() async throws {
        for blockedCharge: UInt16 in [3, 1] {
            let window = SMB2CreditWindow(initialCredits: 4, diagnosticSessionId: "independent-refund-ack-test")
            let reservedBalance = try await window.reserve(charge: 4)
            XCTAssertEqual(reservedBalance, 0)
            let blockedAckEntered = SMBRetirementEvent()
            let blockedAckRelease = SMBRetirementEvent()
            let probe = SMBRetirementCreditProbe()
            let record = SMBUnsentRequestRecord(
                identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: UInt64(blockedCharge)),
                maximumCharge: 4,
                reservedCharge: 4,
                refundCredits: { charge in
                    await probe.started(charge)
                    if charge == blockedCharge {
                        await blockedAckEntered.signal()
                        await blockedAckRelease.wait()
                    }
                    _ = await window.refund(charge: charge)
                    await probe.acknowledged(charge)
                }
            )
            let prepared = await record.prepareCredit(actualCharge: 1)
            XCTAssertTrue(prepared)

            if blockedCharge == 1 {
                try await awaitWithTimeout("surplus acknowledgement before retire") {
                    await probe.waitForAcknowledgement(charge: 3, count: 1)
                }
                try await awaitWithTimeout("surplus refund acknowledgement") {
                    await record.waitForAcknowledgementCountForTesting(atMost: 0)
                }
            } else {
                try await awaitWithTimeout("surplus acknowledgement gate entered") { await blockedAckEntered.wait() }
            }

            let decision = await record.retireUnsent()
            guard case .retiredLocally(let receipt) = decision else {
                XCTFail("request must retire locally")
                return
            }
            if blockedCharge == 3 {
                try await awaitWithTimeout("residual acknowledgement while surplus remains blocked") {
                    await probe.waitForAcknowledgement(charge: 1, count: 1)
                }
            } else {
                try await awaitWithTimeout("residual acknowledgement gate entered") { await blockedAckEntered.wait() }
            }
            let blockedOwner: SMBRequestRefundOwner = blockedCharge == 3 ? .surplus : .residual
            try await awaitWithTimeout("only the selected refund acknowledgement remains") {
                await record.waitForOnlyPendingRefundAcknowledgementForTesting(blockedOwner)
            }
            let acknowledgements = await record.acknowledgementSnapshotForTesting()
            XCTAssertEqual(acknowledgements.outstandingCount, 1)
            XCTAssertEqual(acknowledgements.reservationSettlement, nil)
            XCTAssertEqual(acknowledgements.refunds[.surplus], blockedCharge == 3 ? .pending : .acknowledged)
            XCTAssertEqual(acknowledgements.refunds[.residual], blockedCharge == 1 ? .pending : .acknowledged)
            XCTAssertEqual(acknowledgements.effects[.removeQueuedItem], .acknowledged)
            XCTAssertEqual(acknowledgements.effects[.releaseTimer], .acknowledged)
            XCTAssertEqual(acknowledgements.effects[.completeCaller], .acknowledged)
            XCTAssertFalse(receipt.isComplete, "the one held refund acknowledgement must keep the receipt open")

            await blockedAckRelease.signal()
            try await awaitWithTimeout("single held refund acknowledgement released") { await receipt.wait() }
            let finalAcknowledgements = await record.acknowledgementSnapshotForTesting()
            XCTAssertEqual(finalAcknowledgements.outstandingCount, 0)
            XCTAssertTrue(finalAcknowledgements.refunds.values.allSatisfy { $0 == .acknowledged })
            XCTAssertTrue(finalAcknowledgements.effects.values.allSatisfy { $0 == .acknowledged })
            let finalBalance = await window.balance
            let surplusCalls = await probe.calls(for: 3)
            let residualCalls = await probe.calls(for: 1)
            XCTAssertEqual(finalBalance, 4)
            XCTAssertEqual(surplusCalls, 1)
            XCTAssertEqual(residualCalls, 1)
        }
    }

    func testRetirementRecordHasNoPipelineState() async {
        let record = SMBUnsentRequestRecord(
            identity: SMBRequestIdentity(sessionInstance: UUID(), generation: 1, requestSequence: 5),
            maximumCharge: 4,
            reservedCharge: 4,
            refundCredits: { _ in }
        )
        let labels = Set(Mirror(reflecting: record).children.compactMap(\.label))
        XCTAssertFalse(labels.contains("transferEpoch"))
        XCTAssertFalse(labels.contains("bulkSlot"))
        XCTAssertFalse(labels.contains("byteLease"))
        XCTAssertFalse(labels.contains("delivery"))
    }

    func testRequestIdentityIsStableAndSessionIndexIsReclaimedOnTerminal() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: CommandAwareCloseTimeoutTransport(),
            initialCredits: 1
        )
        let first = Task { try await session.parkPendingForTesting(messageId: 100, command: SMB2Commands.echo) }
        let second = Task { try await session.parkPendingForTesting(messageId: 101, command: SMB2Commands.read) }
        try await awaitWithTimeout("identity records registered") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }
        let firstValue = await session.requestIdentityForTesting(messageId: 100)
        let secondValue = await session.requestIdentityForTesting(messageId: 101)
        let firstIdentity = try XCTUnwrap(firstValue)
        let secondIdentity = try XCTUnwrap(secondValue)
        XCTAssertEqual(firstIdentity.sessionInstance, secondIdentity.sessionInstance)
        XCTAssertEqual(firstIdentity.generation, secondIdentity.generation)
        XCTAssertNotEqual(firstIdentity.requestSequence, secondIdentity.requestSequence)
        let activeBeforeClose = await session.activeRequestIdentityCountForTesting()
        XCTAssertEqual(activeBeforeClose, 2)

        await session.closeTransportAndWait(cause: "test_identity_index_reclamation")
        _ = try? await first.value
        _ = try? await second.value
        let activeAfterClose = await session.activeRequestIdentityCountForTesting()
        let wireRecordsAfterClose = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(activeAfterClose, 0)
        XCTAssertEqual(wireRecordsAfterClose, 0)
    }

    func testOpenSessionReclaimsIdentitiesForFinalCancelledFinalAndCorrelationFailure() async throws {
        let transport = CommandAwareCloseTimeoutTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        defer { Task { await session.closeTransport(cause: "test_identity_removal_paths") } }

        let normalRegistered = SMBRetirementEvent()
        let normalFinal = Task {
            try await session.parkPendingForTesting(
                messageId: 110,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { Task { await normalRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("normal-final pending record registered") { await normalRegistered.wait() }
        await assertPendingIdentityCounts(session, pending: 1, identities: 1)
        try await session.dispatchReceivedPacketForTesting(
            SMB2Header(command: SMB2Commands.echo, messageId: 110).encode()
        )
        _ = try await normalFinal.value
        await assertPendingIdentityCounts(session, pending: 0, identities: 0)

        let cancelledRegistered = SMBRetirementEvent()
        let cancelledFinal = Task {
            try await session.parkPendingForTesting(
                messageId: 111,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { Task { await cancelledRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("cancelled pending record registered") { await cancelledRegistered.wait() }
        await session.failPendingResponseForTesting(messageId: 111, error: CancellationError())
        do {
            _ = try await cancelledFinal.value
            XCTFail("caller cancellation should be delivered before the wire final")
        } catch is CancellationError {
            // The tombstone remains to correlate the late final.
        }
        await assertPendingIdentityCounts(session, pending: 1, identities: 1)
        let tombstoneCount = await session.ordinaryCancellationTombstoneCountForTesting()
        XCTAssertEqual(tombstoneCount, 1, "cancel tombstone remains wire-owned with its identity")
        try await session.dispatchReceivedPacketForTesting(
            SMB2Header(command: SMB2Commands.echo, messageId: 111).encode()
        )
        await assertPendingIdentityCounts(session, pending: 0, identities: 0)

        let correlationRegistered = SMBRetirementEvent()
        let correlationFailure = Task {
            try await session.parkPendingForTesting(
                messageId: 112,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { Task { await correlationRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("correlation-failure pending record registered") { await correlationRegistered.wait() }
        try await session.dispatchReceivedPacketForTesting(
            SMB2Header.asyncHeader(
                status: SMB2Status.pending,
                command: SMB2Commands.echo,
                credits: 0,
                messageId: 112,
                asyncId: 0x1111
            ).encode()
        )
        await assertPendingIdentityCounts(session, pending: 1, identities: 1)
        do {
            try await session.dispatchReceivedPacketForTesting(
                SMB2Header.asyncHeader(
                    command: SMB2Commands.echo,
                    credits: 0,
                    messageId: 112,
                    asyncId: 0x2222
                ).encode()
            )
            XCTFail("a mismatched final must raise a wire correlation fault")
        } catch SMBCodecError.invalidValue {
        }
        await assertPendingIdentityCounts(session, pending: 1, identities: 1)
        let transportClosedBeforeTeardown = await session.isTransportClosedForTesting()
        XCTAssertFalse(transportClosedBeforeTeardown, "the direct validation seam leaves terminal handling to its reader")
        await session.closeTransportAndWait(cause: "test_identity_correlation_wire_fault")
        do {
            _ = try await correlationFailure.value
            XCTFail("mismatched AsyncId must fail its pending request")
        } catch SMBTransportError.connectionClosed {
        }
        await assertPendingIdentityCounts(session, pending: 0, identities: 0)
    }

    func testProductionAndFakeMonotonicTimeSourcesUseTheirPairedClock() async throws {
        let production = SMBSessionMonotonicTime.production()
        let productionStart = production.now()
        try await production.sleep(.milliseconds(1))
        XCTAssertGreaterThanOrEqual(productionStart.duration(to: production.now()), .milliseconds(1))

        let fake = SMBVirtualMonotonicTime()
        let virtual = fake.source
        let virtualStart = virtual.now()
        try await virtual.sleep(.seconds(7))
        XCTAssertEqual(virtualStart.duration(to: virtual.now()), .seconds(7))
    }

    func testSendingStatusPendingAndFinalInOneCompoundKeepCallerBehindSendGate() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let messageId: UInt64 = 0x501
        let asyncId: UInt64 = 0x1122_3344_5566_7788
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sending: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("sending request registered") { await registered.wait() }

        let interim = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: SMB2Commands.echo,
            credits: 3,
            nextCommand: UInt32(SMB2Header.encodedSize),
            messageId: messageId,
            asyncId: asyncId
        ).encode()
        let final = try SMB2Header.asyncHeader(
            command: SMB2Commands.echo,
            credits: 5,
            messageId: messageId,
            asyncId: asyncId
        ).encode()
        _ = try await session.processRawFrameForTesting(interim + final, generation: 1)

        assertAwaitedEqual(await session.pendingAsyncIdForTesting(messageId: messageId), asyncId)
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 8)

        await session.markRequestSentWithoutReaderForTesting(messageId: messageId)
        try await awaitWithTimeout("caller released after full send") { _ = try await caller.value }
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 0)
        await session.closeTransportAndWait(cause: "test_sending_compound_send_gate")
    }

    func testSendingStatusPendingAndFinalAcrossFramesKeepAsyncIdBeforeSendGate() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let messageId: UInt64 = 0x502
        let asyncId: UInt64 = 0x8877_6655_4433_2211
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sending: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("sending request registered") { await registered.wait() }

        let interim = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: SMB2Commands.echo,
            credits: 2,
            messageId: messageId,
            asyncId: asyncId
        ).encode()
        let final = try SMB2Header.asyncHeader(
            command: SMB2Commands.echo,
            credits: 4,
            messageId: messageId,
            asyncId: asyncId
        ).encode()
        _ = try await session.processRawFrameForTesting(interim, generation: 1)
        assertAwaitedEqual(await session.pendingAsyncIdForTesting(messageId: messageId), asyncId)
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))

        _ = try await session.processRawFrameForTesting(final, generation: 1)
        let acceptedAt = try awaitUnwrap(await session.lastFinalAcceptanceForTesting())
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)

        await session.markRequestSentWithoutReaderForTesting(messageId: messageId)
        try await awaitWithTimeout("caller released after full send") { _ = try await caller.value }
        assertAwaitedEqual(await session.lastFinalAcceptanceForTesting(), acceptedAt)
        await session.closeTransportAndWait(cause: "test_sending_frames_send_gate")
    }

    func testSignedCopiedStatusPendingDoesNotVerifySignatureAndKeepsSessionAlive() async throws {
        let signingKey = [UInt8](repeating: 0x81, count: 16)
        let sessionId: UInt64 = 0x1234_5678_9ABC_DEF0
        let asyncId: UInt64 = 0x8877_6655_4433_2211
        let transport = CommandAwareCloseTimeoutTransport(
            heldCommands: [SMB2Commands.echo],
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
        await session.setSessionIdForTesting(sessionId)
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("signed ECHO sent") {
            try await transport.waitUntilSent(command: SMB2Commands.echo, count: 1)
        }
        try await awaitWithTimeout("signed ECHO marked sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await transport.waitUntilReceiveIsBlocked()

        let request = try XCTUnwrap(transport.sentPacket(command: SMB2Commands.echo, occurrence: 1))
        let requestHeader = try SMB2Header.decode(request)
        XCTAssertNotEqual(requestHeader.flags & SMB2Flags.signed, 0)
        var interim = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: SMB2Commands.echo,
            credits: 2,
            flags: (requestHeader.flags & SMB2Flags.signed) | 0x0000_0001,
            messageId: requestHeader.messageId,
            asyncId: asyncId,
            sessionId: requestHeader.sessionId,
            signature: requestHeader.signature
        ).encode()
        interim.append(contentsOf: [9, 0, 0, 0, 0, 0, 0, 0])
        try transport.enqueuePacket(interim)
        await transport.waitUntilReceiveIsBlocked()
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 1)
        assertAwaitedEqual(await session.pendingAsyncIdForTesting(messageId: requestHeader.messageId), asyncId)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: requestHeader.messageId))
        let sessionOpenAfterInterim = !(await session.isTransportClosedForTesting())
        assertAwaitedTrue(sessionOpenAfterInterim)
        guard sessionOpenAfterInterim else { return }

        var final = try SMB2Header.asyncHeader(
            status: SMB2Status.success,
            command: SMB2Commands.echo,
            credits: 2,
            flags: 0x0000_0001,
            messageId: requestHeader.messageId,
            asyncId: asyncId,
            sessionId: sessionId
        ).encode()
        final.append(contentsOf: [4, 0, 0, 0])
        final = try signedTestPacket(final, algorithm: .aesCMAC, key: signingKey, sender: .server)
        try transport.enqueuePacket(final)
        try await awaitWithTimeout("signed async ECHO final accepted") { try await echo.value }
        assertAwaitedFalse(await session.isTransportClosedForTesting())
        XCTAssertEqual(transport.closeCallCount, 0)
        await session.closeTransportAndWait(cause: "test_signed_copied_interim")
    }

    func testMaxMessageIdNotificationWithInvalidSignatureIsDiscardedBeforeVerification() async throws {
        let signingKey = [UInt8](repeating: 0x82, count: 16)
        let sessionId: UInt64 = 0x0A0B_0C0D_0E0F_1011
        let transport = CommandAwareCloseTimeoutTransport(
            heldCommands: [SMB2Commands.echo],
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
        await session.setSessionIdForTesting(sessionId)
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("notification-probe ECHO sent") {
            try await transport.waitUntilSent(command: SMB2Commands.echo, count: 1)
        }
        try await awaitWithTimeout("notification-probe ECHO marked sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await transport.waitUntilReceiveIsBlocked()

        let invalidNotification = try SMB2Header(
            command: SMB2Commands.oplockBreak,
            credits: 12,
            flags: 0x0000_0001 | SMB2Flags.signed,
            messageId: UInt64.max,
            sessionId: sessionId,
            signature: [UInt8](repeating: 0xA5, count: 16)
        ).encode()
        try transport.enqueuePacket(invalidNotification)
        await transport.waitUntilReceiveIsBlocked()
        let sessionOpenAfterNotification = !(await session.isTransportClosedForTesting())
        assertAwaitedTrue(sessionOpenAfterNotification)
        guard sessionOpenAfterNotification else { return }
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)

        transport.releaseNextResponse(command: SMB2Commands.echo)
        try await awaitWithTimeout("outstanding ECHO survives invalid notification") { try await echo.value }
        assertAwaitedFalse(await session.isTransportClosedForTesting())
        XCTAssertEqual(transport.closeCallCount, 0)
        await session.closeTransportAndWait(cause: "test_invalid_signature_mid_max_notification")
    }

    func testCompoundChainCompletesSentRequestAndHoldsSendingRequest() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let sentMessageId: UInt64 = 0x50F
        let sendingMessageId: UInt64 = 0x510
        let sentRegistered = SMBRetirementEvent()
        let sendingRegistered = SMBRetirementEvent()
        let sentCaller = Task {
            try await session.parkPendingForTesting(
                messageId: sentMessageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await sentRegistered.signal() } }
            )
        }
        let sendingCaller = Task {
            try await session.parkPendingForTesting(
                messageId: sendingMessageId,
                command: SMB2Commands.echo,
                sending: true,
                onRegistered: { _ = Task { await sendingRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("both compound requests registered") {
            await sentRegistered.wait()
            await sendingRegistered.wait()
        }

        let first = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 4,
            nextCommand: UInt32(SMB2Header.encodedSize),
            messageId: sentMessageId
        ).encode()
        let second = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 6,
            messageId: sendingMessageId
        ).encode()
        _ = try await session.processRawFrameForTesting(first + second, generation: 1)

        try await awaitWithTimeout("sent slice completes its caller") { _ = try await sentCaller.value }
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: sendingMessageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: sendingMessageId))
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 10)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)

        await session.markRequestSentWithoutReaderForTesting(messageId: sendingMessageId)
        try await awaitWithTimeout("sending slice completes after its send gate") { _ = try await sendingCaller.value }
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 0)
        await session.closeTransportAndWait(cause: "test_mixed_sent_sending_compound")
    }

    func testDuplicateFinalCompoundRejectsBeforeAnyGrantOrCallerCompletion() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 1
        )
        let messageId: UInt64 = 0x503
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("sent request registered") { await registered.wait() }

        let first = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 7,
            nextCommand: UInt32(SMB2Header.encodedSize),
            messageId: messageId
        ).encode()
        let duplicate = try SMB2Header(command: SMB2Commands.echo, credits: 9, messageId: messageId).encode()
        do {
            _ = try await session.processRawFrameForTesting(first + duplicate, generation: 1)
            XCTFail("same-chain duplicate final must be rejected")
        } catch SMBCodecError.invalidValue {
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 1)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        await session.closeTransportAndWait(cause: "test_duplicate_final_compound")
        do {
            try await awaitWithTimeout("duplicate-final caller teardown") { _ = try await caller.value }
            XCTFail("the rejected chain must not complete its caller successfully")
        } catch {
        }
    }

    func testInvalidSignatureCannotGrantOrCompletePendingResponse() async throws {
        let key = [UInt8](repeating: 0x42, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            signingKey: key,
            signingRequired: false,
            initialCredits: 0
        )
        let messageId: UInt64 = 0x504
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("sent request registered") { await registered.wait() }

        var badSignature = try signedTestPacket(
            SMB2Header(command: SMB2Commands.echo, credits: 12, messageId: messageId).encode(),
            algorithm: .aesCMAC,
            key: key,
            sender: .server
        )
        badSignature[48] ^= 0x01
        do {
            _ = try await session.processRawFrameForTesting(badSignature, generation: 1)
            XCTFail("invalid response signature must be rejected")
        } catch SMBCodecError.invalidValue {
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        await session.closeTransportAndWait(cause: "test_invalid_signature_no_grant")
        do {
            try await awaitWithTimeout("invalid-signature caller teardown") { _ = try await caller.value }
            XCTFail("invalid response must not complete its caller successfully")
        } catch {
        }
    }

    func testRequiredResponseProtectionFailureRetainsPendingStateUntilOwnerTeardown() async throws {
        let key = [UInt8](repeating: 0x4A, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            signingKey: key,
            signingRequired: false,
            initialCredits: 0
        )
        let messageId: UInt64 = 0x50E
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                responseProtectionPolicy: .signatureOrAEADRequired,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("protected-response request registered") { await registered.wait() }

        let unsigned = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 13,
            messageId: messageId
        ).encode()
        do {
            _ = try await session.processRawFrameForTesting(unsigned, generation: 1)
            XCTFail("request policy must reject an unsigned final before commit")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("authenticated protection"), message)
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        await session.closeTransportAndWait(cause: "test_request_protection_policy_transaction")
        do {
            try await awaitWithTimeout("protected-response caller teardown") { _ = try await caller.value }
            XCTFail("a rejected final must not complete its caller successfully")
        } catch {
        }
    }

    func testUnknownMessageIdIsDiscardedBeforeLaterRequestReusesIt() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let messageId: UInt64 = 0x505
        _ = try await session.processRawFrameForTesting(
            SMB2Header(command: SMB2Commands.echo, credits: 8, messageId: messageId).encode(),
            generation: 1
        )
        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.orphanResponseCountForTesting(), 0)

        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("reused MessageId request registered") { await registered.wait() }
        let newIdentity = try awaitUnwrap(await session.requestIdentityForTesting(messageId: messageId))
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))

        _ = try await session.processRawFrameForTesting(
            SMB2Header(command: SMB2Commands.echo, credits: 1, messageId: messageId).encode(),
            generation: 1
        )
        try await awaitWithTimeout("new request receives only its own final") { _ = try await caller.value }
        assertAwaitedEqual(await session.requestIdentityForTesting(messageId: messageId), nil)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 1)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        assertAwaitedEqual(await session.orphanResponseCountForTesting(), 0)
        XCTAssertNotNil(newIdentity)
        await session.closeTransportAndWait(cause: "test_unknown_mid_no_replay")
    }

    func testPlaintextCompoundVerifiesSignaturePerSliceIncludingPadding() async throws {
        let key = [UInt8](repeating: 0x53, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            signingKey: key,
            signingRequired: true,
            initialCredits: 0
        )
        let firstId: UInt64 = 0x506
        let secondId: UInt64 = 0x507
        let firstRegistered = SMBRetirementEvent()
        let secondRegistered = SMBRetirementEvent()
        let firstCaller = Task {
            try await session.parkPendingForTesting(
                messageId: firstId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await firstRegistered.signal() } }
            )
        }
        let secondCaller = Task {
            try await session.parkPendingForTesting(
                messageId: secondId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await secondRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("both requests registered") {
            await firstRegistered.wait()
            await secondRegistered.wait()
        }

        var first = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 1,
            nextCommand: 72,
            messageId: firstId
        ).encode()
        first.append(contentsOf: Array(repeating: 0, count: 8))
        first = try signedTestPacket(first, algorithm: .aesCMAC, key: key, sender: .server)
        let second = try signedTestPacket(
            SMB2Header(command: SMB2Commands.echo, credits: 2, messageId: secondId).encode(),
            algorithm: .aesCMAC,
            key: key,
            sender: .server
        )
        _ = try await session.processRawFrameForTesting(first + second, generation: 1)

        try await awaitWithTimeout("first compound caller") { _ = try await firstCaller.value }
        try await awaitWithTimeout("second compound caller") { _ = try await secondCaller.value }
        assertAwaitedEqual(await session.creditBalanceForTesting(), 3)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 2)
        await session.closeTransportAndWait(cause: "test_signed_compound_per_slice")
    }

    func testEncryptedCompoundResponseAuthenticatesAndGrantsEverySlice() async throws {
        let key = [UInt8](repeating: 0x64, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let sessionId: UInt64 = 0x8877_6655_4433_2211
        await session.setSessionIdForTesting(sessionId)
        await session.installEncryptionStateForTesting(encryptionKey: key, decryptionKey: key)
        let firstId: UInt64 = 0x508
        let secondId: UInt64 = 0x509
        let firstRegistered = SMBRetirementEvent()
        let secondRegistered = SMBRetirementEvent()
        let firstCaller = Task {
            try await session.parkPendingForTesting(
                messageId: firstId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await firstRegistered.signal() } }
            )
        }
        let secondCaller = Task {
            try await session.parkPendingForTesting(
                messageId: secondId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await secondRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("both encrypted-response requests registered") {
            await firstRegistered.wait()
            await secondRegistered.wait()
        }
        let first = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 2,
            nextCommand: UInt32(SMB2Header.encodedSize),
            messageId: firstId,
            sessionId: sessionId
        ).encode()
        let second = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 3,
            messageId: secondId,
            sessionId: sessionId
        ).encode()
        let encrypted = try encryptCompoundResponse(first + second, key: key, sessionId: sessionId)
        _ = try await session.processRawFrameForTesting(encrypted, generation: 1)

        try await awaitWithTimeout("first encrypted compound caller") { _ = try await firstCaller.value }
        try await awaitWithTimeout("second encrypted compound caller") { _ = try await secondCaller.value }
        assertAwaitedEqual(await session.creditBalanceForTesting(), 5)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)
        await session.closeTransportAndWait(cause: "test_encrypted_compound_response")
    }

    func testEncryptedSingleResponseRejectsInnerSessionIdZeroOrMismatchBeforeCommit() async throws {
        let outerSessionId: UInt64 = 0x8877_6655_4433_2211
        for innerSessionId in [UInt64(0), outerSessionId ^ 0x100] {
            try await assertEncryptedResponseSessionMismatchDoesNotCommit(
                outerSessionId: outerSessionId,
                innerSessionIds: [innerSessionId],
                credits: [9]
            )
        }
    }

    func testEncryptedCompoundRejectsInnerSessionIdZeroOrMismatchBeforeCommit() async throws {
        let outerSessionId: UInt64 = 0x7766_5544_3322_1100
        for innerSessionId in [UInt64(0), outerSessionId ^ 0x100] {
            try await assertEncryptedResponseSessionMismatchDoesNotCommit(
                outerSessionId: outerSessionId,
                innerSessionIds: [outerSessionId, innerSessionId],
                credits: [7, 9]
            )
        }
    }

    func testEncryptedPostFinalResponseStillChecksInnerSessionId() async throws {
        let key = [UInt8](repeating: 0xA7, count: 16)
        let sessionId: UInt64 = 0x8877_6655_4433_2211
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        await session.setSessionIdForTesting(sessionId)
        await session.installEncryptionStateForTesting(encryptionKey: key, decryptionKey: key)

        let messageId: UInt64 = 0x60A
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sending: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("early-final request registered") { await registered.wait() }

        let earlyFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 0,
            messageId: messageId,
            sessionId: sessionId
        ).encode() + [4, 0, 0, 0]
        _ = try await session.processRawFrameForTesting(
            encryptCompoundResponse(earlyFinal, key: key, sessionId: sessionId),
            generation: 1
        )
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)

        let mismatchedFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 65535,
            messageId: messageId,
            sessionId: 0
        ).encode() + [4, 0, 0, 0]
        do {
            _ = try await session.processRawFrameForTesting(
                encryptCompoundResponse(mismatchedFinal, key: key, sessionId: sessionId),
                generation: 1
            )
            XCTFail("a post-final transform slice with inner SessionId zero must be rejected")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("transform inner session id mismatch"), message)
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        await session.closeTransportAndWait(cause: "test_post_final_transform_session_id")
        do {
            try await awaitWithTimeout("post-final request teardown") { try await caller.value }
            XCTFail("early-final caller must remain behind its send gate")
        } catch {
        }
    }

    func testEncryptedCompoundPostFinalMismatchRejectsEarlierFinalAndGrant() async throws {
        let key = [UInt8](repeating: 0xA8, count: 16)
        let sessionId: UInt64 = 0x7766_5544_3322_1100
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        await session.setSessionIdForTesting(sessionId)
        await session.installEncryptionStateForTesting(encryptionKey: key, decryptionKey: key)

        let firstMessageId: UInt64 = 0x60B
        let earlyFinalMessageId: UInt64 = 0x60C
        let firstRegistered = SMBRetirementEvent()
        let earlyFinalRegistered = SMBRetirementEvent()
        let firstCaller = Task {
            try await session.parkPendingForTesting(
                messageId: firstMessageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await firstRegistered.signal() } }
            )
        }
        let earlyFinalCaller = Task {
            try await session.parkPendingForTesting(
                messageId: earlyFinalMessageId,
                command: SMB2Commands.echo,
                sending: true,
                onRegistered: { _ = Task { await earlyFinalRegistered.signal() } }
            )
        }
        try await awaitWithTimeout("compound requests registered") {
            await firstRegistered.wait()
            await earlyFinalRegistered.wait()
        }

        let earlyFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 0,
            messageId: earlyFinalMessageId,
            sessionId: sessionId
        ).encode() + [4, 0, 0, 0]
        _ = try await session.processRawFrameForTesting(
            encryptCompoundResponse(earlyFinal, key: key, sessionId: sessionId),
            generation: 1
        )
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: earlyFinalMessageId))
        let grantsBeforeCompound = await session.creditGrantReceiptCountForTesting()
        let balanceBeforeCompound = await session.creditBalanceForTesting()

        let firstFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 31,
            nextCommand: UInt32(SMB2Header.encodedSize),
            messageId: firstMessageId,
            sessionId: sessionId
        ).encode()
        let mismatchedPostFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 37,
            messageId: earlyFinalMessageId,
            sessionId: 0
        ).encode()
        do {
            _ = try await session.processRawFrameForTesting(
                encryptCompoundResponse(firstFinal + mismatchedPostFinal, key: key, sessionId: sessionId),
                generation: 1
            )
            XCTFail("a post-final SessionId mismatch must reject the complete compound chain")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("transform inner session id mismatch"), message)
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), balanceBeforeCompound)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), grantsBeforeCompound)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: firstMessageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: firstMessageId))
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: earlyFinalMessageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: earlyFinalMessageId))

        await session.closeTransportAndWait(cause: "test_compound_post_final_transform_session_id")
        for caller in [firstCaller, earlyFinalCaller] {
            do {
                try await awaitWithTimeout("compound request teardown") { try await caller.value }
                XCTFail("rejected compound must not complete either caller")
            } catch {
            }
        }
    }

    func testSeparateFinalAfterEarlySendingFinalIsDiscardedAndDoesNotFailOtherRequest() async throws {
        let transport = CommandAwareCloseTimeoutTransport(heldCommands: [SMB2Commands.echo])
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 5
        )
        let unrelatedRequest = Task { try await session.echo() }
        try await awaitWithTimeout("unrelated ECHO sent") {
            try await transport.waitUntilSent(command: SMB2Commands.echo, count: 1)
        }
        try await awaitWithTimeout("unrelated ECHO marked sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await transport.waitUntilReceiveIsBlocked()

        transport.blockSends(for: [SMB2Commands.echo])
        let earlyFinalRequest = Task { try await session.echo() }
        try await awaitWithTimeout("second ECHO entered blocked send") {
            try await transport.waitUntilSent(command: SMB2Commands.echo, count: 2)
            await transport.waitUntilBlockedSendCount(1)
        }
        try await awaitWithTimeout("both unrelated and early-final requests registered") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }
        let messageIds = transport.messageIds(for: SMB2Commands.echo)
        XCTAssertEqual(messageIds.count, 2)
        let earlyFinalMessageId = try XCTUnwrap(messageIds.last)
        let earlyFinal = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.echo,
            credits: 4,
            messageId: earlyFinalMessageId
        ).encode() + [4, 0, 0, 0]

        try transport.enqueuePacket(earlyFinal)
        try await awaitWithTimeout("early final accepted while send is blocked") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: earlyFinalMessageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: earlyFinalMessageId))
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 7)
        await transport.waitUntilReceiveIsBlocked()

        try transport.enqueuePacket(earlyFinal)
        await transport.waitUntilReceiveIsBlocked()
        let sessionOpenAfterDuplicate = !(await session.isTransportClosedForTesting())
        assertAwaitedTrue(sessionOpenAfterDuplicate)
        guard sessionOpenAfterDuplicate else { return }
        assertAwaitedTrue(await session.pendingFinalSeenForTesting(messageId: earlyFinalMessageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: earlyFinalMessageId))
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 7)
        await transport.waitUntilReceiveIsBlocked()

        transport.releaseBlockedSends(for: SMB2Commands.echo)
        try await awaitWithTimeout("early-final caller succeeds after full send") { try await earlyFinalRequest.value }
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 1)
        transport.releaseNextResponse(command: SMB2Commands.echo)
        try await awaitWithTimeout("unrelated ECHO caller remains successful") { try await unrelatedRequest.value }
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 2)
        assertAwaitedFalse(await session.isTransportClosedForTesting())
        XCTAssertEqual(transport.closeCallCount, 0)
        await session.closeTransportAndWait(cause: "test_duplicate_final_in_later_frame")
    }

    func testMalformedCompoundTailOrNextCommandCannotCommitFirstSlice() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 2
        )
        let messageId: UInt64 = 0x50A
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("request registered") { await registered.wait() }

        var first = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 11,
            nextCommand: 72,
            messageId: messageId
        ).encode()
        first.append(contentsOf: Array(repeating: 0, count: 8))
        let shortTail = Array(repeating: UInt8(0), count: SMB2Header.encodedSize - 1)
        do {
            _ = try await session.processRawFrameForTesting(first + shortTail, generation: 1)
            XCTFail("short later compound header must reject the complete chain")
        } catch SMBCodecError.invalidValue {
        }
        let unaligned = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 11,
            nextCommand: 70,
            messageId: messageId
        ).encode() + Array(repeating: 0, count: 6) + (try SMB2Header(command: SMB2Commands.echo, messageId: messageId).encode())
        do {
            _ = try await session.processRawFrameForTesting(unaligned, generation: 1)
            XCTFail("unaligned NextCommand must reject the complete chain")
        } catch SMBCodecError.invalidValue {
        }
        let shortOffset = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 11,
            nextCommand: 32,
            messageId: messageId
        ).encode() + Array(repeating: UInt8(0), count: 32)
        do {
            _ = try await session.processRawFrameForTesting(shortOffset, generation: 1)
            XCTFail("NextCommand shorter than a complete SMB2 header must reject the chain")
        } catch SMBCodecError.invalidValue {
        }
        let outOfBounds = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 11,
            nextCommand: 256,
            messageId: messageId
        ).encode() + (try SMB2Header(command: SMB2Commands.echo, messageId: messageId).encode())
        do {
            _ = try await session.processRawFrameForTesting(outOfBounds, generation: 1)
            XCTFail("out-of-bounds NextCommand must reject the complete chain")
        } catch SMBCodecError.invalidValue {
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 2)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 0)
        assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))
        assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        await session.closeTransportAndWait(cause: "test_malformed_compound_chain")
        do {
            try await awaitWithTimeout("malformed-chain caller teardown") { _ = try await caller.value }
            XCTFail("malformed chain must not complete its caller successfully")
        } catch {
        }
    }

    func testFinalAcceptancePrecedesCreditActorAcknowledgement() async throws {
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        let messageId: UInt64 = 0x50B
        let registered = SMBRetirementEvent()
        let caller = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { _ = Task { await registered.signal() } }
            )
        }
        try await awaitWithTimeout("request registered") { await registered.wait() }

        let grantGate = SMBContinuationAsyncGate()
        let gateClock = ManualSMBSleeper()
        await session.setCreditGrantActorHookForTesting {
            try? await grantGate.suspend(timeout: .seconds(30), sleeper: { try await gateClock.sleep(for: $0) })
        }
        let processing = Task {
            _ = try await session.processRawFrameForTesting(
                SMB2Header(command: SMB2Commands.echo, credits: 1, messageId: messageId).encode(),
                generation: 1
            )
        }
        try await awaitWithTimeout("credit actor grant paused") {
            try await grantGate.waitUntilSuspended(
                timeout: .seconds(1),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        let acceptedAt = try awaitUnwrap(await session.lastFinalAcceptanceForTesting())
        try await awaitWithTimeout("caller completes while credit actor is paused") { _ = try await caller.value }
        assertAwaitedEqual(await session.lastFinalAcceptanceForTesting(), acceptedAt)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)

        grantGate.release()
        _ = try await processing.value
        assertAwaitedEqual(await session.lastFinalAcceptanceForTesting(), acceptedAt)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 1)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        await session.closeTransportAndWait(cause: "test_final_acceptance_before_credit_ack")
    }

    func testOptionalSigningSessionRejectsUnsignedValidateNegotiateBeforeCommit() async throws {
        let key = [UInt8](repeating: 0x75, count: 16)
        let messageId: UInt64 = 0x50C
        let sessionId: UInt64 = 0x1234_5678
        let response = try SMB2Header(
            command: SMB2Commands.ioctl,
            credits: 13,
            messageId: messageId,
            treeId: 2,
            sessionId: sessionId
        ).encode()
        let transport = SMBContinuationScriptTransport(inbound: try DirectTCPFraming.frame(response))
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: key,
            signingRequired: false,
            initialCredits: 4
        )
        await session.setSessionIdForTesting(sessionId)
        let request = try SMB2Header(
            command: SMB2Commands.ioctl,
            messageId: messageId,
            treeId: 2,
            sessionId: sessionId
        ).encode() + Array(repeating: UInt8(0), count: 86)
        do {
            _ = try await awaitWithTimeout("unsigned VALIDATE_NEGOTIATE_INFO rejection") {
                try await session.validateNegotiateWireTransactionForTesting(packet: request)
            }
            XCTFail("unsigned plaintext VALIDATE_NEGOTIATE_INFO must be rejected")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("authenticated protection"), message)
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 3, "request charge remains consumed; response grant is not applied")
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 0, "the final is not committed")
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), 0, "terminal teardown removes the failed wire record")
        assertAwaitedTrue(await session.isTransportClosedForTesting())
        await session.closeTransportAndWait(cause: "test_unsigned_validate_negotiate_rejected")
    }

    func testOptionalSigningSessionAcceptsSignedValidateNegotiateFinal() async throws {
        let key = [UInt8](repeating: 0x76, count: 16)
        let messageId: UInt64 = 0x50D
        let sessionId: UInt64 = 0x8765_4321
        let unsigned = try SMB2Header(
            command: SMB2Commands.ioctl,
            credits: 7,
            messageId: messageId,
            treeId: 3,
            sessionId: sessionId
        ).encode()
        let response = try signedTestPacket(unsigned, algorithm: .aesCMAC, key: key, sender: .server)
        let transport = SMBContinuationScriptTransport(inbound: try DirectTCPFraming.frame(response))
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: key,
            signingRequired: false,
            initialCredits: 4
        )
        await session.setSessionIdForTesting(sessionId)
        let request = try SMB2Header(
            command: SMB2Commands.ioctl,
            messageId: messageId,
            treeId: 3,
            sessionId: sessionId
        ).encode() + Array(repeating: UInt8(0), count: 86)
        let received = try await awaitWithTimeout("signed VALIDATE_NEGOTIATE_INFO accepted") {
            try await session.validateNegotiateWireTransactionForTesting(packet: request)
        }
        XCTAssertEqual(try SMB2Header.decode(received).messageId, messageId)
        assertAwaitedEqual(await session.creditBalanceForTesting(), 10)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 1)
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 1)
        assertAwaitedFalse(await session.isTransportClosedForTesting())
        await session.closeTransportAndWait(cause: "test_signed_validate_negotiate_accepted")
    }

    private func assertAwaitedEqual<T: Equatable>(
        _ actual: T,
        _ expected: T,
        _ message: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual, expected, message ?? "", file: file, line: line)
    }

    private func assertAwaitedTrue(
        _ actual: Bool,
        _ message: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(actual, message ?? "", file: file, line: line)
    }

    private func assertAwaitedFalse(
        _ actual: Bool,
        _ message: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(actual, message ?? "", file: file, line: line)
    }

    private func awaitUnwrap<T>(
        _ value: T?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> T {
        try XCTUnwrap(value, file: file, line: line)
    }

    private func encryptCompoundResponse(_ plaintext: [UInt8], key: [UInt8], sessionId: UInt64) throws -> [UInt8] {
        let nonce = Array(repeating: UInt8(0x2A), count: 11)
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: sessionId
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        return try header.encode() + sealed.ciphertext
    }

    private func assertEncryptedResponseSessionMismatchDoesNotCommit(
        outerSessionId: UInt64,
        innerSessionIds: [UInt64],
        credits: [UInt16]
    ) async throws {
        XCTAssertEqual(innerSessionIds.count, credits.count)
        let key = [UInt8](repeating: 0xA6, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationScriptTransport(inbound: []),
            initialCredits: 0
        )
        await session.setSessionIdForTesting(outerSessionId)
        await session.installEncryptionStateForTesting(encryptionKey: key, decryptionKey: key)

        var messageIds: [UInt64] = []
        var registrations: [SMBRetirementEvent] = []
        var callers: [Task<Void, Error>] = []
        for index in innerSessionIds.indices {
            let messageId = UInt64(0x600 + index)
            let registered = SMBRetirementEvent()
            messageIds.append(messageId)
            registrations.append(registered)
            callers.append(Task {
                try await session.parkPendingForTesting(
                    messageId: messageId,
                    command: SMB2Commands.echo,
                    sent: true,
                    onRegistered: { _ = Task { await registered.signal() } }
                )
            })
        }
        let registrationEvents = registrations
        try await awaitWithTimeout("all encrypted requests registered") {
            for registered in registrationEvents {
                await registered.wait()
            }
        }

        var plaintext: [UInt8] = []
        for index in innerSessionIds.indices {
            let header = try SMB2Header(
                command: SMB2Commands.echo,
                credits: credits[index],
                nextCommand: index + 1 == innerSessionIds.count ? 0 : UInt32(SMB2Header.encodedSize),
                messageId: messageIds[index],
                sessionId: innerSessionIds[index]
            ).encode()
            plaintext.append(contentsOf: header)
        }
        let encrypted = try encryptCompoundResponse(plaintext, key: key, sessionId: outerSessionId)
        do {
            _ = try await session.processRawFrameForTesting(encrypted, generation: 1)
            XCTFail("inner SessionId mismatch must reject the encrypted response before commit")
        } catch SMBCodecError.invalidValue {
        }

        assertAwaitedEqual(await session.creditBalanceForTesting(), 0)
        assertAwaitedEqual(await session.creditGrantReceiptCountForTesting(), 0)
        assertAwaitedEqual(await session.receivedPacketDispatchCountForTesting(), 0)
        assertAwaitedEqual(await session.wirePendingRecordCountForTesting(), innerSessionIds.count)
        for messageId in messageIds {
            assertAwaitedFalse(await session.pendingFinalSeenForTesting(messageId: messageId))
            assertAwaitedFalse(await session.pendingContinuationResumedForTesting(messageId: messageId))
        }
        assertAwaitedFalse(await session.isTransportClosedForTesting())

        await session.closeTransportAndWait(cause: "test_transform_inner_session_mismatch")
        for caller in callers {
            do {
                try await awaitWithTimeout("mismatched encrypted caller teardown") { try await caller.value }
                XCTFail("rejected encrypted response must not complete a caller")
            } catch {
            }
        }
    }

    private func assertPendingIdentityCounts(
        _ session: SMBSession,
        pending expectedPending: Int,
        identities expectedIdentities: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let pending = await session.wirePendingRecordCountForTesting()
        let identities = await session.activeRequestIdentityCountForTesting()
        XCTAssertEqual(pending, expectedPending, "wire pending record count", file: file, line: line)
        XCTAssertEqual(identities, expectedIdentities, "active request identity count", file: file, line: line)
    }
}

private final class SMBVirtualMonotonicTime: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock().now

    var source: SMBSessionMonotonicTime {
        SMBSessionMonotonicTime(
            now: { self.lock.withLock { self.instant } },
            sleep: { duration in
                self.lock.withLock { self.instant += duration }
            }
        )
    }
}

private actor SMBRetirementEvent {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        guard !signaled else { return }
        signaled = true
        let parked = waiters
        waiters.removeAll()
        parked.forEach { $0.resume() }
    }

    func wait() async {
        if signaled { return }
        await withCheckedContinuation { continuation in
            if signaled {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }
}

private actor SMBRetirementCallbackCounter {
    private(set) var count = 0
    private var waiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func increment() {
        count += 1
        let ready = waiters.filter { count >= $0.target }
        waiters.removeAll { count >= $0.target }
        ready.forEach { $0.continuation.resume() }
    }

    func waitForCount(atLeast target: Int) async {
        if count >= target { return }
        await withCheckedContinuation { continuation in
            if count >= target {
                continuation.resume()
            } else {
                waiters.append((target, continuation))
            }
        }
    }
}

private final class SMBRequestRecordLifetimeProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    var isSignaled: Bool { lock.withLock { signaled } }

    func signal() {
        let parked = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            guard !signaled else { return [] }
            signaled = true
            defer { waiters.removeAll() }
            return waiters
        }
        parked.forEach { $0.resume() }
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let alreadySignaled = lock.withLock { () -> Bool in
                if signaled { return true }
                waiters.append(continuation)
                return false
            }
            if alreadySignaled { continuation.resume() }
        }
    }
}

private final class SMBWeakRequestRecordBox: @unchecked Sendable {
    weak var value: SMBUnsentRequestRecord?

    init(_ value: SMBUnsentRequestRecord) {
        self.value = value
    }
}

private actor SMBRetirementCreditProbe {
    private var callsByCharge: [UInt16: Int] = [:]
    private var acknowledgementsByCharge: [UInt16: Int] = [:]
    private var acknowledgementWaiters: [(charge: UInt16, count: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func started(_ charge: UInt16) {
        callsByCharge[charge, default: 0] += 1
        resumeReadyWaiters()
    }

    func acknowledged(_ charge: UInt16) {
        acknowledgementsByCharge[charge, default: 0] += 1
        resumeReadyWaiters()
    }

    func calls(for charge: UInt16) -> Int {
        callsByCharge[charge, default: 0]
    }

    func waitForAcknowledgement(charge: UInt16, count: Int) async {
        if acknowledgementsByCharge[charge, default: 0] >= count { return }
        await withCheckedContinuation { continuation in
            if acknowledgementsByCharge[charge, default: 0] >= count {
                continuation.resume()
            } else {
                acknowledgementWaiters.append((charge, count, continuation))
            }
        }
    }

    private func resumeReadyWaiters() {
        let readyAcknowledgements = acknowledgementWaiters.filter {
            acknowledgementsByCharge[$0.charge, default: 0] >= $0.count
        }
        acknowledgementWaiters.removeAll {
            acknowledgementsByCharge[$0.charge, default: 0] >= $0.count
        }
        readyAcknowledgements.forEach { $0.continuation.resume() }
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
    private var requestedDurationsStorage: [Duration] = []
    private var waiters: [Waiter] = []
    private let callCountBarrier = SMBContinuationCountBarrier()

    func sleep(for duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let cancelled: Bool
                lock.lock()
                callCountStorage += 1
                requestedDurationsStorage.append(duration)
                cancelled = Task.isCancelled
                if !cancelled {
                    waiters.append(Waiter(id: id, continuation: continuation))
                }
                callCountBarrier.signal()
                lock.unlock()
                if cancelled { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            self.cancel(id: id)
        }
    }

    var requestedDurations: [Duration] {
        lock.withLock { requestedDurationsStorage }
    }

    func waitUntilCallCount(
        atLeast count: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await callCountBarrier.waitForCount(count, timeout: timeout, sleeper: sleeper)
    }

    func reset() {
        let waiters = lock.withLock { () -> [Waiter] in
            callCountStorage = 0
            callCountBarrier.reset()
            defer { self.waiters.removeAll() }
            return self.waiters
        }
        waiters.forEach { $0.continuation.resume(throwing: CancellationError()) }
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
    private var sentPacketStorage: [[UInt8]] = []
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

    func sentPacket(command: UInt16, occurrence: Int) -> [UInt8]? {
        lock.withLock {
            let packets = sentPacketStorage.filter { (try? SMB2Header.decode($0).command) == command }
            guard occurrence > 0, occurrence <= packets.count else { return nil }
            return packets[occurrence - 1]
        }
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
            sentPacketStorage.append(Array(bytes.dropFirst(4)))
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
            let ready = lock.withLock { () -> Bool in
                guard pendingReceive == nil, !isClosed else { return true }
                receiveStateWaiters.append(continuation)
                return false
            }
            if ready { continuation.resume() }
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

    func enqueuePacket(_ packet: [UInt8]) throws {
        let frame = try DirectTCPFraming.frame(packet)
        let result = lock.withLock { () -> (Bool, (PendingReceive, [UInt8])?) in
            guard !isClosed else { return (false, nil) }
            inbound.append(contentsOf: frame)
            return (true, takeReceiveDeliveryLocked())
        }
        guard result.0 else { throw SMBTransportError.connectionClosed }
        if let (pending, bytes) = result.1 {
            pending.continuation.resume(returning: bytes)
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
            packet = try signedTestPacket(packet, algorithm: .aesCMAC, key: signingKey, sender: .server)
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
