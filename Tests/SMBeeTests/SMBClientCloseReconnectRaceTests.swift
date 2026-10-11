import XCTest
@testable import SMBee

final class SMBClientCloseReconnectRaceTests: XCTestCase {
    func testRaceWaitTimeoutIsReportedAndUnregistersTheWaiter() async throws {
        let barrier = SMBContinuationCountBarrier()
        let clock = ManualSMBSleeper()
        let waiter = Task {
            try await barrier.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("barrier timeout sleeper started") {
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        clock.fireNext()
        do {
            try await waiter.value
            XCTFail("expected the deadline to fail the parked wait")
        } catch is SMBContinuationWaitTimedOut {
        }
        XCTAssertEqual(barrier.waiterCount, 0)
    }

    func testBarrierWaitersDrainOnCancelAndReset() async throws {
        let cancelledBarrier = SMBContinuationCountBarrier()
        let cancelledClock = ManualSMBSleeper()
        let cancelledWait = Task {
            try await cancelledBarrier.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await cancelledClock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("cancelled barrier timer started") {
            try await cancelledClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        cancelledWait.cancel()
        do {
            try await cancelledWait.value
            XCTFail("expected barrier cancellation")
        } catch is CancellationError {
        }
        XCTAssertEqual(cancelledBarrier.waiterCount, 0)

        let resetBarrier = SMBContinuationCountBarrier()
        let resetClock = ManualSMBSleeper()
        let resetWait = Task {
            try await resetBarrier.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await resetClock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("reset barrier timer started") {
            try await resetClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        resetBarrier.reset()
        do {
            try await resetWait.value
            XCTFail("expected reset to drain barrier waiters")
        } catch is CancellationError {
        }
        XCTAssertEqual(resetBarrier.waiterCount, 0)
    }

    func testConcurrentSessionCloseWaitsForFirstCleanup() async throws {
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            cleanupSleeper.fireAll()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let firstClose = Task { await client.close() }

        try await smbIssue102AwaitWithTimeout("first close TREE_DISCONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try await smbIssue102AwaitWithTimeout("first close cleanup deadline registration") {
            try await cleanupSleeper.waitForCallCount(1)
        }
        XCTAssertEqual(cleanupSleeper.callCount, 1)
        XCTAssertEqual(cleanupSleeper.pendingCallWaiterCount, 0)

        let secondCloseEvent = SMBContinuationCloseEventLatch()
        let secondCloseCompleted = SMBContinuationCountBarrier()
        defer { secondCloseEvent.reset() }
        let secondClose = Task {
            await client.closeForTesting(onEvent: secondCloseEvent.signal)
            secondCloseCompleted.signal()
        }
        let event = try await smbIssue102AwaitWithTimeout("second close join or early return") {
            try await secondCloseEvent.wait()
        }
        XCTAssertEqual(event, .joinedExistingCleanup)
        try await assertDoesNotComplete(secondCloseCompleted, label: "second session close before cleanup release")
        XCTAssertEqual(secondCloseEvent.pendingWaiterCount, 0)
        XCTAssertEqual(transport.closeCount, 0, "the first cleanup is still held by TREE_DISCONNECT")
        XCTAssertEqual(
            transport.sentCommands.filter { $0 == SMB2Commands.treeDisconnect }.count,
            1,
            "both callers share the same cleanup request"
        )

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("first session close after TREE_DISCONNECT") {
            await firstClose.value
        }
        try await smbIssue102AwaitWithTimeout("second session close after cleanup release") {
            await secondClose.value
        }
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(transport.sentCommands.filter { $0 == SMB2Commands.treeDisconnect }.count, 1)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testScopedTreeCloseWaitsForFirstCleanup() async throws {
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            cleanupSleeper.fireAll()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let child = SMBClientTreeSession(session: session, treeId: 1)
        let firstClose = Task { await child.close() }

        try await smbIssue102AwaitWithTimeout("scoped tree first TREE_DISCONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try await smbIssue102AwaitWithTimeout("scoped tree cleanup deadline registration") {
            try await cleanupSleeper.waitForCallCount(1)
        }
        XCTAssertEqual(cleanupSleeper.callCount, 1)
        XCTAssertEqual(cleanupSleeper.pendingCallWaiterCount, 0)

        let secondCloseEvent = SMBContinuationCloseEventLatch()
        let secondCloseCompleted = SMBContinuationCountBarrier()
        defer { secondCloseEvent.reset() }
        let secondClose = Task {
            await child.closeForTesting(onEvent: secondCloseEvent.signal)
            secondCloseCompleted.signal()
        }
        let event = try await smbIssue102AwaitWithTimeout("scoped tree second close join or early return") {
            try await secondCloseEvent.wait()
        }
        XCTAssertEqual(event, .joinedExistingCleanup)
        try await assertDoesNotComplete(secondCloseCompleted, label: "second scoped-tree close before cleanup release")
        XCTAssertEqual(secondCloseEvent.pendingWaiterCount, 0)
        XCTAssertEqual(transport.closeCount, 0, "the first scoped-tree cleanup is still held")

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("first scoped-tree close after TREE_DISCONNECT") {
            await firstClose.value
        }
        try await smbIssue102AwaitWithTimeout("second scoped-tree close after cleanup release") {
            await secondClose.value
        }
        XCTAssertEqual(transport.sentCommands.filter { $0 == SMB2Commands.treeDisconnect }.count, 1)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testWithTreeReportsTreeDisconnectStatusAsCleanupFailure() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { _ in 42 }
        }

        try await smbIssue102AwaitWithTimeout("scoped TREE_CONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x5566)
        try await smbIssue102AwaitWithTimeout("scoped TREE_DISCONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect(status: SMB2Status.accessDenied)

        do {
            _ = try await smbIssue102AwaitWithTimeout("withTree reports cleanup failure") {
                try await withTree.value
            }
            XCTFail("a successful body must report its TREE_DISCONNECT failure")
        } catch SMBError.cleanupFailed(resource: .tree(treeId: 0x5566), underlying: let reason) {
            XCTAssertTrue(reason.contains("accessDenied"), reason)
            XCTAssertTrue(reason.contains("TREE_DISCONNECT"), reason)
        }
        let wasClosed = await session.isTransportClosedForTesting()
        XCTAssertFalse(wasClosed, "a Tree cleanup status failure is local to that Tree")
        await session.closeTransportAndWait(cause: "with_tree_cleanup_failure_test_complete")
    }

    func testWithTreePreservesBodyFailureWhenCleanupAlsoFails() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let bodyFailure = SMBError.notFound(status: SMB2Status.objectNameNotFound, operation: "BODY")
        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { _ in throw bodyFailure }
        }

        try await smbIssue102AwaitWithTimeout("scoped TREE_CONNECT before body failure") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x6677)
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT after body failure") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect(status: SMB2Status.accessDenied)

        do {
            _ = try await smbIssue102AwaitWithTimeout("withTree returns original body error") {
                try await withTree.value
            }
            XCTFail("expected the body failure")
        } catch let error as SMBError {
            XCTAssertEqual(error, bodyFailure, "cleanup reporting must not replace the body result")
        }
        await session.closeTransportAndWait(cause: "with_tree_body_error_precedence_test_complete")
    }

    func testWithTreeOuterOperationDeadlineOverridesSavedBodyFailure() async throws {
        let clock = SMBActivationTestClock()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            sessionTime: clock.source
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let cancellationObserved = SMBContinuationCountBarrier()
        let bodyFailure = SMBError.notFound(status: SMB2Status.objectNameNotFound, operation: "BODY")
        let operation = Task {
            try await SMBOperationDeadline.$operationCancellationObserverForTesting.withValue(
                { cancellationObserved.signal() },
                operation: {
                    try await SMBOperationDeadline.run(
                    timeout: .seconds(1),
                    time: clock.source,
                    sleeper: { try await clock.source.sleep($0) },
                    operation: {
                        try await client.withTree(share: "other") { _ in throw bodyFailure }
                    }
                    )
                }
            )
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before outer deadline") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x7788)
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT while withTree preserves body error") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        await clock.waitForSleepCount(atLeast: 2)
        clock.advance(by: .seconds(1), resumeDueSleeps: true)
        try await smbIssue102AwaitWithTimeout("outer operation timeout cancels withTree task") {
            try await cancellationObserved.waitForCount(1)
        }
        try transport.completeTreeDisconnect(status: SMB2Status.accessDenied)

        do {
            _ = try await smbIssue102AwaitWithTimeout("deadline wins after cleanup joins") {
                try await operation.value
            }
            XCTFail("the outer operation deadline must win over the saved body failure")
        } catch SMBTransportError.timedOut {
        }
        await session.closeTransportAndWait(cause: "with_tree_outer_deadline_priority_test_complete")
    }

    func testWithTreeHasFiniteHardDeadlineWhenRequestTimeoutIsNil() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { _ in 9 }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before finite cleanup test") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x6677)
        try await smbIssue102AwaitWithTimeout("unanswered TREE_DISCONNECT starts soft deadline") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try await cleanupClock.waitUntilCallCount(
            atLeast: 1,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )
        XCTAssertEqual(cleanupClock.requestedDurations.first, .seconds(5))
        XCTAssertTrue(cleanupClock.fireNext())

        do {
            _ = try await smbIssue102AwaitWithTimeout("withTree returns at soft timeout") {
                try await withTree.value
            }
            XCTFail("expected the Tree cleanup soft timeout")
        } catch SMBError.cleanupFailed(resource: .tree(treeId: 0x6677), underlying: let reason) {
            XCTAssertTrue(reason.contains("timedOut"), reason)
        }
        try await cleanupClock.waitUntilCallCount(
            atLeast: 2,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )
        XCTAssertEqual(cleanupClock.requestedDurations, [.seconds(5), .seconds(60)])
        XCTAssertEqual(transport.closeCount, 0, "soft expiry leaves the Tree drain alive until hardAt")

        XCTAssertTrue(cleanupClock.fireNext())
        try await smbIssue102AwaitWithTimeout("Tree hard deadline closes the session") {
            try await transport.waitForCloseCount(1)
        }
        let wasClosed = await session.isTransportClosedForTesting()
        XCTAssertTrue(wasClosed)
        await session.closeTransportAndWait(cause: "finite_tree_hard_deadline_test_complete")
    }

    func testTreeDisconnectSoftExpiryKeepsOtherTreeOperationsAliveThroughDrain() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBTreeCleanupDrainTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            requestTimeout: nil,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)

        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let optionalTreeBIdentity = await session.ensureTreeIdentity(treeId: treeBId)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let treeBIdentity = try XCTUnwrap(optionalTreeBIdentity)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let treeB = SMBClientTreeSession(session: session, treeId: treeBId, treeIdentity: treeBIdentity)
        let softDeadlineApplied = SMBContinuationCountBarrier()
        await session.setCleanupSoftDeadlineAppliedHookForTesting {
            softDeadlineApplied.signal()
        }
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            cleanupClock.reset()
        }

        let closeTreeA = Task { await treeA.close() }
        try await smbIssue102AwaitWithTimeout("Tree A TREE_DISCONNECT before its soft deadline") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs, [treeAId])
        try await cleanupClock.waitUntilCallCount(
            atLeast: 1,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )

        let inFlightOnTreeB = Task { try await treeB.stat(path: "in-flight-before-soft") }
        let inFlightQuery = try await smbIssue102AwaitWithTimeout("Tree B QUERY_INFO is held before Tree A soft expiry") {
            try await transport.waitForQueryInfo(treeId: treeBId)
        }
        XCTAssertEqual(inFlightQuery.treeId, treeBId)
        let tombstonesBeforeSoftExpiry = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstonesBeforeSoftExpiry, 0)

        XCTAssertTrue(cleanupClock.fireNext(), "expire Tree A cleanup soft deadline while Tree B QUERY_INFO is held")
        try await smbIssue102AwaitWithTimeout("Tree A cleanup caller returns at soft expiry") {
            await closeTreeA.value
        }
        guard transport.closeCount == 0 else {
            XCTFail("soft expiry must leave the shared transport open; closeCount=\(transport.closeCount)")
            return
        }
        try await smbIssue102AwaitWithTimeout("Tree A cleanup enters its tombstone drain") {
            try await softDeadlineApplied.waitForCount(1)
        }
        try await cleanupClock.waitUntilCallCount(
            atLeast: 2,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )
        XCTAssertEqual(cleanupClock.requestedDurations, [.seconds(5), .seconds(60)])
        let tombstonesDuringDrain = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstonesDuringDrain, 1)
        XCTAssertEqual(transport.closeCount, 0, "Tree A is draining while the shared transport remains open")

        try transport.completeQueryInfo(inFlightQuery, fileSize: 101)
        let inFlightResult = try await smbIssue102AwaitWithTimeout("Tree B operation sent before soft expiry succeeds during drain") {
            try await inFlightOnTreeB.value
        }
        XCTAssertEqual(inFlightResult.size, 101)
        XCTAssertEqual(transport.closeCount, 0)

        let startedDuringDrain = Task { try await treeB.stat(path: "started-during-drain") }
        let drainingQuery = try await smbIssue102AwaitWithTimeout("new Tree B QUERY_INFO starts during Tree A drain") {
            try await transport.waitForQueryInfo(treeId: treeBId)
        }
        XCTAssertEqual(drainingQuery.treeId, treeBId)
        try transport.completeQueryInfo(drainingQuery, fileSize: 202)
        let drainingResult = try await smbIssue102AwaitWithTimeout("new Tree B operation succeeds during Tree A drain") {
            try await startedDuringDrain.value
        }
        XCTAssertEqual(drainingResult.size, 202)
        let tombstonesAfterConcurrentDrainOperations = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstonesAfterConcurrentDrainOperations, 1)
        XCTAssertEqual(transport.closeCount, 0)

        try transport.completeTreeDisconnect()
        let usableAfterDrain = Task { try await treeB.stat(path: "after-drain") }
        let afterDrainQuery = try await smbIssue102AwaitWithTimeout("Tree B QUERY_INFO after Tree A final") {
            try await transport.waitForQueryInfo(treeId: treeBId)
        }
        try transport.completeQueryInfo(afterDrainQuery, fileSize: 303)
        let afterDrainResult = try await smbIssue102AwaitWithTimeout("Tree B remains usable after the cleanup final") {
            try await usableAfterDrain.value
        }
        XCTAssertEqual(afterDrainResult.size, 303)
        let tombstonesAfterFinal = await session.cleanupTombstoneCountForTesting()
        XCTAssertEqual(tombstonesAfterFinal, 0)
        XCTAssertEqual(transport.closeCount, 0)

        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "tree_disconnect_soft_expiry_isolation_test_complete")
    }

    func testTreeLocalRefusalDoesNotTriggerWatchReconnect() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let treeId: UInt32 = 0x3344
        _ = await session.ensureTreeIdentity(treeId: treeId)
        let candidateFactory = SMBContinuationTransportFactory(transports: [InMemoryTransport()])
        let client = makeClientSession(
            session: session,
            credentialProvider: { .anonymous },
            makeTransport: { candidateFactory.makeTransport() }
        )
        let disconnect = Task { await session.bestEffortTreeDisconnect(treeId: treeId) }

        try await smbIssue102AwaitWithTimeout("Tree-local cleanup quarantines the watch Tree") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: true) { _ in }
        }
        do {
            try await smbIssue102AwaitWithTimeout("watch propagates a Tree-local refusal") {
                try await watcher.value
            }
            XCTFail("a quarantined Tree must reject the watch locally")
        } catch SMBError.treeUnavailable(treeId: treeId, operation: "CREATE") {
        }
        XCTAssertEqual(candidateFactory.makeCount, 0, "treeUnavailable is not a reconnect trigger")
        XCTAssertFalse(SMBError.treeUnavailable(treeId: treeId, operation: "WATCH").isSMBConnectionLoss)
        XCTAssertFalse(SMBError.cleanupFailed(resource: .tree(treeId: treeId), underlying: "status").isSMBConnectionLoss)

        try transport.completeTreeDisconnect()
        guard case .success = await disconnect.value else {
            return XCTFail("Tree cleanup should complete locally")
        }
        await session.closeTransportAndWait(cause: "tree_local_refusal_reconnect_test_complete")
    }

    func testTreeQuarantineRejectsFileCloseWhileTreeBStillCompletesStat() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let optionalTreeBIdentity = await session.ensureTreeIdentity(treeId: treeBId)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let treeBIdentity = try XCTUnwrap(optionalTreeBIdentity)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let treeB = SMBClientTreeSession(session: session, treeId: treeBId, treeIdentity: treeBIdentity)
        let closeA = Task { await treeA.close() }

        try await smbIssue102AwaitWithTimeout("Tree A quarantine reaches TREE_DISCONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        let nextMIDBeforeRefusal = await session.nextMessageIdForTesting()
        do {
            try await session.closeCreatedHandle(treeId: treeAId, fileId: [UInt8](repeating: 0x31, count: 16))
            XCTFail("File CLOSE on quarantined Tree A must be refused")
        } catch SMBError.treeUnavailable(treeId: treeAId, operation: "CLOSE") {
        }
        let nextMIDAfterRefusal = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMIDAfterRefusal, nextMIDBeforeRefusal, "local Tree refusal must not commit a MID")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.close), "no File CLOSE reaches the wire")

        let stat = Task { try await treeB.stat(path: "file") }
        try await smbIssue102AwaitWithTimeout("Tree B CREATE while Tree A cleanup is pending") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("Tree B QUERY_INFO while Tree A cleanup is pending") {
            try await transport.waitForCommand(SMB2Commands.queryInfo)
        }
        try transport.completeQueryInfo(fileSize: 123)
        let result = try await smbIssue102AwaitWithTimeout("Tree B stat completes before Tree A cleanup") {
            try await stat.value
        }
        XCTAssertEqual(result.size, 123)

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("Tree A close joins its own cleanup") { await closeA.value }
        let wasClosed = await session.isTransportClosedForTesting()
        XCTAssertFalse(wasClosed, "Tree A quarantine does not close the shared session")
        await session.closeTransportAndWait(cause: "tree_quarantine_isolation_test_complete")
    }

    func testTreeQuarantineCancelsOnlyItsProductionCreditWaiter() async throws {
        let transport = SMBContinuationWatchTransport()
        let cleanupClock = ManualSMBSleeper()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let optionalTreeBIdentity = await session.ensureTreeIdentity(treeId: treeBId)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let treeBIdentity = try XCTUnwrap(optionalTreeBIdentity)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let treeB = SMBClientTreeSession(session: session, treeId: treeBId, treeIdentity: treeBIdentity)
        let quarantinePrepared = SMBTreeQuarantineGate()
        let resumeCleanup = SMBTreeQuarantineGate()
        await session.setTreeCleanupIntentPreparedHookForTesting { identity in
            guard identity == treeAIdentity else { return }
            await quarantinePrepared.open()
            await resumeCleanup.wait()
        }
        let statA = Task { try await treeA.stat(path: "a") }
        let statB = Task { try await treeB.stat(path: "b") }

        await session.waitForCreditWaiterCountForTesting(atLeast: 2)
        let nextMIDBeforeQuarantine = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMIDBeforeQuarantine, 100, "credit-waiting Tree requests have not committed MessageIds")
        let closeA = Task { await treeA.close() }
        await quarantinePrepared.wait()
        let remainingWaiters = await session.creditWaiterCountForTesting()
        XCTAssertEqual(remainingWaiters, 1, "quarantine removes Tree A's waiter while Tree B remains parked")
        let nextMIDAfterQuarantine = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMIDAfterQuarantine, 100, "Tree A retirement does not consume a MessageId")
        XCTAssertTrue(transport.sentCommands.isEmpty, "neither parked CREATE may allocate a MessageId")
        let wasClosedBeforeGrant = await session.isTransportClosedForTesting()
        XCTAssertFalse(wasClosedBeforeGrant, "Tree-local cancellation must leave the shared transport open")

        await resumeCleanup.open()
        if remainingWaiters != 1 {
            await session.closeTransportAndWait(cause: "tree_local_waiter_count_mutation_cleanup")
            _ = await statA.result
            _ = await statB.result
            await closeA.value
            return
        }
        await session.waitForCreditWaiterCountForTesting(atLeast: 2)
        await session.grantCreditsForTesting(4)
        try await transport.waitForCommand(SMB2Commands.create)
        try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        XCTAssertEqual(transport.sentCommands.count, 2, "only Tree B CREATE and Tree A TREE_DISCONNECT commit before stat continues")
        try transport.completeCreate()
        try transport.completeTreeDisconnect()
        try await transport.waitForCommand(SMB2Commands.queryInfo)
        try transport.completeQueryInfo(fileSize: 77)

        let statAResult = await statA.result
        guard case .failure(let statAError) = statAResult,
              let treeError = statAError as? SMBError else {
            XCTFail("Tree A's parked CREATE must be refused locally")
            return
        }
        guard case .treeUnavailable(let failedTreeId, let failedOperation) = treeError else {
            XCTFail("Tree A's parked CREATE must return treeUnavailable")
            return
        }
        XCTAssertEqual(failedTreeId, treeAId)
        XCTAssertEqual(failedOperation, "CREATE")
        let statBResult = try await statB.value
        XCTAssertEqual(statBResult.size, 77)
        let nextMIDAfterBothTreesComplete = await session.nextMessageIdForTesting()
        XCTAssertEqual(
            nextMIDAfterBothTreesComplete,
            100 + UInt64(transport.sentCommands.count),
            "Tree A's cancelled request leaves no sequence hole across Tree B CREATE, QUERY_INFO, and CLOSE"
        )
        await closeA.value
        let wasClosedAfterGrant = await session.isTransportClosedForTesting()
        XCTAssertFalse(wasClosedAfterGrant)
        await session.closeTransportAndWait(cause: "tree_local_credit_waiter_test_complete")
    }

    func testTreeQuarantineRetiresAnAlreadyWaitingProductionFileClose() async throws {
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let clock = ManualSMBSleeper()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            sessionTime: clock.sessionTime,
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let fileId = [UInt8](repeating: 0xAC, count: 16)
        let quarantinePrepared = SMBContinuationCountBarrier()
        await session.setTreeCleanupIntentPreparedHookForTesting { _ in quarantinePrepared.signal() }
        let fileClose = Task { try await session.closeCreatedHandle(treeId: treeId, fileId: fileId) }

        await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        let ledgerBeforeQuarantine = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(ledgerBeforeQuarantine, "sending", "the CLOSE is already admitted before quarantine")
        let treeClose = Task { await tree.close() }
        try await smbIssue102AwaitWithTimeout("Tree quarantine cancels the existing File CLOSE credit wait") {
            try await quarantinePrepared.waitForCount(1)
        }
        await session.grantCreditsForTesting(1)
        try await smbIssue102AwaitWithTimeout("Tree quarantine emits its disconnect after cancelling the prior CLOSE wait") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        let closeResult = try await smbIssue102AwaitWithTimeout("pre-existing File CLOSE exits its cancelled credit wait") {
            await fileClose.result
        }
        guard case .failure = closeResult else {
            XCTFail("the File CLOSE should be refused by its quarantined Tree")
            return
        }

        let waitersAfterQuarantine = await session.creditWaiterCountForTesting()
        let ledgerAfterQuarantine = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let closeCommands = transport.sentCommands.filter { $0 == SMB2Commands.close }.count
        XCTAssertEqual(waitersAfterQuarantine, 0)
        XCTAssertEqual(ledgerAfterQuarantine, "retiredUnknown", "Tree retirement keeps the prior File attempt unresolved")
        XCTAssertEqual(closeCommands, 0, "the waiting CLOSE was never committed or sent")
        try transport.completeTreeDisconnect()
        await treeClose.value
        await session.setTreeCleanupIntentPreparedHookForTesting(nil)
        let closed = await session.isTransportClosedForTesting()
        XCTAssertFalse(closed, "retiring a pre-existing CLOSE is Tree-local")
        await session.closeTransportAndWait(cause: "tree_quarantine_retires_prior_file_close")
    }

    func testTreeQuarantineCancelsTransferWaiterAfterPositiveBalanceSnapshot() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let transferClient = SMBClientSession(session: session, treeId: treeAId)
        let snapshotReached = SMBContinuationCountBarrier()
        let releaseSnapshot = SMBAsyncCallbackSuspensionGate()
        let quarantineReached = SMBContinuationCountBarrier()
        let releaseQuarantine = SMBAsyncCallbackSuspensionGate()
        let retirementReached = SMBContinuationCountBarrier()
        let releaseRetirement = SMBAsyncCallbackSuspensionGate()
        let barrierEvaluation = SMBContinuationBooleanLatch()
        await session.setOperationBarrierEvaluationHookForTesting { _, blocked in
            barrierEvaluation.signal(blocked)
        }
        await session.setTransferCreditSnapshotHookForTesting { tree, _ in
            guard tree == treeAIdentity else { return }
            snapshotReached.signal()
            await releaseSnapshot.suspend()
        }
        await session.setTransferCreditRetirementHookForTesting { _ in
            retirementReached.signal()
            await releaseRetirement.suspend()
        }
        await session.setTreeCleanupIntentPreparedHookForTesting { tree in
            guard tree == treeAIdentity else { return }
            quarantineReached.signal()
            await releaseQuarantine.suspend()
        }

        let transfer = Task { try await transferClient.read(path: "a", knownSize: 1) }
        try await smbIssue102AwaitWithTimeout("Tree A CREATE reaches the transport") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 3)
        try await smbIssue102AwaitWithTimeout("transfer observed positive balance before reserve") {
            try await snapshotReached.waitForCount(1)
        }

        // One charge-three session request consumes the exact snapshot balance while the
        // transfer is stopped between its snapshot and credit-actor call.
        let consumer = Task {
            try await session.echoThroughSenderLoopForTesting(treeId: treeBId, creditCharge: 3)
        }
        try await smbIssue102AwaitWithTimeout("Tree B consumes the observed credits") {
            try await transport.waitForCommand(SMB2Commands.echo)
        }
        let balanceAfterConcurrentReservation = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterConcurrentReservation, 0)
        releaseSnapshot.release()
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)

        let closeA = Task { await treeA.close() }
        try await smbIssue102AwaitWithTimeout("Tree A quarantine completes its request scan") {
            try await quarantineReached.waitForCount(1)
        }
        let waitersAfterQuarantine = await session.creditWaiterCountForTesting()
        XCTAssertEqual(
            waitersAfterQuarantine,
            0,
            "the positive-snapshot transfer waiter is still owned by Tree A and must be retired"
        )
        try await smbIssue102AwaitWithTimeout("transfer owner reaches local retirement") {
            try await retirementReached.waitForCount(1)
        }

        releaseQuarantine.release()
        let wasBlockedOnRetirement = try await smbIssue102AwaitWithTimeout(
            "production Tree close evaluates its retirement receipt"
        ) {
            await barrierEvaluation.wait()
        }
        XCTAssertTrue(wasBlockedOnRetirement, "Tree cleanup must wait for the credit reservation owner to retire")
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "TREE_DISCONNECT cannot pass a still-owned credit retirement receipt"
        )
        releaseRetirement.release()
        await session.grantCreditsForTesting(1)
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT follows transfer retirement") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        await closeA.value

        await session.closeTransportAndWait(cause: "positive_snapshot_transfer_waiter_test_cleanup")
        _ = await transfer.result
        _ = await consumer.result
        await session.setTransferCreditSnapshotHookForTesting(nil)
        await session.setTransferCreditRetirementHookForTesting(nil)
        await session.setOperationBarrierEvaluationHookForTesting { _, _ in }
        await session.setTreeCleanupIntentPreparedHookForTesting(nil)
    }

    func testProductionTreeCleanupWaitsForSoftTimedOutFileCloseWireFinal() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let barrierEvaluation = SMBContinuationBooleanLatch()
        await session.setOperationBarrierEvaluationHookForTesting { _, blocked in
            barrierEvaluation.signal(blocked)
        }

        let stat = Task { try await tree.stat(path: "file") }
        try await smbIssue102AwaitWithTimeout("production stat CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("production stat QUERY_INFO") {
            try await transport.waitForCommand(SMB2Commands.queryInfo)
        }
        try transport.completeQueryInfo(fileSize: 123)
        try await smbIssue102AwaitWithTimeout("production File CLOSE is full-sent") {
            try await transport.waitForCommand(SMB2Commands.close)
        }
        await session.waitForRequestSentCountForTesting(atLeast: 3)
        try await smbIssue102AwaitWithTimeout("File CLOSE soft timer is registered") {
            try await cleanupClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        XCTAssertTrue(cleanupClock.fireNext(), "advance the File CLOSE soft deadline")
        try await smbIssue102AwaitWithTimeout("best-effort CLOSE caller returns at soft timeout") {
            _ = try await stat.value
        }

        let closeTree = Task { await tree.close() }
        let didBlockOnWireReceipt = try await smbIssue102AwaitWithTimeout(
            "production Tree cleanup worker evaluates its barrier"
        ) {
            await barrierEvaluation.wait()
        }
        if !didBlockOnWireReceipt {
            try await smbIssue102AwaitWithTimeout("reproduce TREE_DISCONNECT bypass while CLOSE final is held") {
                try await transport.waitForCommand(SMB2Commands.treeDisconnect)
            }
            XCTFail("production sent TREE_DISCONNECT with the earlier File CLOSE still draining")
            await session.closeTransportAndWait(cause: "production_tree_wire_barrier_repro_cleanup")
            _ = await closeTree.result
            _ = await stat.result
            return
        }
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "TREE_DISCONNECT must wait while the earlier File CLOSE wire drain is outstanding"
        )

        try transport.completeClose()
        try await smbIssue102AwaitWithTimeout("Tree cleanup starts after File CLOSE final") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        await closeTree.value
        await session.closeTransportAndWait(cause: "production_tree_wire_barrier_test_complete")
    }

    func testSuccessfulTreeDisconnectReclaimsItsRetiredFileLedgerEntries() async throws {
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let fileId = [UInt8](repeating: 0x55, count: 16)
        let otherTreeId: UInt32 = 0x00b
        let otherFileId = [UInt8](repeating: 0x66, count: 16)
        _ = await session.ensureTreeIdentity(treeId: otherTreeId)

        let fileClose = Task { try await session.closeCreatedHandle(treeId: treeId, fileId: fileId) }
        try await smbIssue102AwaitWithTimeout("File CLOSE with held status") {
            try await transport.waitForCommand(SMB2Commands.close)
        }
        try transport.completeClose(status: SMB2Status.accessDenied)
        do {
            try await fileClose.value
            XCTFail("the File CLOSE status failure should leave a retiredUnknown File entry")
        } catch {
        }
        let otherFileClose = Task {
            try await session.closeCreatedHandle(treeId: otherTreeId, fileId: otherFileId)
        }
        try await smbIssue102AwaitWithTimeout("Tree B File CLOSE with held status") {
            try await transport.waitForCommand(SMB2Commands.close, occurrence: 2)
        }
        try transport.completeClose(status: SMB2Status.accessDenied)
        do {
            try await otherFileClose.value
            XCTFail("the Tree B File CLOSE status failure should leave its ledger entry unresolved")
        } catch {
        }
        let fileLedgerBeforeTreeDisconnect = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(fileLedgerBeforeTreeDisconnect, 2)

        let closeTree = Task { await tree.close() }
        try await smbIssue102AwaitWithTimeout("Tree cleanup after File CLOSE status failure") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        await closeTree.value
        let fileLedgerAfterTreeDisconnect = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(
            fileLedgerAfterTreeDisconnect,
            1,
            "successful TREE_DISCONNECT removes only File entries from its own incarnation"
        )
        let reclaimedA = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let retainedB = await session.cleanupAttemptStateForTesting(fileId: otherFileId)
        XCTAssertNil(reclaimedA)
        XCTAssertEqual(retainedB, "retiredUnknown", "Tree B's unresolved File fence survives Tree A's disconnect")
        await session.closeTransportAndWait(cause: "tree_disconnect_reclaims_file_ledger_test_complete")
    }

    func testTreeWireBarrierWaitsUntilFinalCreditGrantAcknowledgement() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let identity = try XCTUnwrap(optionalIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: identity)
        let grantEntered = SMBContinuationCountBarrier()
        let releaseGrant = SMBAsyncCallbackSuspensionGate()
        let barrierEvaluation = SMBContinuationBooleanLatch()
        await session.setCreditGrantAfterAwaitHookForTesting {
            grantEntered.signal()
            await releaseGrant.suspend()
        }
        await session.setOperationBarrierEvaluationHookForTesting { _, blocked in
            barrierEvaluation.signal(blocked)
        }

        let fileId = [UInt8](repeating: 0x67, count: 16)
        let fileClose = Task { try await session.closeCreatedHandle(treeId: treeId, fileId: fileId) }
        try await smbIssue102AwaitWithTimeout("File CLOSE is held for a final response") {
            try await transport.waitForCommand(SMB2Commands.close)
        }
        try await smbIssue102AwaitWithTimeout("File CLOSE soft timer is registered") {
            try await cleanupClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }
        XCTAssertTrue(cleanupClock.fireNext(), "expire the File CLOSE caller deadline")
        do {
            try await smbIssue102AwaitWithTimeout("soft timeout returns the File CLOSE caller") {
                try await fileClose.value
            }
            XCTFail("the held File CLOSE should time out")
        } catch SMBTransportError.timedOut {
        }
        try await smbIssue102AwaitWithTimeout("the File CLOSE hard drain timer is registered") {
            try await cleanupClock.waitUntilCallCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }

        try transport.completeClose()
        try await smbIssue102AwaitWithTimeout("validated final reaches held credit grant acknowledgement") {
            try await grantEntered.waitForCount(1)
        }

        let closeTree = Task { await tree.close() }
        let blocked = try await smbIssue102AwaitWithTimeout("Tree cleanup observes the pending final credit acknowledgement") {
            await barrierEvaluation.wait()
        }
        XCTAssertTrue(blocked, "the final is accepted, but its credit grant still owns the wire receipt")
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "TREE_DISCONNECT waits until the File CLOSE grant acknowledgement settles"
        )

        releaseGrant.release()
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT follows the acknowledged File final") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        await closeTree.value
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        await session.setOperationBarrierEvaluationHookForTesting { _, _ in }
        await session.closeTransportAndWait(cause: "wire_receipt_waits_for_credit_ack_test_complete")
    }

    func testScopedTreeLifecycleRecordsAreReclaimedAfterEveryProductionClose() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 200)
        let client = SMBClientSession(session: session, treeId: 1)

        for occurrence in 1...24 {
            let operation = Task {
                try await client.withTree(share: "other") { _ in occurrence }
            }
            try await smbIssue102AwaitWithTimeout("production TREE_CONNECT #\(occurrence)") {
                try await transport.waitForCommand(SMB2Commands.treeConnect, occurrence: occurrence)
            }
            try transport.completeTreeConnect(treeId: UInt32(0x100 + occurrence))
            try await smbIssue102AwaitWithTimeout("production TREE_DISCONNECT #\(occurrence)") {
                try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: occurrence)
            }
            try transport.completeTreeDisconnect()
            let result = try await smbIssue102AwaitWithTimeout("withTree #\(occurrence) returns") {
                try await operation.value
            }
            XCTAssertEqual(result, occurrence)
        }

        let records = await session.operationLifecycleRecordCountsForTesting()
        XCTAssertEqual(records.facades, 1, "only the live parent facade remains registered")
        XCTAssertEqual(records.leases, 0)
        XCTAssertEqual(records.barriers, 0)
        XCTAssertEqual(records.closeWorkers, 0, "completed child close workers are reclaimed")
        XCTAssertEqual(records.activeTrees, 0)
        XCTAssertEqual(records.parentRecords, 0, "completed child parent links are reclaimed")
        XCTAssertEqual(records.executorRecords, 1, "only the live parent executor is retained")
        XCTAssertEqual(records.retiredFacades, 0, "no retired facade remains after production close")
        await session.closeTransportAndWait(cause: "scoped_tree_records_reclaimed")
    }

    func testFileAndTreeCleanupShareTheSixtyFourAttemptLimit() async throws {
        let clock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 128,
            cleanupTimeout: .seconds(300),
            sessionTime: clock.sessionTime,
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 300)
        let treeA: UInt32 = 0x00a
        let treeB: UInt32 = 0x00b
        _ = await session.ensureTreeIdentity(treeId: treeA)
        _ = await session.ensureTreeIdentity(treeId: treeB)

        let treeCleanup = Task { await session.bestEffortTreeDisconnect(treeId: treeA) }
        try await smbIssue102AwaitWithTimeout("Tree cleanup reserves one shared attempt") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        let fileCloses = (0..<63).map { index in
            Task {
                await session.bestEffortClose(
                    treeId: treeB,
                    fileId: [UInt8](repeating: UInt8(index), count: 16)
                )
            }
        }
        try await smbIssue102AwaitWithTimeout("63 File CLOSE attempts fill the remaining shared slots") {
            try await transport.waitForCommand(SMB2Commands.close, occurrence: 63)
        }
        let fileAttemptsBeforeOverflow = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(fileAttemptsBeforeOverflow, 63)

        let overflow = Task {
            await session.bestEffortClose(treeId: treeB, fileId: [UInt8](repeating: 0xfe, count: 16))
        }
        try await smbIssue102AwaitWithTimeout("the 65th combined Tree/File attempt closes the session") {
            try await transport.waitForCloseCount(1)
        }
        let remainingFileAttempts = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(transport.sentCommands.filter { $0 == SMB2Commands.close }.count, 63)
        XCTAssertEqual(remainingFileAttempts, 0, "terminal teardown clears all cleanup attempts")

        await overflow.value
        for close in fileCloses { await close.value }
        _ = await treeCleanup.value
        await session.closeTransportAndWait(cause: "shared_cleanup_attempt_limit")
    }

    func testTreeQuarantineRefusesReadTransferLocallyAndKeepsTreeBUsable() async throws {
        try await assertTreeTransferQuarantine(operation: "READ") { tree in
            _ = try await tree.read(path: "a", knownSize: 1)
        }
    }

    func testTreeQuarantineRefusesWriteTransferLocallyAndKeepsTreeBUsable() async throws {
        try await assertTreeTransferQuarantine(operation: "WRITE") { tree in
            try await tree.upload(path: "a", data: [0x41])
        }
    }

    private func assertTreeTransferQuarantine(
        operation: String,
        startTransfer: @escaping @Sendable (SMBClientSession) async throws -> Void
    ) async throws {
        let transport = SMBContinuationWatchTransport()
        let cleanupClock = ManualSMBSleeper()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let optionalTreeBIdentity = await session.ensureTreeIdentity(treeId: treeBId)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let treeBIdentity = try XCTUnwrap(optionalTreeBIdentity)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let treeB = SMBClientTreeSession(session: session, treeId: treeBId, treeIdentity: treeBIdentity)
        let transferClientA = SMBClientSession(session: session, treeId: treeAId)
        let quarantinePrepared = SMBTreeQuarantineGate()
        let resumeCleanup = SMBTreeQuarantineGate()
        await session.setTreeCleanupIntentPreparedHookForTesting { identity in
            guard identity == treeAIdentity else { return }
            await quarantinePrepared.open()
            await resumeCleanup.wait()
        }

        let transferA = Task { try await startTransfer(transferClientA) }
        try await transport.waitForCommand(SMB2Commands.create)
        try transport.completeCreate(credits: 0)
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        let statB = Task { try await treeB.stat(path: "b") }
        await session.waitForCreditWaiterCountForTesting(atLeast: 2)
        let closeA = Task { await treeA.close() }
        await quarantinePrepared.wait()

        let remainingWaiters = await session.creditWaiterCountForTesting()
        XCTAssertEqual(remainingWaiters, 1, "Tree A's transfer waiter is removed while Tree B's CREATE remains parked")
        let nextMIDAfterQuarantine = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMIDAfterQuarantine, 101, "CREATE used one MID; parked transfer used none")
        XCTAssertEqual(transport.sentCommands, [SMB2Commands.create], "the transfer has not reached the wire")

        await resumeCleanup.open()
        if remainingWaiters != 1 {
            await session.closeTransportAndWait(cause: "tree_transfer_waiter_count_mutation_cleanup")
            _ = await transferA.result
            _ = await statB.result
            await closeA.value
            return
        }
        await session.waitForCreditWaiterCountForTesting(atLeast: 2)
        await session.grantCreditsForTesting(8)
        try await transport.waitForCommand(SMB2Commands.create, occurrence: 2)
        try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        try transport.completeCreate(credits: 1)
        try transport.completeTreeDisconnect()
        try await transport.waitForCommand(SMB2Commands.queryInfo)
        try transport.completeQueryInfo(fileSize: 1)

        let transferResult = await transferA.result
        guard case .failure(let transferError) = transferResult,
              let treeError = transferError as? SMBError else {
            XCTFail("Tree A's transfer must fail with a typed Tree-local refusal")
            await closeA.value
            await session.closeTransportAndWait(cause: "tree_transfer_refusal_unexpected_success")
            return
        }
        switch treeError {
        case .treeUnavailable(let failedTreeId, let failedOperation):
            XCTAssertEqual(failedTreeId, treeAId)
            XCTAssertEqual(failedOperation, operation)
        default:
            XCTFail("expected treeUnavailable, got \(treeError)")
        }
        let statBResult = try await statB.value
        XCTAssertEqual(statBResult.size, 1)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.read), "no READ is sent after Tree A quarantine")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.write), "no WRITE is sent after Tree A quarantine")
        await closeA.value
        let nextMID = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMID, 100 + UInt64(transport.sentCommands.count), "Tree-local refusal consumes no transfer MID")
        let isTransportClosed = await session.isTransportClosedForTesting()
        XCTAssertFalse(isTransportClosed, "Tree A cleanup leaves Tree B's transport open")
        await session.closeTransportAndWait(cause: "tree_transfer_quarantine_test_complete")
    }

    func testCloseInsideWithTreeLeaseReturnsBeforeCleanupAndWithTreeJoins() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackCloseReturned = SMBContinuationCountBarrier()
        let holdBody = SMBContinuationAsyncGate()
        let bodyGateClock = ManualSMBSleeper()
        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { tree in
                await tree.close()
                callbackCloseReturned.signal()
                try await holdBody.suspend(
                    timeout: .seconds(60),
                    sleeper: { try await bodyGateClock.sleep(for: $0) }
                )
                return 7
            }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before reentrant close") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x7788)
        try await smbIssue102AwaitWithTimeout("callback close returns while its lease is active") {
            try await callbackCloseReturned.waitForCount(1)
        }
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "the close worker waits for the active withTree lease before sending cleanup"
        )

        holdBody.release()
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT after the lease releases") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        let value = try await smbIssue102AwaitWithTimeout("withTree joins the callback-started cleanup") {
            try await withTree.value
        }
        XCTAssertEqual(value, 7)
        await session.closeTransportAndWait(cause: "reentrant_tree_close_test_complete")
    }

    func testPublicParentCloseWaitsForNestedWithTreeLease() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let parentOwner = await client.facadeOwnerForTesting()
        let callbackCloseReturned = SMBContinuationCountBarrier()
        let bodyGate = SMBAsyncCallbackSuspensionGate()
        let evaluation = SMBContinuationBooleanLatch()
        await session.setOperationBarrierEvaluationHookForTesting { owner, blocked in
            guard owner == parentOwner else { return }
            evaluation.signal(blocked)
        }

        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { _ in
                await client.close()
                callbackCloseReturned.signal()
                await bodyGate.suspend()
                return 7
            }
        }
        try await smbIssue102AwaitWithTimeout("nested TREE_CONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x7788)
        try await smbIssue102AwaitWithTimeout("public parent close returns to its active callback") {
            try await callbackCloseReturned.waitForCount(1)
        }

        let didEvaluateBarrier: Bool
        do {
            didEvaluateBarrier = try await smbIssue102AwaitWithTimeout("parent close evaluates active leases") {
                await evaluation.wait()
            }
        } catch {
            didEvaluateBarrier = false
        }
        if !didEvaluateBarrier {
            if transport.sentTreeDisconnectTreeIDs.isEmpty {
                try await smbIssue102AwaitWithTimeout("reproduce child or parent TREE_DISCONNECT before callback lease release") {
                    try await transport.waitForCommand(SMB2Commands.treeDisconnect)
                }
            }
            XCTAssertTrue(
                transport.sentTreeDisconnectTreeIDs.isEmpty,
                "public parent close must not disconnect any nested Tree while its callback lease is active"
            )
            bodyGate.release()
            await session.closeTransportAndWait(cause: "public_parent_close_barrier_repro_cleanup")
            _ = await withTree.result
            return
        }
        XCTAssertTrue(didEvaluateBarrier, "the public close path must use the operation lifecycle barrier")
        XCTAssertTrue(
            transport.sentTreeDisconnectTreeIDs.isEmpty,
            "the public parent close worker waits before disconnecting the nested Tree or parent Tree"
        )

        bodyGate.release()
        try await smbIssue102AwaitWithTimeout("child TREE_DISCONNECT after lease release") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 1)
        }
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("parent TREE_DISCONNECT after child cleanup") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 2)
        }
        try transport.completeTreeDisconnect()
        let result = try await smbIssue102AwaitWithTimeout("withTree returns after child cleanup") {
            try await withTree.value
        }
        XCTAssertEqual(result, 7)
        await client.close()
        await session.closeTransportAndWait(cause: "public_parent_close_barrier_test_complete")
    }

    func testPublicParentCloseQuarantinesChildBeforeWaitingForItsCreditWaiter() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            while cleanupClock.fireNext() {}
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let quarantinePrepared = SMBContinuationCountBarrier()
        await session.setTreeCleanupIntentPreparedHookForTesting { _ in quarantinePrepared.signal() }

        let scopedOperation = Task {
            try await client.withTree(share: "other") { tree in
                _ = try await tree.stat(path: "a")
            }
        }
        try await smbIssue102AwaitWithTimeout("nested TREE_CONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x7788, credits: 0)
        try await smbIssue102AwaitWithTimeout("child CREATE waits for its credit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }

        let parentClose = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("parent close prepares child quarantine before its lease barrier") {
            try await quarantinePrepared.waitForCount(1)
        }
        let waitersAfterQuarantine = await session.creditWaiterCountForTesting()
        XCTAssertEqual(waitersAfterQuarantine, 0, "the child's queued CREATE is retired before parent close waits")

        await session.grantCreditsForTesting(2)
        try await smbIssue102AwaitWithTimeout("child TREE_DISCONNECT follows credit waiter retirement") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 1)
        }
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs.first, 0x7788)
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("parent TREE_DISCONNECT follows child cleanup") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 2)
        }
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs.last, 1)
        try transport.completeTreeDisconnect()

        await parentClose.value
        if case .success = await scopedOperation.result {
            XCTFail("the quarantined child CREATE must fail locally")
        }
        await session.setTreeCleanupIntentPreparedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "parent_close_quarantines_child_credit_waiter")
    }

    func testTreeCloseRejectsOrdinaryCreditWaitBeforeAnyDeadlineFires() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let maybeTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(maybeTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let catchReached = SMBContinuationCountBarrier()
        let intentPrepared = SMBContinuationCountBarrier()
        let releaseCleanup = SMBAsyncCallbackSuspensionGate()
        defer { releaseCleanup.release() }
        await session.setCleanupCloseCreditWaitCatchHookForTesting { catchReached.signal() }
        await session.setTreeCleanupIntentPreparedHookForTesting { _ in
            intentPrepared.signal()
            await releaseCleanup.suspend()
        }

        let request = Task {
            try await session.flushThroughSenderLoopForTesting(
                treeId: treeId,
                fileId: [UInt8](repeating: 0xA0, count: 16)
            )
        }
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        let treeClose = Task { await tree.close() }
        try await smbIssue102AwaitWithTimeout("Tree close cancels ordinary ECHO credit wait") {
            try await catchReached.waitForCount(1)
        }
        try await smbIssue102AwaitWithTimeout("Tree quarantine finishes its credit cancellation") {
            try await intentPrepared.waitForCount(1)
        }

        let operationRecords = await session.operationLifecycleRecordCountsForTesting()
        let receiptCompletedBeforeDeadline = operationRecords.barriers == 0
        XCTAssertTrue(
            receiptCompletedBeforeDeadline,
            "the cancelled credit waiter must release its close receipt without a timer firing"
        )
        releaseCleanup.release()
        if receiptCompletedBeforeDeadline {
            await session.grantCreditsForTesting(1)
            try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT is sent after ordinary credit refusal") {
                try await transport.waitForCommand(SMB2Commands.treeDisconnect)
            }
            XCTAssertEqual(transport.sentCommands, [SMB2Commands.treeDisconnect])
            try transport.completeTreeDisconnect()
            await treeClose.value
        } else {
            // A failed mutation must fail by assertion while still releasing this test's work.
            await session.closeTransportAndWait(cause: "ordinary_credit_wait_receipt_mutation_cleanup")
            await treeClose.value
        }

        let requestResult = await request.result
        guard case .failure(let error) = requestResult,
              let smbError = error as? SMBError,
              case .treeUnavailable(let failedTreeId, _) = smbError else {
            XCTFail("Tree close must reject the ordinary request locally")
            await session.closeTransportAndWait(cause: "ordinary_credit_wait_expected_local_refusal")
            return
        }
        XCTAssertEqual(failedTreeId, treeId)
        XCTAssertGreaterThan(cleanupClock.callCount, 0, "the manual cleanup deadline was armed")
        let activeRecordsAfterTreeDisconnect = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRecordsAfterTreeDisconnect, 0, "Tree close reclaims the locally refused request before session close")
        await session.setCleanupCloseCreditWaitCatchHookForTesting(nil)
        await session.setTreeCleanupIntentPreparedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "ordinary_credit_wait_tree_close_test_complete")
    }

    func testTreeQuarantineCatchKeepsRecordUntilCreditRefundAcknowledgement() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeAId: UInt32 = 0x00a
        let treeBId: UInt32 = 0x00b
        let maybeTreeAIdentity = await session.ensureTreeIdentity(treeId: treeAId)
        let treeAIdentity = try XCTUnwrap(maybeTreeAIdentity)
        _ = await session.ensureTreeIdentity(treeId: treeBId)
        let treeA = SMBClientTreeSession(session: session, treeId: treeAId, treeIdentity: treeAIdentity)
        let senderAtPrecommit = SMBContinuationCountBarrier()
        let releaseSender = SMBAsyncCallbackSuspensionGate()
        let reservationAtCreditActor = SMBContinuationCountBarrier()
        let releaseReservation = SMBAsyncCallbackSuspensionGate()
        let catchFinished = SMBContinuationCountBarrier()
        defer {
            releaseSender.release()
            releaseReservation.release()
        }
        await session.setSenderPrecommitAdmissionHookForTesting { command in
            guard command == SMB2Commands.flush else { return }
            senderAtPrecommit.signal()
            await releaseSender.suspend()
        }
        await session.setCleanupCloseCreditWaitCatchHookForTesting { catchFinished.signal() }

        let inFlightOtherTree = Task {
            try await session.flushThroughSenderLoopForTesting(
                treeId: treeBId,
                fileId: [UInt8](repeating: 0xB1, count: 16)
            )
        }
        try await smbIssue102AwaitWithTimeout("other Tree FLUSH holds the sender before commit") {
            try await senderAtPrecommit.waitForCount(1)
        }
        let quarantinedRequest = Task {
            try await session.flushThroughSenderLoopForTesting(
                treeId: treeAId,
                fileId: [UInt8](repeating: 0xA1, count: 16)
            )
        }
        await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)

        await session.setCreditReservationAcquiredHookForTesting { _ in
            reservationAtCreditActor.signal()
            await releaseReservation.suspend()
        }
        let creditActorBlocker = Task {
            try await session.flushThroughSenderLoopForTesting(
                treeId: treeBId,
                fileId: [UInt8](repeating: 0xB2, count: 16)
            )
        }
        try await smbIssue102AwaitWithTimeout("a separate credit reservation suspends the credit actor") {
            try await reservationAtCreditActor.waitForCount(1)
        }

        let treeClose = Task { await treeA.close() }
        try await smbIssue102AwaitWithTimeout("Tree isolation fails the queued request continuation") {
            try await catchFinished.waitForCount(1)
        }
        let recordCountBeforeRefundAcknowledgement = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            recordCountBeforeRefundAcknowledgement,
            3,
            "the isolated request record must survive its catch until Tree quarantine refunds its reserved credit"
        )

        releaseReservation.release()
        releaseSender.release()
        if recordCountBeforeRefundAcknowledgement == 3 {
            try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT follows the acknowledged refund") {
                try await transport.waitForCommand(SMB2Commands.treeDisconnect)
            }
            try transport.completeTreeDisconnect()
            await treeClose.value
        } else {
            await session.closeTransportAndWait(cause: "tree_refund_record_mutation_cleanup")
            await treeClose.value
        }

        if case .success = await quarantinedRequest.result {
            XCTFail("Tree isolation must reject its ordinary request")
        }
        let activeRecordsAfterTreeDisconnect = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            activeRecordsAfterTreeDisconnect,
            2,
            "Tree quarantine reclaims its locally refused request; only the two other-Tree requests remain"
        )
        await session.setCreditReservationAcquiredHookForTesting(nil)
        await session.setSenderPrecommitAdmissionHookForTesting(nil)
        await session.setCleanupCloseCreditWaitCatchHookForTesting(nil)
        await session.closeTransportAndWait(cause: "tree_quarantine_refund_receipt_test_complete")
        _ = await inFlightOtherTree.result
        _ = await creditActorBlocker.result
    }

    func testCleanupSoftRetirementKeepsRecordUntilCreditReservationSettles() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let senderAtPrecommit = SMBContinuationCountBarrier()
        let releaseSender = SMBAsyncCallbackSuspensionGate()
        let reservationAtCreditActor = SMBContinuationCountBarrier()
        let releaseReservation = SMBAsyncCallbackSuspensionGate()
        let catchFinished = SMBContinuationCountBarrier()
        let deadlineFinished = SMBContinuationCountBarrier()
        defer {
            releaseSender.release()
            releaseReservation.release()
        }
        await session.setSenderPrecommitAdmissionHookForTesting { command in
            guard command == SMB2Commands.echo else { return }
            senderAtPrecommit.signal()
            await releaseSender.suspend()
        }
        await session.setCleanupCloseCreditWaitCatchHookForTesting { catchFinished.signal() }
        await session.setCleanupSoftDeadlineAppliedHookForTesting { deadlineFinished.signal() }

        let inFlightOtherTree = Task {
            try await session.echoThroughSenderLoopForTesting(treeId: 0x00b)
        }
        try await smbIssue102AwaitWithTimeout("other Tree ECHO holds the sender before cleanup CLOSE") {
            try await senderAtPrecommit.waitForCount(1)
        }
        let cleanupClose = Task {
            await session.bestEffortClose(treeId: 0x00a, fileId: [UInt8](repeating: 0xBC, count: 16))
        }
        try await smbIssue102AwaitWithTimeout("cleanup soft timer is registered") {
            try await cleanupClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(2),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)

        await session.setCreditReservationAcquiredHookForTesting { _ in
            reservationAtCreditActor.signal()
            await releaseReservation.suspend()
        }
        await session.grantCreditsForTesting(1)
        try await smbIssue102AwaitWithTimeout("cleanup CLOSE holds its accepted credit reservation") {
            try await reservationAtCreditActor.waitForCount(1)
        }

        XCTAssertTrue(cleanupClock.fireNext(), "only the manual cleanup soft deadline is advanced")
        try await smbIssue102AwaitWithTimeout("soft timeout retires while CLOSE credit settlement is held") {
            try await deadlineFinished.waitForCount(1)
        }
        let recordCountBeforeReservationSettlement = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            recordCountBeforeReservationSettlement,
            2,
            "soft timeout must retain the CLOSE record while its accepted reservation is still owned"
        )

        releaseReservation.release()
        releaseSender.release()
        try await smbIssue102AwaitWithTimeout("the resumed CLOSE path refunds before catch settlement") {
            try await catchFinished.waitForCount(1)
        }
        let recordCountAfterReservationSettlement = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordCountAfterReservationSettlement, 1, "settled cleanup record is reclaimed")
        let balanceAfterRefundAcknowledgement = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterRefundAcknowledgement, 1, "the held CLOSE credit is refunded")
        await cleanupClose.value
        await session.setCreditReservationAcquiredHookForTesting(nil)
        await session.setSenderPrecommitAdmissionHookForTesting(nil)
        await session.setCleanupCloseCreditWaitCatchHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_soft_refund_receipt_test_complete")
        _ = await inFlightOtherTree.result
    }

    func testCleanupSoftTimeoutKeepsRecordUntilClaimedGrantRefundCompletes() async throws {
        let cleanupClock = ManualSMBSleeper()
        let cleanupSleeper = SMBContinuationSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: SMBContinuationWatchTransport(),
            initialCredits: 0,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let grantClaimed = SMBContinuationCountBarrier()
        let releaseGrantAcceptance = SMBAsyncCallbackSuspensionGate()
        let refundStarted = SMBContinuationCountBarrier()
        let releaseRefund = SMBAsyncCallbackSuspensionGate()
        let catchFinished = SMBContinuationCountBarrier()
        let deadlineFinished = SMBContinuationCountBarrier()
        defer {
            releaseGrantAcceptance.release()
            releaseRefund.release()
            cleanupSleeper.fireAll()
        }
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            switch point {
            case .grantClaimedBeforeAccept(let charge):
                XCTAssertEqual(charge, 1, "the CLOSE request claimed one credit before acceptance")
                grantClaimed.signal()
                await releaseGrantAcceptance.suspend()
            case .refundPending(let charge):
                XCTAssertEqual(charge, 1, "the unaccepted CLOSE grant is refunded once")
                refundStarted.signal()
                await releaseRefund.suspend()
            }
        }
        await session.setCleanupCloseCreditWaitCatchHookForTesting { catchFinished.signal() }
        await session.setCleanupSoftDeadlineAppliedHookForTesting { deadlineFinished.signal() }

        let cleanupClose = Task {
            await session.bestEffortClose(treeId: 0x00a, fileId: [UInt8](repeating: 0xBD, count: 16))
        }
        try await cleanupSleeper.waitForCallCount(1)
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)

        await session.grantCreditsForTesting(1)
        try await grantClaimed.waitForCount(1)
        cleanupClock.advance(by: .seconds(5))
        cleanupSleeper.fireNext()
        try await refundStarted.waitForCount(1)
        releaseGrantAcceptance.release()
        try await catchFinished.waitForCount(1)

        let recordCountWhileRefundIsHeld = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            recordCountWhileRefundIsHeld,
            1,
            "the timed-out request catch must retain its record until the claimed grant refund is acknowledged"
        )
        let balanceWhileRefundIsHeld = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceWhileRefundIsHeld, 0, "the held refund has not returned its credit")

        releaseRefund.release()
        try await deadlineFinished.waitForCount(1)
        let recordCountAfterRefund = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordCountAfterRefund, 0, "the request record is reaped after the refund completes")
        let balanceAfterRefund = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterRefund, 1, "the cancelled grant is returned exactly once")
        await cleanupClose.value
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
        await session.setCleanupCloseCreditWaitCatchHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_claimed_grant_refund_receipt_test_complete")
    }

    func testParentCloseWaitsForPrecommitTransferRefusalToRefundAndCompleteReceipt() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            while cleanupClock.fireNext() {}
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 20)
        let client = SMBClientSession(session: session, treeId: 1)
        let transferClient = SMBClientSession(session: session, treeId: 0x8899)
        let senderAtPrecommit = SMBContinuationCountBarrier()
        let releaseSender = SMBAsyncCallbackSuspensionGate()
        let quarantinePrepared = SMBContinuationCountBarrier()
        defer { releaseSender.release() }
        await session.setSenderPrecommitAdmissionHookForTesting { command in
            guard command == SMB2Commands.read else { return }
            senderAtPrecommit.signal()
            await releaseSender.suspend()
        }
        await session.setTreeCleanupIntentPreparedHookForTesting { _ in quarantinePrepared.signal() }

        let scopedOperation = Task {
            try await client.withTree(share: "other") { _ in
                _ = try await transferClient.read(path: "a", knownSize: 1)
            }
        }
        try await smbIssue102AwaitWithTimeout("nested TREE_CONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x8899, credits: 1)
        try await smbIssue102AwaitWithTimeout("transfer CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 1)
        try await smbIssue102AwaitWithTimeout("READ reaches sender precommit admission") {
            try await senderAtPrecommit.waitForCount(1)
        }

        let parentClose = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("parent close quarantines the scoped Tree") {
            try await quarantinePrepared.waitForCount(1)
        }
        XCTAssertTrue(transport.sentTreeDisconnectTreeIDs.isEmpty, "the popped READ still owns its retirement receipt")
        releaseSender.release()

        try await smbIssue102AwaitWithTimeout("READ refusal refunds credit and completes its retirement receipt") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 1)
        }
        let recordsWhileTreeDisconnectIsPending = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            recordsWhileTreeDisconnectIsPending,
            1,
            "the refused READ record is reclaimed; only the child TREE_DISCONNECT record remains"
        )
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("parent disconnect follows the scoped Tree") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 2)
        }
        try transport.completeTreeDisconnect()
        await parentClose.value
        if case .success = await scopedOperation.result {
            XCTFail("the quarantined READ must fail locally")
        }
        XCTAssertGreaterThanOrEqual(cleanupClock.callCount, 1, "the fixed soft deadline was registered but did not need to expire")
        await session.setSenderPrecommitAdmissionHookForTesting(nil)
        await session.setTreeCleanupIntentPreparedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "parent_close_precommit_transfer_refusal")
    }

    func testWireReceiptCompletesBeforeReapedRecordWhenGrantWasAcknowledgedFirst() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let sendOwnerEntered = SMBContinuationCountBarrier()
        let releaseSendOwner = SMBAsyncCallbackSuspensionGate()
        let softDeadlineApplied = SMBContinuationCountBarrier()
        let grantEntered = SMBContinuationCountBarrier()
        let releaseGrant = SMBAsyncCallbackSuspensionGate()
        let grantAcknowledged = SMBContinuationCountBarrier()
        let recordReaped = SMBContinuationCountBarrier()
        let operationBarrierEvaluation = SMBContinuationBooleanLatch()
        let timeoutRegistrationGuard = ManualSMBSleeper()
        defer {
            releaseSendOwner.release()
            releaseGrant.release()
        }
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            sendOwnerEntered.signal()
            await releaseSendOwner.suspend()
        }
        await session.setCleanupSoftDeadlineAppliedHookForTesting { softDeadlineApplied.signal() }
        await session.setCreditGrantAfterAwaitHookForTesting {
            grantEntered.signal()
            await releaseGrant.suspend()
        }
        await session.setFinalCreditGrantAcknowledgedHookForTesting { grantAcknowledged.signal() }
        await session.setActivePostAuthRequestRecordReapedHookForTesting { _ in recordReaped.signal() }
        await session.setOperationBarrierEvaluationHookForTesting { _, blocked in
            operationBarrierEvaluation.signal(blocked)
        }

        let fileClose = Task { try await session.closeCreatedHandle(treeId: treeId, fileId: [UInt8](repeating: 0x67, count: 16)) }
        try await transport.waitForCommand(SMB2Commands.close)
        try await sendOwnerEntered.waitForCount(1)
        try await cleanupClock.waitUntilCallCount(
            atLeast: 1,
            timeout: .seconds(1),
            sleeper: { try await timeoutRegistrationGuard.sleep(for: $0) }
        )
        XCTAssertTrue(cleanupClock.fireNext(), "the File CLOSE soft deadline is driven by the manual sleeper")
        try await softDeadlineApplied.waitForCount(1)
        do {
            try await fileClose.value
            XCTFail("the File CLOSE caller should time out while the send owner is held")
        } catch SMBTransportError.timedOut {
        }

        try transport.completeClose()
        try await grantEntered.waitForCount(1)
        releaseGrant.release()
        try await grantAcknowledged.waitForCount(1)

        let closeTree = Task { await tree.close() }
        let barrierWasBlocked = await operationBarrierEvaluation.wait()
        XCTAssertTrue(barrierWasBlocked, "Tree close records the outstanding CLOSE wire receipt")
        let barriersBeforeOwnerRecovery = await session.operationLifecycleRecordCountsForTesting().barriers
        XCTAssertEqual(barriersBeforeOwnerRecovery, 1)

        releaseSendOwner.release()
        await session.waitForRequestSentCountForTesting(atLeast: 1)
        try await recordReaped.waitForCount(1)
        let barriersAfterRecordReap = await session.operationLifecycleRecordCountsForTesting().barriers
        XCTAssertEqual(
            barriersAfterRecordReap,
            0,
            "the wire receipt must complete in the same transition that reaps its request record"
        )
        guard barriersAfterRecordReap == 0 else {
            await session.closeTransportAndWait(cause: "wire_receipt_reap_order_reproduction")
            await closeTree.value
            await session.setCleanupFullSendBoundaryHookForTesting(nil)
            await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
            await session.setCreditGrantAfterAwaitHookForTesting(nil)
            await session.setFinalCreditGrantAcknowledgedHookForTesting(nil)
            await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
            return
        }

        try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        try transport.completeTreeDisconnect()
        await closeTree.value
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        await session.setFinalCreditGrantAcknowledgedHookForTesting(nil)
        await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "wire_receipt_reap_order_test_complete")
    }

    func testWireReceiptWaitsForSendOwnerAfterFinalGrantAcknowledgement() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport(holdCloseResponses: true)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(30),
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        let treeId: UInt32 = 0x00a
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: treeId)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: treeId, treeIdentity: treeIdentity)
        let sendOwnerEntered = SMBContinuationCountBarrier()
        let releaseSendOwner = SMBAsyncCallbackSuspensionGate()
        let grantEntered = SMBContinuationCountBarrier()
        let releaseGrant = SMBAsyncCallbackSuspensionGate()
        let grantAcknowledged = SMBContinuationCountBarrier()
        let recordReaped = SMBContinuationCountBarrier()
        let operationBarrierEvaluation = SMBContinuationBooleanLatch()
        defer {
            releaseSendOwner.release()
            releaseGrant.release()
        }
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            sendOwnerEntered.signal()
            await releaseSendOwner.suspend()
        }
        await session.setCreditGrantAfterAwaitHookForTesting {
            grantEntered.signal()
            await releaseGrant.suspend()
        }
        await session.setFinalCreditGrantAcknowledgedHookForTesting { grantAcknowledged.signal() }
        await session.setActivePostAuthRequestRecordReapedHookForTesting { _ in recordReaped.signal() }
        await session.setOperationBarrierEvaluationHookForTesting { _, blocked in
            operationBarrierEvaluation.signal(blocked)
        }

        let fileClose = Task { try await session.closeCreatedHandle(treeId: treeId, fileId: [UInt8](repeating: 0x68, count: 16)) }
        try await transport.waitForCommand(SMB2Commands.close)
        try await sendOwnerEntered.waitForCount(1)
        try transport.completeClose()
        try await grantEntered.waitForCount(1)

        let closeTree = Task { await tree.close() }
        let barrierWasBlocked = await operationBarrierEvaluation.wait()
        XCTAssertTrue(barrierWasBlocked, "Tree close registers its wire receipt while the grant is pending")
        let barriersWhileGrantHeld = await session.operationLifecycleRecordCountsForTesting().barriers
        XCTAssertEqual(barriersWhileGrantHeld, 1)

        releaseGrant.release()
        try await grantAcknowledged.waitForCount(1)
        let barriersAfterGrantAck = await session.operationLifecycleRecordCountsForTesting().barriers
        XCTAssertEqual(
            barriersAfterGrantAck,
            1,
            "grant acknowledgement alone cannot complete a receipt while the original send owner is held"
        )
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))
        guard barriersAfterGrantAck == 1 else {
            releaseSendOwner.release()
            await session.closeTransportAndWait(cause: "wire_receipt_grant_before_owner_reproduction")
            _ = await fileClose.result
            await closeTree.value
            await session.setCleanupFullSendBoundaryHookForTesting(nil)
            await session.setCreditGrantAfterAwaitHookForTesting(nil)
            await session.setFinalCreditGrantAcknowledgedHookForTesting(nil)
            await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
            return
        }

        releaseSendOwner.release()
        await session.waitForRequestSentCountForTesting(atLeast: 1)
        try await recordReaped.waitForCount(1)
        try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        try transport.completeTreeDisconnect()
        try await fileClose.value
        await closeTree.value
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        await session.setFinalCreditGrantAcknowledgedHookForTesting(nil)
        await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "wire_receipt_grant_before_owner_test_complete")
    }

    func testPublicSessionCloseBoundsBlockedLeaseBarrierWithCleanupBudget() async throws {
        let transport = SMBContinuationWatchTransport()
        let clock = ManualSMBSleeper()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            sessionTime: clock.sessionTime,
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let releaseCallback = SMBAsyncCallbackSuspensionGate()
        let childSoftDeadlineApplied = SMBContinuationBooleanLatch()
        await session.setCleanupSoftDeadlineAppliedHookForTesting {
            childSoftDeadlineApplied.signal(true)
        }
        let operation = Task {
            try await client.withTree(share: "other") { _ in
                callbackEntered.signal()
                await releaseCallback.suspend()
                return 11
            }
        }
        try await transport.waitForCommand(SMB2Commands.treeConnect)
        try transport.completeTreeConnect(treeId: 0x7788)
        try await callbackEntered.waitForCount(1)

        let close = Task { await client.close() }
        try await clock.waitUntilCallCount(
            atLeast: 2,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))
        XCTAssertTrue(clock.fireNext(), "expire the prepared child Tree intent")
        let childCallbackCompleted = await childSoftDeadlineApplied.wait()
        XCTAssertTrue(childCallbackCompleted, "the child timeout actor callback reached its hook")
        XCTAssertEqual(transport.closeCount, 0, "a child deadline cannot replace the parent close barrier deadline")
        XCTAssertTrue(clock.fireNext(), "advance the session close barrier budget")
        try await transport.waitForCloseCount(1)
        await close.value
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.logoff))

        releaseCallback.release()
        _ = await operation.result
        let closed = await session.isTransportClosedForTesting()
        XCTAssertTrue(closed)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
    }

    func testPublicCloseScansPastReleasedChildLeaseInInheritedAncestry() async throws {
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let parentOwner = await client.facadeOwnerForTesting()
        let childOwner = SMBFacadeOwnerAllocator.make()
        await session.registerFacade(owner: parentOwner)
        await session.registerFacade(owner: childOwner, parent: parentOwner)
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: 2)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let optionalParentLease = await session.acquireOperationLease(owner: parentOwner, tree: nil)
        let optionalChildLease = await session.acquireOperationLease(owner: childOwner, tree: treeIdentity)
        let parentLease = try XCTUnwrap(optionalParentLease)
        let childLease = try XCTUnwrap(optionalChildLease)
        let closeEvent = SMBContinuationCloseEventLatch()
        let closeReturned = SMBContinuationCountBarrier()
        let eventBeforeParentRelease = await SMBOperationTaskContext.withLease(parentLease) {
            let staleAncestry = await SMBOperationTaskContext.withLease(childLease) {
                SMBOperationTaskContext.ancestry
            }
            await session.releaseOperationLease(childLease)
            _ = Task {
                await SMBOperationTaskContext.$ancestry.withValue(staleAncestry) {
                    await client.closeForTesting { closeEvent.signal($0) }
                }
                closeReturned.signal()
            }
            do {
                return try await smbIssue102AwaitWithTimeout(
                    "public close scans the active parent lease beneath the released child frame"
                ) {
                    try await closeEvent.wait()
                }
            } catch {
                return .joinedExistingCleanup
            }
        }
        XCTAssertEqual(eventBeforeParentRelease, .returnedWithoutJoining)
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "the parent close worker stays behind the active parent lease"
        )

        await session.releaseOperationLease(parentLease)
        try await smbIssue102AwaitWithTimeout("parent TREE_DISCONNECT after parent lease release") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("public close returns after its started cleanup finishes") {
            try await closeReturned.waitForCount(1)
        }
        await client.close()
        await session.closeTransportAndWait(cause: "stale_child_ancestry_public_close")
    }

    func testTreeLeaseSoftExpiryRetiresWithoutLateDisconnect() async throws {
        let cleanupClock = ManualSMBSleeper()
        let transport = SMBContinuationWatchTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 8,
            cleanupTimeout: .seconds(5),
            requestTimeout: nil,
            sessionTime: cleanupClock.sessionTime,
            cleanupTimeoutSleeper: { try await cleanupClock.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 10)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackCloseReturned = SMBContinuationCountBarrier()
        let bodyGate = SMBContinuationAsyncGate()
        let bodySleeper = ManualSMBSleeper()
        let softDeadlineApplied = SMBContinuationCountBarrier()
        await session.setCleanupSoftDeadlineAppliedHookForTesting {
            softDeadlineApplied.signal()
        }
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            bodyGate.release()
            _ = cleanupClock.fireNext()
        }

        let withTree: Task<Int, Error> = Task {
            try await client.withTree(share: "other") { tree in
                await tree.close()
                callbackCloseReturned.signal()
                try await bodyGate.suspend(
                    timeout: .seconds(60),
                    sleeper: { try await bodySleeper.sleep(for: $0) }
                )
                return 7
            }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before held-lease expiry") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(treeId: 0x6677)
        try await smbIssue102AwaitWithTimeout("reentrant close returns with the body lease active") {
            try await callbackCloseReturned.waitForCount(1)
        }
        try await cleanupClock.waitUntilCallCount(
            atLeast: 1,
            timeout: .seconds(1),
            sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
        )
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))

        XCTAssertTrue(cleanupClock.fireNext(), "the cleanup soft deadline expires while the callback lease is held")
        try await smbIssue102AwaitWithTimeout("soft expiry retires the blocked Tree cleanup") {
            try await softDeadlineApplied.waitForCount(1)
        }
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))

        bodyGate.release()
        do {
            _ = try await smbIssue102AwaitWithTimeout("withTree joins the expired lease barrier") {
                try await withTree.value
            }
            XCTFail("expected the expired Tree cleanup to be reported")
        } catch SMBError.cleanupFailed(resource: .tree(treeId: 0x6677), underlying: let reason) {
            XCTAssertTrue(reason.contains("lease barrier exceeded"), reason)
        }
        XCTAssertFalse(
            transport.sentCommands.contains(SMB2Commands.treeDisconnect),
            "a lease released after soft retirement cannot enqueue TREE_DISCONNECT"
        )
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "tree_lease_soft_expiry_test_complete")
    }

    func testCloseBoundsPendingScopedTreeSetupAndClosesTransport() async throws {
        let setupDeadlineSleeper = SMBContinuationSleeperGate()
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            setupDeadlineSleeper.fireAll()
            cleanupSleeper.fireAll()
            setupDeadlineSleeper.reset()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(
            session: session,
            treeId: 1,
            closeSetupDeadlineSleeper: { try await setupDeadlineSleeper.sleep(for: $0) }
        )
        let bodyCalls = SMBContinuationCountBarrier()
        let setup: Task<Void, Error> = Task {
            try await client.withTree(share: "other") { _ in bodyCalls.signal() }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT setup request") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        let close = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("close-owned setup deadline registration") {
            try await setupDeadlineSleeper.waitForCallCount(1)
        }
        XCTAssertEqual(setupDeadlineSleeper.callCount, 1)
        XCTAssertEqual(setupDeadlineSleeper.pendingCallWaiterCount, 0)
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 1)

        setupDeadlineSleeper.fireNext()
        try await smbIssue102AwaitWithTimeout("close after setup deadline closes transport") {
            await close.value
        }
        do {
            try await smbIssue102AwaitWithTimeout("TREE_CONNECT released by close deadline") {
                try await setup.value
            }
            XCTFail("expected the close deadline to fail the pending TREE_CONNECT")
        } catch SMBTransportError.connectionClosed {
            // The close-owned setup deadline closes the transport to release the request.
        }

        XCTAssertEqual(bodyCalls.currentCount, 0, "a setup completing after close must not start its body")
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 0)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testTreeConnectFailureClearsSetupBeforeClientClose() async throws {
        let setupDeadlineSleeper = SMBContinuationSleeperGate()
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            setupDeadlineSleeper.fireAll()
            cleanupSleeper.fireAll()
            setupDeadlineSleeper.reset()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(
            session: session,
            treeId: 1,
            closeSetupDeadlineSleeper: { try await setupDeadlineSleeper.sleep(for: $0) }
        )
        let bodyCalls = SMBContinuationCountBarrier()
        let setup: Task<Void, Error> = Task {
            try await client.withTree(share: "other") { _ in bodyCalls.signal() }
        }

        try await smbIssue102AwaitWithTimeout("failed TREE_CONNECT request") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try transport.completeTreeConnect(status: SMB2Status.accessDenied)
        do {
            try await smbIssue102AwaitWithTimeout("withTree returns TREE_CONNECT failure") {
                try await setup.value
            }
            XCTFail("expected TREE_CONNECT failure")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "TREE_CONNECT") {
            // The server's failed TREE_CONNECT response finishes this setup.
        }

        let setupCount = await client.treeSetupCountForTesting()
        XCTAssertEqual(setupCount, 0)
        XCTAssertEqual(bodyCalls.currentCount, 0)
        let close = Task { await client.close() }
        if setupCount > 0 {
            try await smbIssue102AwaitWithTimeout("unexpected setup deadline during failure cleanup") {
                try await setupDeadlineSleeper.waitForCallCount(1)
            }
            setupDeadlineSleeper.fireAll()
            try await smbIssue102AwaitWithTimeout("close after unexpected failure setup registration") {
                await close.value
            }
            return
        }
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT after failed scoped setup") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        XCTAssertEqual(setupDeadlineSleeper.callCount, 0)
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 0)

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("close after failed scoped setup") {
            await close.value
        }
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs, [1])
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testCancelledTreeConnectClearsSetupBeforeClientClose() async throws {
        let setupDeadlineSleeper = SMBContinuationSleeperGate()
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            setupDeadlineSleeper.fireAll()
            cleanupSleeper.fireAll()
            setupDeadlineSleeper.reset()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(
            session: session,
            treeId: 1,
            closeSetupDeadlineSleeper: { try await setupDeadlineSleeper.sleep(for: $0) }
        )
        let bodyCalls = SMBContinuationCountBarrier()
        let setup: Task<Void, Error> = Task {
            try await client.withTree(share: "other") { _ in bodyCalls.signal() }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before caller cancellation") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        try await smbIssue102AwaitWithTimeout("TREE_CONNECT is marked sent before caller cancellation") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        setup.cancel()
        do {
            try await smbIssue102AwaitWithTimeout("cancelled withTree setup returns") {
                try await setup.value
            }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
            // The caller cancellation ends withTree before the client is closed.
        }

        let setupCount = await client.treeSetupCountForTesting()
        XCTAssertEqual(setupCount, 0)
        XCTAssertEqual(bodyCalls.currentCount, 0)
        let close = Task { await client.close() }
        if setupCount > 0 {
            try await smbIssue102AwaitWithTimeout("unexpected setup deadline during cancellation cleanup") {
                try await setupDeadlineSleeper.waitForCallCount(1)
            }
            setupDeadlineSleeper.fireAll()
            try await smbIssue102AwaitWithTimeout("close after unexpected cancellation setup registration") {
                await close.value
            }
            return
        }
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT after cancelled scoped setup") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        XCTAssertEqual(setupDeadlineSleeper.callCount, 0)
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 0)

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("close after cancelled scoped setup") {
            await close.value
        }
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs, [1])
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testCloseWaitsForScopedTreeSetupAndOwnsPublishedChild() async throws {
        let setupDeadlineSleeper = SMBContinuationSleeperGate()
        let cleanupSleeper = SMBContinuationSleeperGate()
        let transport = SMBContinuationWatchTransport()
        defer {
            if transport.closeCount == 0 { transport.failConnection() }
            setupDeadlineSleeper.fireAll()
            cleanupSleeper.fireAll()
            setupDeadlineSleeper.reset()
            cleanupSleeper.reset()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(
            session: session,
            treeId: 1,
            closeSetupDeadlineSleeper: { try await setupDeadlineSleeper.sleep(for: $0) }
        )
        let bodyCalls = SMBContinuationCountBarrier()
        let setup: Task<Void, Error> = Task {
            try await client.withTree(share: "other") { _ in bodyCalls.signal() }
        }

        try await smbIssue102AwaitWithTimeout("TREE_CONNECT before close") {
            try await transport.waitForCommand(SMB2Commands.treeConnect)
        }
        let close = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("close-owned setup deadline before TREE_CONNECT response") {
            try await setupDeadlineSleeper.waitForCallCount(1)
        }
        XCTAssertEqual(setupDeadlineSleeper.callCount, 1)
        XCTAssertEqual(setupDeadlineSleeper.pendingCallWaiterCount, 0)
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 1)

        try transport.completeTreeConnect(treeId: 0x5566)
        do {
            try await smbIssue102AwaitWithTimeout("close prevents scoped body from starting") {
                try await setup.value
            }
            XCTFail("expected close to reject the scoped tree after setup")
        } catch SMBError.connectionLost(operation: "SESSION") {
            // The close task takes ownership of the connected child before setup drains.
        }

        try await smbIssue102AwaitWithTimeout("close-owned child TREE_DISCONNECT") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 1)
        }
        XCTAssertEqual(setupDeadlineSleeper.pendingSleepCount, 0, "successful setup cancels its deadline")
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("primary TREE_DISCONNECT after child cleanup") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 2)
        }
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("close after setup handoff") { await close.value }

        XCTAssertEqual(bodyCalls.currentCount, 0)
        XCTAssertEqual(transport.sentTreeDisconnectTreeIDs, [0x5566, 1])
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(cleanupSleeper.pendingSleepCount, 0)
    }

    func testConcurrentReconnectRequestsShareOneCandidateSession() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let requestBarrier = SMBContinuationCountBarrier()
        let requestBarrierClock = ManualSMBSleeper()
        let transports = SMBContinuationTransportFactory(
            transports: try (0..<3).map { _ in
                SMBValidateNegotiateScriptTransport(
                    inbound: try SMBIssue102WireFixtures.framed(
                        SMBIssue102WireFixtures.anonymousSessionResponses()
                    ),
                    credential: .anonymous
                )
            }
        )
        let client = makeClientSession(
            credentialProvider: { try await providerGate.getCredential() },
            makeTransport: { transports.makeTransport() }
        )

        let first: Task<Void, Error> = Task {
            try await client.reconnectForTesting(onRequest: { requestBarrier.signal() })
        }
        let second: Task<Void, Error> = Task {
            try await client.reconnectForTesting(onRequest: { requestBarrier.signal() })
        }
        try await smbIssue102AwaitWithTimeout("both reconnect requests") {
            try await requestBarrier.waitForCount(
                2,
                timeout: .seconds(1),
                sleeper: { try await requestBarrierClock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("shared credential provider") {
            try await providerGate.waitForCallCount(1)
        }
        providerGate.release()

        try await smbIssue102AwaitWithTimeout("first shared reconnect waiter") { try await first.value }
        try await smbIssue102AwaitWithTimeout("second shared reconnect waiter") { try await second.value }
        XCTAssertEqual(providerGate.callCount, 1)
        XCTAssertEqual(transports.makeCount, 1)
        await (await client.wireSessionForTesting()).closeTransport(cause: "test_cleanup")
    }

    func testCloseReleasesAllReconnectWaitersBeforeCredentialProviderReturns() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let providerCancellation = SMBContinuationCountBarrier()
        let providerReturned = SMBContinuationCountBarrier()
        let requestBarrier = SMBContinuationCountBarrier()
        let requestBarrierClock = ManualSMBSleeper()
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(SMBIssue102WireFixtures.anonymousSessionResponses()),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport(),
            initialCredits: 4,
            cleanupTimeout: .milliseconds(100)
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: {
                try await withTaskCancellationHandler {
                    let credential = try await providerGate.getCredentialIgnoringCancellation()
                    providerReturned.signal()
                    return credential
                } onCancel: {
                    providerCancellation.signal()
                }
            },
            makeTransport: { transports.makeTransport() }
        )
        let reconnectWaiters: [Task<Void, Error>] = (0..<2).map { _ in
            Task {
                try await client.reconnectForTesting(onRequest: { requestBarrier.signal() })
            }
        }

        defer { providerGate.release() }
        try await smbIssue102AwaitWithTimeout("both reconnect waiters before close") {
            try await requestBarrier.waitForCount(
                2,
                timeout: .seconds(1),
                sleeper: { try await requestBarrierClock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("credential provider before close") {
            try await providerGate.waitForCallCount(1)
        }
        let reconnectTaskForTesting = await client.reconnectTaskForTesting()
        let sharedReconnectTask = try XCTUnwrap(reconnectTaskForTesting)
        let closeTask = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("client close while provider remains parked") {
            await closeTask.value
        }
        XCTAssertFalse(providerGate.isReleased, "close must finish before the provider returns")

        for (index, reconnect) in reconnectWaiters.enumerated() {
            do {
                try await smbIssue102AwaitWithTimeout("reconnect waiter \(index) released by close") {
                    try await reconnect.value
                }
                XCTFail("expected close to win over reconnect")
            } catch SMBError.connectionLost(operation: "RECONNECT") {
                // Close releases each waiter even though the shared provider was parked.
            }
        }

        do {
            try await smbIssue102AwaitWithTimeout("provider cancellation handler after close") {
                try await providerCancellation.waitForCount(1)
            }
        } catch {
            XCTFail("provider cancellation handler was not reached after close: \(error)")
        }
        XCTAssertFalse(providerGate.isReleased, "the cancellation observation must not release the provider")
        XCTAssertEqual(transports.makeCount, 0)

        providerGate.release()
        try await smbIssue102AwaitWithTimeout("provider returns after explicit release") {
            try await providerReturned.waitForCount(1)
        }
        try await smbIssue102AwaitWithTimeout("shared reconnect task exits after provider return") {
            await sharedReconnectTask.value
        }
        XCTAssertEqual(transports.makeCount, 0, "a closed client must not create a candidate session")
        let publishedSession = await client.wireSessionForTesting()
        XCTAssertTrue(publishedSession === oldSession)
    }

    func testCloseWhileWatchReconnectProviderIsParkedStopsTheWatch() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(SMBIssue102WireFixtures.anonymousSessionResponses()),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let transport = SMBContinuationWatchTransport()
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: { try await providerGate.getCredential() },
            makeTransport: { transports.makeTransport() }
        )
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: true) { _ in }
        }

        try await smbIssue102AwaitWithTimeout("watch CREATE before reconnect") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("watch CHANGE_NOTIFY before disconnect") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        transport.failConnection()
        try await smbIssue102AwaitWithTimeout("watch reconnect provider") {
            try await providerGate.waitForCallCount(1)
        }
        defer { providerGate.release() }
        try await smbIssue102AwaitWithTimeout("close releases watch reconnect waiter") {
            await client.close()
        }

        try await smbIssue102AwaitWithTimeout("watcher returns after close") { try await watcher.value }
        XCTAssertEqual(providerGate.callCount, 1)
        XCTAssertEqual(transports.makeCount, 0)
        XCTAssertEqual(transport.sentCommands.filter { $0 == SMB2Commands.create }.count, 1)
    }

    func testCloseFromReconnectOverflowCallbackStopsBeforeNextWatchIteration() async throws {
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(
                SMBIssue102WireFixtures.anonymousReconnectResponsesWithCleanup()
            ),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let transport = SMBContinuationWatchTransport()
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: { .anonymous },
            makeTransport: { transports.makeTransport() }
        )
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: true) { event in
                if event == .overflow { await client.close() }
            }
        }

        try await smbIssue102AwaitWithTimeout("overflow watch CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("overflow watch CHANGE_NOTIFY") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        transport.failConnection()
        try await smbIssue102AwaitWithTimeout("watcher stops after overflow callback close") {
            try await watcher.value
        }

        XCTAssertEqual(transports.makeCount, 1)
        XCTAssertFalse(try outboundCommands(candidate.outbound).contains(SMB2Commands.create))
    }

    func testCloseDuringCandidateTreeConnectClosesCandidateWithoutPublishingIt() async throws {
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        let candidateResponses = Array(try SMBIssue102WireFixtures.anonymousSessionResponses().prefix(3))
        let candidateTransport = SMBContinuationScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(candidateResponses)
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: { .anonymous },
            makeTransport: { candidateTransport }
        )
        let reconnect: Task<Void, Error> = Task {
            try await client.reconnectForTesting(onRequest: {})
        }

        try await smbIssue102AwaitWithTimeout("candidate TREE_CONNECT sent") {
            try await candidateTransport.waitForCommand(SMB2Commands.treeConnect)
        }
        try await smbIssue102AwaitWithTimeout("close candidate with unanswered TREE_CONNECT") {
            await client.close()
        }

        do {
            try await smbIssue102AwaitWithTimeout("candidate reconnect waiter after close") {
                try await reconnect.value
            }
            XCTFail("expected close to prevent candidate publication")
        } catch SMBError.connectionLost(operation: "RECONNECT") {
            // Closing the unpublished candidate transport fails its unanswered TREE_CONNECT.
        }
        let publishedSession = await client.wireSessionForTesting()
        XCTAssertTrue(publishedSession === oldSession)
        XCTAssertGreaterThan(candidateTransport.closeCount, 0)
        candidateTransport.close()
    }

    func testCloseAfterWatchCreateStopsBeforeChangeNotify() async throws {
        let transport = SMBContinuationWatchTransport(autoRespondChangeNotify: true)
        let createSendGate = SMBContinuationAsyncGate()
        let createSendGateClock = ManualSMBSleeper()
        let disconnectSendGate = SMBContinuationAsyncGate()
        let disconnectSendGateClock = ManualSMBSleeper()
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.create {
                try? await createSendGate.suspend(
                    timeout: .seconds(3),
                    sleeper: { try await createSendGateClock.sleep(for: $0) }
                )
            }
            if command == SMB2Commands.treeDisconnect {
                try? await disconnectSendGate.suspend(
                    timeout: .seconds(3),
                    sleeper: { try await disconnectSendGateClock.sleep(for: $0) }
                )
            }
        }
        defer {
            createSendGate.release()
            disconnectSendGate.release()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir") { _ in }
        }

        try await smbIssue102AwaitWithTimeout("CREATE before close") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        let closeTask = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT while CREATE is pending") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeCreate()
        try transport.completeTreeDisconnect()
        createSendGate.release()
        disconnectSendGate.release()
        var watcherError: Error?
        do {
            try await smbIssue102AwaitWithTimeout("watcher close check after CREATE") { try await watcher.value }
        } catch {
            watcherError = error
        }
        let sentChangeNotify = transport.sentCommands.contains(SMB2Commands.changeNotify)

        try await smbIssue102AwaitWithTimeout("close after TREE_DISCONNECT response") { await closeTask.value }
        XCTAssertNil(watcherError)
        XCTAssertFalse(sentChangeNotify)
    }

    func testTreeDisconnectRequestIsSavedBeforeItsReachedSignal() async throws {
        let transport = SMBContinuationWatchTransport(autoRespondChangeNotify: true)
        let disconnectSendGate = SMBContinuationAsyncGate()
        let disconnectSendGateClock = ManualSMBSleeper()
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.treeDisconnect {
                try? await disconnectSendGate.suspend(
                    timeout: .seconds(3),
                    sleeper: { try await disconnectSendGateClock.sleep(for: $0) }
                )
            }
        }
        defer {
            disconnectSendGate.release()
            transport.failConnection()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir") { _ in }
        }

        try await smbIssue102AwaitWithTimeout("CREATE before TREE_DISCONNECT capture check") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("CHANGE_NOTIFY before TREE_DISCONNECT capture check") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        do {
            try await smbIssue102AwaitWithTimeout("watcher before TREE_DISCONNECT capture check") {
                try await watcher.value
            }
            XCTFail("expected the scripted CHANGE_NOTIFY error")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "CHANGE_NOTIFY") {
            // The watcher has closed its handle; the tree remains open until client.close().
        }

        let closeTask = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT reached before response") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        disconnectSendGate.release()
        try await smbIssue102AwaitWithTimeout("client close after TREE_DISCONNECT capture check") {
            await closeTask.value
        }
    }

    func testFakeTreeDisconnectStateIsAvailableWhenReachedWaiterResumes() async throws {
        let transport = SMBContinuationWatchTransport()
        let sendGate = SMBContinuationAsyncGate()
        let sendGateClock = ManualSMBSleeper()
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.treeDisconnect {
                try? await sendGate.suspend(
                    timeout: .seconds(3),
                    sleeper: { try await sendGateClock.sleep(for: $0) }
                )
            }
        }
        defer {
            sendGate.release()
            transport.failConnection()
        }
        var packet = try SMB2Header(
            command: SMB2Commands.treeDisconnect,
            messageId: 17,
            treeId: 1,
            sessionId: 2
        ).encode()
        packet.append(contentsOf: [4, 0, 0, 0])
        let sendTask: Task<Void, Error> = Task {
            try await transport.send(DirectTCPFraming.frame(packet))
        }

        try await smbIssue102AwaitWithTimeout("fake TREE_DISCONNECT reached signal") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        try transport.completeTreeDisconnect()
        sendGate.release()
        try await smbIssue102AwaitWithTimeout("fake TREE_DISCONNECT send") { try await sendTask.value }
    }

    func testCancellingOneWatchReconnectWaiterReturnsCancellationError() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(SMBIssue102WireFixtures.anonymousSessionResponses()),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let transport = SMBContinuationWatchTransport()
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: { try await providerGate.getCredential() },
            makeTransport: { transports.makeTransport() }
        )
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: true) { _ in }
        }

        try await smbIssue102AwaitWithTimeout("CREATE before watcher cancellation") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("CHANGE_NOTIFY before watcher cancellation") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        transport.failConnection()
        try await smbIssue102AwaitWithTimeout("watcher enters reconnect provider") {
            try await providerGate.waitForCallCount(1)
        }
        defer { providerGate.release() }

        watcher.cancel()
        do {
            try await smbIssue102AwaitWithTimeout("cancelled reconnect waiter") { try await watcher.value }
            XCTFail("expected watcher cancellation to propagate")
        } catch is CancellationError {
            // Cancelling this waiter does not wait for the shared provider task.
        }
        providerGate.release()
        try await smbIssue102AwaitWithTimeout("close after watcher cancellation") {
            await client.close()
        }
        XCTAssertEqual(transports.makeCount, 0)
    }

    func testSessionSetupCancelledStatusIsNotRetriedByWatchReconnect() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let cancelledCandidates = try (0..<6).map { _ in
            SMBContinuationScriptTransport(
                inbound: try SMBIssue102WireFixtures.framed(
                    SMBIssue102WireFixtures.anonymousReconnectCancelledAtSessionSetupResponses()
                )
            )
        }
        let transports = SMBContinuationTransportFactory(transports: cancelledCandidates)
        let transport = SMBContinuationWatchTransport()
        let oldSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = makeClientSession(
            session: oldSession,
            credentialProvider: { try await providerGate.getCredential() },
            makeTransport: { transports.makeTransport() }
        )
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: true) { _ in }
        }

        try await smbIssue102AwaitWithTimeout("CREATE before reconnect SESSION_SETUP cancellation") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("CHANGE_NOTIFY before reconnect SESSION_SETUP cancellation") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        transport.failConnection()
        try await smbIssue102AwaitWithTimeout("credential provider before cancelled SESSION_SETUP") {
            try await providerGate.waitForCallCount(1)
        }
        providerGate.release()

        do {
            try await smbIssue102AwaitWithTimeout("watch propagates SESSION_SETUP cancellation") {
                try await watcher.value
            }
            XCTFail("expected SESSION_SETUP STATUS_CANCELLED to propagate")
        } catch is CancellationError {
            XCTAssertEqual(transports.makeCount, 1, "STATUS_CANCELLED must not start another reconnect")
        }
    }

    func testCloseDuringBlockedChangeNotifyCallbackDoesNotResubscribe() async throws {
        let transport = SMBContinuationWatchTransport()
        let callbackReached = SMBContinuationCountBarrier()
        let callbackReachedClock = ManualSMBSleeper()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        defer {
            callbackGate.release()
            transport.failConnection()
        }
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir") { event in
                XCTAssertEqual(event, .overflow)
                callbackReached.signal()
                try? await callbackGate.suspend(
                    timeout: .seconds(3),
                    sleeper: { try await callbackGateClock.sleep(for: $0) }
                )
            }
        }

        try await smbIssue102AwaitWithTimeout("watch CREATE before blocked callback") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("first CHANGE_NOTIFY before callback") {
            try await transport.waitForCommand(SMB2Commands.changeNotify)
        }
        try transport.completeChangeNotify()
        try await smbIssue102AwaitWithTimeout("overflow callback is blocked") {
            try await callbackReached.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await callbackReachedClock.sleep(for: $0) }
            )
        }

        let closeTask = Task { await client.close() }
        try await smbIssue102AwaitWithTimeout("TREE_DISCONNECT held while callback is blocked") {
            try await transport.waitForCommand(SMB2Commands.treeDisconnect)
        }
        callbackGate.release()
        try await smbIssue102AwaitWithTimeout("watcher returns after close during callback") {
            try await watcher.value
        }
        XCTAssertEqual(
            transport.sentCommands.filter { $0 == SMB2Commands.changeNotify }.count,
            1,
            "close during the callback must prevent the next CHANGE_NOTIFY"
        )

        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("close after blocked callback test") { await closeTask.value }
    }

    private func makeClientSession(
        session: SMBSession? = nil,
        credentialProvider: @escaping SMBCredentialProvider,
        makeTransport: @escaping @Sendable () -> SMBTransport
    ) -> SMBClientSession {
        let oldSession = session ?? SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        let reconnectInfo = SMBClientSession.ReconnectInfo(
            host: "server",
            port: 445,
            share: "share",
            credentialProvider: credentialProvider,
            makeTransport: makeTransport,
            requestTimeout: nil,
            requestTimeoutSleeper: { try await Task.sleep(for: $0) }
        )
        return SMBClientSession(session: oldSession, treeId: 0x3344, reconnectInfo: reconnectInfo)
    }

    private func assertDoesNotComplete(
        _ completion: SMBContinuationCountBarrier,
        label: String
    ) async throws {
        do {
            try await smbIssue102AwaitWithTimeout(label, timeout: .milliseconds(50)) {
                try await completion.waitForCount(1)
            }
            XCTFail("\(label) completed while cleanup was held")
        } catch is SMBIssue102WaitTimeout {
            // The completion latch stays quiet until the first close releases cleanup.
        }
    }

    private func outboundCommands(_ bytes: [UInt8]) throws -> [UInt16] {
        var commands: [UInt16] = []
        var cursor = 0
        while cursor < bytes.count {
            let frameLength = try DirectTCPFraming.length(from: Array(bytes[cursor..<(cursor + 4)]))
            let start = cursor + 4
            let end = start + frameLength
            commands.append(try SMB2Header.decode(Array(bytes[start..<end])).command)
            cursor = end
        }
        return commands
    }
}

private actor SMBTreeQuarantineGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}
