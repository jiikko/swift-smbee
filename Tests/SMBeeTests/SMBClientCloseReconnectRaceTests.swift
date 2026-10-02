import XCTest
@testable import SMBee

final class SMBClientCloseReconnectRaceTests: XCTestCase {
    func testRaceWaitTimeoutIsReportedAndUnregistersTheWaiter() async throws {
        let barrier = SMBContinuationCountBarrier()
        do {
            try await smbIssue102AwaitWithTimeout("missing race signal", timeout: .milliseconds(10)) {
                try await barrier.waitForCount(1)
            }
            XCTFail("expected the deadline to fail the parked wait")
        } catch let error as SMBIssue102WaitTimeout {
            XCTAssertEqual(error.label, "missing race signal")
        }
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
            try await requestBarrier.waitForCount(2)
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
            try await requestBarrier.waitForCount(2)
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
        let disconnectSendGate = SMBContinuationAsyncGate()
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.create { await createSendGate.suspend() }
            if command == SMB2Commands.treeDisconnect { await disconnectSendGate.suspend() }
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
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.treeDisconnect { await disconnectSendGate.suspend() }
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
        transport.installAfterCommandSignalHook { command in
            if command == SMB2Commands.treeDisconnect { await sendGate.suspend() }
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
        let callbackGate = SMBContinuationAsyncGate()
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
                await callbackGate.suspend()
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
            try await callbackReached.waitForCount(1)
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
            requestTimeout: nil
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
