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
        let requestBarrier = SMBContinuationCountBarrier()
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(SMBIssue102WireFixtures.anonymousSessionResponses()),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let client = makeClientSession(
            credentialProvider: { try await providerGate.getCredential() },
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
        try await smbIssue102AwaitWithTimeout("client close with reconnect waiter") {
            await client.close()
        }

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
        XCTAssertEqual(transports.makeCount, 0)
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
