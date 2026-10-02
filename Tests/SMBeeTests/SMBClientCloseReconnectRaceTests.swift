import XCTest
@testable import SMBee

final class SMBClientCloseReconnectRaceTests: XCTestCase {
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
        await requestBarrier.waitForCount(2)
        await providerGate.waitForCallCount(1)
        providerGate.release()

        try await first.value
        try await second.value
        XCTAssertEqual(providerGate.callCount, 1)
        XCTAssertEqual(transports.makeCount, 1)
        await (await client.wireSessionForTesting()).closeTransport(cause: "test_cleanup")
    }

    func testCloseDuringCredentialProviderPreventsReconnectCandidateCreation() async throws {
        let providerGate = SMBContinuationCredentialGate(credential: .anonymous)
        let candidate = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(SMBIssue102WireFixtures.anonymousSessionResponses()),
            credential: .anonymous
        )
        let transports = SMBContinuationTransportFactory(transports: [candidate])
        let client = makeClientSession(
            credentialProvider: { try await providerGate.getCredential() },
            makeTransport: { transports.makeTransport() }
        )
        let reconnect: Task<Void, Error> = Task {
            try await client.reconnectForTesting(onRequest: {})
        }

        await providerGate.waitForCallCount(1)
        await client.close()
        providerGate.release()

        do {
            try await reconnect.value
            XCTFail("expected close to win over reconnect")
        } catch SMBError.connectionLost(operation: "RECONNECT") {
            // The provider completed after close; no candidate transport should be created.
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

        await transport.waitForCommand(SMB2Commands.create)
        try transport.completeCreate()
        await transport.waitForCommand(SMB2Commands.changeNotify)
        transport.failConnection()
        await providerGate.waitForCallCount(1)
        await client.close()
        providerGate.release()

        try await watcher.value
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

        await transport.waitForCommand(SMB2Commands.create)
        try transport.completeCreate()
        await transport.waitForCommand(SMB2Commands.changeNotify)
        transport.failConnection()
        try await watcher.value

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

        await candidateTransport.waitForCommand(SMB2Commands.treeConnect)
        await client.close()
        try candidateTransport.completeTreeConnect()

        do {
            try await reconnect.value
            XCTFail("expected close to prevent candidate publication")
        } catch SMBError.connectionLost(operation: "RECONNECT") {
            // The candidate is closed after TREE_CONNECT returns from its gated continuation.
        }
        let publishedSession = await client.wireSessionForTesting()
        XCTAssertTrue(publishedSession === oldSession)
        XCTAssertGreaterThan(candidateTransport.closeCount, 0)
    }

    func testCloseAfterWatchCreateStopsBeforeChangeNotify() async throws {
        let transport = SMBContinuationWatchTransport(autoRespondChangeNotify: true)
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

        await transport.waitForCommand(SMB2Commands.create)
        let closeTask = Task { await client.close() }
        await transport.waitForCommand(SMB2Commands.treeDisconnect)
        try transport.completeCreate()
        var watcherError: Error?
        do {
            try await watcher.value
        } catch {
            watcherError = error
        }
        let sentChangeNotify = transport.sentCommands.contains(SMB2Commands.changeNotify)

        try transport.completeTreeDisconnect()
        await closeTask.value
        XCTAssertNil(watcherError)
        XCTAssertFalse(sentChangeNotify)
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
