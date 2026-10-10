import XCTest
@testable import SMBee

#if DEBUG
final class SMBSessionExecutorTests: XCTestCase {
    func testTaskPreferenceForDirectAndStructuredTasks() async throws {
        let executor = SMBSessionExecutor(label: "SMBee.session.executor-test")

        let preferredTask = Task(executorPreference: executor) {
            executor.executionContextForTesting(.preferredTask)
        }
        let preferred = await preferredTask.value
        assertUsesExecutor(preferred)

        let ordinaryTask = await withTaskExecutorPreference(executor, isolation: nil) {
            await Task {
                executor.executionContextForTesting(.ordinaryTask)
            }.value
        }
        XCTAssertFalse(ordinaryTask.isOnExecutorQueue)
        XCTAssertFalse(ordinaryTask.taskExecutorMatches)

        let inheritedChild = await withTaskExecutorPreference(executor, isolation: nil) {
            await withTaskGroup(of: SMBSessionExecutorObservation.self) { group in
                group.addTask {
                    executor.executionContextForTesting(.taskGroupChild)
                }
                return await group.next()
            }
        }
        let child = try XCTUnwrap(inheritedChild)
        assertUsesExecutor(child)

        let nilPreference = await withTaskExecutorPreference(executor, isolation: nil) {
            await withTaskExecutorPreference(nil, isolation: nil) {
                executor.executionContextForTesting(.nilPreference)
            }
        }
        assertUsesExecutor(nilPreference)

        let detachedTask = Task.detached {
            executor.executionContextForTesting(.detachedTask)
        }
        let detached = await detachedTask.value
        XCTAssertFalse(detached.isOnExecutorQueue)
        XCTAssertFalse(detached.taskExecutorMatches)

        let explicitActor = await withTaskExecutorPreference(executor, isolation: nil) {
            await MainActor.run {
                MainActor.preconditionIsolated()
                return executor.executionContextForTesting(.explicitActor)
            }
        }
        XCTAssertFalse(explicitActor.isOnExecutorQueue)
    }

    func testSessionActorSenderAndReaderUseOneSessionExecutor() async throws {
        let response = try echoResponse(messageId: 0, sessionId: 1)
        let transport = InMemoryTransport(inbound: try DirectTCPFraming.frame(response))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport
        )
        let (stream, continuation) = AsyncStream.makeStream(of: SMBSessionExecutorObservation.self)
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            continuation.yield(observation)
        }

        let actorContext = await session.executionContextForTesting()
        XCTAssertTrue(actorContext.isOnExecutorQueue)
        await session.installSenderLoopStateForTesting(sessionId: 1)
        try await session.echoThroughSenderLoopForTesting()
        await session.waitForActiveSendTasksForTesting()
        await session.closeTransportAndWait(cause: "session_executor_placement_test")
        continuation.finish()

        var observations: [SMBSessionExecutorProbePoint: SMBSessionExecutorObservation] = [:]
        for await observation in stream {
            observations[observation.point] = observation
        }

        for point in [
            SMBSessionExecutorProbePoint.senderTask,
            .senderLoop,
            .creditReservationFastPath,
            .readerTask,
            .readerLoop,
            .closeJoin
        ] {
            let observation = try XCTUnwrap(observations[point], "missing execution probe for \(point)")
            if point == .closeJoin || point == .creditReservationFastPath {
                XCTAssertTrue(observation.isOnExecutorQueue)
            } else {
                assertUsesExecutor(observation)
            }
            XCTAssertEqual(observation.executorIdentity, actorContext.executorIdentity)
        }

        let secondSession = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        let secondActorContext = await secondSession.executionContextForTesting()
        XCTAssertNotEqual(actorContext.executorIdentity, secondActorContext.executorIdentity)
    }

    func testTimerCleanupAndTerminalizerTasksUseSessionExecutor() async throws {
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport(mode: .waitUntilClosed),
            requestTimeoutSleeper: { _ in },
            cleanupTimeoutSleeper: { _ in }
        )
        let (stream, continuation) = AsyncStream.makeStream(of: SMBSessionExecutorObservation.self)
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            continuation.yield(observation)
        }

        let timeout = await session.startRequestTimeoutForTesting()
        await timeout.value
        await session.closeTransportAndWait(cause: "before_cleanup_executor_test")
        await session.disconnect(treeId: 1)
        await session.beginWireDrainTerminalizationForTesting()
        await session.waitForWireDrainTerminalizationCountForTesting(atLeast: 1)
        continuation.finish()

        var observations: [SMBSessionExecutorProbePoint: SMBSessionExecutorObservation] = [:]
        for await observation in stream {
            observations[observation.point] = observation
        }

        for point in [
            SMBSessionExecutorProbePoint.requestTimeoutWake,
            .cleanupDisconnectTask,
            .terminalizerTask,
            .closeJoin
        ] {
            let observation = try XCTUnwrap(observations[point], "missing execution probe for \(point)")
            assertUsesExecutor(observation)
        }
    }

    func testCleanupTimeoutAndDrainTimerTasksUseSessionExecutor() async throws {
        let cleanupSleeper = ManualSMBSleeper()
        let drainSleeper = ManualSMBSleeper()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport(mode: .waitUntilClosed),
            cleanupTimeout: .seconds(5),
            requestTimeout: .seconds(7),
            requestTimeoutSleeper: { try await drainSleeper.sleep(for: $0) },
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let executorEvents = SMBSessionExecutorObservationRecorder()
        session.sessionExecutor.setExecutionObserverForTesting { executorEvents.append($0) }

        let registeredClose = Task {
            try await session.parkCleanupPendingForTesting(
                messageId: 10,
                sessionId: 1,
                treeId: 1,
                fileId: [UInt8](repeating: 0x10, count: 16)
            )
        }
        try await smbIssue102AwaitWithTimeout("registered cleanup timer sleeps") {
            try await cleanupSleeper.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        XCTAssertTrue(cleanupSleeper.fireNext())
        do {
            try await smbIssue102AwaitWithTimeout("registered cleanup timeout releases its caller") {
                try await registeredClose.value
            }
            XCTFail("registered cleanup unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }

        let (sentCloseParked, sentCloseParkedContinuation) = AsyncStream.makeStream(of: Void.self)
        let sentClose = Task {
            try await session.parkCleanupPendingForTesting(
                messageId: 11,
                sessionId: 1,
                treeId: 1,
                fileId: [UInt8](repeating: 0x11, count: 16),
                onRegistered: { sentCloseParkedContinuation.yield(()) }
            )
        }
        try await smbIssue102AwaitWithTimeout("sent cleanup request is parked") {
            var iterator = sentCloseParked.makeAsyncIterator()
            _ = await iterator.next()
        }
        sentCloseParkedContinuation.finish()
        try await smbIssue102AwaitWithTimeout("sent cleanup timeout sleeps") {
            try await cleanupSleeper.waitUntilCallCount(
                atLeast: 2,
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        await session.markRequestSentWithoutReaderForTesting(messageId: 11)
        XCTAssertTrue(cleanupSleeper.fireNext())
        do {
            try await smbIssue102AwaitWithTimeout("sent cleanup timeout releases its caller") {
                try await sentClose.value
            }
            XCTFail("sent cleanup unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        try await smbIssue102AwaitWithTimeout("cleanup drain timer sleeps") {
            try await drainSleeper.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        XCTAssertTrue(drainSleeper.fireNext())
        try await smbIssue102AwaitWithTimeout("cleanup drain timeout closes the session") {
            while !executorEvents.contains(.cleanupDrainTimeoutWake) {
                await Task.yield()
            }
        }

        let cleanupWake = try XCTUnwrap(executorEvents.observation(for: .cleanupTimeoutWake))
        let drainWake = try XCTUnwrap(executorEvents.observation(for: .cleanupDrainTimeoutWake))
        assertUsesExecutor(cleanupWake)
        assertUsesExecutor(drainWake)
        await session.closeTransportAndWait(cause: "cleanup_timer_executor_test_complete")
    }

    func testRecursiveActionCallbackUsesTheSessionExecutor() async throws {
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport()
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackExecution = SMBCallbackExecutionRecorder()

        try await client.delete(path: "dry-run.txt", dryRun: true) { _ in
            callbackExecution.record(on: session.sessionExecutor)
        }

        let observation = try XCTUnwrap(callbackExecution.observation)
        XCTAssertTrue(observation.isOnExecutorQueue)
        XCTAssertTrue(observation.taskExecutorMatches)
    }

    private func assertUsesExecutor(
        _ observation: SMBSessionExecutorObservation,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(observation.isOnExecutorQueue, "\(observation.point) was not on its session queue", file: file, line: line)
        XCTAssertTrue(observation.taskExecutorMatches, "\(observation.point) had the wrong task executor context", file: file, line: line)
    }

    private func echoResponse(messageId: UInt64, sessionId: UInt64) throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.echo,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        return response
    }
}
#endif
