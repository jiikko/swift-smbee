import Foundation
import XCTest
@testable import SMBee

final class SMBOperationDeadlineTests: XCTestCase {
    func testDeadlineTransportReceiveAfterCloseFailsEvenWithUnreadResponses() async throws {
        // Close is terminal: a response released by an earlier send must not satisfy a receive
        // that starts after close (found by the M3 merge-point review).
        let echo = try SMB2Header(command: SMB2Commands.echo, messageId: 0).encode()
        let transport = SMBDeadlineTransport(inbound: try DirectTCPFraming.frame(echo))
        try await transport.send(try DirectTCPFraming.frame(echo))
        transport.close()
        do {
            _ = try await awaitWithDeadlineHangGuard("receive after close") {
                try await transport.receive(maxLength: 4)
            }
            XCTFail("receive after close must not return buffered bytes")
        } catch SMBTransportError.connectionClosed {
            XCTAssertEqual(transport.closeCount, 1)
        }
    }

    func testDeadlineHangGuardPropagatesImmediateFailure() async throws {
        do {
            try await awaitWithDeadlineHangGuard("immediate operation failure") {
                throw SMBTransportError.timedOut
            }
            XCTFail("the hang guard must preserve the operation error")
        } catch SMBTransportError.timedOut {
            // Expected operation failure.
        }
    }

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
        await assertDeadlineExpiresAfterCancellation(
            operation,
            clock: clock,
            gates: [chunkGate],
            label: "session stream"
        )

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
        await assertDeadlineExpiresAfterCancellation(
            oneShotOperation,
            clock: oneShotClock,
            gates: [oneShotGate],
            label: "one-shot stream"
        )
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
        let installGate = SMBDeadlineCancellationReleaseGate()
        let operation = Task {
            try await SMBDownloadTestSeams.$beforeDestinationInstall.withValue({ try await installGate.suspendUntilReleased() }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({ try await clock.sleep(for: $0) }, operation: {
                    try await client.download(path: "file.bin", localFile: destination, operationTimeout: .seconds(30))
                })
            })
        }

        guard await waitForCancellationReleaseGateEntry(installGate, operation: operation, clock: clock, label: "download install") else {
            return
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        let stagedBeforeTimeout = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(stagedBeforeTimeout.count, 1, "the download should have a temporary file before install")
        guard await waitForDeadlineTimer(
            clock,
            operation: operation,
            gates: [],
            cancellationGates: [installGate],
            label: "download timer"
        ) else {
            return
        }
        await assertDeadlineExpiresAfterCancellation(
            operation,
            clock: clock,
            cancellationGates: [installGate],
            label: "session download"
        )

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

    func testSessionDeadlinesStartBeforeActorAdmission() async throws {
        // Keep the actor blocked until the manual sleeper reports deadline registration.
        let streamTransport = SMBDeadlineTransport(inbound: [])
        let streamSession = SMBSession(host: "server", port: 445, credential: .anonymous, transport: streamTransport)
        let streamClient = SMBClientSession(session: streamSession, treeId: deadlineTreeId)
        let streamBlocker = SMBDeadlineActorBlocker()
        defer { streamBlocker.release() }
        let streamActorTask = Task { await streamClient.blockActorForDeadlineTest(using: streamBlocker) }
        try await awaitWithDeadlineHangGuard("stream actor blocker entered") {
            try await streamBlocker.waitUntilEntered()
        }

        let streamClock = SMBDeadlineManualSleeper()
        let streamCancellation = SMBDeadlineTestEvent()
        let streamOperation = Task {
            try await SMBOperationDeadline.$operationCancellationObserverForTesting.withValue({
                streamCancellation.signal()
            }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({
                    try await streamClock.sleep(for: $0)
                }, operation: {
                    try await streamClient.withReadStream(path: "file.bin", operationTimeout: .seconds(30)) { _ in }
                })
            })
        }
        do {
            try await awaitWithDeadlineHangGuard("stream deadline before actor admission") {
                try await streamClock.waitForCallCount(1)
            }
        } catch {
            await releaseDeadlineOperationAndDrain(
                streamOperation,
                actorTask: streamActorTask,
                blocker: streamBlocker,
                clock: streamClock,
                label: "stream"
            )
            XCTFail("stream deadline did not start before actor admission: \(error)")
            return
        }
        XCTAssertEqual(streamClock.requestedDurations, [.seconds(30)])
        XCTAssertTrue(streamClock.fireNext())
        guard await waitForQueuedDeadlineOperationCancellation(
            streamCancellation,
            operation: streamOperation,
            actorTask: streamActorTask,
            blocker: streamBlocker,
            clock: streamClock,
            label: "stream"
        ) else {
            return
        }
        streamBlocker.release()
        try await awaitWithDeadlineHangGuard("stream actor blocker release") { await streamActorTask.value }
        await assertDeadlineExpired(streamOperation, clock: streamClock, gates: [], label: "stream queued behind actor")
        XCTAssertEqual(try deadlineCommands(streamTransport.outbound), [], "queued stream must not send CREATE after its deadline")
        streamClock.reset()

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-actor-download-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("download.bin")
        let downloadTransport = SMBDeadlineTransport(inbound: [])
        let downloadSession = SMBSession(host: "server", port: 445, credential: .anonymous, transport: downloadTransport)
        let downloadClient = SMBClientSession(session: downloadSession, treeId: deadlineTreeId)
        let downloadBlocker = SMBDeadlineActorBlocker()
        defer { downloadBlocker.release() }
        let downloadActorTask = Task { await downloadClient.blockActorForDeadlineTest(using: downloadBlocker) }
        try await awaitWithDeadlineHangGuard("download actor blocker entered") {
            try await downloadBlocker.waitUntilEntered()
        }

        let downloadClock = SMBDeadlineManualSleeper()
        let downloadCancellation = SMBDeadlineTestEvent()
        let downloadOperation = Task {
            try await SMBOperationDeadline.$operationCancellationObserverForTesting.withValue({
                downloadCancellation.signal()
            }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({
                    try await downloadClock.sleep(for: $0)
                }, operation: {
                    try await downloadClient.download(path: "file.bin", localFile: destination, operationTimeout: .seconds(30))
                })
            })
        }
        do {
            try await awaitWithDeadlineHangGuard("download deadline before actor admission") {
                try await downloadClock.waitForCallCount(1)
            }
        } catch {
            await releaseDeadlineOperationAndDrain(
                downloadOperation,
                actorTask: downloadActorTask,
                blocker: downloadBlocker,
                clock: downloadClock,
                label: "download"
            )
            XCTFail("download deadline did not start before actor admission: \(error)")
            return
        }
        XCTAssertEqual(downloadClock.requestedDurations, [.seconds(30)])
        XCTAssertTrue(downloadClock.fireNext())
        guard await waitForQueuedDeadlineOperationCancellation(
            downloadCancellation,
            operation: downloadOperation,
            actorTask: downloadActorTask,
            blocker: downloadBlocker,
            clock: downloadClock,
            label: "download"
        ) else {
            return
        }
        downloadBlocker.release()
        try await awaitWithDeadlineHangGuard("download actor blocker release") { await downloadActorTask.value }
        await assertDeadlineExpired(downloadOperation, clock: downloadClock, gates: [], label: "download queued behind actor")
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path), "queued download must not install after its deadline")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [], "queued download must not create a temporary file")
        XCTAssertEqual(try deadlineCommands(downloadTransport.outbound), [], "queued download must not send CREATE after its deadline")
        downloadClock.reset()
    }

    func testTemporaryCreationFailuresRemovePartialFilesForSessionAndOneShotDownloads() async throws {
        let sessionDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-session-temp-failure-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: sessionDirectory) }
        let sessionTransport = SMBDeadlineTransport(inbound: [])
        let session = SMBSession(host: "server", port: 445, credential: .anonymous, transport: sessionTransport)
        let client = SMBClientSession(session: session, treeId: deadlineTreeId)
        do {
            try await SMBDownloadTestSeams.$createTemporaryFile.withValue({ url in
                try writePartialTemporaryCandidate(at: url)
            }, operation: {
                try await client.download(path: "file.bin", localFile: sessionDirectory.appendingPathComponent("download.bin"))
            })
            XCTFail("session download unexpectedly created a temporary file")
        } catch SMBTemporaryCreationFailure.injected {
            // Expected injected failure.
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: sessionDirectory.path), [])
        XCTAssertEqual(try deadlineCommands(sessionTransport.outbound), [], "temporary creation failure must happen before CREATE")

        let oneShotDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-one-shot-temp-failure-\(UUID().uuidString)")
        let oneShotDestination = oneShotDirectory.appendingPathComponent("download.bin")
        defer { try? FileManager.default.removeItem(at: oneShotDirectory) }
        let factoryCount = SMBDeadlineCounter()
        do {
            try await SMBDownloadTestSeams.$createTemporaryFile.withValue({ url in
                try writePartialTemporaryCandidate(at: url)
            }, operation: {
                try await SMBClient.download(
                    host: "server",
                    share: "share",
                    path: "file.bin",
                    localFile: oneShotDestination,
                    credential: .anonymous,
                    makeTransport: {
                        factoryCount.increment()
                        return SMBDeadlineTransport(inbound: [])
                    }
                )
            })
            XCTFail("one-shot download unexpectedly created a temporary file")
        } catch SMBTemporaryCreationFailure.injected {
            // Expected injected failure.
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: oneShotDirectory.path), [])
        XCTAssertEqual(factoryCount.value, 0, "temporary creation failure must happen before connecting")
        XCTAssertFalse(FileManager.default.fileExists(atPath: oneShotDestination.path))
    }

    func testOneShotNonResumeInstallCancellationPreservesMissingAndExistingDestinations() async throws {
        try await assertOneShotInstallCancellation(overwriteExistingDestination: false)
        try await assertOneShotInstallCancellation(overwriteExistingDestination: true)
    }

    func testSuccessfulDeadlineRunIsHangGuardedAndReleasesTimerChild() async throws {
        let clock = SMBDeadlineManualSleeper()
        let operation = Task {
            try await SMBOperationDeadline.$sleeperForTesting.withValue({
                try await clock.sleep(for: $0)
            }, operation: {
                try await SMBOperationDeadline.run(timeout: .seconds(30)) {
                    try await clock.waitForCallCount(1)
                    return 42
                }
            })
        }

        do {
            let value = try await awaitWithDeadlineHangGuard("successful deadline completion") {
                try await operation.value
            }
            XCTAssertEqual(value, 42)
        } catch {
            clock.reset()
            _ = try? await awaitWithDeadlineHangGuard("successful deadline timer child drain") {
                try await operation.value
            }
            throw error
        }
        XCTAssertEqual(clock.requestedDurations, [.seconds(30)])
        clock.reset()
    }

    private func assertOneShotInstallCancellation(overwriteExistingDestination: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-one-shot-install-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("download.bin")
        if overwriteExistingDestination {
            try Data("original".utf8).write(to: destination)
        }
        let transport = try makeResumeTransport(readBytes: Array("new!".utf8), fileSize: 4)
        let factoryCount = SMBDeadlineCounter()
        let clock = SMBDeadlineManualSleeper()
        let installGate = SMBDeadlineCancellationReleaseGate()
        let operation = Task {
            try await SMBDownloadTestSeams.$beforeDestinationInstall.withValue({
                try await installGate.suspendUntilReleased()
            }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({
                    try await clock.sleep(for: $0)
                }, operation: {
                    try await SMBClient.download(
                        host: "server",
                        share: "share",
                        path: "file.bin",
                        localFile: destination,
                        overwrite: overwriteExistingDestination,
                        resume: false,
                        credential: .anonymous,
                        operationTimeout: .seconds(30),
                        makeTransport: {
                            factoryCount.increment()
                            return transport
                        }
                    )
                })
            })
        }

        guard await waitForCancellationReleaseGateEntry(installGate, operation: operation, clock: clock, label: "one-shot install") else {
            return
        }
        guard await waitForDeadlineTimer(
            clock,
            operation: operation,
            gates: [],
            cancellationGates: [installGate],
            label: "one-shot install timer"
        ) else {
            return
        }
        await assertDeadlineExpiresAfterCancellation(
            operation,
            clock: clock,
            cancellationGates: [installGate],
            label: "one-shot install"
        )

        if overwriteExistingDestination {
            XCTAssertEqual(try Data(contentsOf: destination), Data("original".utf8), "cancellation must prevent replacing an existing destination")
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [destination.lastPathComponent])
        } else {
            XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path), "cancellation must prevent installing a new destination")
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
        XCTAssertEqual(factoryCount.value, 1)
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
        await assertDeadlineExpiresAfterCancellation(
            stream,
            clock: streamClock,
            gates: [streamGate],
            label: "stream provider"
        )
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
        await assertDeadlineExpiresAfterCancellation(
            download,
            clock: downloadClock,
            gates: [downloadGate],
            label: "download provider"
        )
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
        let successfulGate = SMBDeadlineAsyncGate()
        let successfulOperation = Task {
            try await SMBDownloadTestSeams.$beforeResumePrefixComparison.withValue({
                try await successfulGate.suspend()
            }, operation: {
                try await SMBOperationDeadline.$sleeperForTesting.withValue({
                    try await successfulClock.sleep(for: $0)
                }, operation: {
                    try await SMBClient.download(
                        host: "server",
                        share: "share",
                        path: "remote.bin",
                        localFile: successfulDestination,
                        overwrite: false,
                        resume: true,
                        credential: .anonymous,
                        operationTimeout: .seconds(30),
                        makeTransport: { successfulFactory.make() }
                    )
                })
            })
        }
        guard await waitForDeadlineGate(successfulGate, operation: successfulOperation, clock: successfulClock, label: "successful resume prefix") else {
            return
        }
        guard await waitForDeadlineTimer(successfulClock, operation: successfulOperation, gates: [successfulGate], label: "successful resume timer") else {
            return
        }
        XCTAssertEqual(successfulClock.requestedDurations, [.seconds(30)])
        successfulGate.release()
        do {
            try await awaitWithDeadlineHangGuard("successful resume completion") {
                try await successfulOperation.value
            }
        } catch {
            successfulClock.reset()
            successfulGate.release()
            _ = try? await awaitWithDeadlineHangGuard("successful resume child drain") {
                try await successfulOperation.value
            }
            throw error
        }
        XCTAssertEqual(try Data(contentsOf: successfulDestination), Data("hello world".utf8))
        XCTAssertEqual(successfulFactory.makeCount, 2, "resume prefix validation and append use separate one-shot sessions")
        successfulClock.reset()
        successfulGate.reset()

        try await assertResumeCancellationDoesNotReachAppend(phase: .beforeComparison, directory: directory)
        try await assertResumeCancellationDoesNotReachAppend(phase: .afterComparison, directory: directory)
    }

    private func assertResumeCancellationDoesNotReachAppend(
        phase: SMBResumeCancellationPhase,
        directory: URL
    ) async throws {
        let destination = directory.appendingPathComponent("resume-\(phase.rawValue).bin")
        try Data("hello ".utf8).write(to: destination)
        let prefixTransport = try makeResumeTransport(readBytes: Array("hello ".utf8))
        let unusedAppendTransport = try makeResumeTransport(readBytes: Array("world".utf8))
        let factory = SMBDeadlineTransportSequence([prefixTransport, unusedAppendTransport])
        let afterComparisonCount = SMBDeadlineCounter()
        let appendBoundaryCount = SMBDeadlineCounter()
        let clock = SMBDeadlineManualSleeper()
        let cancellationGate = SMBDeadlineCancellationReleaseGate()
        let operation = Task {
            try await SMBDownloadTestSeams.$beforeResumePrefixComparison.withValue({
                if phase == .beforeComparison {
                    try await cancellationGate.suspendUntilReleased()
                }
            }, operation: {
                try await SMBDownloadTestSeams.$afterResumePrefixComparison.withValue({
                    afterComparisonCount.increment()
                    if phase == .afterComparison {
                        try await cancellationGate.suspendUntilReleased()
                    }
                }, operation: {
                    try await SMBDownloadTestSeams.$beforeResumeAppendConnection.withValue({
                        appendBoundaryCount.increment()
                    }, operation: {
                        try await SMBOperationDeadline.$sleeperForTesting.withValue({
                            try await clock.sleep(for: $0)
                        }, operation: {
                            try await SMBClient.download(
                                host: "server",
                                share: "share",
                                path: "remote.bin",
                                localFile: destination,
                                overwrite: false,
                                resume: true,
                                credential: .anonymous,
                                operationTimeout: .seconds(30),
                                makeTransport: { factory.make() }
                            )
                        })
                    })
                })
            })
        }

        guard await waitForCancellationReleaseGateEntry(cancellationGate, operation: operation, clock: clock, label: "resume \(phase.rawValue)") else {
            return
        }
        guard await waitForDeadlineTimer(
            clock,
            operation: operation,
            gates: [],
            cancellationGates: [cancellationGate],
            label: "resume \(phase.rawValue) timer"
        ) else {
            return
        }
        XCTAssertEqual(clock.requestedDurations, [.seconds(30)])
        await assertDeadlineExpiresAfterCancellation(
            operation,
            clock: clock,
            cancellationGates: [cancellationGate],
            label: "resume \(phase.rawValue)"
        )

        XCTAssertEqual(factory.makeCount, 1, "cancellation must prevent the append one-shot connection")
        XCTAssertEqual(try Data(contentsOf: destination), Data("hello ".utf8), "cancellation must preserve the resume destination")
        XCTAssertEqual(appendBoundaryCount.value, 0, "cancellation must stop before entering the append connection")
        if phase == .beforeComparison {
            XCTAssertEqual(afterComparisonCount.value, 0, "the pre-comparison check must stop prefix comparison")
        } else {
            XCTAssertEqual(afterComparisonCount.value, 1, "the post-comparison gate must run after equality is computed")
        }
        XCTAssertEqual(prefixTransport.closeCount, 1)
        clock.reset()
        cancellationGate.reset()
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
    private struct PendingReceive {
        let id: UUID
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private let lock = NSLock()
    private var inbound: [UInt8]
    private var responsesByRequest: [SMBWireRequestIdentity: [[UInt8]]] = [:]
    private var responsePreparationError: Error?
    private var sentRequestIds: Set<UInt64> = []
    private var pendingReceive: PendingReceive?
    private var isClosed = false
    private var outboundStorage: [UInt8] = []
    private var closeCountStorage = 0

    init(inbound: [UInt8]) {
        self.inbound = []
        do {
            for frame in try Self.unframe(inbound) {
                let header = try SMB2Header.decode(Array(frame.dropFirst(4)))
                let identity = SMBWireRequestIdentity(messageId: header.messageId, command: header.command)
                responsesByRequest[identity, default: []].append(frame)
            }
        } catch {
            responsePreparationError = error
        }
    }

    var outbound: [UInt8] { lock.withLock { outboundStorage } }
    var closeCount: Int { lock.withLock { closeCountStorage } }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        guard !lock.withLock({ isClosed }) else { throw SMBTransportError.connectionClosed }
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let descriptor = try Self.requestDescriptor(bytes)
        let shouldWake = try lock.withLock { () throws -> Bool in
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            if let responsePreparationError { throw responsePreparationError }

            let identity = descriptor.identity
            if identity.command == SMB2Commands.cancel {
                guard sentRequestIds.contains(identity.messageId) else {
                    throw SMBCodecError.invalidValue("CANCEL does not identify a previously sent request")
                }
                outboundStorage.append(contentsOf: bytes)
                return false
            }
            guard !sentRequestIds.contains(identity.messageId) else {
                throw SMBCodecError.invalidValue("duplicate SMB request MessageId \(identity.messageId)")
            }
            guard let frames = responsesByRequest.removeValue(forKey: identity) else {
                throw SMBCodecError.invalidValue(
                    "unexpected SMB request command=\(identity.command) messageId=\(identity.messageId)"
                )
            }
            sentRequestIds.insert(identity.messageId)
            outboundStorage.append(contentsOf: bytes)
            inbound.append(contentsOf: frames.flatMap { $0 })
            return !frames.isEmpty
        }
        if shouldWake { resumePendingReceiveIfReady() }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<[UInt8], Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    // Close is terminal (SMBTransport contract): unread bytes must not satisfy a
                    // receive that starts after close.
                    if isClosed { return .failure(SMBTransportError.connectionClosed) }
                    if !inbound.isEmpty { return .success(takeAvailableChunk(maxLength: maxLength)) }
                    guard pendingReceive == nil else {
                        return .failure(SMBCodecError.invalidValue("concurrent receive on deadline transport"))
                    }
                    pendingReceive = PendingReceive(id: id, maxLength: maxLength, continuation: continuation)
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            self.cancelPendingReceive(id: id)
        }
    }

    func close() {
        let waiter = lock.withLock { () -> PendingReceive? in
            guard !isClosed else { return nil }
            closeCountStorage += 1
            isClosed = true
            defer { pendingReceive = nil }
            return pendingReceive
        }
        waiter?.continuation.resume(throwing: SMBTransportError.connectionClosed)
    }

    private func resumePendingReceiveIfReady() {
        let result: (PendingReceive, [UInt8])? = lock.withLock {
            guard let waiter = pendingReceive, !inbound.isEmpty else { return nil }
            pendingReceive = nil
            return (waiter, takeAvailableChunk(maxLength: waiter.maxLength))
        }
        if let (waiter, bytes) = result { waiter.continuation.resume(returning: bytes) }
    }

    private func takeAvailableChunk(maxLength: Int) -> [UInt8] {
        let count = min(maxLength, inbound.count)
        let result = Array(inbound.prefix(count))
        inbound.removeFirst(count)
        return result
    }

    private func cancelPendingReceive(id: UUID) {
        let waiter = lock.withLock { () -> PendingReceive? in
            guard pendingReceive?.id == id else { return nil }
            defer { pendingReceive = nil }
            return pendingReceive
        }
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private static func unframe(_ bytes: [UInt8]) throws -> [[UInt8]] {
        var frames: [[UInt8]] = []
        var offset = 0
        while offset < bytes.count {
            guard offset + 4 <= bytes.count, bytes[offset] == 0 else { throw SMBCodecError.truncated }
            let length = try DirectTCPFraming.length(from: Array(bytes[offset..<(offset + 4)]))
            let end = offset + 4 + length
            guard end <= bytes.count else { throw SMBCodecError.truncated }
            frames.append(Array(bytes[offset..<end]))
            offset = end
        }
        return frames
    }

    private static func requestDescriptor(_ framedBytes: [UInt8]) throws -> SMBWireRequestDescriptor {
        guard framedBytes.count >= 4 else { throw SMBCodecError.truncated }
        let length = try DirectTCPFraming.length(from: Array(framedBytes.prefix(4)))
        guard framedBytes.count == length + 4 else { throw SMBCodecError.truncated }
        return try SMBWireRequestDescriptor(packet: Array(framedBytes.dropFirst(4)))
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
    private var requestedDurationsStorage: [Duration] = []
    private let callsChanged = SMBDeadlineTestEvent()

    var requestedDurations: [Duration] { lock.withLock { requestedDurationsStorage } }

    func sleep(for duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let cancelled = lock.withLock { () -> Bool in
                    guard !Task.isCancelled else { return true }
                    callCount += 1
                    requestedDurationsStorage.append(duration)
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

    func fireNext() -> Bool {
        let waiter = lock.withLock { timers.isEmpty ? nil : timers.removeFirst() }
        // Simulate the timer throwing inside its child before operation cancellation is observed.
        waiter?.continuation.resume(throwing: SMBTransportError.timedOut)
        return waiter != nil
    }

    func reset() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            let pending = timers.map(\.continuation)
            timers.removeAll()
            callCount = 0
            requestedDurationsStorage.removeAll()
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
    private let cancellation = SMBDeadlineTestEvent()

    func suspend() async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let registration = lock.withLock { () -> Int in
                    guard !Task.isCancelled else { return -1 }
                    guard !released else { return 1 }
                    waiters.append(Waiter(id: id, continuation: continuation))
                    return 0
                }
                entered.signal()
                if registration < 0 {
                    continuation.resume(throwing: CancellationError())
                } else if registration > 0 {
                    continuation.resume()
                }
            }
        } onCancel: {
            self.cancelWaiter(id: id)
            self.cancellation.signal()
        }
    }

    func waitUntilEntered() async throws {
        try await entered.wait(until: 1)
    }

    func waitUntilCancellationObserved() async throws {
        try await cancellation.wait(until: 1)
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
        cancellation.reset()
    }

    private func cancelWaiter(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class SMBDeadlineCancellationReleaseGate: @unchecked Sendable {
    private let lock = NSLock()
    private var waiters: [CheckedContinuation<Void, Error>] = []
    private var released = false
    private var cancellationObserved = false
    private var resumedNormallyWhileCancelledCountStorage = 0
    private let entered = SMBDeadlineTestEvent()
    private let cancellation = SMBDeadlineTestEvent()

    var resumedNormallyWhileCancelledCount: Int { lock.withLock { resumedNormallyWhileCancelledCountStorage } }

    func suspendUntilReleased() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> (resume: Bool, notifyCancellation: Bool) in
                    guard !released else { return (true, false) }
                    waiters.append(continuation)
                    guard Task.isCancelled else { return (false, false) }
                    let notify = !cancellationObserved
                    cancellationObserved = true
                    return (false, notify)
                }
                entered.signal()
                if state.notifyCancellation { cancellation.signal() }
                if state.resume { continuation.resume() }
            }
        } onCancel: {
            let shouldSignal = self.lock.withLock { () -> Bool in
                guard !self.cancellationObserved else { return false }
                self.cancellationObserved = true
                return true
            }
            if shouldSignal { self.cancellation.signal() }
        }
        if Task.isCancelled {
            lock.withLock { resumedNormallyWhileCancelledCountStorage += 1 }
        }
    }

    func waitUntilEntered() async throws {
        try await entered.wait(until: 1)
    }

    func waitUntilCancellationObserved() async throws {
        try await cancellation.wait(until: 1)
    }

    func releaseNormally() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            released = true
            let pending = waiters
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume() }
    }

    func releaseNormallyAfterCancellation() -> Int {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            released = true
            let pending = waiters
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume() }
        return pending.count
    }

    func reset() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            released = false
            cancellationObserved = false
            resumedNormallyWhileCancelledCountStorage = 0
            let pending = waiters
            waiters.removeAll()
            return pending
        }
        pending.forEach { $0.resume(throwing: CancellationError()) }
        entered.reset()
        cancellation.reset()
    }
}

private final class SMBDeadlineActorBlocker: @unchecked Sendable {
    private let lock = NSLock()
    private let releaseSemaphore = DispatchSemaphore(value: 0)
    private var released = false
    private let entered = SMBDeadlineTestEvent()

    func blockActor() {
        entered.signal()
        releaseSemaphore.wait()
    }

    func waitUntilEntered() async throws {
        try await entered.wait(until: 1)
    }

    func release() {
        let shouldSignal = lock.withLock { () -> Bool in
            guard !released else { return false }
            released = true
            return true
        }
        if shouldSignal { releaseSemaphore.signal() }
    }
}

private extension SMBClientSession {
    func blockActorForDeadlineTest(using blocker: SMBDeadlineActorBlocker) {
        blocker.blockActor()
    }
}

private enum SMBTemporaryCreationFailure: Error {
    case injected
}

private func writePartialTemporaryCandidate(at url: URL) throws -> FileHandle {
    try Data("partial candidate".utf8).write(to: url)
    throw SMBTemporaryCreationFailure.injected
}

private enum SMBResumeCancellationPhase: String {
    case beforeComparison
    case afterComparison
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
        let storedResult = lock.withLock { () -> Result<T, Error>? in
            if completed, let storedResult = self.result {
                self.result = nil
                return storedResult
            }
            self.continuation = continuation
            return nil
        }
        guard let storedResult else { return }
        switch storedResult {
        case .success(let value):
            continuation.resume(returning: value)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
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
        guard let continuation else { return }
        switch result {
        case .success(let value):
            continuation.resume(returning: value)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}

func awaitWithDeadlineHangGuard<T: Sendable>(
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

private func waitForCancellationReleaseGateEntry(
    _ gate: SMBDeadlineCancellationReleaseGate,
    operation: Task<Void, Error>,
    clock: SMBDeadlineManualSleeper,
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) event") { try await gate.waitUntilEntered() }
        return true
    } catch {
        XCTFail("\(label): \(error)")
        operation.cancel()
        gate.releaseNormally()
        clock.reset()
        _ = try? await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
        gate.reset()
        return false
    }
}

private func waitForCancellationObservation(
    _ gate: SMBDeadlineCancellationReleaseGate,
    operation: Task<Void, Error>,
    clock: SMBDeadlineManualSleeper,
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) observation") { try await gate.waitUntilCancellationObserved() }
        return true
    } catch {
        XCTFail("\(label): \(error)")
        operation.cancel()
        gate.releaseNormally()
        clock.reset()
        _ = try? await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
        gate.reset()
        return false
    }
}

private func waitForDeadlineTimer(
    _ clock: SMBDeadlineManualSleeper,
    operation: Task<Void, Error>,
    gates: [SMBDeadlineAsyncGate],
    cancellationGates: [SMBDeadlineCancellationReleaseGate] = [],
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) registration") { try await clock.waitForCallCount(1) }
        XCTAssertEqual(clock.requestedDurations, [.seconds(30)], "the manual sleeper must receive the requested deadline")
        return true
    } catch {
        XCTFail("\(label): \(error)")
        operation.cancel()
        gates.forEach { $0.release() }
        cancellationGates.forEach { $0.releaseNormally() }
        clock.reset()
        _ = try? await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
        gates.forEach { $0.reset() }
        cancellationGates.forEach { $0.reset() }
        return false
    }
}

private func assertDeadlineExpiresAfterCancellation(
    _ operation: Task<Void, Error>,
    clock: SMBDeadlineManualSleeper,
    gates: [SMBDeadlineAsyncGate] = [],
    cancellationGates: [SMBDeadlineCancellationReleaseGate] = [],
    label: String
) async {
    guard clock.fireNext() else {
        await failAndDrainDeadlineOperation(
            operation,
            gates: gates,
            cancellationGates: cancellationGates,
            clock: clock,
            label: label,
            error: SMBDeadlineHangGuardError(label: "\(label) timer was not registered")
        )
        return
    }

    for gate in gates {
        do {
            try await awaitWithDeadlineHangGuard("\(label) operation cancellation") {
                try await gate.waitUntilCancellationObserved()
            }
        } catch {
            await failAndDrainDeadlineOperation(
                operation,
                gates: gates,
                cancellationGates: cancellationGates,
                clock: clock,
                label: label,
                error: error
            )
            return
        }
    }

    for gate in cancellationGates {
        guard await waitForCancellationObservation(
            gate,
            operation: operation,
            clock: clock,
            label: "\(label) operation cancellation"
        ) else {
            return
        }
        let resumedWaiterCount = gate.releaseNormallyAfterCancellation()
        guard resumedWaiterCount == 1 else {
            await failAndDrainDeadlineOperation(
                operation,
                gates: gates,
                cancellationGates: cancellationGates,
                clock: clock,
                label: label,
                error: SMBDeadlineHangGuardError(label: "\(label) cancellation gate had \(resumedWaiterCount) waiters")
            )
            return
        }
    }

    await assertDeadlineExpired(operation, clock: clock, gates: gates, label: label)
    cancellationGates.forEach {
        XCTAssertEqual($0.resumedNormallyWhileCancelledCount, 1, "\(label) gate must resume normally after the operation task is cancelled")
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

private func releaseDeadlineOperationAndDrain(
    _ operation: Task<Void, Error>,
    actorTask: Task<Void, Never>,
    blocker: SMBDeadlineActorBlocker,
    clock: SMBDeadlineManualSleeper,
    label: String
) async {
    blocker.release()
    do {
        try await awaitWithDeadlineHangGuard("\(label) actor blocker drain") { await actorTask.value }
    } catch {
        XCTFail("\(label) actor blocker did not drain: \(error)")
    }
    do {
        try await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
    } catch let error as SMBDeadlineHangGuardError {
        XCTFail("\(label) operation did not drain after actor release: \(error)")
    } catch {
        // The empty transport can fail once the operation enters the actor; this only drains it.
    }
    clock.reset()
}

private func waitForQueuedDeadlineOperationCancellation(
    _ cancellation: SMBDeadlineTestEvent,
    operation: Task<Void, Error>,
    actorTask: Task<Void, Never>,
    blocker: SMBDeadlineActorBlocker,
    clock: SMBDeadlineManualSleeper,
    label: String
) async -> Bool {
    do {
        try await awaitWithDeadlineHangGuard("\(label) queued operation cancellation") {
            try await cancellation.wait(until: 1)
        }
        return true
    } catch {
        await releaseDeadlineOperationAndDrain(
            operation,
            actorTask: actorTask,
            blocker: blocker,
            clock: clock,
            label: label
        )
        XCTFail("\(label) operation child was not cancelled before actor admission was released: \(error)")
        return false
    }
}

private func failAndDrainDeadlineOperation(
    _ operation: Task<Void, Error>,
    gates: [SMBDeadlineAsyncGate],
    cancellationGates: [SMBDeadlineCancellationReleaseGate] = [],
    clock: SMBDeadlineManualSleeper,
    label: String,
    error: Error
) async {
    XCTFail("\(label): \(error)")
    operation.cancel()
    gates.forEach { $0.release() }
    cancellationGates.forEach { $0.releaseNormally() }
    clock.reset()
    _ = try? await awaitWithDeadlineHangGuard("\(label) operation drain") { try await operation.value }
    gates.forEach { $0.reset() }
    cancellationGates.forEach { $0.reset() }
}
