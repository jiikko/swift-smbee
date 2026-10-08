import XCTest
@testable import SMBee

final class SMBReadPipelineTests: XCTestCase {
    private let chunkSize = 1_048_576

    func testFourReadSlotsStayOccupiedDuringCallbackAndDeliverInOffsetOrder() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        let collector = SMBReadPipelineChunkCollector()
        defer {
            callbackGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 5)) { data in
                let chunkNumber = collector.append(data)
                if chunkNumber == 1 {
                    callbackEntered.signal()
                    try await callbackGate.suspend(
                        timeout: .seconds(30),
                        sleeper: { try await callbackGateClock.sleep(for: $0) }
                    )
                }
            }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "READ pipeline CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let firstEpoch = transport.readRequests
        XCTAssertEqual(firstEpoch.count, 4)
        XCTAssertEqual(firstEpoch.map(\.offset), [0, 1, 2, 3].map { UInt64($0 * chunkSize) })
        XCTAssertEqual(firstEpoch.map(\.length), Array(repeating: UInt32(chunkSize), count: 4))

        for (index, request) in firstEpoch.enumerated().reversed() where index > 0 {
            try transport.respond(to: request, payload: Array(repeating: UInt8(index + 1), count: chunkSize))
        }
        try transport.respond(to: firstEpoch[0], payload: Array(repeating: 1, count: chunkSize))
        try await smbIssue102AwaitWithTimeout("first ordered READ callback entered") {
            try await callbackEntered.waitForCount(1)
        }
        try await smbIssue102AwaitWithTimeout("all first-epoch READ finals dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 5)
        }
        XCTAssertEqual(transport.readRequests.count, 4, "the fourth slot remains occupied while onChunk is suspended")

        callbackGate.release()
        try await waitForReadCount(transport, 5)
        let allRequests = transport.readRequests
        XCTAssertEqual(allRequests[4].offset, UInt64(chunkSize * 4))
        XCTAssertEqual(allRequests.map { $0.header.messageId }, [1, 17, 33, 49, 65])
        try transport.respond(to: allRequests[4], payload: Array(repeating: 5, count: chunkSize))
        try await smbIssue102AwaitWithTimeout("five-request READ stream completion") {
            try await operation.value
        }

        XCTAssertEqual(collector.chunks, (1...5).map { Array(repeating: UInt8($0), count: chunkSize) })
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterSuccess = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterSuccess, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_test_complete")
    }

    func testShortReadDrainsThenRebasesAndOutranksLaterStatusError() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let collector = SMBReadPipelineChunkCollector()
        defer { transport.failConnection() }

        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 4)) { data in
                _ = collector.append(data)
            }
        }
        try await waitForCommand(transport, SMB2Commands.create, label: "short READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let firstEpoch = transport.readRequests

        try transport.respond(to: firstEpoch[2], status: SMB2Status.accessDenied, credits: 16)
        try transport.respond(
            to: firstEpoch[1],
            payload: Array(repeating: 0x20, count: chunkSize / 2),
            credits: 16
        )
        try transport.respond(to: firstEpoch[0], payload: Array(repeating: 0x10, count: chunkSize), credits: 16)
        try transport.respond(to: firstEpoch[3], payload: Array(repeating: 0x30, count: chunkSize), credits: 16)
        try await waitForReadCount(transport, 7)

        let rebased = Array(transport.readRequests.dropFirst(4))
        XCTAssertEqual(rebased.map(\.offset), [UInt64(chunkSize + chunkSize / 2), UInt64(chunkSize * 2 + chunkSize / 2), UInt64(chunkSize * 3 + chunkSize / 2)])
        XCTAssertEqual(rebased.map(\.length), [UInt32(chunkSize), UInt32(chunkSize), UInt32(chunkSize / 2)])
        for (index, request) in rebased.enumerated().reversed() {
            try transport.respond(to: request, payload: Array(repeating: UInt8(0x40 + index), count: Int(request.length)), credits: 16)
        }
        try await smbIssue102AwaitWithTimeout("short READ rebase completion") {
            try await operation.value
        }

        XCTAssertEqual(collector.chunks, [
            Array(repeating: UInt8(0x10), count: chunkSize),
            Array(repeating: UInt8(0x20), count: chunkSize / 2),
            Array(repeating: UInt8(0x40), count: chunkSize),
            Array(repeating: UInt8(0x41), count: chunkSize),
            Array(repeating: UInt8(0x42), count: chunkSize / 2)
        ])
        let pendingAfterRebase = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterRebase, 0)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        await session.closeTransportAndWait(cause: "read_short_rebase_test_complete")
    }

    func testEOFAndEmptySuccessFailWithoutRebase() async throws {
        for status in [SMB2Status.endOfFile, SMB2Status.success] {
            let testChunkSize = chunkSize
            let transport = SMBReadPipelineScriptTransport()
            let session = makeSession(transport: transport, credits: 32)
            let client = SMBClientSession(session: session, treeId: 1)
            defer { transport.failConnection() }
            let operation = Task {
                try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize)) { _ in }
            }
            try await waitForCommand(transport, SMB2Commands.create, label: "EOF READ CREATE")
            try transport.completeCreate()
            try await waitForReadCount(transport, 1)
            try transport.respond(to: transport.readRequests[0], status: status, credits: 1)
            do {
                try await smbIssue102AwaitWithTimeout("EOF or empty READ failure") {
                    try await operation.value
                }
                XCTFail("EOF and empty success must fail the requested stream")
            } catch let error as SMBCodecError {
                guard case .invalidValue(let message) = error else {
                    return XCTFail("unexpected codec error: \(error)")
                }
                XCTAssertTrue(message.contains("short SMB read"), message)
            }
            XCTAssertEqual(transport.readRequests.count, 1)
            let pendingAfterEOF = await session.pendingCountForTesting()
            XCTAssertEqual(pendingAfterEOF, 0)
            XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
            await session.closeTransportAndWait(cause: "read_eof_test_complete")
        }
    }

    func testAccessDeniedReadUsesErrorResponseBody() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 16)
        let client = SMBClientSession(session: session, treeId: 1)
        defer { transport.failConnection() }
        let operation = Task {
            try await client.withReadStream(path: "denied.bin", knownSize: UInt64(testChunkSize)) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "access-denied READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 1)
        try transport.respond(to: transport.readRequests[0], status: SMB2Status.accessDenied)
        XCTAssertEqual(transport.errorResponseBodies, [[9, 0, 0, 0, 0, 0, 0, 0]])
        do {
            try await smbIssue102AwaitWithTimeout("access-denied READ response") { try await operation.value }
            XCTFail("access-denied READ unexpectedly succeeded")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "READ") {
            // The fake returned an SMB ERROR response structure, not a successful READ body.
        }

        XCTAssertEqual(transport.readRequests.count, 1)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterAccessDenied = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterAccessDenied, 0)
    }

    func testReadLengthPrecheckSuccessAlwaysDecodesRetirementPayload() throws {
        let packetLengths = [72, 73, 79, 80, 81, 127, 255, 256, 320]
        let dataOffsets: [UInt8] = [0, 1, 63, 64, 71, 72, 79, 80, 81, 127, 255]
        let dataLengths: [UInt32] = [0, 1, 7, 8, 9, 16, 64, 127, 255, 256, .max]

        for packetLength in packetLengths {
            for dataOffset in dataOffsets {
                for dataLength in dataLengths {
                    var response = try SMB2Header(command: SMB2Commands.read, messageId: 1).encode()
                    response.append(contentsOf: Array(repeating: 0, count: packetLength - response.count))
                    writeUInt16LE(17, to: &response, at: SMB2Header.encodedSize)
                    response[SMB2Header.encodedSize + 2] = dataOffset
                    writeUInt32LE(dataLength, to: &response, at: SMB2Header.encodedSize + 4)
                    guard let checkedLength = try? SMB2Read.responsePayloadLength(response) else { continue }

                    let decodedPayload = try SMB2Read.decodeResponse(response)
                    XCTAssertEqual(decodedPayload.count, checkedLength)
                }
            }
        }
    }

    func testCallerCancellationDrainsCommittedReadsWithoutCancelPackets() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 8)) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "cancel READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let committed = transport.readRequests
        operation.cancel()
        for request in committed {
            try transport.respond(to: request, payload: Array(repeating: 0x5a, count: testChunkSize))
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled READ transfer drain") {
                try await operation.value
            }
            XCTFail("cancelled stream unexpectedly succeeded")
        } catch is CancellationError {
            // The caller cancellation wins after all committed requests receive finals.
        }

        XCTAssertEqual(transport.readRequests.count, 4, "cancellation stops later commits")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterCancel = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterCancel, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_cancel_test_complete")
    }

    func testCallbackThrowDrainsOtherCommittedReadsAndPreservesCallbackError() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let cleanupSleeper = ManualSMBSleeper()
        let session = makeSession(
            transport: transport,
            credits: 256,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        defer {
            callbackGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 8)) { _ in
                callbackEntered.signal()
                try await callbackGate.suspend(
                    timeout: .seconds(30),
                    sleeper: { try await callbackGateClock.sleep(for: $0) }
                )
                throw SMBReadPipelineCallbackFailure.injected
            }
        }
        try await waitForCommand(transport, SMB2Commands.create, label: "callback-error READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let committed = transport.readRequests
        try transport.respond(to: committed[0], payload: Array(repeating: 0x10, count: testChunkSize))
        try await smbIssue102AwaitWithTimeout("throwing onChunk entered") {
            try await callbackEntered.waitForCount(1)
        }
        let pendingBeforeCallbackThrow = await session.pendingCountForTesting()
        guard pendingBeforeCallbackThrow == 3 else {
            return XCTFail("three other READ responses must still be outstanding before the callback throws")
        }
        callbackGate.release()
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "callback throw starts bounded READ drain")
        XCTAssertEqual(cleanupSleeper.requestedDurations.count, 1)
        XCTAssertGreaterThan(cleanupSleeper.requestedDurations[0], .seconds(4))
        XCTAssertLessThanOrEqual(cleanupSleeper.requestedDurations[0], .seconds(5))
        let pendingDuringCallbackDrain = await session.pendingCountForTesting()
        XCTAssertEqual(pendingDuringCallbackDrain, 3, "three READ finals are still outstanding when onChunk throws")
        for request in committed.dropFirst() {
            try transport.respond(to: request, payload: Array(repeating: 0x20, count: testChunkSize))
        }
        do {
            try await smbIssue102AwaitWithTimeout("callback failure after READ drain") {
                try await operation.value
            }
            XCTFail("callback error was not propagated")
        } catch SMBReadPipelineCallbackFailure.injected {
            // The callback error is selected after all requests already on the wire drain.
        }

        XCTAssertEqual(transport.readRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterCallbackError = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterCallbackError, 0)
        XCTAssertEqual(transport.closeCount, 0, "callback errors preserve the usable session")

        let nextOperation = Task {
            try await client.withReadStream(path: "still-usable.bin", knownSize: UInt64(testChunkSize)) { _ in }
        }
        try await waitForCommand(transport, SMB2Commands.create, label: "post-callback-error CREATE", occurrence: 2)
        try transport.completeCreate()
        try await waitForReadCount(transport, 5)
        try transport.respond(to: transport.readRequests[4], payload: Array(repeating: 0x5a, count: testChunkSize))
        try await smbIssue102AwaitWithTimeout("session remains usable after callback error") {
            try await nextOperation.value
        }
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testOperationDeadlineDrainsCommittedReadsWithoutCancelPackets() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { _ in }
        )
        let session = makeSession(transport: transport, credits: 81, sessionTime: sessionTime)
        let client = SMBClientSession(session: session, treeId: 1)
        let deadline = virtualTime.now().advanced(by: .seconds(5))
        let operation = Task {
            try await SMBOperationDeadline.$operationContext.withValue(
                SMBOperationContext(now: { virtualTime.now() }, deadline: deadline),
                operation: {
                    try await client.withReadStream(
                        path: "file.bin",
                        knownSize: UInt64(testChunkSize * 8),
                        operationTimeout: nil
                    ) { _ in }
                }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, label: "deadline READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let committed = transport.readRequests
        virtualTime.advance(by: .seconds(6))
        for request in committed {
            try transport.respond(to: request, payload: Array(repeating: 0x6b, count: testChunkSize))
        }
        do {
            try await smbIssue102AwaitWithTimeout("deadline READ transfer drain") {
                try await operation.value
            }
            XCTFail("expired READ operation unexpectedly succeeded")
        } catch SMBTransportError.timedOut {
            // Operation deadline wins after all committed READs finish.
        }

        XCTAssertEqual(transport.readRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterDeadline = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterDeadline, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_deadline_test_complete")
    }

    func testOperationDeadlineClosesWithUnansweredCommittedRead() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let cleanupSleeper = ManualSMBSleeper()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { _ in }
        )
        let session = makeSession(
            transport: transport,
            credits: 81,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let deadline = virtualTime.now().advanced(by: .seconds(5))
        let operationJoined = SMBContinuationCountBarrier()
        let operation = Task {
            defer { operationJoined.signal() }
            try await SMBOperationDeadline.$operationContext.withValue(
                SMBOperationContext(now: { virtualTime.now() }, deadline: deadline),
                operation: {
                    try await client.withReadStream(
                        path: "file.bin",
                        knownSize: UInt64(testChunkSize * 8),
                        operationTimeout: nil
                    ) { _ in }
                }
            )
        }
        defer {
            cleanupSleeper.fireNext()
            transport.failConnection()
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "absolute-deadline READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try await smbIssue102AwaitWithTimeout("deadline READ send owners join") {
            await session.waitForActiveSendTasksForTesting()
        }
        let committed = transport.readRequests

        virtualTime.advance(by: .seconds(5))
        operation.cancel()
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "drain at operation deadline")
        XCTAssertFalse(cleanupSleeper.requestedDurations.isEmpty)
        XCTAssertTrue(cleanupSleeper.requestedDurations.allSatisfy { $0 == .zero })
        try await driveReadDrainTimersUntilClose(
            transport,
            sleeper: cleanupSleeper,
            closeCount: 1,
            label: "unanswered READ closes at operation deadline"
        )
        XCTAssertTrue(cleanupSleeper.requestedDurations.allSatisfy { $0 == .zero })
        try await smbIssue102AwaitWithTimeout("absolute operation deadline terminal join") {
            try await operationJoined.waitForCount(1)
        }
        if case .failure(let error) = await operation.result {
            guard let transportError = error as? SMBTransportError,
                  transportError == .timedOut || transportError == .connectionClosed else {
                return XCTFail("unexpected absolute-deadline result: \(error)")
            }
        } else {
            XCTFail("operation deadline unexpectedly succeeded")
        }

        XCTAssertEqual(transport.readRequests, committed)
        let pendingAfterDeadline = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterDeadline, 0)
        await session.closeTransportAndWait(cause: "absolute_deadline_test_complete")
    }

    func testLateDrainBeforeTimerCallbackStillClosesTransport() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let cleanupSleeper = ManualSMBSleeper()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { _ in }
        )
        let session = makeSession(
            transport: transport,
            credits: 81,
            cleanupTimeout: .seconds(5),
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 8)) { _ in }
        }
        defer {
            cleanupSleeper.fireNext()
            transport.failConnection()
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "late-drain READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try await smbIssue102AwaitWithTimeout("late-drain READ send owners join") {
            await session.waitForActiveSendTasksForTesting()
        }
        let committed = transport.readRequests
        operation.cancel()
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "late-drain timer")
        XCTAssertFalse(cleanupSleeper.requestedDurations.isEmpty)
        XCTAssertTrue(cleanupSleeper.requestedDurations.allSatisfy { $0 == .seconds(5) })

        virtualTime.advance(by: .seconds(5))
        for request in committed {
            try transport.respond(to: request, payload: patternedPayload(seed: Int(request.offset), count: testChunkSize))
        }
        try await smbIssue102AwaitWithTimeout("finals drain exactly at cleanup deadline") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 5)
        }
        do {
            try await smbIssue102AwaitWithTimeout("late-drain terminal join") { try await operation.value }
            XCTFail("caller cancellation unexpectedly succeeded after the drain deadline")
        } catch is CancellationError {
            // Caller cancellation remains the selected transfer result after forced teardown.
        }

        XCTAssertEqual(transport.closeCount, 1, "a drain recorded at deadline equality must close the wire")
        let pendingAfterLateDrain = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterLateDrain, 0)
    }

    func testReservationGrantedAfterOperationDeadlineIsRefunded() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { _ in }
        )
        let session = makeSession(transport: transport, credits: 32, sessionTime: sessionTime)
        let client = SMBClientSession(session: session, treeId: 1)
        defer { transport.failConnection() }
        let grantingRead = Task {
            try await client.withReadStream(path: "granting.bin", knownSize: UInt64(testChunkSize)) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "granting READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 1)

        let deadline = virtualTime.now().advanced(by: .seconds(5))
        let deadlineRead = Task {
            try await SMBOperationDeadline.$operationContext.withValue(
                SMBOperationContext(now: { virtualTime.now() }, deadline: deadline),
                operation: {
                    try await client.withReadStream(
                        path: "deadline.bin",
                        knownSize: UInt64(testChunkSize + 1),
                        operationTimeout: nil
                    ) { _ in }
                }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, label: "deadline READ CREATE", occurrence: 2)
        try transport.completeCreate()
        try await waitForReadCount(transport, 2)
        let requests = transport.readRequests
        XCTAssertEqual(requests.map(\.length), [UInt32(testChunkSize), UInt32(testChunkSize)])
        try transport.respond(
            to: requests[1],
            payload: patternedPayload(seed: 0x71, count: Int(requests[1].length)),
            credits: 0
        )
        try await waitForCreditWaiter(session, count: 1)

        virtualTime.advance(by: .seconds(6))
        try transport.respond(
            to: requests[0],
            payload: patternedPayload(seed: 0x32, count: Int(requests[0].length)),
            credits: 3
        )
        try await smbIssue102AwaitWithTimeout("granting READ completion") { try await grantingRead.value }
        do {
            try await smbIssue102AwaitWithTimeout("expired reservation retirement") { try await deadlineRead.value }
            XCTFail("READ reservation after operation deadline unexpectedly succeeded")
        } catch SMBTransportError.timedOut {
            // The acquired credit is returned after the owner observes the expired deadline.
        } catch SMBError.connectionLost(operation: "READ") {
            // The public stream maps an expired timed-out READ to its established connection-loss error.
        } catch {
            throw error
        }

        XCTAssertEqual(transport.readRequests.count, 2, "the expired transfer does not commit another READ")
        let finalCreditBalance = await session.creditBalanceForTesting()
        XCTAssertEqual(finalCreditBalance, 3, "the unused acquired credit is refunded after both CLOSE requests")
        let pendingAfterReservation = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterReservation, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_reservation_refund_test_complete")
    }

    func testCreditWaitReturnsAfterIndependentClientClose() async throws {
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let sessionTime = SMBSessionMonotonicTime(now: { virtualTime.now() }, sleep: { _ in })
        let cleanupSleeper = ManualSMBSleeper()
        let session = makeSession(
            transport: transport,
            credits: 1,
            cleanupTimeout: .seconds(5),
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        defer { transport.failConnection() }
        let operationDeadline = virtualTime.now().advanced(by: .seconds(60))
        let operation = Task {
            try await SMBOperationDeadline.$operationContext.withValue(
                SMBOperationContext(now: { virtualTime.now() }, deadline: operationDeadline),
                operation: {
                    try await client.withReadStream(
                        path: "credit-close.bin",
                        knownSize: 65_536,
                        operationTimeout: nil
                    ) { _ in }
                }
            )
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "credit-close READ CREATE")
        virtualTime.startObservingNow()
        try transport.completeCreate()
        try await waitForReadCount(transport, 1)
        await session.waitForActiveSendTasksForTesting()
        try await smbIssue102AwaitWithTimeout("READ owner parks on its empty credit revision") {
            try await virtualTime.waitForObservedNowCount(3)
        }

        let close = Task { await client.close() }
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "TREE_DISCONNECT cleanup timeout")
        cleanupSleeper.fireNext()
        try await smbIssue102AwaitWithTimeout("client close tears down the session") { await close.value }

        do {
            try await smbIssue102AwaitWithTimeout("READ owner returns after independent close") {
                try await operation.value
            }
            XCTFail("READ unexpectedly succeeded after its session closed")
        } catch SMBError.connectionLost(operation: "READ") {
            // External client close terminalizes the READ transfer and joins its send owner.
        } catch SMBTransportError.connectionClosed {
            // The public stream may preserve the transport close error at this boundary.
        }
    }

    func testFailedPlaintextReadSendDoesNotCommitAnotherRead() async throws {
        try await assertFailedReadSendDoesNotCommitAnotherRead(encrypted: false)
    }

    func testFailedEncryptedReadSendDoesNotCommitAnotherRead() async throws {
        try await assertFailedReadSendDoesNotCommitAnotherRead(encrypted: true)
    }

    private func assertFailedReadSendDoesNotCommitAnotherRead(encrypted: Bool) async throws {
        let transport = SMBReadFailAfterSendTransport(encrypted: encrypted)
        let virtualTime = SMBReadPipelineVirtualClock()
        let sessionTime = SMBSessionMonotonicTime(now: { virtualTime.now() }, sleep: { _ in })
        let requestTrace = SMBReadPipelineRequestTrace()
        let debugLogger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: false, traceWireFull: false),
            sink: requestTrace.append
        )
        let session = makeSession(
            transport: transport,
            credits: 2,
            sessionTime: sessionTime,
            debugLogger: debugLogger
        )
        let failingClient = SMBClientSession(session: session, treeId: 1)
        let waitingClient = SMBClientSession(session: session, treeId: 1)
        defer { transport.failConnection() }
        let operationDeadline = virtualTime.now().advanced(by: .seconds(60))
        let failingOperation = Task {
            try await SMBOperationDeadline.$operationContext.withValue(
                SMBOperationContext(now: { virtualTime.now() }, deadline: operationDeadline),
                operation: {
                    try await failingClient.withReadStream(
                        path: encrypted ? "encrypted-send-failure.bin" : "plaintext-send-failure.bin",
                        knownSize: 65_536,
                        operationTimeout: nil
                    ) { _ in }
                }
            )
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "failing READ CREATE")
        let makeWaitingOperation = {
            Task {
                try await SMBOperationDeadline.$operationContext.withValue(
                    SMBOperationContext(now: { virtualTime.now() }, deadline: operationDeadline),
                    operation: {
                        try await waitingClient.withReadStream(
                            path: encrypted ? "encrypted-waiting-read.bin" : "plaintext-waiting-read.bin",
                            knownSize: 65_536,
                            operationTimeout: nil
                        ) { _ in }
                    }
                )
            }
        }
        var waitingOperation: Task<Void, Error>?
        if encrypted {
            waitingOperation = makeWaitingOperation()
            try await waitForCommand(transport, SMB2Commands.create, label: "waiting READ CREATE", occurrence: 2)
        }
        if encrypted {
            await session.installEncryptionStateForTesting(
                encryptionKey: Array(repeating: 0x31, count: 16),
                decryptionKey: Array(repeating: 0x31, count: 16),
                sessionId: 1
            )
        }
        try transport.completeCreate(credits: 1)
        try await transport.waitUntilReadSendIsGated()
        if !encrypted {
            waitingOperation = makeWaitingOperation()
            try await waitForCommand(transport, SMB2Commands.create, label: "waiting READ CREATE", occurrence: 2)
        }
        try transport.completeCreate(credits: 0)
        try await smbIssue102AwaitWithTimeout("second READ owner waits for its first credit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        transport.releaseReadSend()

        try await waitForTransportClose(
            transport,
            count: 1,
            label: encrypted ? "encrypted READ send failure closes session" : "plaintext READ send failure closes session"
        )
        try await assertReadFailure(failingOperation, label: "failed READ send terminates its owner")
        try await assertReadFailure(
            try XCTUnwrap(waitingOperation),
            label: "terminal close wakes the other READ owner"
        )

        XCTAssertEqual(transport.readSendCount, 1, "a send failure must not send a later READ (encrypted=\(encrypted))")
        XCTAssertEqual(transport.readRequests.count, encrypted ? 0 : 1)
        XCTAssertEqual(
            requestTrace.readRequestCount,
            1,
            "a failed committed send must not commit another READ before terminal close (encrypted=\(encrypted))"
        )
        let pendingAfterSendFailure = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterSendFailure, 0)
        let wireRecordsAfterSendFailure = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(wireRecordsAfterSendFailure, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_send_failure_test_complete")
    }

    func testEarlyFinalDoesNotShortenAnotherReadDrainDeadline() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let cleanupSleeper = ManualSMBSleeper()
        let requestSleeper = ManualSMBSleeper()
        let time = SMBSessionMonotonicTime(now: { virtualTime.now() }, sleep: { _ in })
        let session = makeSession(
            transport: transport,
            credits: 256,
            cleanupTimeout: .seconds(5),
            requestTimeout: .seconds(1),
            sessionTime: time,
            requestTimeoutSleeper: { try await requestSleeper.sleep(for: $0) },
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let firstSendGate = SMBContinuationAsyncGate()
        let laterSendGate = SMBContinuationAsyncGate()
        let sendGateClock = ManualSMBSleeper()
        transport.installAfterCommandSignalHook { command in
            guard command == SMB2Commands.read else { return }
            switch transport.readRequests.count {
            case 2:
                do {
                    try await firstSendGate.suspend(
                        timeout: .seconds(60),
                        sleeper: { try await sendGateClock.sleep(for: $0) }
                    )
                } catch {
                    // Teardown releases this synthetic send gate.
                }
            case 3, 4:
                do {
                    try await laterSendGate.suspend(
                        timeout: .seconds(60),
                        sleeper: { try await sendGateClock.sleep(for: $0) }
                    )
                } catch {
                    // Teardown releases these synthetic send gates.
                }
            default:
                break
            }
        }
        defer {
            firstSendGate.release()
            laterSendGate.release()
            transport.failConnection()
        }
        let operation = Task {
            try await client.withReadStream(
                path: "early-final-deadline.bin",
                knownSize: UInt64(testChunkSize * 4)
            ) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "early-final deadline CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        let requests = transport.readRequests
        try await smbIssue102AwaitWithTimeout("R1 send is in sending phase") {
            try await firstSendGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("R2 and R3 sends remain in sending phase") {
            try await laterSendGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }

        try transport.respondTogether([
            (request: requests[0], payload: Array(repeating: 0x10, count: testChunkSize)),
            (request: requests[1], payload: Array(repeating: 0x20, count: testChunkSize / 2))
        ])
        try await smbIssue102AwaitWithTimeout("early R1 final is accepted and stops the READ") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 3)
        }
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "five-second READ drain starts")

        virtualTime.advance(by: .milliseconds(100))
        firstSendGate.release()
        try await waitForSleeperCall(cleanupSleeper, count: 2, label: "R1 full-send updates the drain timer")
        let rescheduledDrain = cleanupSleeper.requestedDurations[1]
        XCTAssertGreaterThan(
            rescheduledDrain,
            .seconds(4),
            "R1 already has a final, so its one-second response timeout must not shorten the five-second drain"
        )

        virtualTime.advance(by: .seconds(1))
        if rescheduledDrain <= .seconds(1) {
            cleanupSleeper.fireNext()
            try await waitForTransportClose(transport, count: 1, label: "incorrect early-final deadline closes the session")
            XCTAssertEqual(transport.closeCount, 0, "an early final must not close R2/R3's still-draining session")
            return
        }
        XCTAssertEqual(transport.closeCount, 0, "the original cleanup deadline has not elapsed")

        virtualTime.advance(by: .milliseconds(900))
        laterSendGate.release()
        await session.waitForActiveSendTasksForTesting()
        try transport.respond(to: requests[2], payload: Array(repeating: 0x30, count: testChunkSize))
        try transport.respond(to: requests[3], payload: Array(repeating: 0x40, count: testChunkSize))
        try await smbIssue102AwaitWithTimeout("R2 and R3 finals drain at virtual time two") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 5)
        }

        for expectedCount in 5...7 {
            try await waitForReadCount(transport, expectedCount)
            let request = transport.readRequests[expectedCount - 1]
            try transport.respond(
                to: request,
                payload: Array(repeating: UInt8(0x40 + expectedCount), count: Int(request.length))
            )
        }
        try await smbIssue102AwaitWithTimeout("short READ rebases after all old requests drain") {
            try await operation.value
        }
        XCTAssertEqual(transport.closeCount, 0)
        await session.closeTransportAndWait(cause: "read_pipeline_early_final_deadline_test_complete")
    }

    func testEarlyShortFinalStopsReadAdmissionBeforeSendReturns() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let sendGate = SMBContinuationAsyncGate()
        let sendGateClock = ManualSMBSleeper()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        let readSendCount = SMBContinuationCountBarrier()
        let callbackCount = SMBContinuationCountBarrier()
        transport.installAfterCommandSignalHook { command in
            guard command == SMB2Commands.read else { return }
            readSendCount.signal()
            if readSendCount.currentCount == 4 {
                do {
                    try await sendGate.suspend(
                        timeout: .seconds(30),
                        sleeper: { try await sendGateClock.sleep(for: $0) }
                    )
                } catch {
                    // The transport's teardown releases this synthetic send gate.
                }
            }
        }
        let collector = SMBReadPipelineChunkCollector()
        defer {
            sendGate.release()
            callbackGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 6)) { data in
                let count = collector.append(data)
                callbackCount.signal()
                if count == 1 {
                    try await callbackGate.suspend(
                        timeout: .seconds(30),
                        sleeper: { try await callbackGateClock.sleep(for: $0) }
                    )
                }
            }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "early-short READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try await smbIssue102AwaitWithTimeout("fourth READ send remains gated") {
            try await sendGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await sendGateClock.sleep(for: $0) }
            )
        }
        let firstEpoch = transport.readRequests
        XCTAssertEqual(firstEpoch.map(\.offset), [0, 1, 2, 3].map { UInt64($0 * testChunkSize) })

        try transport.respond(
            to: firstEpoch[0],
            payload: patternedPayload(seed: 0x10, count: testChunkSize),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("first callback blocks before early final") {
            try await callbackCount.waitForCount(1)
        }
        try transport.respond(
            to: firstEpoch[3],
            payload: patternedPayload(seed: 0x43, count: testChunkSize / 2),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("early short final accepted while READ send is gated") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 3)
        }
        let earlyFinalWasStored = await session.pendingFinalSeenForTesting(messageId: firstEpoch[3].header.messageId)
        XCTAssertTrue(earlyFinalWasStored)

        callbackGate.release()
        try transport.respond(
            to: firstEpoch[1],
            payload: patternedPayload(seed: 0x21, count: testChunkSize),
            credits: 16
        )
        try transport.respond(
            to: firstEpoch[2],
            payload: patternedPayload(seed: 0x32, count: testChunkSize),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("earlier READ finals dispatch") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 5)
        }
        sendGate.release()

        try await waitForReadCount(transport, 5)
        let firstFollowUp = transport.readRequests[4]
        let expectedRebaseOffset = UInt64(testChunkSize * 3 + testChunkSize / 2)
        XCTAssertEqual(
            firstFollowUp.offset,
            expectedRebaseOffset,
            "an early short final stops the old epoch before it can commit an overfetch at offset 4 MiB"
        )
        guard firstFollowUp.offset == expectedRebaseOffset else {
            transport.failConnection()
            await session.closeTransportAndWait(cause: "early_final_regression_cleanup")
            do {
                try await operation.value
                XCTFail("failed early-final case unexpectedly succeeded")
            } catch SMBError.connectionLost(operation: "READ") {
                // Cleanup after the regression assertion above.
            } catch SMBTransportError.connectionClosed {
                // Cleanup after the regression assertion above.
            } catch is CancellationError {
                // Cleanup after the regression assertion above.
            }
            return
        }

        try transport.respond(
            to: firstFollowUp,
            payload: patternedPayload(seed: 0x54, count: Int(firstFollowUp.length)),
            credits: 16
        )
        try await waitForReadCount(transport, 6)
        let secondFollowUp = transport.readRequests[5]
        XCTAssertEqual(secondFollowUp.offset, UInt64(testChunkSize * 4 + testChunkSize / 2))
        try transport.respond(
            to: secondFollowUp,
            payload: patternedPayload(seed: 0x65, count: Int(secondFollowUp.length)),
            credits: 16
        )
        try await waitForReadCount(transport, 7)
        let thirdFollowUp = transport.readRequests[6]
        XCTAssertEqual(thirdFollowUp.offset, UInt64(testChunkSize * 5 + testChunkSize / 2))
        XCTAssertEqual(thirdFollowUp.length, UInt32(testChunkSize / 2))
        try transport.respond(
            to: thirdFollowUp,
            payload: patternedPayload(seed: 0x76, count: Int(thirdFollowUp.length)),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("early-short read rebase completes") { try await operation.value }

        XCTAssertEqual(collector.chunks, [
            patternedPayload(seed: 0x10, count: testChunkSize),
            patternedPayload(seed: 0x21, count: testChunkSize),
            patternedPayload(seed: 0x32, count: testChunkSize),
            patternedPayload(seed: 0x43, count: testChunkSize / 2),
            patternedPayload(seed: 0x54, count: testChunkSize),
            patternedPayload(seed: 0x65, count: testChunkSize),
            patternedPayload(seed: 0x76, count: testChunkSize / 2)
        ])
        let pendingAfterEarlyFinal = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterEarlyFinal, 0)
    }

    func testEarlyErrorFinalStopsReadAdmissionBeforeSendReturns() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        let sendGate = SMBContinuationAsyncGate()
        let sendGateClock = ManualSMBSleeper()
        transport.installAfterCommandSignalHook { command in
            guard command == SMB2Commands.read else { return }
            if transport.readRequests.count == 4 {
                do {
                    try await sendGate.suspend(
                        timeout: .seconds(60),
                        sleeper: { try await sendGateClock.sleep(for: $0) }
                    )
                } catch {
                    // Teardown releases this synthetic send gate.
                }
            } else if transport.readRequests.count > 4, let extraRequest = transport.readRequests.last {
                try? transport.respond(
                    to: extraRequest,
                    payload: patternedPayload(seed: 0x4b, count: Int(extraRequest.length)),
                    credits: 16
                )
            }
        }
        defer {
            callbackGate.release()
            sendGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "early-error.bin", knownSize: UInt64(testChunkSize * 6)) { _ in
                callbackEntered.signal()
                try await callbackGate.suspend(
                    timeout: .seconds(30),
                    sleeper: { try await callbackGateClock.sleep(for: $0) }
                )
            }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "early-error READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try await smbIssue102AwaitWithTimeout("fourth error READ send remains gated") {
            try await sendGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await sendGateClock.sleep(for: $0) }
            )
        }
        let firstEpoch = transport.readRequests
        try transport.respond(
            to: firstEpoch[0],
            payload: patternedPayload(seed: 0x18, count: testChunkSize),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("callback blocks before early error") {
            try await callbackEntered.waitForCount(1)
        }
        try transport.respond(to: firstEpoch[3], status: SMB2Status.accessDenied, credits: 16)
        try await smbIssue102AwaitWithTimeout("early access-denied final accepted while send is gated") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 3)
        }
        let earlyErrorWasStored = await session.pendingFinalSeenForTesting(messageId: firstEpoch[3].header.messageId)
        XCTAssertTrue(earlyErrorWasStored)

        callbackGate.release()
        try transport.respond(
            to: firstEpoch[1],
            payload: patternedPayload(seed: 0x29, count: testChunkSize),
            credits: 16
        )
        try transport.respond(
            to: firstEpoch[2],
            payload: patternedPayload(seed: 0x3a, count: testChunkSize),
            credits: 16
        )
        try await smbIssue102AwaitWithTimeout("preceding READ finals dispatch before send release") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 5)
        }
        sendGate.release()

        do {
            try await smbIssue102AwaitWithTimeout("early READ error terminates the stream") {
                try await operation.value
            }
            XCTFail("access-denied READ unexpectedly succeeded")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "READ") {
            // The error body is decoded after send ownership joins and stops the transfer.
        } catch SMBError.connectionLost(operation: "READ") {
            // The public stream maps errors after yielding a chunk to connection loss.
        }

        XCTAssertEqual(transport.readRequests.count, 4, "the early error prevents a fifth READ commit")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterEarlyError = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterEarlyError, 0)
    }

    func testTransferSendCancellationClosesSessionInsteadOfLeavingTombstone() async throws {
        let transport = SMBReadPipelineCancellationSendTransport()
        let session = makeSession(transport: transport, credits: 16)
        let client = SMBClientSession(session: session, treeId: 1)
        let testChunkSize = chunkSize
        defer { transport.failConnection() }
        let operation = Task {
            try await client.withReadStream(path: "cancelled-send.bin", knownSize: UInt64(testChunkSize)) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "cancelled-send READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 1)
        try await smbIssue102AwaitWithTimeout("cancelled READ send task joins") {
            await session.waitForActiveSendTasksForTesting()
        }

        let closeCountAfterSendFailure = transport.closeCount
        XCTAssertEqual(closeCountAfterSendFailure, 1, "a failed transfer send must close the session immediately")
        if closeCountAfterSendFailure == 0 {
            await session.closeTransportAndWait(cause: "read_pipeline_cancelled_send_test_cleanup")
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled READ send owner terminates") { try await operation.value }
            XCTFail("failed READ send unexpectedly succeeded")
        } catch is CancellationError {
            // The failed send terminalizes the transfer and its wire generation.
        } catch SMBTransportError.connectionClosed {
            // The failed send terminalizes the transfer and its wire generation.
        }
        let pendingAfterSendFailure = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterSendFailure, 0)
    }

    func testTransportDisconnectFailsAndReclaimsCommittedReads() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let callbackGate = SMBContinuationAsyncGate()
        let callbackGateClock = ManualSMBSleeper()
        defer {
            callbackGate.release()
            transport.failConnection()
        }
        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 8)) { _ in
                callbackEntered.signal()
                try await callbackGate.suspend(
                    timeout: .seconds(30),
                    sleeper: { try await callbackGateClock.sleep(for: $0) }
                )
            }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "disconnect READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try transport.respond(
            to: transport.readRequests[0],
            payload: Array(repeating: 0x7c, count: testChunkSize)
        )
        try await smbIssue102AwaitWithTimeout("disconnect after first yielded READ chunk") {
            try await callbackEntered.waitForCount(1)
        }
        XCTAssertEqual(transport.readRequests.count, 4, "callback still owns the first slot at disconnect")
        transport.failConnection()
        try await waitForTransportClose(transport, count: 2, label: "production READ disconnect terminalizes the session")
        callbackGate.release()
        do {
            try await smbIssue102AwaitWithTimeout("disconnected READ transfer terminal join") {
                try await operation.value
            }
            XCTFail("disconnected READ stream unexpectedly succeeded")
        } catch let error as SMBError {
            XCTAssertEqual(error, .connectionLost(operation: "READ"))
        }

        XCTAssertEqual(transport.readRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterDisconnect = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterDisconnect, 0)
        XCTAssertGreaterThanOrEqual(transport.closeCount, 2, "the transport fault and session terminalization both close it")
    }

    func testSingleCreditKeepsReadRequestsSerialAndMessageIDsStable() async throws {
        let requestLength = 65_536
        let transport = SMBReadPipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        let client = SMBClientSession(session: session, treeId: 1)
        let operation = Task {
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(requestLength * 3)) { _ in }
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "single-credit READ CREATE")
        try transport.completeCreate()
        for sequence in 0..<3 {
            try await waitForReadCount(transport, sequence + 1)
            let requests = transport.readRequests
            XCTAssertEqual(requests.count, sequence + 1, "one credit permits only one outstanding READ")
            let request = requests[sequence]
            XCTAssertEqual(request.offset, UInt64(sequence * requestLength))
            XCTAssertEqual(request.length, UInt32(requestLength))
            XCTAssertEqual(request.header.messageId, UInt64(sequence + 1))
            try transport.respond(to: request, payload: Array(repeating: UInt8(sequence + 1), count: requestLength))
        }
        try await smbIssue102AwaitWithTimeout("single-credit READ completion") {
            try await operation.value
        }

        XCTAssertEqual(transport.readRequests.map(\.length), Array(repeating: UInt32(requestLength), count: 3))
        XCTAssertEqual(transport.readRequests.map { $0.header.messageId }, [1, 2, 3])
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        await session.closeTransportAndWait(cause: "read_pipeline_single_credit_test_complete")
    }

    func testDrainDeadlineClosesTransportAndReclaimsPendingReads() async throws {
        let testChunkSize = chunkSize
        let transport = SMBReadPipelineScriptTransport()
        let virtualTime = SMBReadPipelineVirtualClock()
        let cleanupSleeper = ManualSMBSleeper()
        let time = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { _ in }
        )
        let session = makeSession(
            transport: transport,
            credits: 81,
            cleanupTimeout: .seconds(5),
            sessionTime: time,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let operationJoined = SMBContinuationCountBarrier()
        let operation = Task {
            defer { operationJoined.signal() }
            try await client.withReadStream(path: "file.bin", knownSize: UInt64(testChunkSize * 8)) { _ in }
        }
        defer {
            cleanupSleeper.fireNext()
            transport.failConnection()
        }

        try await waitForCommand(transport, SMB2Commands.create, label: "drain-deadline READ CREATE")
        try transport.completeCreate()
        try await waitForReadCount(transport, 4)
        try await smbIssue102AwaitWithTimeout("drain-deadline READ send owners join") {
            await session.waitForActiveSendTasksForTesting()
        }
        operation.cancel()
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "five-second drain timeout scheduled")
        let requestedDrainDurations = cleanupSleeper.requestedDurations
        guard !requestedDrainDurations.isEmpty,
              requestedDrainDurations.allSatisfy({ $0 > .seconds(4) && $0 <= .seconds(5) }) else {
            await session.closeTransportAndWait(cause: "invalid_drain_deadline_test_duration")
            return XCTFail("the cleanup sleeper must receive a duration no longer than five seconds")
        }
        virtualTime.advance(by: .milliseconds(4_999))
        XCTAssertEqual(transport.closeCount, 0, "the session remains open before the cleanup deadline")
        virtualTime.advance(by: .milliseconds(1))
        try await driveReadDrainTimersUntilClose(
            transport,
            sleeper: cleanupSleeper,
            closeCount: 1,
            label: "drain deadline closes READ transport"
        )
        try await smbIssue102AwaitWithTimeout("READ drain timeout terminal join") {
            try await operationJoined.waitForCount(1)
        }
        if case .failure(let error) = await operation.result {
            XCTAssertTrue(error is CancellationError, "unexpected terminal result: \(error)")
        } else {
            XCTFail("caller cancellation unexpectedly succeeded after the drain deadline")
        }

        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pendingAfterDrainTimeout = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterDrainTimeout, 0)
    }

    private func makeSession(
        transport: SMBReadPipelineScriptTransport,
        credits: UInt32,
        cleanupTimeout: Duration = .seconds(30),
        requestTimeout: Duration? = nil,
        sessionTime: SMBSessionMonotonicTime = .production(),
        requestTimeoutSleeper: (@Sendable (Duration) async throws -> Void)? = nil,
        cleanupTimeoutSleeper: (@Sendable (Duration) async throws -> Void)? = nil,
        debugLogger: SMBSessionDebugLogger = .environment
    ) -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: credits,
            cleanupTimeout: cleanupTimeout,
            requestTimeout: requestTimeout,
            sessionTime: sessionTime,
            requestTimeoutSleeper: requestTimeoutSleeper,
            cleanupTimeoutSleeper: cleanupTimeoutSleeper,
            debugLogger: debugLogger
        )
    }

    private func waitForCommand(
        _ transport: SMBReadPipelineScriptTransport,
        _ command: UInt16,
        label: String
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await transport.waitForCommand(command)
        }
    }

    private func waitForReadCount(_ transport: SMBReadPipelineScriptTransport, _ count: Int) async throws {
        try await smbIssue102AwaitWithTimeout("\(count) READ sends") {
            try await transport.waitForReadCount(count)
        }
    }

    private func waitForCommand(
        _ transport: SMBReadPipelineScriptTransport,
        _ command: UInt16,
        label: String,
        occurrence: Int
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await transport.waitForCommand(command, occurrence: occurrence)
        }
    }

    private func waitForSleeperCall(_ sleeper: ManualSMBSleeper, count: Int, label: String) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await sleeper.waitUntilCallCount(
                atLeast: count,
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
    }

    private func waitForTransportClose(
        _ transport: SMBContinuationScriptTransport,
        count: Int,
        label: String
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await transport.waitForCloseCount(count)
        }
    }

    private func waitForCreditWaiter(_ session: SMBSession, count: Int) async throws {
        try await smbIssue102AwaitWithTimeout("READ credit waiter") {
            await session.waitForCreditWaiterCountForTesting(atLeast: count)
        }
    }

    private func assertReadFailure(_ operation: Task<Void, Error>, label: String) async throws {
        do {
            try await smbIssue102AwaitWithTimeout(label) { try await operation.value }
            XCTFail("READ unexpectedly succeeded")
        } catch SMBError.connectionLost(operation: "READ") {
            // Terminal session failure is the expected public READ result.
        } catch is CancellationError {
            // The terminal session may preserve its cancellation error at the stream boundary.
        } catch SMBTransportError.connectionClosed {
            // The terminal session may preserve its transport close error at the stream boundary.
        }
    }
}

private enum SMBReadPipelineCallbackFailure: Error {
    case injected
}

private final class SMBReadPipelineVirtualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    private var observingNow = false
    private let observedNowBarrier = SMBContinuationCountBarrier()

    func now() -> ContinuousClock.Instant {
        let result = lock.withLock { () -> (ContinuousClock.Instant, Bool) in
            (instant, observingNow)
        }
        if result.1 { observedNowBarrier.signal() }
        return result.0
    }

    func advance(by duration: Duration) {
        lock.withLock { instant += duration }
    }

    func startObservingNow() {
        lock.withLock { observingNow = true }
    }

    func waitForObservedNowCount(_ count: Int) async throws {
        try await observedNowBarrier.waitForCount(
            count,
            timeout: .seconds(60),
            sleeper: { try await Task.sleep(for: $0) }
        )
    }
}

private final class SMBReadPipelineChunkCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [[UInt8]] = []

    func append(_ chunk: [UInt8]) -> Int {
        lock.withLock {
            storage.append(chunk)
            return storage.count
        }
    }

    var chunks: [[UInt8]] {
        lock.withLock { storage }
    }
}

private final class SMBReadPipelineRequestTrace: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) {
        lock.withLock { lines.append(line) }
    }

    var readRequestCount: Int {
        lock.withLock { lines.filter { $0.hasPrefix("READ request (") }.count }
    }
}

private func patternedPayload(seed: Int, count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: ($0 &* 31) + seed) }
}

private func driveReadDrainTimersUntilClose(
    _ transport: SMBReadPipelineScriptTransport,
    sleeper: ManualSMBSleeper,
    closeCount: Int,
    label: String
) async throws {
    var firedSleeperCalls = 0
    while transport.closeCount < closeCount {
        let requestedSleeperCalls = sleeper.requestedDurations.count
        while firedSleeperCalls < requestedSleeperCalls {
            sleeper.fireNext()
            firedSleeperCalls += 1
        }
        guard transport.closeCount < closeCount else { return }

        let nextSleeperCall = firedSleeperCalls + 1
        let closeObserved = try await smbIssue102AwaitWithTimeout("\(label): close or timer reschedule") {
            try await withThrowingTaskGroup(of: Bool.self) { group in
                group.addTask {
                    try await transport.waitForCloseCount(closeCount)
                    return true
                }
                group.addTask {
                    try await sleeper.waitUntilCallCount(
                        atLeast: nextSleeperCall,
                        timeout: .seconds(60),
                        sleeper: { try await Task.sleep(for: $0) }
                    )
                    return false
                }

                guard let firstEvent = try await group.next() else {
                    throw CancellationError()
                }
                group.cancelAll()
                do {
                    try await group.waitForAll()
                } catch is CancellationError {
                    // The losing event waiter is intentionally cancelled after the first event.
                }
                return firstEvent
            }
        }
        if closeObserved { return }
    }
}

private final class SMBReadFailAfterSendTransport: SMBReadPipelineScriptTransport, @unchecked Sendable {
    private let encrypted: Bool
    private let sendGate = SMBContinuationAsyncGate()
    private let sendGateClock = ManualSMBSleeper()
    private let sendLock = NSLock()
    private var readSendCountStorage = 0

    init(encrypted: Bool) {
        self.encrypted = encrypted
        super.init()
    }

    override func send(_ bytes: [UInt8]) async throws {
        let isTargetRead = Self.commandInFrame(bytes, encrypted: encrypted) == SMB2Commands.read
        try await super.send(bytes)

        guard isTargetRead else { return }
        let failureNumber = sendLock.withLock { () -> Int in
            readSendCountStorage += 1
            return readSendCountStorage
        }
        guard failureNumber == 1 else { return }
        do {
            try await self.sendGate.suspend(
                timeout: .seconds(60),
                sleeper: { try await self.sendGateClock.sleep(for: $0) }
            )
        } catch {
            // The test releases the gate before teardown; cancellation also unblocks it.
        }
        throw CancellationError()
    }

    var readSendCount: Int {
        sendLock.withLock { readSendCountStorage }
    }

    func waitUntilReadSendIsGated() async throws {
        try await smbIssue102AwaitWithTimeout("READ send reaches the injected failure gate") {
            try await self.sendGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
    }

    func releaseReadSend() {
        sendGate.release()
    }

    private static func commandInFrame(_ bytes: [UInt8], encrypted: Bool) -> UInt16? {
        guard let length = try? DirectTCPFraming.length(from: Array(bytes.prefix(4))),
              length == bytes.count - 4 else { return nil }
        let packet = Array(bytes.dropFirst(4))
        if packet.starts(with: SMB3TransformHeader.protocolId), encrypted,
           let header = try? SMB3TransformHeader.decode(packet),
           packet.count >= SMB3TransformHeader.encodedSize,
           let plaintext = try? AESCCM.open(
               key: Array(repeating: 0x31, count: 16),
               nonce: Array(header.nonce.prefix(11)),
               ciphertext: Array(packet.dropFirst(SMB3TransformHeader.encodedSize)),
               authenticatedData: try header.authenticatedData(),
               tag: header.signature
           ) {
            return try? SMB2Header.decode(plaintext).command
        }
        guard packet.starts(with: [0xfe, 0x53, 0x4d, 0x42]) else { return nil }
        return try? SMB2Header.decode(packet).command
    }
}
