import Foundation
import XCTest
@testable import SMBee

final class SMBUnsentRequestActivationTests: XCTestCase {
    func testCancelledTreeRequestKeepsNextTreeDisconnectAndTreeBMessageIdsContiguous() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
        try await session.parkCreditWaiterForTesting(charge: 2)

        let treeA = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("Tree A request waits before commit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        treeA.cancel()
        do {
            try await withHangGuard("Tree A local retirement finishes") { try await treeA.value }
            XCTFail("expected precommit Tree A cancellation")
        } catch is CancellationError {
        }

        let noWireRecord = await session.wirePendingRecordCountForTesting()
        let noActiveIdentity = await session.activeRequestIdentityCountForTesting()
        let noSessionRecord = await session.activePostAuthRequestRecordCountForTesting()
        let unchangedMID = await session.nextMessageIdForTesting()
        let creditWaiters = await session.creditWaiterCountForTesting()
        let noFrames = transport.sentPackets.isEmpty
        XCTAssertEqual(creditWaiters, 0)
        XCTAssertEqual(noWireRecord, 0)
        XCTAssertEqual(noActiveIdentity, 0)
        XCTAssertEqual(noSessionRecord, 0)
        XCTAssertEqual(unchangedMID, 100)
        XCTAssertTrue(noFrames, "precommit retirement must not emit Tree A or CANCEL")

        await session.refundCreditsForTesting(2)
        let disconnect = Task { try await session.treeDisconnectThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("Tree A disconnect is sent") { try await transport.waitForSendCount(1) }
        let disconnectHeader = try SMB2Header.decode(transport.sentPackets[0])
        XCTAssertEqual(disconnectHeader.command, SMB2Commands.treeDisconnect)
        guard disconnectHeader.messageId == 100 else {
            await session.closeTransportAndWait(cause: "eager_mid_mutation_cleanup")
            _ = await disconnect.result
            XCTFail("precommit Tree A retirement must leave MID 100 for TREE_DISCONNECT")
            return
        }
        XCTAssertEqual(disconnectHeader.treeId, 0xA)
        transport.releaseNextSend()
        try await withHangGuard("Tree A disconnect full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.treeDisconnect,
            messageId: 100,
            sessionId: 1,
            treeId: 0xA,
            credits: 0
        ))
        try await withHangGuard("Tree A disconnect final") { try await disconnect.value }

        let treeB = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xB) }
        try await withHangGuard("Tree B request is sent") { try await transport.waitForSendCount(2) }
        let treeBHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(treeBHeader.command, SMB2Commands.echo)
        XCTAssertEqual(treeBHeader.messageId, 101)
        XCTAssertEqual(treeBHeader.treeId, 0xB)
        transport.releaseNextSend()
        try await withHangGuard("Tree B full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 101, sessionId: 1, credits: 0))
        try await withHangGuard("Tree B final") { try await treeB.value }
        XCTAssertEqual(try transport.sentPackets.map { try SMB2Header.decode($0).command }, [
            SMB2Commands.treeDisconnect, SMB2Commands.echo
        ])
        await session.closeTransportAndWait(cause: "precommit_tree_retirement_test")
    }

    func testFinalAdmissionGuardRefundsAndRetiresFileRequestWithoutAMessageId() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 900)

        let first = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("first frame owns the sender") { try await transport.waitForSendCount(1) }
        let fileId = Array(repeating: UInt8(0xA5), count: 16)
        let guarded = Task { try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("FLUSH waits behind the in-flight frame") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        await session.retireFileIdForTesting(fileId)
        transport.releaseNextSend(command: SMB2Commands.echo)

        let race = SMBActivationRace()
        let callerObserver = Task {
            await withTaskCancellationHandler {
                _ = await guarded.result
                race.finish(true)
            } onCancel: {
                guarded.cancel()
            }
        }
        let sendObserver = Task {
            do {
                try await transport.waitForSendCount(2)
                race.finish(false)
            } catch {
            }
        }
        let callerReturnedFirst = try await withHangGuard("admission decision or unexpected FLUSH send") {
            await race.wait()
        }
        callerObserver.cancel()
        sendObserver.cancel()
        guard callerReturnedFirst else {
            await session.closeTransportAndWait(cause: "unexpected_file_request_commit")
            _ = await guarded.result
            XCTFail("queued FLUSH reached the transport after its FileId was retired")
            return
        }
        switch await guarded.result {
        case .success:
            XCTFail("expected final FileId admission refusal")
        case .failure(let error as SMBCodecError):
            XCTAssertEqual(error, .invalidValue("SMB FileId is unresolved after CLOSE"))
        case .failure(let error):
            XCTFail("unexpected FileId admission error: \(error)")
        }
        let firstAndNoFlush = transport.sentPackets
        let cursorAfterGuard = await session.nextMessageIdForTesting()
        let balanceAfterGuard = await session.creditBalanceForTesting()
        let pendingAfterGuard = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(firstAndNoFlush.count, 1)
        XCTAssertEqual(try SMB2Header.decode(firstAndNoFlush[0]).messageId, 900)
        XCTAssertEqual(cursorAfterGuard, 901)
        XCTAssertEqual(balanceAfterGuard, 1, "precommit guard returns the reserved credit")
        XCTAssertEqual(pendingAfterGuard, 1)

        try transport.enqueueResponse(try echoResponse(messageId: 900, sessionId: 1, credits: 0))
        try await withHangGuard("first request final") { try await first.value }
        let following = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xB) }
        try await withHangGuard("post-refusal request consumes the returned credit") {
            try await transport.waitForSendCount(2)
        }
        let followingHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(followingHeader.messageId, 901)
        XCTAssertEqual(followingHeader.command, SMB2Commands.echo)
        transport.releaseNextSend()
        try await withHangGuard("post-refusal request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 901, sessionId: 1, credits: 0))
        try await withHangGuard("post-refusal request final") { try await following.value }
        await session.closeTransportAndWait(cause: "final_file_admission_guard_test")
    }

    func testCommittedChargeThreeRetirementPreservesRangeAndRemainingCredit() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 4,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let large = Task { try await session.echoThroughSenderLoopForTesting(creditCharge: 3) }
        try await withHangGuard("charge-three original send starts") { try await transport.waitForSendCount(1) }
        let rangeCursor = await session.nextMessageIdForTesting()
        let oneCreditRemains = await session.creditBalanceForTesting()
        XCTAssertEqual(rangeCursor, 103)
        XCTAssertEqual(oneCreditRemains, 1)
        large.cancel()
        do {
            try await withHangGuard("charge-three caller cancellation returns") { try await large.value }
            XCTFail("expected committed request cancellation")
        } catch is CancellationError {
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("charge-three send owner returns") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("charge-three CANCEL is selected") {
            try await transport.waitForSendCount(2)
        }
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("CANCEL send owner returns") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        let balanceAfterCancel = await session.creditBalanceForTesting()
        let cursorAfterCancel = await session.nextMessageIdForTesting()
        let pendingAfterCancel = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(balanceAfterCancel, 1, "CANCEL consumes no credit")
        XCTAssertEqual(cursorAfterCancel, 103, "CANCEL consumes no MessageId")
        XCTAssertEqual(pendingAfterCancel, 1, "CANCEL completion is not the original final")

        let small = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("remaining charge-one request sends") { try await transport.waitForSendCount(3) }
        let smallHeader = try SMB2Header.decode(transport.sentPackets[2])
        guard smallHeader.messageId == 103 else {
            await session.closeTransportAndWait(cause: "charge_range_mutation_cleanup")
            _ = await small.result
            XCTFail("the charge-three request must retire the complete range 100...102")
            return
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("charge-one request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 103, sessionId: 1, credits: 0))
        try await withHangGuard("charge-one final") { try await small.value }
        try transport.enqueueResponse(try echoResponse(messageId: 100, sessionId: 1, credits: 0))
        try await withHangGuard("charge-three original final drains") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 2)
        }
        await session.closeTransportAndWait(cause: "charge_range_retirement_test")
    }

    func testCancelUsesLatestAsyncIdWithoutCreditOrMessageIdAndDoesNotRetireOriginal() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 400)

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("async ECHO starts") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend()
        try await withHangGuard("async ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try transport.enqueueResponse(try asyncPendingResponse(
            command: SMB2Commands.echo,
            messageId: 400,
            asyncId: 0xA11C_E001,
            sessionId: 1
        ))
        try await withHangGuard("STATUS_PENDING stores AsyncId") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let activeSnapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: 400)
        XCTAssertEqual(activeSnapshot?.caller, .pending)
        XCTAssertEqual(activeSnapshot?.send, .fullySent)
        XCTAssertEqual(activeSnapshot?.wire, .statusPending(asyncId: 0xA11C_E001))
        XCTAssertEqual(activeSnapshot?.credit, .committed(actualCharge: 1))
        let asyncId = await session.pendingAsyncIdForTesting(messageId: 400)
        XCTAssertEqual(asyncId, 0xA11C_E001)

        caller.cancel()
        do {
            try await withHangGuard("cancelled async caller returns") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        let cancelledSnapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: 400)
        XCTAssertEqual(cancelledSnapshot?.caller, .cancelled)
        XCTAssertEqual(cancelledSnapshot?.send, .fullySent)
        XCTAssertEqual(cancelledSnapshot?.wire, .statusPending(asyncId: 0xA11C_E001))
        try await withHangGuard("async CANCEL reaches transport") { try await transport.waitForSendCount(2) }
        let cancelHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, 400)
        XCTAssertTrue(cancelHeader.isAsync)
        XCTAssertEqual(cancelHeader.asyncId, 0xA11C_E001)
        let maybeIdentity = await session.requestIdentityForTesting(messageId: 400)
        let identity = try XCTUnwrap(maybeIdentity)
        let firstDeadline = await session.wireDrainDeadlineForTesting(messageId: 400)
        let firstTimerIdentity = await session.wireDrainTimerIdentityForTesting(messageId: 400)
        await session.cancelPostAuthRequestForTesting(identity: identity)
        let deadlineAfterRepeatedCancel = await session.wireDrainDeadlineForTesting(messageId: 400)
        let timerAfterRepeatedCancel = await session.wireDrainTimerIdentityForTesting(messageId: 400)
        XCTAssertEqual(deadlineAfterRepeatedCancel, firstDeadline)
        XCTAssertEqual(timerAfterRepeatedCancel, firstTimerIdentity)
        let balanceDuringCancel = await session.creditBalanceForTesting()
        let cursorDuringCancel = await session.nextMessageIdForTesting()
        XCTAssertEqual(balanceDuringCancel, 0, "CANCEL consumes no credit")
        XCTAssertEqual(cursorDuringCancel, 401, "CANCEL consumes no MessageId")

        // A repeated cancel or a later CANCEL send must not extend the first deadline.
        clock.advance(by: .seconds(3), resumeDueSleeps: false)
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("CANCEL full-send is not an original final") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        let deadlineAfterCancelSend = await session.wireDrainDeadlineForTesting(messageId: 400)
        let timerAfterCancelSend = await session.wireDrainTimerIdentityForTesting(messageId: 400)
        XCTAssertEqual(deadlineAfterCancelSend, firstDeadline)
        XCTAssertEqual(timerAfterCancelSend, firstTimerIdentity)
        let pendingAfterCancelSend = await session.wirePendingRecordCountForTesting()
        let finalSeenAfterCancelSend = await session.pendingFinalSeenForTesting(messageId: 400)
        XCTAssertEqual(pendingAfterCancelSend, 1)
        XCTAssertFalse(finalSeenAfterCancelSend, "CANCEL success cannot fabricate an original final")
        clock.advance(by: .seconds(10), resumeDueSleeps: true)
        try await withHangGuard("missing original final reaches its fixed deadline") {
            await transport.waitForCloseCount(atLeast: 1)
        }
        await session.closeTransportAndWait(cause: "async_cancel_drain_test")
    }

    func testFinalDrainReleasesTimerBeforeCreditGrantAckAndReapsRecordAfterAck() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 2,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 500)
        let grantEntered = SMBActivationEvent()
        let releaseGrant = SMBActivationEvent()
        await session.setCreditGrantActorHookForTesting {
            grantEntered.signal()
            await releaseGrant.wait()
        }
        defer {
            releaseGrant.signal()
            Task { await session.closeTransportAndWait(cause: "credit_grant_ack_test_cleanup") }
        }

        let cancelled = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("cancelled request sends") { try await transport.waitForSendCount(1) }
        let original = try SMB2Header.decode(transport.sentPackets[0])
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("cancelled request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        cancelled.cancel()
        do {
            try await withHangGuard("cancelled caller completes") { try await cancelled.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("CANCEL is selected") { try await transport.waitForSendCount(2) }
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("CANCEL owner completes") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        try await withHangGuard("wire-drain timer is armed") { await clock.waitForSleepCount(atLeast: 1) }
        let deadlineBeforeFinal = await session.wireDrainDeadlineForTesting(messageId: original.messageId)
        XCTAssertNotNil(deadlineBeforeFinal)

        clock.advance(by: .seconds(9), resumeDueSleeps: false)
        try transport.enqueueResponse(try echoResponse(messageId: original.messageId, sessionId: 1, credits: 1))
        try await withHangGuard("credit grant acknowledgement is held before applying credits") {
            await grantEntered.wait()
        }

        let acceptedAt = await session.lastFinalAcceptanceForTesting()
        let pendingAfterDrain = await session.wirePendingRecordCountForTesting()
        let timerAfterDrain = await session.wireDrainTimerIdentityForTesting(messageId: original.messageId)
        let recordCountBeforeAck = await session.activePostAuthRequestRecordCountForTesting()
        let heldRecord = await session.postAuthRequestRecordSnapshotForTesting(messageId: original.messageId)
        let sessionClosedBeforeAck = await session.isTransportClosedForTesting()
        XCTAssertLessThan(try XCTUnwrap(acceptedAt), try XCTUnwrap(deadlineBeforeFinal))
        XCTAssertEqual(pendingAfterDrain, 0, "drain finalizes before the credit grant actor acknowledges")
        XCTAssertNil(timerAfterDrain, "the fixed drain timer is released at final drain completion")
        XCTAssertEqual(recordCountBeforeAck, 1, "the final identity record stays owned until grant acknowledgement")
        XCTAssertEqual(heldRecord?.outstandingAcknowledgements, 1)
        XCTAssertFalse(sessionClosedBeforeAck)

        let following = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("session remains usable while the final grant acknowledgement is held") {
            try await transport.waitForSendCount(3)
        }
        let followingHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(followingHeader.command, SMB2Commands.echo)
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("following request full-send before grant acknowledgement") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }

        clock.advance(by: .seconds(2), resumeDueSleeps: true)
        let stillOpenAfterDeadline = await session.isTransportClosedForTesting()
        XCTAssertFalse(stillOpenAfterDeadline, "the completed drain timer cannot terminalize after its deadline")
        releaseGrant.signal()
        try transport.enqueueResponse(try echoResponse(messageId: followingHeader.messageId, sessionId: 1, credits: 0))
        try await withHangGuard("following request completes after grant acknowledgement") { try await following.value }

        let recordCountAfterAck = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordCountAfterAck, 0, "the final identity record is reaped after its grant acknowledgement")
        await session.setCreditGrantActorHookForTesting(nil)
        await session.closeTransportAndWait(cause: "credit_grant_ack_test_complete")
    }

    func testFinalQueuedBehindCurrentFrameDropsCancelBeforeSelection() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 500)

        let first = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("first ECHO starts") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend()
        try await withHangGuard("first ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }

        let second = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("second ECHO blocks the sender loop") { try await transport.waitForSendCount(2) }
        first.cancel()
        do {
            try await withHangGuard("first caller cancellation returns") { try await first.value }
            XCTFail("expected first caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("CANCEL demand waits behind the current frame") {
            await session.waitForQueuedControlSendCountForTesting(atLeast: 1)
        }

        try transport.enqueueResponse(try echoResponse(messageId: 500, sessionId: 1, credits: 0))
        try await withHangGuard("final removes unselected CANCEL demand") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let controlsAfterFinal = (await session.senderLoopStatisticsForTesting()).queuedControls
        let pendingAfterFinal = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(controlsAfterFinal, 0)
        XCTAssertEqual(pendingAfterFinal, 1, "second request still owns the wire")
        XCTAssertEqual(transport.sentPackets.count, 2, "CANCEL was never selected")

        transport.releaseNextSend()
        try await withHangGuard("second ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 501, sessionId: 1, credits: 0))
        try await withHangGuard("second caller final") { try await second.value }
        let commands = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        XCTAssertEqual(commands, [SMB2Commands.echo, SMB2Commands.echo])
        await session.closeTransportAndWait(cause: "cancel_selection_race_test")
    }

    func testCancelSendCancellationErrorTerminalizesBeforeFollowingRequestBytes() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 800)
        defer { Task { await session.closeTransportAndWait(cause: "partial_cancel_send_test_cleanup") } }

        let cancelled = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("original ECHO reaches transport") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("original ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        cancelled.cancel()
        do {
            try await withHangGuard("cancelled caller returns") { try await cancelled.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }

        try await withHangGuard("CANCEL send is selected and held") { try await transport.waitForSendCount(2) }
        XCTAssertTrue(transport.isSendBlocked(command: SMB2Commands.cancel))
        let following = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("request B queues behind the selected CANCEL") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }

        try transport.failBlockedSendAfterWritingPrefix(
            command: SMB2Commands.cancel,
            prefixLength: 67,
            error: CancellationError()
        )
        var terminalizedByCancelFailure = false
        do {
            try await withHangGuard("CANCEL failure terminalizes the active generation") {
                await transport.waitForCloseCount(atLeast: 1)
            }
            terminalizedByCancelFailure = true
        } catch {
            terminalizedByCancelFailure = false
        }
        let closedByCancelFailure = await session.isTransportClosedForTesting()
        let packetsBeforeCleanup = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        XCTAssertTrue(terminalizedByCancelFailure, "an incomplete CANCEL frame must terminalize the active generation")
        XCTAssertTrue(closedByCancelFailure, "the active generation must close after a partial CANCEL")
        XCTAssertEqual(packetsBeforeCleanup, [SMB2Commands.echo, SMB2Commands.cancel])
        await session.closeTransportAndWait(cause: "partial_cancel_send_test_cleanup")
        do {
            try await following.value
            XCTFail("request B unexpectedly completed after a partial CANCEL")
        } catch is CancellationError {
        } catch SMBTransportError.connectionClosed {
        }
        let partialSends = transport.partialSendPackets
        XCTAssertEqual(partialSends.count, 1)
        XCTAssertEqual(partialSends.first?.count, 67)
        XCTAssertEqual(partialSends.first.map { readUInt16LE($0, at: 12) }, SMB2Commands.cancel)
    }

    func testOriginalSendStallWithoutFinalTerminalizesAndJoinsReaderAndSender() async throws {
        let (weakSession, deinitEvent) = try await runOriginalSendStallScenario()
        try await withHangGuard("terminal session deinitializes") { await deinitEvent.wait() }
        XCTAssertNil(weakSession.value)
    }

    private func runOriginalSendStallScenario() async throws -> (
        SMBActivationWeakSessionReference,
        SMBActivationEvent
    ) {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 600)
        let deinitEvent = SMBActivationEvent()
        let weakSession = SMBActivationWeakSessionReference(session)
        await session.setSessionDeinitHookForTesting { deinitEvent.signal() }
        let readerExitEntered = SMBActivationEvent()
        let releaseReaderExit = SMBActivationEvent()
        await session.setReaderTaskExitHookForTesting { _ in
            readerExitEntered.signal()
            await releaseReaderExit.wait()
        }

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("original request send stalls") { try await transport.waitForSendCount(1) }
        caller.cancel()
        do {
            try await withHangGuard("cancelled caller is completed once") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("drain deadline is armed") { await clock.waitForSleepCount(atLeast: 1) }
        let maybeTimerIdentity = await session.wireDrainTimerIdentityForTesting(messageId: 600)
        guard let timerIdentity = maybeTimerIdentity else {
            XCTFail("committed cancellation must retain its record and drain timer until owner recovery")
            releaseReaderExit.signal()
            await session.closeTransportAndWait(cause: "missing_wire_record_mutation_cleanup")
            return (weakSession, deinitEvent)
        }

        clock.advance(by: .seconds(10), resumeDueSleeps: true)
        try await withHangGuard("no-final request reaches deadline terminal") {
            await transport.waitForCloseCount(atLeast: 1)
        }
        try await withHangGuard("terminalizer reaches reader join") { await readerExitEntered.wait() }
        let fenceBeforeJoin = await session.terminalWireDrainTimerFenceForTesting(timerIdentity)
        XCTAssertTrue(fenceBeforeJoin)
        transport.releaseNextSend(command: SMB2Commands.echo)
        releaseReaderExit.signal()
        await session.closeTransportAndWait(cause: "original_send_stall_test")
        try await withHangGuard("deadline terminalizer joins all owners") {
            await session.waitForWireDrainTerminalizationCountForTesting(atLeast: 1)
        }
        let closed = await session.isTransportClosedForTesting()
        let pending = await session.wirePendingRecordCountForTesting()
        let active = await session.activeRequestIdentityCountForTesting()
        let stats = await session.senderLoopStatisticsForTesting()
        let readers = await session.readerTaskCountForTesting()
        let recordsAfterJoin = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertTrue(closed)
        XCTAssertEqual(pending, 0)
        XCTAssertEqual(active, 0)
        XCTAssertEqual(readers, 0)
        XCTAssertEqual(recordsAfterJoin, 0)
        XCTAssertFalse(stats.isRunning)
        XCTAssertEqual(stats.queuedRequests, 0)
        XCTAssertEqual(stats.queuedControls, 0)
        return (weakSession, deinitEvent)
    }

    func testWireDrainDeadlineUsesFinalAndOwnerTimestampsAcrossCallbackOrder() async throws {
        let beforeDeadline = try await runFinalAndOwnerBoundary(
            finalAt: .nanoseconds(-1),
            ownerAt: .nanoseconds(-1)
        )
        XCTAssertFalse(beforeDeadline)
        for callbackFirst in [false, true] {
            let atDeadline = try await runFinalAndOwnerBoundary(
                finalAt: .nanoseconds(-1),
                ownerAt: .zero,
                deadlineCallbackFirst: callbackFirst
            )
            XCTAssertTrue(atDeadline)
            let afterDeadline = try await runFinalAndOwnerBoundary(
                finalAt: .nanoseconds(-1),
                ownerAt: .nanoseconds(1),
                deadlineCallbackFirst: callbackFirst
            )
            XCTAssertTrue(afterDeadline)
        }
        let finalAtDeadline = try await runFinalAndOwnerBoundary(finalAt: .zero, ownerAt: .nanoseconds(1))
        let finalAfterDeadline = try await runFinalAndOwnerBoundary(
            finalAt: .nanoseconds(1),
            ownerAt: .nanoseconds(1)
        )
        XCTAssertTrue(finalAtDeadline)
        XCTAssertTrue(finalAfterDeadline)
    }

    func testEveryPostCommitBuildSigningEncryptionAndSendFailureIsTerminalWithoutRefund() async throws {
        for stage in ["build", "signing", "encryption", "send"] {
            let transport = SMBActivationEventTransport()
            let signingKey: [UInt8]? = stage == "signing" ? nil : Array(repeating: 0x11, count: 16)
            let session = makeSession(transport: transport, initialCredits: 1, signingKey: signingKey)
            await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 800)

            let operation: Task<Void, Error>
            switch stage {
            case "build":
                await session.failNextPostAuthFrameBuildForTesting()
                operation = Task { try await session.echoThroughSenderLoopForTesting() }
            case "send":
                transport.failNextSend(SMBTransportError.connectionClosed)
                operation = Task { try await session.echoThroughSenderLoopForTesting() }
            case "signing", "encryption":
                let snapshot = try SMBNegotiateRequestSnapshot(
                    clientGuid: Array(repeating: 0, count: 16),
                    capabilities: SMBNegotiateConstants.globalCapEncryption,
                    securityMode: SMBNegotiateConstants.signingEnabled,
                    dialects: SMBNegotiateCodec.authenticatedDialects
                )
                let packet = try SMB2ValidateNegotiateInfo.encodeRequest(
                    messageId: UInt64.max,
                    sessionId: 1,
                    treeId: 0xA,
                    snapshot: snapshot
                )
                operation = Task {
                    _ = try await session.validateNegotiateWireTransactionForTesting(
                        packet: packet,
                        encrypt: stage == "encryption"
                    )
                }
            default:
                throw SMBActivationTimeout(label: "unknown failure stage: \(stage)")
            }

            try await withHangGuard("\(stage) failure closes the committed session") {
                await transport.waitForCloseCount(atLeast: 1)
            }
            do {
                _ = try await withHangGuard("\(stage) failure returns to caller") { try await operation.value }
                XCTFail("expected \(stage) failure")
            } catch is SMBActivationTimeout {
                throw SMBActivationTimeout(label: "\(stage) failure did not release its caller")
            } catch {
            }

            let cursor = await session.nextMessageIdForTesting()
            let balance = await session.creditBalanceForTesting()
            let pending = await session.wirePendingRecordCountForTesting()
            let active = await session.activeRequestIdentityCountForTesting()
            let closed = await session.isTransportClosedForTesting()
            XCTAssertEqual(cursor, 801, "\(stage) failure cannot reuse the committed MID")
            XCTAssertEqual(balance, 0, "\(stage) failure cannot refund committed credit")
            XCTAssertEqual(pending, 0)
            XCTAssertEqual(active, 0)
            XCTAssertTrue(closed)
            await session.closeTransportAndWait(cause: "post_commit_\(stage)_failure_test")
        }
    }

    func testSourceShapeSenderLoopHasNoNestedTasksOrGlobalExecutorHops() throws {
        // This remains a source-form check: Swift provides no runtime hook for arbitrary Task
        // allocations inside the sender loop. The companion event test below observes the
        // dedicated sender-loop Task count while multiple request frames are sent.
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let loopStart = try XCTUnwrap(source.range(of: "private func runSenderLoop("))
        let controlStart = try XCTUnwrap(source.range(of: "private func sendQueuedControl(", range: loopStart.upperBound..<source.endIndex))
        let senderLoopSource = source[loopStart.lowerBound..<controlStart.lowerBound]
        XCTAssertFalse(senderLoopSource.contains("Task {"))
        XCTAssertFalse(senderLoopSource.contains("Task.detached"))
        XCTAssertFalse(senderLoopSource.contains("Task<"))
        // CANCEL ownership and final-response ordering are covered by event-based tests:
        // testFinalQueuedBehindCurrentFrameDropsCancelBeforeSelection,
        // testEarlyFinalThenCancellationDoesNotQueueCancelAndSendOwnerDrains, and
        // testSelectedCancelSendOwnerKeepsDrainAliveUntilDeadlineAndJoin.
    }

    func testPostAuthSenderCommitsInFIFOAndDoesNotWaitForResponseFinal() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let first = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("first request reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        let second = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("second request remains in the sender queue") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }

        let queuedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(queuedStats.wakes, 1)
        // starts is incremented at the single sender-loop Task creation site; the queued
        // second request remains in the same loop instead of launching a per-request Task.
        XCTAssertEqual(queuedStats.starts, 1)
        XCTAssertEqual(queuedStats.frames, 0)
        XCTAssertEqual(queuedStats.queuedRequests, 1)

        transport.releaseNextSend()
        try await withHangGuard("second request starts after the first full-send") {
            try await transport.waitForSendCount(2)
        }
        let selectedHeaders = try transport.sentPackets.map(SMB2Header.decode)
        XCTAssertEqual(selectedHeaders.map(\.messageId), [100, 101])
        XCTAssertEqual(selectedHeaders.map(\.command), [SMB2Commands.echo, SMB2Commands.echo])

        transport.releaseNextSend()
        try await withHangGuard("both request frames finish") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        try await withHangGuard("sender loop reaches idle") {
            await session.waitForSenderLoopExitCountForTesting(atLeast: 1)
        }
        let drainedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(drainedStats.wakes, 1)
        XCTAssertEqual(drainedStats.starts, 1)
        XCTAssertEqual(drainedStats.exits, 1)
        XCTAssertEqual(drainedStats.frames, 2)
        XCTAssertFalse(drainedStats.isRunning)

        try transport.enqueueResponse(try echoResponse(messageId: 100, sessionId: 1, credits: 0))
        try transport.enqueueResponse(try echoResponse(messageId: 101, sessionId: 1, credits: 0))
        try await withHangGuard("first caller receives its final") { try await first.value }
        try await withHangGuard("second caller receives its final") { try await second.value }

        await session.grantCreditsForTesting(1)
        let third = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("new demand starts a replacement idle loop") { try await transport.waitForSendCount(3) }
        let thirdHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(thirdHeader.messageId, 102)
        transport.releaseNextSend()
        try await withHangGuard("replacement loop sends the third frame") {
            await session.waitForSenderFrameCountForTesting(atLeast: 3)
        }
        try await withHangGuard("replacement loop returns to idle") {
            await session.waitForSenderLoopExitCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 102, sessionId: 1, credits: 0))
        try await withHangGuard("third caller receives its final") { try await third.value }
        let restartedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(restartedStats.wakes, 2)
        XCTAssertEqual(restartedStats.starts, 2)
        XCTAssertEqual(restartedStats.exits, 2)
        XCTAssertEqual(restartedStats.frames, 3)
        XCTAssertFalse(restartedStats.isRunning)
        await session.closeTransportAndWait(cause: "sender_fifo_test")
    }

    func testCancelledCreditWaiterNeverConsumesAMessageId() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 0)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let cancelled = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("request waits before commit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        cancelled.cancel()
        do {
            try await withHangGuard("precommit cancellation returns") { try await cancelled.value }
            XCTFail("expected precommit cancellation")
        } catch is CancellationError {
        }

        let pendingWire = await session.wirePendingRecordCountForTesting()
        let activeIdentities = await session.activeRequestIdentityCountForTesting()
        let creditsAfterRetire = await session.creditBalanceForTesting()
        XCTAssertEqual(pendingWire, 0)
        XCTAssertEqual(activeIdentities, 0)
        XCTAssertEqual(creditsAfterRetire, 0)
        XCTAssertTrue(transport.sentPackets.isEmpty)
        let cursorAfterRetire = await session.nextMessageIdForTesting()
        XCTAssertEqual(cursorAfterRetire, 100)

        await session.grantCreditsForTesting(1)
        let next = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("next request is sent") { try await transport.waitForSendCount(1) }
        let sentHeader = try SMB2Header.decode(transport.sentPackets[0])
        XCTAssertEqual(sentHeader.messageId, 100)
        XCTAssertEqual(sentHeader.command, SMB2Commands.echo)
        transport.releaseNextSend()
        try await withHangGuard("next request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 100, sessionId: 1, credits: 0))
        try await withHangGuard("next request final") { try await next.value }
        let sentCommands = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        XCTAssertEqual(sentCommands, [SMB2Commands.echo])
        await session.closeTransportAndWait(cause: "precommit_retire_test")
    }

    func testEarlyFinalThenCancellationDoesNotQueueCancelAndSendOwnerDrains() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 200)

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("original request send is owned") { try await transport.waitForSendCount(1) }
        try transport.enqueueResponse(try echoResponse(messageId: 200, sessionId: 1, credits: 0))
        try await withHangGuard("early final is correlated while send is blocked") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let earlyFinalSeen = await session.pendingFinalSeenForTesting(messageId: 200)
        XCTAssertTrue(earlyFinalSeen)

        caller.cancel()
        do {
            try await withHangGuard("cancelled caller is released before send") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        let ownerSnapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: 200)
        XCTAssertEqual(ownerSnapshot?.send, .committed(messageId: 200, charge: 1))
        XCTAssertEqual(ownerSnapshot?.wire, .finalAccepted)
        try await withHangGuard("fixed drain sleeper is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        let deadlineBeforeSendCompletion = await session.wireDrainDeadlineForTesting(messageId: 200)
        XCTAssertNotNil(deadlineBeforeSendCompletion)
        XCTAssertEqual(transport.sentPackets.count, 1, "early final must suppress CANCEL demand")

        transport.releaseNextSend()
        try await withHangGuard("original owner returns and completes the drain") {
            await session.waitForSenderFrameCountForTesting(atLeast: 1)
        }
        let wireRecords = await session.wirePendingRecordCountForTesting()
        let controls = (await session.senderLoopStatisticsForTesting()).queuedControls
        XCTAssertEqual(wireRecords, 0)
        XCTAssertEqual(controls, 0)
        XCTAssertEqual(transport.sentPackets.count, 1)
        let isClosedBeforeTeardown = await session.isTransportClosedForTesting()
        XCTAssertFalse(isClosedBeforeTeardown)
        await session.closeTransportAndWait(cause: "early_final_cancel_test")
    }

    func testEarlyFinalStopsReaderBeforeNextBufferedResponseUntilSendCompletes() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        let readerExited = SMBActivationEvent()
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 300)
        await session.setReaderTaskExitHookForTesting { _ in readerExited.signal() }

        let first = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("first send is blocked after commit") {
            try await transport.waitForSendCount(1)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 300, sessionId: 1, credits: 0))
        try await withHangGuard("first early final is accepted") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }

        let secondResponse = try echoResponse(messageId: 301, sessionId: 1, credits: 0)
        let secondFrame = try DirectTCPFraming.frame(secondResponse)
        try transport.enqueueResponse(secondResponse)
        try await withHangGuard("reader stops after the early final") { await readerExited.wait() }
        XCTAssertEqual(transport.bufferedInboundByteCount, secondFrame.count)
        let dispatchCountBeforeNextCommit = await session.receivedPacketDispatchCountForTesting()
        XCTAssertEqual(dispatchCountBeforeNextCommit, 1)

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("first send owner completes") { try await first.value }
        let second = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("second send starts") { try await transport.waitForSendCount(2) }
        try await withHangGuard("second early final is accepted after its commit") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 2)
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("second send owner completes") { try await second.value }
        await session.closeTransportAndWait(cause: "early_final_reader_fence_test")
    }

    func testSelectedCancelSendOwnerKeepsDrainAliveUntilDeadlineAndJoin() async throws {
        let (weakSession, deinitEvent) = try await runSelectedCancelOwnerTerminalization()
        try await withHangGuard("CANCEL owner terminal session deinitializes") { await deinitEvent.wait() }
        XCTAssertNil(weakSession.value)
    }

    private func runSelectedCancelOwnerTerminalization() async throws -> (
        SMBActivationWeakSessionReference,
        SMBActivationEvent
    ) {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 300)
        let deinitEvent = SMBActivationEvent()
        let weakSession = SMBActivationWeakSessionReference(session)
        await session.setSessionDeinitHookForTesting { deinitEvent.signal() }
        let readerExitEntered = SMBActivationEvent()
        let releaseReaderExit = SMBActivationEvent()
        await session.setReaderTaskExitHookForTesting { _ in
            readerExitEntered.signal()
            await releaseReaderExit.wait()
        }

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("original request send starts") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend()
        try await withHangGuard("original request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        caller.cancel()
        do {
            try await withHangGuard("cancelled caller is returned once") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("selected CANCEL reaches transport") {
            try await transport.waitForSendCount(2)
        }
        let headers = try transport.sentPackets.map(SMB2Header.decode)
        XCTAssertEqual(headers.map(\.command), [SMB2Commands.echo, SMB2Commands.cancel])
        XCTAssertEqual(headers.map(\.messageId), [300, 300], "CANCEL reuses its target MID")
        let maybeIdentity = await session.requestIdentityForTesting(messageId: 300)
        let identity = try XCTUnwrap(maybeIdentity)
        let maybeDeadline = await session.wireDrainDeadlineForTesting(messageId: 300)
        let originalDeadline = try XCTUnwrap(maybeDeadline)
        let maybeTimerIdentity = await session.wireDrainTimerIdentityForTesting(messageId: 300)
        let timerIdentity = try XCTUnwrap(maybeTimerIdentity)
        try await withHangGuard("wire drain sleeper is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }

        try transport.enqueueResponse(try echoResponse(messageId: 300, sessionId: 1, credits: 0))
        try await withHangGuard("original final is accepted while CANCEL send is owned") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let pendingWhileCancelOwned = await session.wirePendingRecordCountForTesting()
        let finalSeenWhileCancelOwned = await session.pendingFinalSeenForTesting(messageId: 300)
        XCTAssertEqual(pendingWhileCancelOwned, 1)
        XCTAssertTrue(finalSeenWhileCancelOwned)
        await session.cancelPostAuthRequestForTesting(identity: identity)
        let deadlineAfterRepeatedCancel = await session.wireDrainDeadlineForTesting(messageId: 300)
        let timerIdentityAfterRepeatedCancel = await session.wireDrainTimerIdentityForTesting(messageId: 300)
        XCTAssertEqual(deadlineAfterRepeatedCancel, originalDeadline)
        XCTAssertEqual(timerIdentityAfterRepeatedCancel, timerIdentity)
        XCTAssertTrue(transport.isSendBlocked(command: SMB2Commands.cancel))

        clock.advance(by: .seconds(10), resumeDueSleeps: false)
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("deadline wins over last owner completion at D") {
            await transport.waitForCloseCount(atLeast: 1)
        }
        try await withHangGuard("reader reaches the terminalizer join gate") {
            await readerExitEntered.wait()
        }
        let fenceStillOwned = await session.terminalWireDrainTimerFenceForTesting(timerIdentity)
        XCTAssertTrue(fenceStillOwned, "deadline identity stays live until reader and sender joins finish")
        releaseReaderExit.signal()
        await session.closeTransportAndWait(cause: "selected_cancel_owner_deadline_test")
        try await withHangGuard("deadline terminalizer finishes its join") {
            await session.waitForWireDrainTerminalizationCountForTesting(atLeast: 1)
        }

        let closed = await session.isTransportClosedForTesting()
        let pending = await session.wirePendingRecordCountForTesting()
        let identities = await session.activeRequestIdentityCountForTesting()
        let readerTasks = await session.readerTaskCountForTesting()
        let senderStats = await session.senderLoopStatisticsForTesting()
        let recordsAfterJoin = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertTrue(closed)
        XCTAssertEqual(pending, 0)
        XCTAssertEqual(identities, 0)
        XCTAssertEqual(readerTasks, 0)
        XCTAssertEqual(recordsAfterJoin, 0)
        XCTAssertFalse(senderStats.isRunning)
        XCTAssertEqual(senderStats.queuedRequests, 0)
        XCTAssertEqual(senderStats.queuedControls, 0)
        return (weakSession, deinitEvent)
    }

    private func makeSession(
        transport: SMBActivationEventTransport,
        initialCredits: UInt32,
        clock: SMBActivationTestClock? = nil,
        wireDrainGrace: Duration = .seconds(10),
        signingKey: [UInt8]? = nil
    ) -> SMBSession {
        SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            signingKey: signingKey,
            initialCredits: initialCredits,
            requestTimeout: nil,
            wireDrainGrace: wireDrainGrace,
            sessionTime: clock?.source ?? .production()
        )
    }

    private func runFinalAndOwnerBoundary(
        finalAt: Duration,
        ownerAt: Duration,
        deadlineCallbackFirst: Bool = false
    ) async throws -> Bool {
        let transport = SMBActivationEventTransport(holdBlockedSendsAfterClose: true)
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 700)
        let terminalExpected = finalAt >= .zero || ownerAt >= .zero
        let readerExitEntered = SMBActivationEvent()
        let releaseReaderExit = SMBActivationEvent()
        if terminalExpected {
            await session.setReaderTaskExitHookForTesting { _ in
                readerExitEntered.signal()
                await releaseReaderExit.wait()
            }
        }

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("boundary request send starts") { try await transport.waitForSendCount(1) }
        caller.cancel()
        do {
            try await withHangGuard("boundary caller cancellation returns") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("boundary fixed deadline is registered") { await clock.waitForSleepCount(atLeast: 1) }
        let maybeTimerIdentity = await session.wireDrainTimerIdentityForTesting(messageId: 700)
        let maybeDeadline = await session.wireDrainDeadlineForTesting(messageId: 700)
        let timerIdentity = try XCTUnwrap(maybeTimerIdentity)
        let deadline = try XCTUnwrap(maybeDeadline)

        var finalAdvance = Duration.seconds(10)
        finalAdvance += finalAt
        clock.advance(by: finalAdvance, resumeDueSleeps: false)
        try transport.enqueueResponse(try echoResponse(messageId: 700, sessionId: 1, credits: 0))
        try await withHangGuard("boundary final is correlated") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let maybeFinalAcceptance = await session.lastFinalAcceptanceForTesting()
        let finalAcceptance = try XCTUnwrap(maybeFinalAcceptance)
        if finalAt < .zero {
            XCTAssertEqual(deadline.duration(to: finalAcceptance), .nanoseconds(-1))
        }

        if terminalExpected {
            let ownerDelta = ownerAt - finalAt
            if deadlineCallbackFirst, finalAt < .zero {
                clock.advance(by: .zero - finalAt, resumeDueSleeps: true)
                try await withHangGuard("deadline callback wins the actor turn") {
                    await transport.waitForCloseCount(atLeast: 1)
                }
                try await withHangGuard("deadline callback starts reader join") { await readerExitEntered.wait() }
                if ownerAt > .zero {
                    clock.advance(by: ownerAt, resumeDueSleeps: false)
                }
            } else {
                clock.advance(by: ownerDelta, resumeDueSleeps: false)
                if finalAt >= .zero {
                    try await withHangGuard("D final wins before a timer callback") {
                        await transport.waitForCloseCount(atLeast: 1)
                    }
                    try await withHangGuard("D final starts reader join") { await readerExitEntered.wait() }
                } else {
                    transport.releaseNextSend(command: SMB2Commands.echo)
                    try await withHangGuard("owner recovery at or after D terminalizes") {
                        await transport.waitForCloseCount(atLeast: 1)
                    }
                    try await withHangGuard("owner recovery starts reader join") { await readerExitEntered.wait() }
                }
            }

            let fenceWhileJoining = await session.terminalWireDrainTimerFenceForTesting(timerIdentity)
            XCTAssertTrue(fenceWhileJoining, "deadline identity stays fenced through reader and sender joins")
            let recordStillOwned = await session.activePostAuthRequestRecordCountForTesting()
            XCTAssertEqual(recordStillOwned, 1, "terminal record remains until the joined owners return")
            transport.releaseNextSend(command: SMB2Commands.echo)
            releaseReaderExit.signal()
            await session.closeTransportAndWait(cause: "wire_drain_boundary_test")
            try await withHangGuard("boundary terminalizer completes") {
                await session.waitForWireDrainTerminalizationCountForTesting(atLeast: 1)
            }
            let closed = await session.isTransportClosedForTesting()
            let pending = await session.wirePendingRecordCountForTesting()
            let timerFence = await session.terminalWireDrainTimerFenceForTesting(timerIdentity)
            XCTAssertTrue(closed)
            XCTAssertEqual(pending, 0)
            XCTAssertFalse(timerFence)
            return true
        }

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("pre-deadline owner returns and drains") {
            await session.waitForSenderFrameCountForTesting(atLeast: 1)
        }
        let pending = await session.wirePendingRecordCountForTesting()
        let closed = await session.isTransportClosedForTesting()
        let deadlineCleared = await session.wireDrainDeadlineForTesting(messageId: 700)
        XCTAssertEqual(pending, 0)
        XCTAssertFalse(closed)
        XCTAssertNil(deadlineCleared)
        await session.closeTransportAndWait(cause: "wire_drain_before_deadline_test")
        return false
    }

    private func echoResponse(messageId: UInt64, sessionId: UInt64, credits: UInt16) throws -> [UInt8] {
        var packet = try SMB2Header(
            command: SMB2Commands.echo,
            credits: credits,
            flags: 0x0000_0001,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [4, 0, 0, 0])
        return packet
    }

    private func statusResponse(
        command: UInt16,
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        credits: UInt16
    ) throws -> [UInt8] {
        var packet = try SMB2Header(
            status: SMB2Status.success,
            command: command,
            credits: credits,
            flags: 0x0000_0001,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [4, 0, 0, 0])
        return packet
    }

    private func asyncPendingResponse(
        command: UInt16,
        messageId: UInt64,
        asyncId: UInt64,
        sessionId: UInt64
    ) throws -> [UInt8] {
        var packet = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: command,
            credits: 0,
            flags: 0x0000_0001,
            messageId: messageId,
            asyncId: asyncId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [9, 0, 0, 0, 0, 0, 0, 0])
        return packet
    }

    private func withHangGuard<T: Sendable>(
        _ label: String,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: .seconds(3))
                throw SMBActivationTimeout(label: label)
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw SMBActivationTimeout(label: label) }
            return result
        }
    }
}

private struct SMBActivationTimeout: Error {
    let label: String
}

private final class SMBActivationWeakSessionReference: @unchecked Sendable {
    weak var value: SMBSession?

    init(_ value: SMBSession) {
        self.value = value
    }
}

private final class SMBActivationRace: @unchecked Sendable {
    private let lock = NSLock()
    private var winner: Bool?
    private var waiter: (UUID, CheckedContinuation<Bool, Never>)?

    func finish(_ result: Bool) {
        let continuation = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            guard winner == nil else { return nil }
            winner = result
            defer { waiter = nil }
            return waiter?.1
        }
        continuation?.resume(returning: result)
    }

    func wait() async -> Bool {
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let result = lock.withLock { () -> Bool? in
                    if let winner { return winner }
                    waiter = (id, continuation)
                    return nil
                }
                if let result { continuation.resume(returning: result) }
            }
        } onCancel: {
            self.cancelWaiter(id)
        }
    }

    private func cancelWaiter(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            guard waiter?.0 == id else { return nil }
            defer { waiter = nil }
            return waiter?.1
        }
        continuation?.resume(returning: false)
    }
}

private final class SMBActivationEvent: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Never>
    }

    private let lock = NSLock()
    private var signaled = false
    private var waiters: [Waiter] = []

    func signal() {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            signaled = true
            defer { waiters.removeAll() }
            return waiters.map(\.continuation)
        }
        ready.forEach { $0.resume() }
    }

    func wait() async {
        let id = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let resumeNow = lock.withLock { () -> Bool in
                    guard !signaled else { return true }
                    waiters.append(Waiter(id: id, continuation: continuation))
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            self.cancelWaiter(id)
        }
    }

    private func cancelWaiter(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume()
    }
}

final class SMBActivationTestClock: @unchecked Sendable {
    private struct Sleeper {
        let id: UUID
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, Error>
    }

    private struct CountWaiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private let lock = NSLock()
    private var instant = ContinuousClock().now
    private var sleepers: [Sleeper] = []
    private var sleepCount = 0
    private var countWaiters: [CountWaiter] = []

    var source: SMBSessionMonotonicTime {
        SMBSessionMonotonicTime(
            now: { self.lock.withLock { self.instant } },
            sleep: { duration in try await self.sleep(for: duration) }
        )
    }

    func waitForSleepCount(atLeast target: Int) async {
        let id = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let resumeNow = lock.withLock { () -> Bool in
                    guard sleepCount < target else { return true }
                    countWaiters.append(CountWaiter(id: id, target: target, continuation: continuation))
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            self.cancelCountWaiter(id)
        }
    }

    private func cancelCountWaiter(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            guard let index = countWaiters.firstIndex(where: { $0.id == id }) else { return nil }
            return countWaiters.remove(at: index).continuation
        }
        continuation?.resume()
    }

    func advance(by duration: Duration, resumeDueSleeps: Bool) {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            instant += duration
            guard resumeDueSleeps else { return [] }
            let ready = sleepers.filter { $0.deadline <= instant }.map(\.continuation)
            sleepers.removeAll { $0.deadline <= instant }
            return ready
        }
        ready.forEach { $0.resume() }
    }

    private func sleep(for duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let result = lock.withLock { () -> (Bool, [CheckedContinuation<Void, Never>]) in
                    sleepCount += 1
                    let readyCounts = countWaiters.filter { sleepCount >= $0.target }.map(\.continuation)
                    countWaiters.removeAll { sleepCount >= $0.target }
                    if instant >= instant.advanced(by: duration) {
                        return (true, readyCounts)
                    }
                    sleepers.append(Sleeper(id: id, deadline: instant.advanced(by: duration), continuation: continuation))
                    return (false, readyCounts)
                }
                result.1.forEach { $0.resume() }
                if result.0 { continuation.resume() }
            }
        } onCancel: {
            self.cancelSleeper(id)
        }
    }

    private func cancelSleeper(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = sleepers.firstIndex(where: { $0.id == id }) else { return nil }
            return sleepers.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class SMBActivationEventTransport: SMBTransport, @unchecked Sendable {
    private struct PendingSend {
        let id: UUID
        let command: UInt16
        let bytes: [UInt8]
        let continuation: CheckedContinuation<Void, Error>
    }

    private struct PendingReceive {
        let id: UUID
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private struct SendCountWaiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private struct CloseCountWaiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private let lock = NSLock()
    private let holdBlockedSendsAfterClose: Bool
    private var packetStorage: [[UInt8]] = []
    private var partialSendPacketsStorage: [[UInt8]] = []
    private var blockedSends: [PendingSend] = []
    private var sendCountWaiters: [SendCountWaiter] = []
    private var inbound: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var closeCountStorage = 0
    private var closed = false
    private var nextSendError: Error?
    private var closeCountWaiters: [CloseCountWaiter] = []

    init(holdBlockedSendsAfterClose: Bool = false) {
        self.holdBlockedSendsAfterClose = holdBlockedSendsAfterClose
    }

    var sentPackets: [[UInt8]] {
        lock.withLock { packetStorage }
    }

    var partialSendPackets: [[UInt8]] {
        lock.withLock { partialSendPacketsStorage }
    }

    var bufferedInboundByteCount: Int {
        lock.withLock { inbound.count }
    }

    func isSendBlocked(command: UInt16) -> Bool {
        lock.withLock { blockedSends.contains { $0.command == command } }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        let packet = try Self.unframe(bytes)
        let header = try SMB2Header.decode(packet)
        let injectedError = lock.withLock { () -> Error? in
            defer { nextSendError = nil }
            return nextSendError
        }
        if let injectedError { throw injectedError }
        let sendID = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let result = lock.withLock { () -> (Error?, [CheckedContinuation<Void, Error>]) in
                    guard !closed else { return (SMBTransportError.connectionClosed, []) }
                    packetStorage.append(packet)
                    blockedSends.append(PendingSend(
                        id: sendID,
                        command: header.command,
                        bytes: bytes,
                        continuation: continuation
                    ))
                    let ready = sendCountWaiters.filter { packetStorage.count >= $0.target }.map(\.continuation)
                    sendCountWaiters.removeAll { packetStorage.count >= $0.target }
                    return (nil, ready)
                }
                result.1.forEach { $0.resume() }
                if let error = result.0 { continuation.resume(throwing: error) }
            }
        } onCancel: {
            self.cancelSend(sendID)
        }
    }

    func waitForSendCount(_ target: Int) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let immediate = lock.withLock { () -> Result<Void, Error>? in
                    if packetStorage.count >= target { return .success(()) }
                    if closed { return .failure(SMBTransportError.connectionClosed) }
                    sendCountWaiters.append(SendCountWaiter(id: id, target: target, continuation: continuation))
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            self.cancelSendCountWaiter(id)
        }
    }

    func releaseNextSend(command: UInt16? = nil) {
        let pending = lock.withLock { () -> PendingSend? in
            guard let index = blockedSends.firstIndex(where: { command == nil || $0.command == command }) else {
                return nil
            }
            return blockedSends.remove(at: index)
        }
        pending?.continuation.resume()
    }

    func failBlockedSendAfterWritingPrefix(
        command: UInt16,
        prefixLength: Int,
        error: Error
    ) throws {
        guard let pending = lock.withLock({ () -> PendingSend? in
            guard let index = blockedSends.firstIndex(where: { $0.command == command }) else { return nil }
            return blockedSends.remove(at: index)
        }) else {
            throw SMBCodecError.invalidValue("no blocked send for command \(command)")
        }
        let packet = try Self.unframe(pending.bytes)
        guard prefixLength > 0, prefixLength < packet.count else {
            pending.continuation.resume(throwing: SMBCodecError.invalidValue("partial prefix must be shorter than the frame"))
            throw SMBCodecError.invalidValue("partial prefix must be shorter than the frame")
        }
        lock.withLock { partialSendPacketsStorage.append(Array(packet.prefix(prefixLength))) }
        pending.continuation.resume(throwing: error)
    }

    func failNextSend(_ error: Error) {
        lock.withLock { nextSendError = error }
    }

    func enqueueResponse(_ packet: [UInt8]) throws {
        let framed = try DirectTCPFraming.frame(packet)
        let delivery = lock.withLock { () -> (PendingReceive, [UInt8])? in
            inbound.append(contentsOf: framed)
            guard let pendingReceive, !inbound.isEmpty else { return nil }
            self.pendingReceive = nil
            let count = min(pendingReceive.maxLength, inbound.count)
            let bytes = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            return (pendingReceive, bytes)
        }
        if let (pending, bytes) = delivery { pending.continuation.resume(returning: bytes) }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
                let immediate: Result<[UInt8], Error>? = lock.withLock {
                    if closed { return .failure(SMBTransportError.connectionClosed) }
                    if !inbound.isEmpty {
                        let count = min(maxLength, inbound.count)
                        let bytes = Array(inbound.prefix(count))
                        inbound.removeFirst(count)
                        return .success(bytes)
                    }
                    pendingReceive = PendingReceive(id: id, maxLength: maxLength, continuation: continuation)
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            self.cancelReceive(id)
        }
    }

    func waitForCloseCount(atLeast target: Int) async {
        let id = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let resumeNow = lock.withLock { () -> Bool in
                    guard closeCountStorage < target else { return true }
                    closeCountWaiters.append(CloseCountWaiter(
                        id: id,
                        target: target,
                        continuation: continuation
                    ))
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            self.cancelCloseCountWaiter(id)
        }
    }

    func close() {
        let result = lock.withLock {
            () -> ([PendingSend], PendingReceive?, [CheckedContinuation<Void, Error>], [CheckedContinuation<Void, Never>]) in
            closed = true
            closeCountStorage += 1
            let sends: [PendingSend]
            if holdBlockedSendsAfterClose {
                sends = []
            } else {
                sends = blockedSends
                blockedSends.removeAll()
            }
            let receive = pendingReceive
            pendingReceive = nil
            let sendWaiters = sendCountWaiters.map(\.continuation)
            sendCountWaiters.removeAll()
            let closeWaiters = closeCountWaiters.filter { closeCountStorage >= $0.target }.map(\.continuation)
            closeCountWaiters.removeAll { closeCountStorage >= $0.target }
            return (sends, receive, sendWaiters, closeWaiters)
        }
        result.0.forEach { $0.continuation.resume(throwing: SMBTransportError.connectionClosed) }
        result.1?.continuation.resume(throwing: SMBTransportError.connectionClosed)
        result.2.forEach { $0.resume() }
        result.3.forEach { $0.resume() }
    }

    private func cancelSend(_ id: UUID) {
        let pending = lock.withLock { () -> PendingSend? in
            guard let index = blockedSends.firstIndex(where: { $0.id == id }) else { return nil }
            if closed && holdBlockedSendsAfterClose { return nil }
            return blockedSends.remove(at: index)
        }
        pending?.continuation.resume(throwing: CancellationError())
    }

    private func cancelReceive(_ id: UUID) {
        let pending = lock.withLock { () -> PendingReceive? in
            guard pendingReceive?.id == id else { return nil }
            defer { pendingReceive = nil }
            return pendingReceive
        }
        pending?.continuation.resume(throwing: CancellationError())
    }

    private func cancelSendCountWaiter(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = sendCountWaiters.firstIndex(where: { $0.id == id }) else { return nil }
            return sendCountWaiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private func cancelCloseCountWaiter(_ id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            guard let index = closeCountWaiters.firstIndex(where: { $0.id == id }) else { return nil }
            return closeCountWaiters.remove(at: index).continuation
        }
        continuation?.resume()
    }

    private static func unframe(_ bytes: [UInt8]) throws -> [UInt8] {
        guard bytes.count >= 4,
              bytes[0] == 0,
              try DirectTCPFraming.length(from: Array(bytes.prefix(4))) == bytes.count - 4 else {
            throw SMBCodecError.truncated
        }
        return Array(bytes.dropFirst(4))
    }
}
