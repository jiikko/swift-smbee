import Foundation
import XCTest
@testable import SMBee

final class SMBUnsentRequestActivationTests: XCTestCase {
    func testM3AdmissionScopeMatchesTreeIncarnationAndFullFileKeyOnly() {
        let sessionInstance = UUID()
        let treeA = SMBTreeIdentity(
            sessionInstance: sessionInstance,
            generation: 3,
            treeId: 0xA,
            incarnationSequence: 7
        )
        let recycledTreeA = SMBTreeIdentity(
            sessionInstance: sessionInstance,
            generation: 3,
            treeId: 0xA,
            incarnationSequence: 8
        )
        let treeB = SMBTreeIdentity(
            sessionInstance: sessionInstance,
            generation: 3,
            treeId: 0xB,
            incarnationSequence: 9
        )
        let bytesA = [UInt8](repeating: 0xA1, count: 16)
        let bytesB = [UInt8](repeating: 0xB2, count: 16)
        let fileA = SMBFileIdLedgerKey(bytes: bytesA, treeIdentity: treeA)
        let sameBytesInRecycledTree = SMBFileIdLedgerKey(bytes: bytesA, treeIdentity: recycledTreeA)
        let sameBytesInOtherTree = SMBFileIdLedgerKey(bytes: bytesA, treeIdentity: treeB)
        let otherFileInTreeA = SMBFileIdLedgerKey(bytes: bytesB, treeIdentity: treeA)

        let fileScope = SMBTransferAdmissionScope.file(fileA)
        XCTAssertTrue(fileScope.matches(treeIdentity: treeA, fileId: fileA))
        XCTAssertFalse(fileScope.matches(treeIdentity: recycledTreeA, fileId: sameBytesInRecycledTree))
        XCTAssertFalse(fileScope.matches(treeIdentity: treeB, fileId: sameBytesInOtherTree))
        XCTAssertFalse(fileScope.matches(treeIdentity: treeA, fileId: otherFileInTreeA))

        let treeScope = SMBTransferAdmissionScope.tree(treeA)
        XCTAssertTrue(treeScope.matches(treeIdentity: treeA, fileId: fileA))
        XCTAssertFalse(treeScope.matches(treeIdentity: recycledTreeA, fileId: sameBytesInRecycledTree))
        XCTAssertFalse(treeScope.matches(treeIdentity: treeB, fileId: sameBytesInOtherTree))
    }

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
        await session.retireFileIdForTesting(fileId, treeId: 0xA)
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

#if DEBUG
    func testM3FileIdRefusalRetiresReadTransferLocally() async throws {
        try await assertM3FileIdTransferRefusal(operation: .read)
    }

    func testM3FileIdRefusalRetiresWriteTransferLocally() async throws {
        try await assertM3FileIdTransferRefusal(operation: .write)
    }

    func testM3FileRefusalSelectsOnlyTheFullTreeAndFileIdKey() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 4)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_500)
        let fileA = [UInt8](repeating: 0xA1, count: 16)
        let fileB = [UInt8](repeating: 0xB2, count: 16)

        let blocker = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("scope blocker holds the sender") {
            try await transport.waitForSendCount(1)
        }
        // A: the refused key. B: same Tree, other FileId. C: same FileId bytes, other Tree.
        let readA = Task {
            try await session.readTransferThroughPipelineForTesting(treeId: 0xA, fileId: fileA, length: 1)
        }
        try await withHangGuard("File A READ queues") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        let readB = Task {
            try await session.readTransferThroughPipelineForTesting(treeId: 0xA, fileId: fileB, length: 1)
        }
        try await withHangGuard("same-Tree File B READ queues") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 2)
        }
        let readC = Task {
            try await session.readTransferThroughPipelineForTesting(treeId: 0xB, fileId: fileA, length: 1)
        }
        try await withHangGuard("other-Tree same-bytes READ queues") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 3)
        }

        let close = Task { await session.bestEffortClose(treeId: 0xA, fileId: fileA) }
        do {
            _ = try await withHangGuard("only File A receives the local refusal") { try await readA.value }
            XCTFail("File A READ unexpectedly passed its CLOSE intent")
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("SMB FileId is unresolved after CLOSE"))
        }

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("scope blocker full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let blockerHeader = try SMB2Header.decode(transport.sentPackets[0])
        try transport.enqueueResponse(try echoResponse(
            messageId: blockerHeader.messageId,
            sessionId: 1,
            credits: 1,
            treeId: 0xA
        ))
        try await withHangGuard("scope blocker final") { try await blocker.value }

        var payloadByTree: [UInt32: UInt8] = [0xA: 0x42, 0xB: 0x43]
        for sendIndex in 1...3 {
            try await withHangGuard("scope request \(sendIndex) reaches the transport") {
                try await transport.waitForSendCount(sendIndex + 1)
            }
            let header = try SMB2Header.decode(transport.sentPackets[sendIndex])
            transport.releaseNextSend(command: header.command)
            try await withHangGuard("scope request \(sendIndex) full-send") {
                await session.waitForRequestSentCountForTesting(atLeast: sendIndex + 1)
            }
            if header.command == SMB2Commands.read {
                let payload = try XCTUnwrap(payloadByTree.removeValue(forKey: header.treeId))
                try transport.enqueueResponse(try readResponse(
                    payload: [payload],
                    messageId: header.messageId,
                    sessionId: 1,
                    treeId: header.treeId,
                    credits: 1
                ))
            } else {
                XCTAssertEqual(header.command, SMB2Commands.close)
                XCTAssertEqual(header.treeId, 0xA)
                try transport.enqueueResponse(try statusResponse(
                    command: SMB2Commands.close,
                    messageId: header.messageId,
                    sessionId: 1,
                    treeId: 0xA,
                    credits: 1
                ))
            }
        }
        let bytesB = try await withHangGuard("same-Tree File B READ completes") { try await readB.value }
        let bytesC = try await withHangGuard("other-Tree same-bytes READ completes") { try await readC.value }
        try await withHangGuard("File A CLOSE final") { await close.value }
        XCTAssertEqual(bytesB, [0x42])
        XCTAssertEqual(bytesC, [0x43])
        XCTAssertTrue(payloadByTree.isEmpty, "both unrefused READs reached the wire")

        let sessionClosed = await session.isTransportClosedForTesting()
        let records = await session.activePostAuthRequestRecordCountForTesting()
        let transfers = await session.transferLifecycleCountsForTesting()
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(records, 0)
        XCTAssertEqual(transfers.readTransfers, 0)
        await session.closeTransportAndWait(cause: "m3_file_refusal_scope_test")
    }

    func testM3TreeRefusalClosesOnlyTreeAReceiptAfterItsRefundAck() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 3)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_600)
        let ownership = SMBM3OwnershipLog()
        await session.setTransferRequestOwnershipHookForTesting { ownership.append($0) }
        let refundReached = SMBActivationEvent()
        let releaseRefund = SMBActivationUncancelledGate()
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            guard case .refundPending = point else { return }
            refundReached.signal()
            await releaseRefund.wait()
        }

        let blocker = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xC) }
        try await withHangGuard("Tree isolation blocker holds the sender") {
            try await transport.waitForSendCount(1)
        }
        let readA = Task {
            try await session.readTransferThroughPipelineForTesting(
                treeId: 0xA,
                fileId: [UInt8](repeating: 0xA1, count: 16),
                length: 1
            )
        }
        try await withHangGuard("Tree A READ queues") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        let readB = Task {
            try await session.readTransferThroughPipelineForTesting(
                treeId: 0xB,
                fileId: [UInt8](repeating: 0xB2, count: 16),
                length: 1
            )
        }
        try await withHangGuard("Tree B READ queues") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 2)
        }
        let optionalTreeAIdentity = await session.ensureTreeIdentity(treeId: 0xA)
        let treeAIdentity = try XCTUnwrap(optionalTreeAIdentity)
        let intent = Task {
            await session.prepareTreeCleanupIntent(treeAIdentity, facadeOwner: SMBFacadeOwnerAllocator.make())
        }
        try await withHangGuard("Tree A retirement reaches its gated refund") { await refundReached.wait() }
        let receiptsWhileGated = ownership.receipts
        let receiptTransfers = Set(receiptsWhileGated.map(\.transferIdentifier))
        XCTAssertEqual(receiptTransfers.count, 1, "exactly one queued ticket (Tree A's) enters a retirement receipt")
        let transferA = try XCTUnwrap(receiptTransfers.first)
        XCTAssertFalse(receiptsWhileGated.contains { $0.complete }, "the receipt stays open until the refund ack")

        await releaseRefund.signal()
        do {
            _ = try await withHangGuard("Tree A READ returns its local refusal") { try await readA.value }
            XCTFail("Tree A READ unexpectedly passed its quarantine")
        } catch let error as SMBError {
            guard case .treeUnavailable(treeId: 0xA, operation: _) = error else {
                XCTFail("Tree A READ returned an unexpected SMBError: \(error)")
                throw error
            }
        }
        let preparedIntent = await intent.value
        XCTAssertNotNil(preparedIntent)
        let receiptsAfterAck = ownership.receipts
        XCTAssertEqual(Set(receiptsAfterAck.map(\.transferIdentifier)), [transferA])
        XCTAssertTrue(receiptsAfterAck.contains { $0.complete }, "Tree A's receipt closes after its refund ack")

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("Tree isolation blocker full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let blockerHeader = try SMB2Header.decode(transport.sentPackets[0])
        try transport.enqueueResponse(try echoResponse(
            messageId: blockerHeader.messageId,
            sessionId: 1,
            credits: 1,
            treeId: 0xC
        ))
        try await withHangGuard("Tree isolation blocker final") { try await blocker.value }
        try await withHangGuard("Tree B READ reaches the transport") {
            try await transport.waitForSendCount(2)
        }
        let readBHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(readBHeader.command, SMB2Commands.read)
        XCTAssertEqual(readBHeader.treeId, 0xB)
        XCTAssertEqual(readBHeader.messageId, blockerHeader.messageId + 1, "the retired Tree A ticket used no MessageId")
        transport.releaseNextSend(command: SMB2Commands.read)
        try await withHangGuard("Tree B READ full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try readResponse(
            payload: [0x42],
            messageId: readBHeader.messageId,
            sessionId: 1,
            treeId: 0xB,
            credits: 1
        ))
        let bytesB = try await withHangGuard("Tree B READ completes") { try await readB.value }
        XCTAssertEqual(bytesB, [0x42])
        XCTAssertFalse(
            ownership.receipts.contains { $0.transferIdentifier != transferA },
            "Tree B never receives a retirement receipt"
        )

        let sessionClosed = await session.isTransportClosedForTesting()
        let records = await session.activePostAuthRequestRecordCountForTesting()
        let transfers = await session.transferLifecycleCountsForTesting()
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(records, 0)
        XCTAssertEqual(transfers.readTransfers, 0)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
        await session.setTransferRequestOwnershipHookForTesting(nil)
        await session.closeTransportAndWait(cause: "m3_tree_receipt_isolation_test")
    }

    func testM3CommitBeforeFileCleanupIntentKeepsCommittedReadWireOwner() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2, wireDrainGrace: .seconds(10))
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_100)
        let fileId = [UInt8](repeating: 0xA1, count: 16)

        let read = Task {
            try await session.readTransferThroughPipelineForTesting(
                treeId: 0xA,
                fileId: fileId,
                length: 1
            )
        }
        try await withHangGuard("committed File A READ reaches transport") {
            try await transport.waitForSendCount(1)
        }
        let readHeader = try SMB2Header.decode(transport.sentPackets[0])
        XCTAssertEqual(readHeader.command, SMB2Commands.read)
        transport.releaseNextSend(command: SMB2Commands.read)
        try await withHangGuard("File A READ full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let creditBalanceBeforeClose = await session.creditBalanceForTesting()

        // commit -> quarantine: the READ won the wire commit before the CLOSE intent, so the
        // File refusal must keep its committed wire and credit owners on the existing drain.
        let close = Task { await session.bestEffortClose(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("CLOSE reaches transport while the committed READ is on the wire") {
            try await transport.waitForSendCount(2)
        }
        let closeHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(closeHeader.command, SMB2Commands.close)
        XCTAssertEqual(closeHeader.messageId, readHeader.messageId + 1, "no MessageId hole between READ and CLOSE")
        let committedSnapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: readHeader.messageId)
        let creditBalanceAfterClose = await session.creditBalanceForTesting()
        XCTAssertEqual(committedSnapshot?.credit, .committed(actualCharge: 1))
        XCTAssertEqual(
            creditBalanceAfterClose,
            creditBalanceBeforeClose - 1,
            "only CLOSE is charged; the committed READ is not locally refunded"
        )

        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("File A CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try readResponse(
            payload: [0x41],
            messageId: readHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        let bytes = try await withHangGuard("committed File A READ completes on its own final") {
            try await read.value
        }
        XCTAssertEqual(bytes, [0x41], "the File refusal must not stop a committed READ's transfer")
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: closeHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("File A CLOSE final") { await close.value }

        let sessionClosed = await session.isTransportClosedForTesting()
        let activeRecords = await session.activePostAuthRequestRecordCountForTesting()
        let transferCounts = await session.transferLifecycleCountsForTesting()
        let cleanupLedgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(activeRecords, 0)
        XCTAssertEqual(transferCounts.readTransfers, 0)
        XCTAssertEqual(cleanupLedgerCount, 0)
        await session.closeTransportAndWait(cause: "m3_committed_file_use_close_test")
    }

    func testM3WatchCancellationWaitsForChangeNotifyWireBeforeClose() async throws {
        let harness = try await startM3CancelledWatch(firstMessageId: 1_200)
        let transport = harness.transport
        let session = harness.session
        let registeredWaiters = await session.requestReclaimWaiterCountForTesting()
        XCTAssertEqual(registeredWaiters, 1, "the cancelled CHANGE_NOTIFY caller registered its owner wait")
        let notifyHeader = harness.notifyHeader

        let originalDeadline = await session.wireDrainDeadlineForTesting(messageId: notifyHeader.messageId)
        XCTAssertNotNil(originalDeadline)
        let commandsBeforeNotifyFinal = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        XCTAssertEqual(commandsBeforeNotifyFinal, [
            SMB2Commands.changeNotify,
            SMB2Commands.cancel
        ])

        try transport.enqueueResponse(try changeNotifyResponse(
            messageId: notifyHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("watch CLOSE starts after CHANGE_NOTIFY final") {
            try await transport.waitForSendCount(3)
        }
        let closeHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(closeHeader.command, SMB2Commands.close)
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("watch CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: closeHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("cancelled watch and cleanup CLOSE finish") { await harness.watch.value }
        let cancellationWasObserved = try await withHangGuard("watch cancellation catch is observed") {
            await harness.caughtCancellation.wait()
        }
        let finalDeadline = await session.wireDrainDeadlineForTesting(messageId: notifyHeader.messageId)
        let sessionClosed = await session.isTransportClosedForTesting()
        let reclaimWaiters = await session.requestReclaimWaiterCountForTesting()
        let activeRecords = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertTrue(cancellationWasObserved)
        XCTAssertNil(finalDeadline)
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(reclaimWaiters, 0)
        XCTAssertEqual(activeRecords, 0)
        XCTAssertEqual(try transport.sentPackets.map { try SMB2Header.decode($0).command }, [
            SMB2Commands.changeNotify,
            SMB2Commands.cancel,
            SMB2Commands.close
        ])
        await session.closeTransportAndWait(cause: "m3_watch_cancel_file_close_barrier_test")
    }

    func testM3CancelledOrdinaryFileIdRequestWaitsForItsWireBeforeClose() async throws {
        // FLUSH goes through `signedWireTransaction`, not the long-poll path the watch uses.
        let harness = try await startM3CancelledWatch(
            firstMessageId: 1_800,
            command: SMB2Commands.flush
        ) { session, fileId in
            try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId)
        }
        let transport = harness.transport
        let session = harness.session
        let flushHeader = harness.notifyHeader
        let registeredWaiters = await session.requestReclaimWaiterCountForTesting()
        XCTAssertEqual(registeredWaiters, 1, "the cancelled FLUSH caller registered its owner wait")
        XCTAssertEqual(try transport.sentPackets.map { try SMB2Header.decode($0).command }, [
            SMB2Commands.flush,
            SMB2Commands.cancel
        ])

        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.flush,
            messageId: flushHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("cleanup CLOSE starts after the cancelled FLUSH final") {
            try await transport.waitForSendCount(3)
        }
        let closeHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(closeHeader.command, SMB2Commands.close)
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("cleanup CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: closeHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("cancelled FLUSH and cleanup CLOSE finish") { await harness.watch.value }
        let cancellationWasObserved = try await withHangGuard("FLUSH cancellation catch is observed") {
            await harness.caughtCancellation.wait()
        }
        let sessionClosed = await session.isTransportClosedForTesting()
        let reclaimWaiters = await session.requestReclaimWaiterCountForTesting()
        let activeRecords = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertTrue(cancellationWasObserved)
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(reclaimWaiters, 0, "the registered owner wait was released by the FLUSH record reclaim")
        XCTAssertEqual(activeRecords, 0)
        await session.closeTransportAndWait(cause: "m3_cancelled_flush_close_barrier_test")
    }

    func testM3LedgerLimitTerminationReleasesCancelledFileIdUseWaiter() async throws {
        let harness = try await startM3CancelledWatch(
            firstMessageId: 1_900,
            command: SMB2Commands.flush
        ) { session, fileId in
            try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId)
        }
        let session = harness.session
        for index in 0..<64 {
            var retired = [UInt8](repeating: 0xE0, count: 16)
            retired[15] = UInt8(index)
            await session.retireFileIdForTesting(retired, treeId: 0xA)
        }
        // A new CLOSE now trips the cleanup ledger limit, which ends the session with the
        // synchronous closeTransport path while the cancelled FLUSH caller waits for its owner.
        let limitClose = Task { await session.bestEffortClose(treeId: 0xA, fileId: [UInt8](repeating: 0xF1, count: 16)) }
        try await withHangGuard("ledger-limit CLOSE returns") { await limitClose.value }
        let sessionClosed = await session.isTransportClosedForTesting()
        XCTAssertTrue(sessionClosed, "the ledger limit terminalizes the session")

        // The regression (no terminal join) is the absence of any event, so only a bounded wait
        // can show it; after the terminal close the count waiters return early on `wireFailure`.
        // Margin: the whole test passes in at most 3 ms (20 macOS runs, 2026-10-15) against the
        // 3 s hang guard, about three orders of magnitude.
        let returned = SMBActivationRace()
        let returnObserver = Task {
            await harness.watch.value
            returned.finish(true)
        }
        let watchReturned = try await withHangGuard("cancelled FLUSH caller returns after the ledger-limit terminal") {
            await returned.wait()
        }
        XCTAssertTrue(watchReturned)
        if watchReturned {
            await returnObserver.value
            let reclaimWaiters = await session.requestReclaimWaiterCountForTesting()
            XCTAssertEqual(reclaimWaiters, 0)
        }
        await session.closeTransportAndWait(cause: "m3_ledger_limit_terminal_test")
    }

    func testM3AbandonedCloseIntentDoesNotRewriteLaterCommittedRequestError() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 2, clock: clock, wireDrainGrace: .seconds(10))
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 2_000)
        let fileId = [UInt8](repeating: 0xC7, count: 16)

        let blocker = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xC) }
        try await withHangGuard("abandoned-CLOSE blocker holds the sender") { try await transport.waitForSendCount(1) }
        let flush = Task { () -> Error? in
            do {
                try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId)
                return nil
            } catch {
                return error
            }
        }
        try await withHangGuard("FLUSH queues behind the blocker") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        // The CLOSE intent marks the queued FLUSH, then the CLOSE is abandoned before commit.
        let close = Task { try await session.close(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("CLOSE waits for credit after its intent") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        let refusedOrdinaryRecords = await session.admissionRefusedOrdinaryRecordCountForTesting()
        XCTAssertEqual(refusedOrdinaryRecords, 1, "the CLOSE intent marks the queued FLUSH on the same FileId")
        close.cancel()
        _ = try await withHangGuard("abandoned CLOSE returns") { await close.result }
        let ledgerAfterAbandon = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(ledgerAfterAbandon, 0, "the abandoned CLOSE released its FileId attempt")

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("abandoned-CLOSE blocker full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let blockerHeader = try SMB2Header.decode(transport.sentPackets[0])
        try transport.enqueueResponse(try echoResponse(messageId: blockerHeader.messageId, sessionId: 1, credits: 1, treeId: 0xC))
        try await withHangGuard("abandoned-CLOSE blocker final") { try await blocker.value }
        try await withHangGuard("FLUSH commits after the CLOSE was abandoned") { try await transport.waitForSendCount(2) }
        let flushHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(flushHeader.command, SMB2Commands.flush)
        transport.releaseNextSend(command: SMB2Commands.flush)
        try await withHangGuard("FLUSH full-send") { await session.waitForRequestSentCountForTesting(atLeast: 2) }

        flush.cancel()
        try await withHangGuard("FLUSH cancellation sends CANCEL") { try await transport.waitForSendCount(3) }
        transport.releaseNextSend(command: SMB2Commands.cancel)
        let waitOrReturn = SMBActivationRace()
        let waitObserver = Task {
            await session.waitForRequestReclaimWaiterCountForTesting(atLeast: 1)
            waitOrReturn.finish(true)
        }
        let returnObserver = Task {
            _ = await flush.value
            waitOrReturn.finish(false)
        }
        let waited = try await withHangGuard("cancelled FLUSH waits for its owner or returns") { await waitOrReturn.wait() }
        waitObserver.cancel()
        try await withHangGuard("owner-wait observer exits") { await waitObserver.value }
        XCTAssertTrue(waited, "the cancelled FLUSH keeps its CancellationError and waits for its wire owner")

        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.flush,
            messageId: flushHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        let flushError = try await withHangGuard("cancelled FLUSH returns") { await flush.value }
        try await withHangGuard("FLUSH return observer exits") { await returnObserver.value }
        XCTAssertTrue(flushError is CancellationError, "unexpected FLUSH error: \(String(describing: flushError))")
        await session.closeTransportAndWait(cause: "m3_abandoned_close_intent_test")
    }

    func testM3CancelledFileIdUseWaitsForFinalCreditGrantAckBeforeClose() async throws {
        let harness = try await startM3CancelledWatch(
            firstMessageId: 2_100,
            command: SMB2Commands.flush
        ) { session, fileId in
            try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId)
        }
        let transport = harness.transport
        let session = harness.session
        let grantReached = SMBActivationEvent()
        let releaseGrant = SMBActivationUncancelledGate()
        await session.setCreditGrantAfterAwaitHookForTesting {
            grantReached.signal()
            await releaseGrant.wait()
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.flush,
            messageId: harness.notifyHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        // The final is accepted but its credit grant has not been acknowledged yet: the FLUSH's
        // credit owner is still alive, so the FileId use is not complete.
        try await withHangGuard("cancelled FLUSH final reaches its credit grant") { await grantReached.wait() }
        let waitersDuringGrant = await session.requestReclaimWaiterCountForTesting()
        let commandsDuringGrant = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        XCTAssertEqual(waitersDuringGrant, 1, "the FLUSH caller still waits while its credit grant is unacknowledged")
        XCTAssertEqual(commandsDuringGrant, [SMB2Commands.flush, SMB2Commands.cancel], "no CLOSE before the credit owner completes")

        await releaseGrant.signal()
        try await withHangGuard("cleanup CLOSE starts after the credit grant ack") {
            try await transport.waitForSendCount(3)
        }
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        let closeHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(closeHeader.command, SMB2Commands.close)
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("cleanup CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: closeHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("cancelled FLUSH and cleanup CLOSE finish") { await harness.watch.value }
        let reclaimWaiters = await session.requestReclaimWaiterCountForTesting()
        XCTAssertEqual(reclaimWaiters, 0)
        await session.closeTransportAndWait(cause: "m3_credit_grant_ack_close_barrier_test")
    }

    func testM3WatchCancellationCloseWaitEndsAtExistingDrainDeadline() async throws {
        let harness = try await startM3CancelledWatch(firstMessageId: 1_250)
        let transport = harness.transport
        let session = harness.session
        let registeredWaiters = await session.requestReclaimWaiterCountForTesting()
        XCTAssertEqual(registeredWaiters, 1, "the cancelled CHANGE_NOTIFY caller registered its owner wait")
        let originalDeadline = await session.wireDrainDeadlineForTesting(messageId: harness.notifyHeader.messageId)
        XCTAssertNotNil(originalDeadline)

        // The server never answers the cancelled CHANGE_NOTIFY. The wait for its wire owner
        // must not add a grace of its own: the request's existing fixed drain deadline ends it.
        harness.clock.advance(by: .seconds(11), resumeDueSleeps: true)
        try await withHangGuard("cancelled CHANGE_NOTIFY reaches its existing drain deadline") {
            await session.waitForWireDrainTerminalizationCountForTesting(atLeast: 1)
        }
        try await withHangGuard("watch returns after the drain deadline") { await harness.watch.value }
        let cancellationWasObserved = try await withHangGuard("watch cancellation catch is observed") {
            await harness.caughtCancellation.wait()
        }
        let reclaimWaiters = await session.requestReclaimWaiterCountForTesting()
        XCTAssertTrue(cancellationWasObserved)
        XCTAssertEqual(reclaimWaiters, 0)
        XCTAssertEqual(
            try transport.sentPackets.map { try SMB2Header.decode($0).command },
            [SMB2Commands.changeNotify, SMB2Commands.cancel],
            "CLOSE must not reuse the FileId while the cancelled CHANGE_NOTIFY still owns the wire"
        )
        await session.closeTransportAndWait(cause: "m3_watch_cancel_drain_deadline_test")
    }

    func testM3TimedOutFileIdUseNeverLetsItsCleanupCloseReachTheWire() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            requestTimeout: .seconds(5)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_700)
        let fileId = [UInt8](repeating: 0xD4, count: 16)
        // Mirrors the public `do { op } catch { bestEffortClose }` shape.
        let caller = Task { () -> Bool in
            do {
                try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileId)
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
                return false
            } catch SMBTransportError.timedOut {
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
                return true
            } catch {
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
                return false
            }
        }
        try await withHangGuard("FileId FLUSH reaches transport") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend(command: SMB2Commands.flush)
        try await withHangGuard("FileId FLUSH full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("FileId FLUSH arms its request timeout") { await clock.waitForSleepCount(atLeast: 1) }

        // A request timeout terminalizes the session before the caller resumes, so the
        // FLUSH's wire owner can never be followed by a CLOSE for the same FileId on this wire.
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        let closeBoundaryRace = SMBActivationRace()
        let closeObserver = Task {
            do {
                // Closing the transport also wakes this waiter, so only a real second send counts.
                try await transport.waitForSendCount(2)
                if transport.sentPackets.count >= 2 { closeBoundaryRace.finish(false) }
            } catch {
            }
        }
        let returnObserver = Task { () -> Bool in
            let timedOut = await caller.value
            closeBoundaryRace.finish(true)
            return timedOut
        }
        let returnedWithoutClose = try await withHangGuard("timed-out FileId use returns or its CLOSE is sent") {
            await closeBoundaryRace.wait()
        }
        closeObserver.cancel()
        try await withHangGuard("timed-out CLOSE observer exits") { await closeObserver.value }
        XCTAssertTrue(returnedWithoutClose, "the cleanup CLOSE must not reuse the FileId on the timed-out wire")
        if !returnedWithoutClose {
            await session.closeTransportAndWait(cause: "m3_timed_out_file_use_close_reached_wire")
        }
        let timedOut = try await withHangGuard("timed-out FileId use and its cleanup return") {
            await returnObserver.value
        }
        let commands = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        let sessionClosed = await session.isTransportClosedForTesting()
        XCTAssertTrue(timedOut)
        XCTAssertTrue(sessionClosed)
        XCTAssertEqual(commands, [SMB2Commands.flush], "the cleanup CLOSE must not reuse the FileId on the timed-out wire")
        await session.closeTransportAndWait(cause: "m3_timed_out_file_use_test")
    }

    func testM3FileIdDescriptorMutationIsASeparateCodecFault() async throws {
        try await assertM3FileIdDescriptorCodecFault(truncatePacket: false)
    }

    func testM3MalformedFileIdDescriptorIsASeparateCodecFault() async throws {
        try await assertM3FileIdDescriptorCodecFault(truncatePacket: true)
    }
#endif

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

    func testPostAuthRequestTimeoutStartsIndependentTerminalizerJoin() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            requestTimeout: .seconds(5)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 450)
        let terminalizerStarted = SMBActivationEvent()
        let joinStarted = SMBActivationEvent()
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            if observation.point == .terminalizerTask { terminalizerStarted.signal() }
            if observation.point == .closeJoin { joinStarted.signal() }
        }
        defer {
            session.sessionExecutor.setExecutionObserverForTesting(nil)
            Task { await session.closeTransportAndWait(cause: "request_timeout_terminalizer_test_cleanup") }
        }

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("timeout request reaches transport") { try await transport.waitForSendCount(1) }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("timeout request is fully sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await clock.waitForSleepCount(atLeast: 1)

        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        await transport.waitForCloseCount(atLeast: 1)
        do {
            try await withHangGuard("timed out caller receives its result") { try await caller.value }
            XCTFail("request unexpectedly succeeded without a response")
        } catch SMBTransportError.timedOut {
        }
        try await withHangGuard("request timeout starts its independent terminalizer") {
            await terminalizerStarted.wait()
        }
        try await withHangGuard("request timeout terminalizer begins the join") {
            await joinStarted.wait()
        }
        try await withHangGuard("request timeout terminalizer reclaims active records") {
            while await session.activePostAuthRequestRecordCountForTesting() != 0 {
                await Task.yield()
            }
        }
        let recordsAfterTerminalJoin = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsAfterTerminalJoin, 0)
    }

    func testPostAuthSendFailureStartsIndependentTerminalizerJoin() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 1)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 470)
        await session.failNextPostAuthFrameBuildForTesting()
        let terminalizerStarted = SMBActivationEvent()
        let joinStarted = SMBActivationEvent()
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            if observation.point == .terminalizerTask { terminalizerStarted.signal() }
            if observation.point == .closeJoin { joinStarted.signal() }
        }
        defer {
            session.sessionExecutor.setExecutionObserverForTesting(nil)
            Task { await session.closeTransportAndWait(cause: "send_failure_terminalizer_test_cleanup") }
        }

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        await transport.waitForCloseCount(atLeast: 1)
        do {
            try await withHangGuard("post-auth frame build failure reaches caller") { try await caller.value }
            XCTFail("post-auth frame build failure unexpectedly succeeded")
        } catch SMBCodecError.invalidValue("injected post-auth frame build failure") {
        } catch {
            XCTFail("unexpected post-auth send error: \(error)")
        }
        let cursorAfterFailedCommit = await session.nextMessageIdForTesting()
        XCTAssertEqual(cursorAfterFailedCommit, 471)
        XCTAssertTrue(transport.sentPackets.isEmpty)
        try await withHangGuard("post-auth send fault starts its independent terminalizer") {
            await terminalizerStarted.wait()
        }
        try await withHangGuard("post-auth send fault begins the join") {
            await joinStarted.wait()
        }
        try await withHangGuard("post-auth send fault reclaims active records") {
            while await session.activePostAuthRequestRecordCountForTesting() != 0 {
                await Task.yield()
            }
        }
        let recordsAfterTerminalJoin = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsAfterTerminalJoin, 0)
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

    func testPostAuthCancellationEnforcesTombstoneLimit() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 65,
            clock: clock,
            wireDrainGrace: .seconds(60)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 600)
        defer { Task { await session.closeTransportAndWait(cause: "cancellation_tombstone_limit_test_cleanup") } }

        for index in 0..<65 {
            let caller = Task { try await session.echoThroughSenderLoopForTesting() }
            let echoSendCount = index * 2 + 1
            try await withHangGuard("post-auth ECHO \(index + 1) reaches transport") {
                try await transport.waitForSendCount(echoSendCount)
            }
            let request = try SMB2Header.decode(transport.sentPackets[echoSendCount - 1])
            XCTAssertEqual(request.command, SMB2Commands.echo)
            transport.releaseNextSend(command: SMB2Commands.echo)
            try await withHangGuard("post-auth ECHO \(index + 1) full-send") {
                await session.waitForRequestSentCountForTesting(atLeast: index + 1)
            }

            caller.cancel()
            do {
                try await withHangGuard("post-auth ECHO \(index + 1) cancellation returns") {
                    try await caller.value
                }
                XCTFail("cancelled ECHO unexpectedly succeeded")
            } catch is CancellationError {
            }

            if index < 64 {
                let cancelSendCount = echoSendCount + 1
                try await withHangGuard("CANCEL \(index + 1) reaches transport") {
                    try await transport.waitForSendCount(cancelSendCount)
                }
                transport.releaseNextSend(command: SMB2Commands.cancel)
                try await withHangGuard("CANCEL \(index + 1) full-send") {
                    await session.waitForSenderFrameCountForTesting(atLeast: (index + 1) * 2)
                }
                let tombstoneCount = await session.ordinaryCancellationTombstoneCountForTesting()
                XCTAssertEqual(tombstoneCount, index + 1)
                let transportClosed = await session.isTransportClosedForTesting()
                XCTAssertFalse(transportClosed, "the 64-entry bound permits the first 64 tombstones")
            } else {
                try await withHangGuard("65th post-auth cancellation closes at the tombstone bound") {
                    await transport.waitForCloseCount(atLeast: 1)
                }
            }
        }

        let sentPacketCount = transport.sentPackets.count
        XCTAssertEqual(sentPacketCount, 129, "the 65th cancellation closes before sending another CANCEL")
        try await withHangGuard("cancellation tombstone terminalizer reclaims post-auth records") {
            while await session.activePostAuthRequestRecordCountForTesting() != 0 {
                await Task.yield()
            }
        }
        let recordsAfterClose = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsAfterClose, 0)
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
        let (grantAcknowledgements, grantAcknowledgementContinuation) = AsyncStream.makeStream(
            of: SMBSessionExecutorObservation.self
        )
        let (reapedRecords, reapedRecordContinuation) = AsyncStream.makeStream(of: UInt64.self)
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            if observation.point == .creditGrantAcknowledgement {
                grantAcknowledgementContinuation.yield(observation)
            }
        }
        await session.setActivePostAuthRequestRecordReapedHookForTesting {
            reapedRecordContinuation.yield($0)
        }
        await session.setCreditGrantActorHookForTesting {
            grantEntered.signal()
            await releaseGrant.wait()
        }
        defer {
            grantAcknowledgementContinuation.finish()
            reapedRecordContinuation.finish()
            session.sessionExecutor.setExecutionObserverForTesting(nil)
            releaseGrant.signal()
            Task {
                await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
                await session.closeTransportAndWait(cause: "credit_grant_ack_test_cleanup")
            }
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
        let acknowledgedGrant = try await withHangGuard("final credit grant acknowledgement completes") {
            var iterator = grantAcknowledgements.makeAsyncIterator()
            return await iterator.next()
        }
        let acknowledgement = try XCTUnwrap(acknowledgedGrant)
        XCTAssertTrue(acknowledgement.isOnExecutorQueue)
        let reapedMessageId = try await withHangGuard("final grant acknowledgement reaps the original record") {
            var iterator = reapedRecords.makeAsyncIterator()
            return await iterator.next()
        }
        XCTAssertEqual(reapedMessageId, original.messageId)
        let originalRecordAfterAck = await session.postAuthRequestRecordSnapshotForTesting(messageId: original.messageId)
        XCTAssertNil(originalRecordAfterAck, "the final identity record is reaped after its grant acknowledgement")
        try transport.enqueueResponse(try echoResponse(messageId: followingHeader.messageId, sessionId: 1, credits: 0))
        try await withHangGuard("following request completes after grant acknowledgement") { try await following.value }

        try await withHangGuard("sender task releases the following request record") {
            await session.waitForActiveSendTasksForTesting()
        }
        let recordCountAfterAck = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordCountAfterAck, 0, "the following request record is reaped after its final response")
        await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
        await session.setCreditGrantActorHookForTesting(nil)
        await session.closeTransportAndWait(cause: "credit_grant_ack_test_complete")
    }

    func testCompoundFinalCreditGrantAcknowledgementsReapPostAuthRecords() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 520)

        let grantEntered = SMBActivationEvent()
        let releaseGrant = SMBActivationEvent()
        let (reapedRecords, reapedRecordContinuation) = AsyncStream.makeStream(of: UInt64.self)
        await session.setActivePostAuthRequestRecordReapedHookForTesting {
            reapedRecordContinuation.yield($0)
        }
        await session.setCreditGrantActorHookForTesting {
            grantEntered.signal()
            await releaseGrant.wait()
        }
        defer {
            reapedRecordContinuation.finish()
            releaseGrant.signal()
            Task {
                await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
                await session.setCreditGrantActorHookForTesting(nil)
                await session.closeTransportAndWait(cause: "compound_credit_ack_test_cleanup")
            }
        }

        let first = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("first compound response request sends") { try await transport.waitForSendCount(1) }
        let firstRequest = try SMB2Header.decode(transport.sentPackets[0])
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("first compound response request is fully sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }

        let second = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xB) }
        try await withHangGuard("second compound response request sends") { try await transport.waitForSendCount(2) }
        let secondRequest = try SMB2Header.decode(transport.sentPackets[1])
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("second compound response request is fully sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }

        var firstFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 1,
            flags: 0x0000_0001,
            nextCommand: 72,
            messageId: firstRequest.messageId,
            sessionId: 1
        ).encode()
        firstFinal.append(contentsOf: [4, 0, 0, 0])
        firstFinal.append(contentsOf: [UInt8](repeating: 0, count: 4))
        var secondFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 1,
            flags: 0x0000_0001,
            messageId: secondRequest.messageId,
            sessionId: 1
        ).encode()
        secondFinal.append(contentsOf: [4, 0, 0, 0])
        try transport.enqueueResponse(firstFinal + secondFinal)

        try await withHangGuard("compound credit grant acknowledgement is held") { await grantEntered.wait() }
        try await withHangGuard("both compound final slices are dispatched") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 2)
        }
        let firstRecordBeforeAck = await session.postAuthRequestRecordSnapshotForTesting(messageId: firstRequest.messageId)
        let secondRecordBeforeAck = await session.postAuthRequestRecordSnapshotForTesting(messageId: secondRequest.messageId)
        let recordsBeforeAck = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(firstRecordBeforeAck?.outstandingAcknowledgements, 1)
        XCTAssertEqual(secondRecordBeforeAck?.outstandingAcknowledgements, 1)
        XCTAssertEqual(recordsBeforeAck, 2)

        releaseGrant.signal()
        let reapedMessageIds = try await withHangGuard("both compound final grants reap their records") {
            var iterator = reapedRecords.makeAsyncIterator()
            var messageIds: [UInt64] = []
            while messageIds.count < 2, let messageId = await iterator.next() {
                messageIds.append(messageId)
            }
            return messageIds
        }
        XCTAssertEqual(Set(reapedMessageIds), Set([firstRequest.messageId, secondRequest.messageId]))
        let recordsAfterAck = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsAfterAck, 0)
        try await withHangGuard("first compound caller completes") { try await first.value }
        try await withHangGuard("second compound caller completes") { try await second.value }
        await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
        await session.setCreditGrantActorHookForTesting(nil)
        await session.closeTransportAndWait(cause: "compound_credit_ack_test_complete")
    }

    func testFinalAfterAbsoluteResponseDeadlineTimesOutBeforeTimerJobRuns() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let timeoutSleeper = SMBKeyedManualSleeper()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            requestTimeout: .seconds(41),
            sessionTime: clock.source,
            requestTimeoutSleeper: { try await timeoutSleeper.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 550)

        let request = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("timeout-race ECHO sends") {
            try await transport.waitForSendCount(1)
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("timeout-race ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("absolute response timeout sleeper is installed") {
            await timeoutSleeper.waitUntilSleeping(for: .seconds(41))
        }

        clock.advance(by: .seconds(41) + .nanoseconds(1), resumeDueSleeps: false)
        try transport.enqueueResponse(try echoResponse(messageId: 550, sessionId: 1, credits: 0))
        try await withHangGuard("late final is dispatched before the timeout sleeper is released") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }

        do {
            try await withHangGuard("late final loses to the absolute request deadline") {
                _ = try await request.value
            }
            XCTFail("final response after the absolute deadline unexpectedly succeeded")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("absolute request deadline returned unexpected error: \(error)")
        }
        let timeoutCompletions = await session.requestTimeoutCompletionCountForTesting()
        let pendingAfterTimeout = await session.wirePendingRecordCountForTesting()
        let transportClosed = await session.isTransportClosedForTesting()
        XCTAssertEqual(timeoutCompletions, 1)
        XCTAssertEqual(pendingAfterTimeout, 0)
        XCTAssertTrue(transportClosed)
        await session.closeTransportAndWait(cause: "absolute_request_timeout_test_complete")
        timeoutSleeper.fire(for: .seconds(41))
    }

    func testOperationDeadlineShortensOrdinaryCancelledRequestDrain() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let drainSleeper = SMBKeyedManualSleeper()
        let operationSleeper = SMBKeyedManualSleeper()
        let sessionTime = SMBSessionMonotonicTime(
            now: { clock.source.now() },
            sleep: { try await drainSleeper.sleep(for: $0) }
        )
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            requestTimeout: nil,
            wireDrainGrace: .seconds(30),
            sessionTime: sessionTime
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 600)
        let readerJoinStarted = SMBContinuationCountBarrier()
        await session.setReaderTaskJoinSnapshotHookForTesting { _ in
            readerJoinStarted.signal()
        }
        let outerDeadline = clock.source.now().advanced(by: .seconds(5))

        let operation = Task {
            try await SMBOperationDeadline.run(
                timeout: .seconds(5),
                time: sessionTime,
                sleeper: { try await operationSleeper.sleep(for: $0) },
                operation: {
                    try await session.echoThroughSenderLoopForTesting()
                }
            )
        }
        try await withHangGuard("deadline-wrapped ordinary ECHO sends") {
            try await transport.waitForSendCount(1)
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("deadline-wrapped ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("outer operation deadline sleeper is installed") {
            await operationSleeper.waitUntilSleeping(for: .seconds(5))
        }

        clock.advance(by: .seconds(5), resumeDueSleeps: false)
        operationSleeper.fire(for: .seconds(5))
        try await withHangGuard("outer timeout cancellation fixes the ordinary drain deadline") {
            while await session.wireDrainDeadlineForTesting(messageId: 600) == nil {
                await Task.yield()
            }
        }
        let drainDeadline = await session.wireDrainDeadlineForTesting(messageId: 600)
        XCTAssertEqual(drainDeadline, outerDeadline)
        guard drainDeadline == outerDeadline else {
            await session.closeTransportAndWait(cause: "operation_deadline_drain_regression_cleanup")
            _ = try? await operation.value
            return
        }
        try await withHangGuard("outer deadline drain timer is armed at zero remaining time") {
            await drainSleeper.waitUntilSleeping(for: .zero)
        }
        drainSleeper.fire(for: .zero)
        try await withHangGuard("ordinary request closes at the enclosing operation deadline") {
            await transport.waitForCloseCount(atLeast: 1)
        }
        try await withHangGuard("ordinary request deadline joins its reader") {
            try await readerJoinStarted.waitForCount(1)
        }
        try await withHangGuard("ordinary request deadline reclaims active records") {
            while await session.activePostAuthRequestRecordCountForTesting() != 0 {
                await Task.yield()
            }
        }
        do {
            try await withHangGuard("outer operation reports its deadline") {
                _ = try await operation.value
            }
            XCTFail("operation with an unanswered request unexpectedly succeeded")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("outer operation returned unexpected error: \(error)")
        }
        await session.closeTransportAndWait(cause: "operation_deadline_drain_test_complete")
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

    func testSourceShapeCleanupLedgerIsMutatedOnlyThroughTransitionFunction() throws {
        // The cleanup FileId ledger was broken twice by writes outside one state machine (a
        // retirement record dropped, then a sent `.draining` overwritten). All writes go through
        // transitionCleanupLedger, whose transition table is the single owner of the states.
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let nsSource = source as NSString

        let functionStart = nsSource.range(of: "private func transitionCleanupLedger(")
        XCTAssertNotEqual(functionStart.location, NSNotFound, "transition function not found")
        let afterStart = NSRange(
            location: functionStart.location + functionStart.length,
            length: nsSource.length - functionStart.location - functionStart.length
        )
        let nextMember = try NSRegularExpression(pattern: "\\n    (private |fileprivate |nonisolated )*(func|var|let) ")
            .firstMatch(in: source, range: afterStart)
        let functionEnd = nextMember?.range.location ?? nsSource.length
        let body = NSRange(location: functionStart.location, length: functionEnd - functionStart.location)

        let mutation = try NSRegularExpression(
            pattern: "cleanupLedger\\s*\\[[^\\]]*\\]\\s*=(?!=)"
                + "|cleanupLedger\\.(removeValue|removeAll|updateValue|merge|remove|reserveCapacity)\\b"
                + "|(?<!var )cleanupLedger\\s*=(?!=)"
        )
        let matches = mutation.matches(in: source, range: NSRange(location: 0, length: nsSource.length))
        XCTAssertFalse(matches.isEmpty, "the scan must see the writes inside the transition function")
        let outside = matches.filter { !NSLocationInRange($0.range.location, body) }
        let outsideLines = outside.map { match in
            source.prefix(match.range.location).filter { $0 == "\n" }.count + 1
        }
        XCTAssertEqual(outsideLines, [], "cleanupLedger written outside transitionCleanupLedger at lines \(outsideLines)")
    }

    func testSourceShapeTreeCleanupStatesStayInsideOwnerTransitions() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let nsSource = source as NSString
        let mutation = try NSRegularExpression(
            pattern: "treeLifecycle\\s*\\[[^\\]]*\\]\\s*=(?!=)"
                + "|treeLifecycle\\.(removeValue|removeAll|updateValue|merge|remove)\\b"
                + "|treeCleanupLedger\\s*\\[[^\\]]*\\]\\s*=(?!=)"
                + "|treeCleanupLedger\\.(removeValue|removeAll|updateValue|merge|remove)\\b"
        )
        let matches = mutation.matches(in: source, range: NSRange(location: 0, length: nsSource.length))
        XCTAssertFalse(matches.isEmpty, "the scan must observe Tree state writes")

        var transitionRanges: [NSRange] = []
        for signature in ["private func transitionTreeLifecycle(", "private func transitionTreeCleanupLedger("] {
            let start = nsSource.range(of: signature)
            XCTAssertNotEqual(start.location, NSNotFound, "missing Tree transition: \(signature)")
            let afterStart = NSRange(
                location: start.location + start.length,
                length: nsSource.length - start.location - start.length
            )
            let nextMember = try NSRegularExpression(pattern: "\\n    (private |fileprivate |nonisolated )*(func|var|let) ")
                .firstMatch(in: source, range: afterStart)
            let end = nextMember?.range.location ?? nsSource.length
            transitionRanges.append(NSRange(location: start.location, length: end - start.location))
        }

        let outside = matches.filter { match in
            !transitionRanges.contains { NSLocationInRange(match.range.location, $0) }
        }
        let lines = outside.map { match in
            nsSource.substring(to: match.range.location).filter { $0 == "\n" }.count + 1
        }
        XCTAssertEqual(lines, [], "Tree cleanup state writes escaped owner transitions at lines \(lines)")
    }

    func testSourceShapeTransferNoTicketCloseUsesCanonicalSynchronousTransition() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let normalized = Self.normalizedSource(source)
        let transitionStart = try XCTUnwrap(normalized.range(of: "privatefunctransitionTransferRequest("))
        let sourceEOFStart = try XCTUnwrap(normalized.range(of: "case.sourceEOF(", range: transitionStart.lowerBound..<normalized.endIndex))
        let sourceEOFEnd = try XCTUnwrap(normalized.range(of: "case.revokePreparing(", range: sourceEOFStart.upperBound..<normalized.endIndex))
        let sourceEOF = normalized[sourceEOFStart.lowerBound..<sourceEOFEnd.lowerBound]

        XCTAssertTrue(sourceEOF.contains("closeNoTicketTransferRequest(record,refunded:false)"))
        XCTAssertTrue(sourceEOF.contains("reclaimActivePostAuthRequestRecordIfEligible(key.requestIdentity)"))
        XCTAssertFalse(sourceEOF.contains("SMBRetirementReceipt("), "effect-free EOF must not allocate a receipt")
        XCTAssertFalse(sourceEOF.contains("SMBRetirementReceiptCompletion("))
        XCTAssertFalse(sourceEOF.contains("NSLock("))
        XCTAssertFalse(sourceEOF.contains("Task("), "effect-free EOF must not create a Task")

        let updateHelper = try XCTUnwrap(normalized.range(of: "privatefuncupdateActivePostAuthRecord("))
        let updateHelperEnd = try XCTUnwrap(normalized.range(of: "privatefuncmessageId(for", range: updateHelper.upperBound..<normalized.endIndex))
        let updateBody = normalized[updateHelper.lowerBound..<updateHelperEnd.lowerBound]
        XCTAssertTrue(updateBody.contains("record.transferOwner==nil"), "generic record writes must leave transfer ownership to the transition")

        let noTicketHelper = try XCTUnwrap(normalized.range(of: "privatefunccloseNoTicketTransferRequest("))
        let noTicketHelperEnd = try XCTUnwrap(normalized.range(of: "privatefunccloseTransferRetirementReceiptIfReady(", range: noTicketHelper.upperBound..<normalized.endIndex))
        let noTicketBody = normalized[noTicketHelper.lowerBound..<noTicketHelperEnd.lowerBound]
        XCTAssertTrue(noTicketBody.contains("record.caller=.noWireWork"))
        XCTAssertTrue(noTicketBody.contains("record.send=.neverSubmitted"))
        XCTAssertTrue(noTicketBody.contains("record.wire=.notApplicable"))
        XCTAssertTrue(noTicketBody.contains("record.credit=.notApplicable"))
        XCTAssertTrue(noTicketBody.contains("owner.slotReleased=true"))
        XCTAssertFalse(noTicketBody.contains("SMBRetirementReceipt("), "no-ticket close has no external effect to acknowledge")
        XCTAssertFalse(noTicketBody.contains("SMBRetirementReceiptCompletion("))
        XCTAssertFalse(noTicketBody.contains("NSLock("))
        XCTAssertFalse(noTicketBody.contains("Task("))
    }

    /// Every terminal transition must reach the terminal join: a session ended without it kept
    /// records whose wire-drain timers were cancelled but never normalized (a reclaim waiter
    /// never resumed). Only these functions may end the session without scheduling the join
    /// themselves, because each of them joins or schedules the join right after.
    func testSourceShapeOnlyJoiningTerminalizersEndTheSessionWithoutJoin() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let lines = try String(contentsOf: sourceURL, encoding: .utf8).components(separatedBy: "\n")
        let allowed: Set<String> = [
            "closeTransport",
            "closeTransportAndWait",
            "beginSessionFaultTerminalization",
            "beginWireDrainTerminalization",
            "beginTransferDrainTerminalization"
        ]
        var enclosingFunction: String?
        var callers: [String] = []
        var bodies: [String: String] = [:]
        for line in lines {
            if let range = line.range(of: "func "),
               let open = line[range.upperBound...].firstIndex(where: { $0 == "(" || $0 == "<" }) {
                enclosingFunction = String(line[range.upperBound..<open])
            }
            if let name = enclosingFunction {
                bodies[name, default: ""] += line.filter { !$0.isWhitespace }
            }
            guard line.contains("terminateTransportWithoutJoin("), !line.contains("func ") else { continue }
            callers.append(enclosingFunction ?? "<top level>")
        }
        XCTAssertFalse(callers.isEmpty, "the scan must find the terminal entry's callers")
        XCTAssertEqual(
            Set(callers).subtracting(allowed),
            [],
            "only joining terminalizers may call terminateTransportWithoutJoin; use closeTransport elsewhere"
        )
        for name in ["closeTransport", "beginSessionFaultTerminalization", "beginWireDrainTerminalization",
                     "beginTransferDrainTerminalization"] {
            let body = try XCTUnwrap(bodies[name], "\(name) must exist")
            XCTAssertTrue(body.contains("scheduleTerminalJoin("), "\(name) must schedule the terminal join")
        }
        let closeAndWait = try XCTUnwrap(bodies["closeTransportAndWait"])
        XCTAssertTrue(closeAndWait.contains("normalizeActiveRequestRecordAtTerminalJoin("), "closeTransportAndWait is the join")
    }

    func testSourceShapeTreeAdapterAndUnsentReceiptShareTheCanonicalTransition() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let normalized = Self.normalizedSource(source)
        let transitionStart = try XCTUnwrap(normalized.range(of: "privatefunctransitionTransferRequest("))

        let treeAdapterStart = try XCTUnwrap(normalized.range(of: "privatefuncrefuseTransferRequestForTree("))
        let treeAdapterEnd = try XCTUnwrap(normalized.range(
            of: "privatefuncterminateTransferAdmissionFailure(",
            range: treeAdapterStart.upperBound..<normalized.endIndex
        ))
        let treeAdapter = normalized[treeAdapterStart.lowerBound..<treeAdapterEnd.lowerBound]
        XCTAssertTrue(
            treeAdapter.contains("refuseTransferRequestForAdmission(ticket,refusal:refusal)"),
            "Tree adapter must send its exact Tree scope through the common admission transition"
        )
        XCTAssertFalse(treeAdapter.contains("window.retireUnsent("))
        XCTAssertFalse(treeAdapter.contains("window.releaseRetiredSlot("))

        let admissionRefusalStart = try XCTUnwrap(normalized.range(
            of: "case.admissionRefusal(letticket,letrefusal,lettime):",
            range: transitionStart.lowerBound..<normalized.endIndex
        ))
        let admissionRefusalEnd = try XCTUnwrap(normalized.range(
            of: "case.admissionRefusalPreparation(",
            range: admissionRefusalStart.upperBound..<normalized.endIndex
        ))
        let admissionRefusal = normalized[admissionRefusalStart.lowerBound..<admissionRefusalEnd.lowerBound]
        XCTAssertTrue(admissionRefusal.contains("refusal.scope.matches(treeIdentity:record.treeIdentity,fileId:record.fileId)"))
        XCTAssertTrue(admissionRefusal.contains("guardrecord.messageId==nilelse"))
        XCTAssertTrue(admissionRefusal.contains("retireUnsentTransferRequestInTransition(ticket,window:window,at:time)"))

        let retirementStart = try XCTUnwrap(normalized.range(of: "privatefuncretireUnsentTransferRequestInTransition("))
        let retirementEnd = try XCTUnwrap(normalized.range(
            of: "privatefuncreportTransferRequestOwnershipForTesting(",
            range: retirementStart.upperBound..<normalized.endIndex
        ))
        let retirement = normalized[retirementStart.lowerBound..<retirementEnd.lowerBound]
        let existingReceipt = try XCTUnwrap(retirement.range(of: "ifletreceipt=record.transferOwner?.retirementReceipt"))
        let receiptCreation = try XCTUnwrap(retirement.range(of: "SMBRetirementReceipt("))
        XCTAssertLessThan(existingReceipt.lowerBound, receiptCreation.lowerBound, "duplicate retirement must return the record's receipt")
        XCTAssertTrue(retirement.contains("queuedPostAuthRequests.remove(at:queuedIndex)"), "retirement removes a queued item before the sender can select it")
        XCTAssertTrue(retirement.contains("record.send=.neverSubmitted"))
        XCTAssertTrue(retirement.contains("record.wire=.notApplicable"))

        let precommitStart = try XCTUnwrap(normalized.range(of: "case.selectedPrecommit(letticket):", range: transitionStart.lowerBound..<normalized.endIndex))
        let precommitEnd = try XCTUnwrap(normalized.range(of: "case.precommitRejected(", range: precommitStart.upperBound..<normalized.endIndex))
        let precommit = normalized[precommitStart.lowerBound..<precommitEnd.lowerBound]
        XCTAssertTrue(precommit.contains("record.transferOwner?.packetOwned=true"))

        let selectedReturnStart = try XCTUnwrap(normalized.range(of: "case.selectedPrecommitReturned(letticket,", range: transitionStart.lowerBound..<normalized.endIndex))
        let selectedReturnEnd = try XCTUnwrap(normalized.range(of: "case.wireCommitted(", range: selectedReturnStart.upperBound..<normalized.endIndex))
        let selectedReturn = normalized[selectedReturnStart.lowerBound..<selectedReturnEnd.lowerBound]
        XCTAssertTrue(selectedReturn.contains("record.transferOwner?.packetOwned=false"))
        XCTAssertTrue(selectedReturn.contains("reportTransferRequestOwnershipForTesting(record)"))

        let receiptCloseStart = try XCTUnwrap(normalized.range(of: "varcanCloseRetirementReceipt:Bool{"))
        let receiptCloseEnd = try XCTUnwrap(normalized.range(of: "varcanReleaseRetiringSlot:Bool{", range: receiptCloseStart.upperBound..<normalized.endIndex))
        let receiptClose = normalized[receiptCloseStart.lowerBound..<receiptCloseEnd.lowerBound]
        XCTAssertTrue(receiptClose.contains("SMBTransferRetirementReceiptReadiness.isReady("))
        let receiptReadinessStart = try XCTUnwrap(normalized.range(of: "enumSMBTransferRetirementReceiptReadiness{"))
        let receiptReadinessEnd = try XCTUnwrap(
            normalized.range(of: "structSMBTransferRequestOwnershipSnapshot:", range: receiptReadinessStart.upperBound..<normalized.endIndex)
        )
        let receiptReadiness = normalized[receiptReadinessStart.lowerBound..<receiptReadinessEnd.lowerBound]
        XCTAssertTrue(receiptReadiness.contains("!supplierOwned"))
        XCTAssertTrue(receiptReadiness.contains("!decodeOwned"))
        XCTAssertTrue(receiptReadiness.contains("!deliveryOwned"))
        XCTAssertTrue(receiptReadiness.contains("!selectedPrecommitOwned"))
        XCTAssertTrue(receiptReadiness.contains("!packetOwned"))
        XCTAssertTrue(receiptReadiness.contains("slotReleased"))

        XCTAssertEqual(
            normalized.components(separatedBy: "window.reclaimEpochOwner()").count - 1,
            1,
            "an owner acknowledgement can decrement the epoch count only through the common reclaimer"
        )
        let receiptArchivePattern = try NSRegularExpression(
            pattern: #"[A-Za-z_][A-Za-z0-9_]*:\[SMBRequestIdentity:SMBRetirementReceipt\]"#
        )
        XCTAssertEqual(
            receiptArchivePattern.numberOfMatches(
                in: normalized,
                range: NSRange(location: 0, length: (normalized as NSString).length)
            ),
            0,
            "receipt values stay on request handles instead of a session identity archive"
        )

        let preparationAckStart = try XCTUnwrap(normalized.range(of: "case.preparationRetirementAcknowledged("))
        let preparationAckEnd = try XCTUnwrap(
            normalized.range(of: "case.sendStarted(", range: preparationAckStart.upperBound..<normalized.endIndex)
        )
        let preparationAck = normalized[preparationAckStart.lowerBound..<preparationAckEnd.lowerBound]
        XCTAssertTrue(preparationAck.contains("pendingRefunds>0"), "duplicate preparation ack is an idempotent no-op")

        let finalGrantAckStart = try XCTUnwrap(normalized.range(of: "case.finalCreditGrantAcknowledged("))
        let finalGrantAckEnd = try XCTUnwrap(
            normalized.range(of: "case.callerTerminal(", range: finalGrantAckStart.upperBound..<normalized.endIndex)
        )
        let finalGrantAck = normalized[finalGrantAckStart.lowerBound..<finalGrantAckEnd.lowerBound]
        XCTAssertTrue(
            finalGrantAck.contains("record.outstandingCreditGrantAcknowledgements>0"),
            "duplicate final grant ack cannot decrement the record more than once"
        )
    }

    func testSourceShapeTransferOwnershipWritesStayInsideCanonicalTransition() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let memberEndSignatures = [
            ("private func transitionTransferRequest(", "private func transferRecord(for ticket:"),
            ("private func closeNoTicketTransferRequest(", "private func closeTransferRetirementReceiptIfReady("),
            ("private func finishUnsentRetirementSlotIfReady(", "private func retireUnsentTransferRequestInTransition("),
            ("private func retireUnsentTransferRequestInTransition(", "private func reportTransferRequestOwnershipForTesting(")
        ]
        var ownerWriteRanges: [Range<String.Index>] = []
        for (startSignature, endSignature) in memberEndSignatures {
            let start = try XCTUnwrap(source.range(of: startSignature), "missing state owner: \(startSignature)")
            let end = try XCTUnwrap(source.range(of: endSignature, range: start.upperBound..<source.endIndex))
            ownerWriteRanges.append(start.lowerBound..<end.lowerBound)
        }
        let nsSource = source as NSString
        let assignmentPattern = try NSRegularExpression(
            pattern: #"record\.transferOwner(?:[?!]?\.[A-Za-z_][A-Za-z0-9_]*)*\s*(?:=(?!=)|\+=|-=)"#
        )
        let optionalChainWrite = "record.transferOwner?.slotReleased = true"
        let optionalChainMatches = assignmentPattern.matches(
            in: optionalChainWrite,
            range: NSRange(location: 0, length: (optionalChainWrite as NSString).length)
        )
        XCTAssertEqual(
            optionalChainMatches.count,
            1,
            "the ownership source check must recognize optional-chain member assignments"
        )
        let forcedUnwrapWrite = "record.transferOwner!.slotReleased = true"
        let forcedUnwrapMatches = assignmentPattern.matches(
            in: forcedUnwrapWrite,
            range: NSRange(location: 0, length: (forcedUnwrapWrite as NSString).length)
        )
        XCTAssertEqual(
            forcedUnwrapMatches.count,
            1,
            "the ownership source check must recognize forced-unwrap member assignments"
        )
        let matches = assignmentPattern.matches(
            in: source,
            range: NSRange(location: 0, length: nsSource.length)
        )
        let outsideLines = matches.compactMap { match -> Int? in
            guard let range = Range(match.range, in: source),
                  !ownerWriteRanges.contains(where: { $0.lowerBound <= range.lowerBound && range.lowerBound < $0.upperBound }) else {
                return nil
            }
            return nsSource.substring(to: match.range.location).filter { $0 == "\n" }.count + 1
        }
        XCTAssertEqual(
            outsideLines,
            [],
            "all canonical transfer owner writes must use transitionTransferRequest or its private helpers; lines \(outsideLines)"
        )

        let finishDeliveryStart = try XCTUnwrap(source.range(of: "case .finishDelivery(let ticket, let advanceFrontier, let outcome):"))
        let finishDeliveryEnd = try XCTUnwrap(
            source.range(of: "case .releaseSlot(let ticket):", range: finishDeliveryStart.upperBound..<source.endIndex)
        )
        let finishDelivery = source[finishDeliveryStart.lowerBound..<finishDeliveryEnd.lowerBound]
        XCTAssertTrue(
            finishDelivery.contains("reclaimActivePostAuthRequestRecordIfEligible(ticket.requestIdentity)"),
            "delivery owner return must re-evaluate canonical record reclamation"
        )
    }

    func testSourceShapeSenderHotPathHasNoNestedTasksOrGlobalExecutorHops() throws {
        // E6 puts the one sender-loop Task on the session executor, but that does not remove
        // the per-frame cost of accidentally adding more Tasks. Runtime placement is covered
        // by SMBSessionExecutorTests; this source check covers the whole hot-path call chain,
        // including control sends, credit reservation, and packet sends.
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        let methodPairs = [
            ("private func enqueuePostAuthRequest(", "private func startSenderLoopIfNeeded("),
            ("private func runSenderLoop(", "private func sendQueuedControl("),
            ("private func sendQueuedControl(", "private func cancelPostAuthRequest("),
            ("private func sendCancelWithoutGate(", "private func handleCancelSendFailure("),
            ("private func sendUnsigned(", "private func requireEncryptionKeyIfSessionDemandsEncryption("),
            ("private func sendSigned(", "private func sendValidateNegotiateSigned("),
            ("private func sendValidateNegotiateSigned(", "private func signedPacket("),
            ("private func sendPlaintext(", "private func sendEncrypted("),
            ("private func sendEncrypted(", "private func terminalizeSendFailureBeforeCreditRefund("),
            ("private func reserveCredit(", "private func claimOrReserveCredit("),
            ("private func claimOrReserveCredit(", "private func reserveVariableCredit("),
            ("private func reserveVariableCredit(", "private func refundUnclaimedCredit(")
        ]
        var hotPathSources: [Substring] = []
        for (method, nextMethod) in methodPairs {
            let start = try XCTUnwrap(source.range(of: method), "missing hot-path method \(method)")
            let end = try XCTUnwrap(source.range(of: nextMethod, range: start.upperBound..<source.endIndex), "missing boundary \(nextMethod)")
            hotPathSources.append(source[start.lowerBound..<end.lowerBound])
        }
        let senderHotPathSource = hotPathSources.joined(separator: "\n")
        let taskInitializer = try NSRegularExpression(
            pattern: #"\bTask(?:\s*<[^>]+>)?\s*(?:\([^)]*\)\s*)?\{"#
        )
        let taskExamples = [
            "Task { await send() }",
            "Task(priority: .background) { await send() }.value",
            "Task(executorPreference: sessionExecutor) { await send() }"
        ]
        for example in taskExamples {
            let range = NSRange(example.startIndex..<example.endIndex, in: example)
            XCTAssertNotNil(taskInitializer.firstMatch(in: example, range: range), "test pattern must reject \(example)")
        }
        let forbiddenPatterns = [
            taskInitializer,
            try NSRegularExpression(pattern: #"\bTask\s*\.\s*detached\b"#),
            try NSRegularExpression(pattern: #"\bwithTaskExecutorPreference\s*\("#),
            try NSRegularExpression(pattern: #"\bDispatchQueue\s*\.\s*global\s*\("#),
            try NSRegularExpression(pattern: #"\bMainActor\s*\.\s*run\s*\{"#)
        ]
        let hotPathRange = NSRange(senderHotPathSource.startIndex..<senderHotPathSource.endIndex, in: senderHotPathSource)
        for forbidden in forbiddenPatterns {
            XCTAssertNil(forbidden.firstMatch(in: String(senderHotPathSource), range: hotPathRange), "sender hot path contains a forbidden task or executor hop")
        }
        for forbidden in ["withTaskExecutorPreference(", "DispatchQueue.global(", "MainActor.run {"] {
            XCTAssertFalse(senderHotPathSource.contains(forbidden), "sender hot path contains \(forbidden)")
        }
        // CANCEL ownership and final-response ordering are covered by event-based tests:
        // testFinalQueuedBehindCurrentFrameDropsCancelBeforeSelection,
        // testEarlyFinalThenCancellationDoesNotQueueCancelAndSendOwnerDrains, and
        // testSelectedCancelSendOwnerKeepsDrainAliveUntilDeadlineAndJoin.
    }

    func testPostAuthCreditReservationUsesAvailableBalanceFastPath() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 1)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 540)
        let (observations, observationContinuation) = AsyncStream.makeStream(
            of: SMBSessionExecutorObservation.self
        )
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            observationContinuation.yield(observation)
        }
        defer {
            observationContinuation.finish()
            session.sessionExecutor.setExecutionObserverForTesting(nil)
            Task { await session.closeTransportAndWait(cause: "credit_fast_path_test_cleanup") }
        }

        let request = Task { try await session.echoThroughSenderLoopForTesting() }
        let observation: SMBSessionExecutorObservation? = try await withHangGuard(
            "available credit takes the synchronous reservation path"
        ) {
            var iterator = observations.makeAsyncIterator()
            while let observation = await iterator.next() {
                if observation.point == .creditReservationFastPath { return observation }
            }
            return nil
        }
        let fastPath = try XCTUnwrap(observation)
        XCTAssertTrue(fastPath.isOnExecutorQueue)
        let balanceAfterReservation = await session.creditBalanceForTesting()
        let waitersAfterReservation = await session.creditWaiterCountForTesting()
        XCTAssertEqual(balanceAfterReservation, 0)
        XCTAssertEqual(waitersAfterReservation, 0)

        try await withHangGuard("fast-path ECHO sends") { try await transport.waitForSendCount(1) }
        let requestHeader = try SMB2Header.decode(transport.sentPackets[0])
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("fast-path ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try transport.enqueueResponse(try echoResponse(messageId: requestHeader.messageId, sessionId: 1, credits: 0))
        try await withHangGuard("fast-path ECHO final") { try await request.value }
        await session.closeTransportAndWait(cause: "credit_fast_path_test_complete")
    }

    func testPostAuthSenderCommitsInFIFOAndDoesNotWaitForResponseFinal() async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 3)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let first = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("first request reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        let second = Task { try await session.echoThroughSenderLoopForTesting(treeId: 22) }
        // Start the third only after the second is queued: two concurrently started Tasks reach
        // the queue in no guaranteed order (Linux enqueued tree 33 first).
        try await withHangGuard("second request is queued") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        let third = Task { try await session.echoThroughSenderLoopForTesting(treeId: 33) }
        try await withHangGuard("two requests remain in the sender queue") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 2)
        }

        let queuedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(queuedStats.wakes, 1)
        // starts is incremented at the single sender-loop Task creation site; the queued
        // second request remains in the same loop instead of launching a per-request Task.
        XCTAssertEqual(queuedStats.starts, 1)
        XCTAssertEqual(queuedStats.frames, 0)
        XCTAssertEqual(queuedStats.queuedRequests, 2)

        transport.releaseNextSend()
        try await withHangGuard("second request starts after the first full-send") {
            try await transport.waitForSendCount(2)
        }
        transport.releaseNextSend()
        try await withHangGuard("third request starts after the second full-send") {
            try await transport.waitForSendCount(3)
        }
        let selectedHeaders = try transport.sentPackets.map(SMB2Header.decode)
        XCTAssertEqual(selectedHeaders.map(\.messageId), [100, 101, 102])
        XCTAssertEqual(selectedHeaders.map(\.treeId), [0, 22, 33])
        XCTAssertEqual(selectedHeaders.map(\.command), Array(repeating: SMB2Commands.echo, count: 3))

        transport.releaseNextSend()
        try await withHangGuard("both request frames finish") {
            await session.waitForSenderFrameCountForTesting(atLeast: 3)
        }
        try await withHangGuard("sender loop reaches idle") {
            await session.waitForSenderLoopExitCountForTesting(atLeast: 1)
        }
        let drainedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(drainedStats.wakes, 1)
        XCTAssertEqual(drainedStats.starts, 1)
        XCTAssertEqual(drainedStats.exits, 1)
        XCTAssertEqual(drainedStats.frames, 3)
        XCTAssertFalse(drainedStats.isRunning)

        try transport.enqueueResponse(try echoResponse(messageId: 100, sessionId: 1, credits: 0))
        try transport.enqueueResponse(try echoResponse(messageId: 101, sessionId: 1, credits: 0, treeId: 22))
        try transport.enqueueResponse(try echoResponse(messageId: 102, sessionId: 1, credits: 0, treeId: 33))
        try await withHangGuard("first caller receives its final") { try await first.value }
        try await withHangGuard("second caller receives its final") { try await second.value }
        try await withHangGuard("third caller receives its final") { try await third.value }

        await session.grantCreditsForTesting(1)
        let fourth = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("new demand starts a replacement idle loop") { try await transport.waitForSendCount(4) }
        let fourthHeader = try SMB2Header.decode(transport.sentPackets[3])
        XCTAssertEqual(fourthHeader.messageId, 103)
        transport.releaseNextSend()
        try await withHangGuard("replacement loop sends the fourth frame") {
            await session.waitForSenderFrameCountForTesting(atLeast: 4)
        }
        try await withHangGuard("replacement loop returns to idle") {
            await session.waitForSenderLoopExitCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try echoResponse(messageId: 103, sessionId: 1, credits: 0))
        try await withHangGuard("fourth caller receives its final") { try await fourth.value }
        let restartedStats = await session.senderLoopStatisticsForTesting()
        XCTAssertEqual(restartedStats.wakes, 2)
        XCTAssertEqual(restartedStats.starts, 2)
        XCTAssertEqual(restartedStats.exits, 2)
        XCTAssertEqual(restartedStats.frames, 4)
        XCTAssertFalse(restartedStats.isRunning)
        await session.closeTransportAndWait(cause: "sender_fifo_test")
    }

    func testCompoundFinalUsesItsSliceValidationTimeForDeadline() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            requestTimeout: .seconds(5),
            sessionTime: clock.source
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("deadline-test request reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("deadline-test request is fully sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await clock.waitForSleepCount(atLeast: 1)

        await session.setResponseSliceValidatedHookForTesting { sliceIndex in
            if sliceIndex == 0 {
                // Model the later signed slice taking the clock from D−ε to D+ε.
                clock.advance(by: .seconds(2), resumeDueSleeps: false)
            }
        }
        clock.advance(by: .seconds(4), resumeDueSleeps: false)

        var firstFinal = try echoResponse(messageId: 100, sessionId: 1, credits: 0)
        firstFinal[20] = 72
        firstFinal[21] = 0
        firstFinal[22] = 0
        firstFinal[23] = 0
        firstFinal.append(contentsOf: [0, 0, 0, 0])
        var laterSlice = try SMB2Header(
            command: SMB2Commands.oplockBreak,
            messageId: UInt64.max,
            sessionId: 1
        ).encode()
        laterSlice.append(contentsOf: [4, 0, 0, 0])
        firstFinal.append(contentsOf: laterSlice)
        try transport.enqueueResponse(firstFinal)

        try await withHangGuard("the pre-deadline slice final is accepted after chain validation") {
            try await caller.value
        }
        let terminal = await session.isTransportClosedForTesting()
        XCTAssertFalse(terminal, "a later compound slice cannot move an earlier final past its deadline")
        await session.closeTransportAndWait(cause: "compound_slice_deadline_test_complete")
    }

    func testCompoundFinalDrainsAtItsAcceptedTimeAfterSendOwnersReturnBeforeDeadline() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let caller = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("compound drain original send starts") {
            try await transport.waitForSendCount(1)
        }
        caller.cancel()
        do {
            try await withHangGuard("compound drain caller cancellation returns") { try await caller.value }
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
        }
        try await withHangGuard("compound drain deadline is installed") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        try await withHangGuard("compound drain CANCEL demand is queued") {
            await session.waitForQueuedControlSendCountForTesting(atLeast: 1)
        }

        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("compound drain original owner returns and CANCEL starts") {
            try await transport.waitForSendCount(2)
        }
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("compound drain CANCEL owner returns") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        let optionalDeadline = await session.wireDrainDeadlineForTesting(messageId: 100)
        let deadline = try XCTUnwrap(optionalDeadline)

        await session.setResponseSliceValidatedHookForTesting { sliceIndex in
            if sliceIndex == 0 {
                clock.advance(by: .nanoseconds(2), resumeDueSleeps: false)
            }
        }
        clock.advance(by: .seconds(10) + .nanoseconds(-1), resumeDueSleeps: false)

        var firstFinal = try echoResponse(messageId: 100, sessionId: 1, credits: 0)
        firstFinal[20] = 72
        firstFinal[21] = 0
        firstFinal[22] = 0
        firstFinal[23] = 0
        firstFinal.append(contentsOf: [0, 0, 0, 0])
        var laterSlice = try SMB2Header(
            command: SMB2Commands.oplockBreak,
            messageId: UInt64.max,
            sessionId: 1
        ).encode()
        laterSlice.append(contentsOf: [4, 0, 0, 0])
        firstFinal.append(contentsOf: laterSlice)
        try transport.enqueueResponse(firstFinal)

        try await withHangGuard("compound final commits after later-slice validation") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let optionalAcceptedAt = await session.lastFinalAcceptanceForTesting()
        let acceptedAt = try XCTUnwrap(optionalAcceptedAt)
        let closed = await session.isTransportClosedForTesting()
        let activeDeadline = await session.wireDrainDeadlineForTesting(messageId: 100)
        XCTAssertEqual(deadline.duration(to: acceptedAt), .nanoseconds(-1))
        XCTAssertFalse(closed, "the final slice was accepted before D and both send owners had already returned")
        XCTAssertNil(activeDeadline, "pre-deadline drain completion cancels its timer")
        await session.closeTransportAndWait(cause: "compound_wire_drain_slice_time_test_complete")
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

    func testCleanupDeadlineRetiresPostAuthCloseAfterCreditReservationBeforeEnqueueResumes() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let fileId = [UInt8](repeating: 0xD1, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            cleanupTimeout: .seconds(5),
            sessionTime: clock.source,
            cleanupTimeoutSleeper: { duration in try await clock.source.sleep(duration) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let reservationAcquired = SMBActivationEvent()
        let releaseReservation = SMBActivationUncancelledGate()
        let cancellationApplied = SMBActivationEvent()
        await session.setCreditReservationAcquiredHookForTesting { _ in
            reservationAcquired.signal()
            await releaseReservation.wait()
        }
        await session.setCleanupSoftDeadlineAppliedHookForTesting {
            cancellationApplied.signal()
        }

        let close = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await withHangGuard("cleanup CLOSE deadline sleeper is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        try await withHangGuard("cleanup CLOSE waits for credit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }

        await session.grantCreditsForTesting(1)
        try await withHangGuard("credit reservation is held before enqueue resumes") {
            await reservationAcquired.wait()
        }
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        try await withHangGuard("cleanup deadline marks the FileId retired") {
            await cancellationApplied.wait()
        }
        let retiredBeforeEnqueueResumes = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(retiredBeforeEnqueueResumes, "retiredUnknown")

        await releaseReservation.signal()
        try await withHangGuard("cleanup CLOSE precommit retirement returns") { await close.value }

        let finalCleanupState = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let cleanupCount = await session.cleanupLedgerCountForTesting()
        let activeRecords = await session.activePostAuthRequestRecordCountForTesting()
        let pendingRecords = await session.wirePendingRecordCountForTesting()
        let nextMessageId = await session.nextMessageIdForTesting()
        let creditBalance = await session.creditBalanceForTesting()
        XCTAssertEqual(finalCleanupState, "retiredUnknown", "enqueue cancellation must preserve the deadline retirement")
        XCTAssertEqual(cleanupCount, 1)
        XCTAssertEqual(activeRecords, 0)
        XCTAssertEqual(pendingRecords, 0)
        XCTAssertEqual(nextMessageId, 100, "a precommit cleanup timeout must not consume a MID")
        XCTAssertEqual(creditBalance, 1, "the acquired precommit credit is refunded exactly once")
        XCTAssertTrue(transport.sentPackets.isEmpty)

        await session.setCreditReservationAcquiredHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_close_credit_reservation_race_test")
    }

    func testCleanupSoftDeadlineUsesOneAbsoluteTimerForParkedCreditWait() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let fileId = [UInt8](repeating: 0xD2, count: 16)
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 0,
            cleanupTimeout: .seconds(5),
            sessionTime: clock.source,
            cleanupTimeoutSleeper: { duration in try await clock.source.sleep(duration) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let creditWaitCatchRetired = SMBActivationEvent()
        await session.setCleanupCloseCreditWaitCatchHookForTesting {
            creditWaitCatchRetired.signal()
        }

        let close = Task { await session.bestEffortClose(treeId: 1, fileId: fileId) }
        try await withHangGuard("cleanup CLOSE catch-path deadline sleeper is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        try await withHangGuard("cleanup CLOSE catch-path credit waiter is registered") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        let cleanupTimerCount = clock.sleepCallCount
        XCTAssertEqual(cleanupTimerCount, 1, "cleanup has one intent-owned soft timer")
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        try await withHangGuard("credit waiter catch establishes FileId retirement first") {
            await creditWaitCatchRetired.wait()
        }

        let stateAfterRetirement = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let activeRecordsAfterRetirement = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(stateAfterRetirement, "retiredUnknown")
        XCTAssertEqual(activeRecordsAfterRetirement, 0)
        XCTAssertTrue(transport.sentPackets.isEmpty)

        try await withHangGuard("cleanup CLOSE catch-path task returns") { await close.value }
        let finalState = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let nextMessageId = await session.nextMessageIdForTesting()
        XCTAssertEqual(finalState, "retiredUnknown", "the later handler must not need the removed request record to retire the FileId")
        XCTAssertEqual(nextMessageId, 100)

        await session.setCleanupCloseCreditWaitCatchHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_close_credit_wait_catch_race_test")
    }

    func testCleanupFullSendAtSoftDeadlineExactAndAfterIsTerminal() async throws {
        for (index, lateness) in [Duration.zero, .nanoseconds(1)].enumerated() {
            let transport = SMBActivationEventTransport()
            let clock = SMBActivationTestClock()
            let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
            await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
            let close = Task {
                await session.bestEffortClose(
                    treeId: 0xA,
                    fileId: [UInt8](repeating: UInt8(0xD3 + index), count: 16)
                )
            }
            try await withHangGuard("cleanup CLOSE reaches the held full-send boundary") {
                try await transport.waitForSendCount(1)
            }
            let packet = try XCTUnwrap(transport.sentPackets.first)
            let header = try SMB2Header.decode(packet)
            XCTAssertEqual(header.command, SMB2Commands.close)
            XCTAssertEqual(header.messageId, 100)
            try await withHangGuard("cleanup soft timer is registered before full-send") {
                await clock.waitForSleepCount(atLeast: 1)
            }

            clock.advance(by: .seconds(5) + lateness, resumeDueSleeps: false)
            transport.releaseNextSend(command: SMB2Commands.close)
            try await withHangGuard("the exact/late full-send terminalizes the session") {
                await transport.waitForCloseCount(atLeast: 1)
            }
            await close.value
            let closed = await session.isTransportClosedForTesting()
            let pending = await session.wirePendingRecordCountForTesting()
            let credits = await session.creditBalanceForTesting()
            let requestSentCount = await session.requestSentCountForTesting()
            XCTAssertTrue(closed, "full-send at (lateness) must lose to softAt")
            XCTAssertEqual(pending, 0)
            XCTAssertEqual(requestSentCount, 0, "terminal is observed from the close event, never the sent-count waiter")
            XCTAssertEqual(credits, 0, "a committed cleanup charge is never refunded")
            await session.closeTransportAndWait(cause: "cleanup_soft_boundary_test_complete")
        }
    }

    func testCleanupFullSendBeforeSoftWinsWhileSendOwnerCallbackIsDelayed() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
        let fullSendCompleted = SMBActivationEvent()
        let releaseSendOwner = SMBActivationUncancelledGate()
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            fullSendCompleted.signal()
            await releaseSendOwner.wait()
        }
        let fileId = [UInt8](repeating: 0xC6, count: 16)
        let close = Task { await session.bestEffortClose(treeId: 0xA, fileId: fileId) }

        try await withHangGuard("cleanup CLOSE reaches its held sender") {
            try await transport.waitForSendCount(1)
        }
        let header = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.first))
        XCTAssertEqual(header.command, SMB2Commands.close)
        XCTAssertEqual(header.messageId, 100)
        try await withHangGuard("absolute cleanup soft sleeper is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        transport.releaseNextSend(command: SMB2Commands.close)
        do {
            try await withHangGuard("plain cleanup full-send boundary is observed") {
                await fullSendCompleted.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "early_cleanup_final_full_send_repro_cleanup")
            _ = await close.result
            throw error
        }

        // The transport send has returned before softAt, while the actor callback which
        // normally marks the request sent is deliberately paused.
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        let terminalizedInsteadOfDraining = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await transport.waitForCloseCount(atLeast: 1)
                return true
            }
            group.addTask {
                await clock.waitForSleepCount(atLeast: 2)
                return false
            }
            let first = await group.next() ?? true
            group.cancelAll()
            return first
        }
        XCTAssertFalse(
            terminalizedInsteadOfDraining,
            "pre-soft full-send must become a soft timeout tombstone even when owner recovery runs later"
        )
        guard !terminalizedInsteadOfDraining else {
            await releaseSendOwner.signal()
            await close.value
            await session.closeTransportAndWait(cause: "cleanup_full_send_time_repro_cleanup")
            return
        }

        try await withHangGuard("soft timeout returns the best-effort caller") { await close.value }
        let drainingState = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertTrue(drainingState?.hasPrefix("draining:") == true)
        await releaseSendOwner.signal()
        try await withHangGuard("delayed sender callback records full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let stillOpenAfterOwnerRecovery = await session.isTransportClosedForTesting()
        XCTAssertFalse(stillOpenAfterOwnerRecovery)

        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: header.messageId,
            sessionId: header.sessionId,
            treeId: header.treeId,
            credits: 0
        ))
        try await withHangGuard("late cleanup final completes before fixed hardAt") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let ledgerAfterFinal = await session.cleanupAttemptStateForTesting(fileId: fileId)
        let stillOpenAfterFinal = await session.isTransportClosedForTesting()
        XCTAssertNil(ledgerAfterFinal)
        XCTAssertFalse(stillOpenAfterFinal)
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_full_send_pre_soft_test_complete")
    }

    func testEarlyCleanupFinalKeepsSoftAndHardDeadlinesUntilSendOwnerReturns() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 110)
        let fullSendCompleted = SMBActivationEvent()
        let releaseSendOwner = SMBActivationUncancelledGate()
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            fullSendCompleted.signal()
            await releaseSendOwner.wait()
        }
        let softDeadlineApplied = SMBActivationEvent()
        await session.setCleanupSoftDeadlineAppliedHookForTesting { softDeadlineApplied.signal() }
        let fileId = [UInt8](repeating: 0xC7, count: 16)
        let closeReturned = SMBActivationEvent()
        let close = Task {
            await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            closeReturned.signal()
        }

        try await withHangGuard("CLOSE reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        let header = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.first))
        try await withHangGuard("cleanup soft deadline is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        transport.releaseNextSend(command: SMB2Commands.close)
        do {
            try await withHangGuard("plain cleanup full-send boundary is observed while its owner stays held") {
                await fullSendCompleted.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "cleanup_final_before_soft_full_send_repro_cleanup")
            _ = await close.result
            throw error
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: header.messageId,
            sessionId: header.sessionId,
            treeId: header.treeId,
            credits: 0
        ))
        try await withHangGuard("early final is accepted while the original send owner is held") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }

        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        do {
            try await withHangGuard("early final still lets the soft deadline apply") {
                await softDeadlineApplied.wait()
            }
            try await withHangGuard("soft deadline releases the cleanup caller despite the early final") {
                await closeReturned.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "early_cleanup_final_deadline_repro_cleanup")
            _ = await close.result
            throw error
        }

        let draining = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertTrue(draining?.hasPrefix("draining:") == true)
        let openAtSoft = await session.isTransportClosedForTesting()
        XCTAssertFalse(openAtSoft, "a full-send before softAt retains the finite wire drain")
        await releaseSendOwner.signal()
        try await withHangGuard("the original send owner returns after the soft deadline") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let stillOpenAfterOwnerRecovery = await session.isTransportClosedForTesting()
        XCTAssertFalse(stillOpenAfterOwnerRecovery)
        let activeRecords = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRecords, 0, "the already accepted final completes after owner recovery")
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "early_cleanup_final_deadline_test_complete")
    }

    func testCleanupFinalAfterSoftButBeforeSoftCallbackUsesFixedHardDeadline() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 120)
        let fullSendCompleted = SMBActivationEvent()
        let releaseSendOwner = SMBActivationUncancelledGate()
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            fullSendCompleted.signal()
            await releaseSendOwner.wait()
        }
        let softDeadlineApplied = SMBActivationEvent()
        await session.setCleanupSoftDeadlineAppliedHookForTesting { softDeadlineApplied.signal() }
        let fileId = [UInt8](repeating: 0xC8, count: 16)
        let closeReturned = SMBActivationEvent()
        let close = Task {
            await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            closeReturned.signal()
        }

        try await withHangGuard("CLOSE reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        let header = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.first))
        try await withHangGuard("cleanup soft deadline is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        transport.releaseNextSend(command: SMB2Commands.close)
        do {
            try await withHangGuard("plain cleanup full-send boundary is observed before the delayed soft callback") {
                await fullSendCompleted.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "cleanup_final_before_soft_callback_full_send_repro_cleanup")
            _ = await close.result
            throw error
        }
        clock.advance(by: .seconds(5), resumeDueSleeps: false)
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: header.messageId,
            sessionId: header.sessionId,
            treeId: header.treeId,
            credits: 0
        ))
        try await withHangGuard("final at softAt is handled before the delayed soft callback") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        do {
            try await withHangGuard("final acceptance applies the fixed soft deadline") {
                await softDeadlineApplied.wait()
            }
            try await withHangGuard("the soft outcome returns independently of the held send owner") {
                await closeReturned.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "cleanup_final_before_soft_callback_deadline_repro_cleanup")
            _ = await close.result
            throw error
        }
        let closedBeforeOwnerRecovery = await session.isTransportClosedForTesting()
        XCTAssertFalse(closedBeforeOwnerRecovery, "pre-soft full-send is draining until fixed hardAt")
        let drainSleeperCount = clock.sleepCallCount
        XCTAssertGreaterThanOrEqual(drainSleeperCount, 2, "sent soft timeout owns the fixed hard sleeper")

        await releaseSendOwner.signal()
        try await withHangGuard("the original send owner recovers before hardAt") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let stateAfterOwnerRecovery = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertNil(stateAfterOwnerRecovery, "the valid final and recovered owner drain the request")
        let closedAfterDrain = await session.isTransportClosedForTesting()
        XCTAssertFalse(closedAfterDrain)
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_final_before_soft_callback_test_complete")
    }

    func testCleanupOwnerRecoveryAtHardDeadlineWinsBeforeDelayedHardCallback() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            requestTimeout: .seconds(3)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 125)
        let fullSendCompleted = SMBActivationEvent()
        let releaseSendOwner = SMBActivationUncancelledGate()
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            fullSendCompleted.signal()
            await releaseSendOwner.wait()
        }
        let softDeadlineApplied = SMBActivationEvent()
        await session.setCleanupSoftDeadlineAppliedHookForTesting { softDeadlineApplied.signal() }
        let fileId = [UInt8](repeating: 0xC8, count: 16)
        let closeReturned = SMBActivationEvent()
        let close = Task {
            await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            closeReturned.signal()
        }

        try await withHangGuard("CLOSE reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        let header = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.first))
        try await withHangGuard("cleanup soft deadline is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        transport.releaseNextSend(command: SMB2Commands.close)
        do {
            try await withHangGuard("cleanup full-send is recorded while sender owner remains active") {
                await fullSendCompleted.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "cleanup_hard_owner_recovery_full_send_repro_cleanup")
            _ = await close.result
            throw error
        }

        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        do {
            try await withHangGuard("soft timeout returns while the owner and final remain outstanding") {
                await softDeadlineApplied.wait()
            }
            try await withHangGuard("soft timeout returns while the owner and final remain outstanding") {
                await closeReturned.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "cleanup_hard_owner_recovery_soft_repro_cleanup")
            _ = await close.result
            throw error
        }
        try await withHangGuard("the hard sleeper is registered at the fixed hardAt") {
            await clock.waitForSleepCount(atLeast: 2)
        }
        let draining = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertTrue(draining?.hasPrefix("draining:") == true)
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: header.messageId,
            sessionId: header.sessionId,
            treeId: header.treeId,
            credits: 0
        ))
        try await withHangGuard("the final is accepted after softAt but before hardAt") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        clock.advance(by: .seconds(3), resumeDueSleeps: false)
        await releaseSendOwner.signal()
        do {
            try await withHangGuard("owner recovery at hardAt terminalizes before the delayed hard callback") {
                await transport.waitForCloseCount(atLeast: 1)
            }
        } catch {
            await session.closeTransportAndWait(cause: "cleanup_hard_owner_recovery_repro_cleanup")
            _ = await close.result
            throw error
        }
        let closed = await session.isTransportClosedForTesting()
        XCTAssertTrue(closed, "hardAt owner recovery is terminal even when the timer callback is delayed")
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "cleanup_hard_owner_recovery_test_complete")
    }

    func testEncryptedCleanupFullSendIsRecordedBeforeSoftExpiry() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 130)
        await session.installEncryptionStateForTesting(
            encryptionKey: [UInt8](repeating: 0x31, count: 16),
            decryptionKey: [UInt8](repeating: 0x31, count: 16),
            sessionId: 1
        )
        let sendReturned = SMBActivationEvent()
        let releaseSendOwner = SMBActivationUncancelledGate()
        await session.setCleanupFullSendBoundaryHookForTesting { _ in
            sendReturned.signal()
            await releaseSendOwner.wait()
        }
        let softDeadlineApplied = SMBActivationEvent()
        await session.setCleanupSoftDeadlineAppliedHookForTesting { softDeadlineApplied.signal() }
        let closeReturned = SMBActivationEvent()
        let fileId = [UInt8](repeating: 0xC9, count: 16)
        let close = Task {
            await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            closeReturned.signal()
        }

        try await withHangGuard("encrypted CLOSE reaches the transport") {
            try await transport.waitForSendCount(1)
        }
        try await withHangGuard("encrypted cleanup soft deadline is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        transport.releaseNextSend()
        do {
            try await withHangGuard("encrypted cleanup full-send boundary is observed") {
                await sendReturned.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "encrypted_cleanup_full_send_boundary_repro_cleanup")
            _ = await close.result
            throw error
        }
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        do {
            try await withHangGuard("encrypted pre-soft full-send becomes a bounded drain") {
                await softDeadlineApplied.wait()
            }
            try await withHangGuard("encrypted soft deadline returns to its caller") {
                await closeReturned.wait()
            }
        } catch {
            await releaseSendOwner.signal()
            await session.closeTransportAndWait(cause: "encrypted_cleanup_full_send_repro_cleanup")
            _ = await close.result
            throw error
        }
        let closedAtSoft = await session.isTransportClosedForTesting()
        XCTAssertFalse(closedAtSoft, "encrypted and plaintext sends share full-send deadline recording")
        await releaseSendOwner.signal()
        try await withHangGuard("encrypted send owner returns after the soft deadline") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        await session.setCleanupFullSendBoundaryHookForTesting(nil)
        await session.setCleanupSoftDeadlineAppliedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "encrypted_cleanup_full_send_test_complete")
    }

    func testOrdinaryFullSendReadsNoCleanupClockMetadata() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(transport: transport, initialCredits: 1, clock: clock)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 140)

        let request = Task { try await session.echoThroughSenderLoopForTesting() }
        try await withHangGuard("ordinary ECHO reaches its held send") {
            try await transport.waitForSendCount(1)
        }
        let clockReadsBeforeFullSend = clock.nowCallCount
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("ordinary ECHO owner returns") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let fullSendClockReads = clock.nowCallCount - clockReadsBeforeFullSend
        XCTAssertEqual(fullSendClockReads, 1, "only ordinary owner-recovery time is read; cleanup full-send metadata is skipped")

        try transport.enqueueResponse(try echoResponse(messageId: 140, sessionId: 1, credits: 0))
        try await withHangGuard("ordinary ECHO final returns") { try await request.value }
        await session.closeTransportAndWait(cause: "ordinary_full_send_cleanup_metadata_test_complete")
    }

    func testTransferCreditBalanceSnapshotIsLimitedToTestingHook() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = root.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let start = try XCTUnwrap(source.range(of: "private func reserveTransferCredit("))
        let end = try XCTUnwrap(source.range(of: "private func applyCreditRequest(", range: start.lowerBound..<source.endIndex))
        let body = source[start.lowerBound..<end.lowerBound]
        let normalizedBody = Self.normalizedSource(String(body))
        let normalizedSource = Self.normalizedSource(source)
        let hook = try XCTUnwrap(
            normalizedBody.range(of: "ifwaitIfUnavailable,lethook=transferCreditSnapshotHookForTesting")
        )
        let snapshot = try XCTUnwrap(normalizedBody.range(of: "creditWindow.balanceSnapshot"))
        XCTAssertLessThan(hook.lowerBound, snapshot.lowerBound, "the lock-taking snapshot is inside the optional hook")
        let hookOpenBrace = try XCTUnwrap(normalizedBody[hook.upperBound...].firstIndex(of: "{"))
        var cursor = hookOpenBrace
        var depth = 0
        var hookCloseBrace: String.Index?
        while cursor < normalizedBody.endIndex {
            switch normalizedBody[cursor] {
            case "{": depth += 1
            case "}":
                depth -= 1
                if depth == 0 {
                    hookCloseBrace = cursor
                }
            default: break
            }
            if hookCloseBrace != nil { break }
            normalizedBody.formIndex(after: &cursor)
        }
        let closeBrace = try XCTUnwrap(hookCloseBrace)
        XCTAssertLessThan(hookOpenBrace, snapshot.lowerBound)
        XCTAssertLessThan(
            snapshot.lowerBound,
            closeBrace,
            "the balance snapshot must stay within the optional testing hook body"
        )
        XCTAssertEqual(
            normalizedBody.components(separatedBy: "creditWindow.balanceSnapshot").count - 1,
            1,
            "the only snapshot read belongs inside the optional testing hook"
        )
        XCTAssertEqual(
            normalizedSource.components(separatedBy: "creditWindow.balanceSnapshot").count - 1,
            3,
            "only the reserve hook, credit diagnostic, and packet patch may read this snapshot"
        )
    }

    func testActiveRecordRemovalUsesReclaimerAndTerminalJoinNormalization() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = root.appendingPathComponent("Sources/SMBee/SMBClient.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let normalized = Self.normalizedSource(source)
        let activeRecordRemovalToken = "activePostAuthRequestRecords.removeValue(forKey:"
        let removal = try XCTUnwrap(normalized.range(of: activeRecordRemovalToken))
        XCTAssertEqual(
            normalized.components(separatedBy: activeRecordRemovalToken).count - 1,
            1,
            "only the guarded reclamation function may remove an individual active record"
        )
        XCTAssertNil(
            normalized.range(of: #"activePostAuthRequestRecords\[[^\]]+\]=nil"#, options: .regularExpression),
            "active records may not be deleted through a nil subscript assignment"
        )
        XCTAssertFalse(normalized.contains("markOperationBarrierComplete"))

        let helperStart = try XCTUnwrap(
            normalized.range(of: "privatefuncreclaimActivePostAuthRequestRecordIfEligible(")
        )
        let helperOpenBrace = try XCTUnwrap(normalized[helperStart.upperBound...].firstIndex(of: "{"))
        var cursor = helperOpenBrace
        var depth = 0
        var helperCloseBrace: String.Index?
        while cursor < normalized.endIndex {
            switch normalized[cursor] {
            case "{": depth += 1
            case "}":
                depth -= 1
                if depth == 0 { helperCloseBrace = cursor }
            default: break
            }
            if helperCloseBrace != nil { break }
            normalized.formIndex(after: &cursor)
        }
        let helperEnd = try XCTUnwrap(helperCloseBrace)
        XCTAssertTrue(
            helperStart.lowerBound <= removal.lowerBound && removal.lowerBound < helperEnd,
            "the sole removeValue must be inside the guarded reclamation function"
        )
        let helperBody = normalized[helperStart.lowerBound..<helperEnd]
        let receiptCheck = try XCTUnwrap(helperBody.range(of: "completeOperationBarrierIfWireWorkIsComplete(for:identity)"))
        let helperRemoval = try XCTUnwrap(helperBody.range(of: activeRecordRemovalToken))
        XCTAssertLessThan(receiptCheck.lowerBound, helperRemoval.lowerBound)
        XCTAssertTrue(
            helperBody.contains("outstandingCreditGrantAcknowledgements:record.outstandingCreditGrantAcknowledgements"),
            "transfer record reclamation must include its outstanding grant acknowledgements"
        )
        let reclamationPolicyStart = try XCTUnwrap(normalized.range(of: "enumSMBTransferRecordReclamation{"))
        let reclamationPolicyEnd = try XCTUnwrap(
            normalized.range(of: "enumSMBTransferRetiringSlotRelease{", range: reclamationPolicyStart.upperBound..<normalized.endIndex)
        )
        let reclamationPolicy = normalized[reclamationPolicyStart.lowerBound..<reclamationPolicyEnd.lowerBound]
        XCTAssertTrue(reclamationPolicy.contains("outstandingCreditGrantAcknowledgements==0"))

        let removeAllToken = "activePostAuthRequestRecords.removeAll()"
        XCTAssertEqual(
            normalized.components(separatedBy: removeAllToken).count - 1,
            0,
            "terminal join must normalize records and reclaim them individually"
        )
        let terminalJoinFunction = try XCTUnwrap(normalized.range(of: "funccloseTransportAndWait("))
        let terminalJoin = try XCTUnwrap(normalized.range(of: "progress:.terminalJoinCompleted"))
        let terminalNormalization = try XCTUnwrap(
            normalized.range(of: "normalizeActiveRequestRecordAtTerminalJoin(record)", range: terminalJoin.lowerBound..<normalized.endIndex)
        )
        XCTAssertLessThan(terminalJoinFunction.lowerBound, terminalJoin.lowerBound)
        XCTAssertLessThan(terminalJoin.lowerBound, terminalNormalization.lowerBound)
        let terminalHelper = try XCTUnwrap(normalized.range(of: "privatefuncnormalizeActiveRequestRecordAtTerminalJoin("))
        let terminalHelperOpenBrace = try XCTUnwrap(normalized[terminalHelper.upperBound...].firstIndex(of: "{"))
        var terminalCursor = terminalHelperOpenBrace
        var terminalDepth = 0
        var terminalHelperEnd: String.Index?
        while terminalCursor < normalized.endIndex {
            switch normalized[terminalCursor] {
            case "{": terminalDepth += 1
            case "}":
                terminalDepth -= 1
                if terminalDepth == 0 { terminalHelperEnd = terminalCursor }
            default: break
            }
            if terminalHelperEnd != nil { break }
            normalized.formIndex(after: &terminalCursor)
        }
        let terminalEnd = try XCTUnwrap(terminalHelperEnd)
        let terminalBody = normalized[terminalHelper.lowerBound..<terminalEnd]
        XCTAssertTrue(terminalBody.contains("record.send=.failed"))
        XCTAssertTrue(terminalBody.contains("record.wire=.sessionTerminal"))
        XCTAssertTrue(terminalBody.contains("record.credit=.discardedOnTerminal"))
        XCTAssertTrue(terminalBody.contains("record.outstandingCreditGrantAcknowledgements=0"))
        XCTAssertTrue(terminalBody.contains("record.originalSendOwned=false"))
        XCTAssertTrue(terminalBody.contains("record.cleanupTimeoutTask=nil"))
        XCTAssertTrue(terminalBody.contains("record.cleanupTimeoutIdentity=nil"))
        XCTAssertTrue(terminalBody.contains("record.wireDrainTask=nil"))
        XCTAssertTrue(terminalBody.contains("record.wireDrainTimerIdentity=nil"))
    }

    private static func normalizedSource(_ source: String) -> String {
        let withoutSelf = source.replacingOccurrences(
            of: #"self\s*\.\s*"#,
            with: "",
            options: .regularExpression
        )
        let compact = withoutSelf.replacingOccurrences(of: #"\s+"#, with: "", options: .regularExpression)
        var normalized = compact
        while true {
            let withoutReceiverParens = normalized.replacingOccurrences(
                of: #"\((activePostAuthRequestRecords|creditWindow)\)"#,
                with: "$1",
                options: .regularExpression
            )
            guard withoutReceiverParens != normalized else { return normalized }
            normalized = withoutReceiverParens
        }
    }

    func testFinalBeforeSoftInvalidatesAnAlreadyWokenCleanupTimeout() async throws {
        let transport = SMBActivationEventTransport()
        let time = SMBActivationTestClock()
        let timeoutSleeper = ManualSMBSleeper()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            cleanupTimeout: .seconds(5),
            sessionTime: time.source,
            cleanupTimeoutSleeper: { try await timeoutSleeper.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)

        let timeoutWakeEntered = SMBActivationEvent()
        let releaseTimeoutWake = SMBActivationUncancelledGate()
        let timeoutIdentityCheck = SMBContinuationBooleanLatch()
        let creditGrantEntered = SMBActivationEvent()
        let releaseCreditGrant = SMBActivationUncancelledGate()
        let recordReaped = SMBActivationEvent()
        await session.setCleanupTimeoutDeliveryHooksForTesting(
            onWake: { _ in
                timeoutWakeEntered.signal()
                await releaseTimeoutWake.wait()
            },
            onIdentityCheck: { isCurrent in timeoutIdentityCheck.signal(isCurrent) }
        )
        await session.setCreditGrantAfterAwaitHookForTesting {
            creditGrantEntered.signal()
            await releaseCreditGrant.wait()
        }
        await session.setActivePostAuthRequestRecordReapedHookForTesting { _ in recordReaped.signal() }

        let fileId = [UInt8](repeating: 0xF1, count: 16)
        let close = Task { await session.bestEffortClose(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("cleanup CLOSE reaches transport") {
            try await transport.waitForSendCount(1)
        }
        let header = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.first))
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("cleanup CLOSE owner recovers before its final") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("cleanup timeout sleeper is registered") {
            try await timeoutSleeper.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(60),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }

        XCTAssertTrue(timeoutSleeper.fireNext(), "the timeout task is now waiting to deliver its callback")
        await timeoutWakeEntered.wait()
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: header.messageId,
            sessionId: header.sessionId,
            treeId: header.treeId,
            credits: 1
        ))
        await creditGrantEntered.wait()
        try await withHangGuard("accepted CLOSE final completes before credit acknowledgement") { await close.value }

        let recordWhileAcknowledgementIsHeld = await session.postAuthRequestRecordSnapshotForTesting(messageId: header.messageId)
        XCTAssertEqual(recordWhileAcknowledgementIsHeld?.send, .fullySent)
        XCTAssertEqual(recordWhileAcknowledgementIsHeld?.wire, .finalAccepted)
        XCTAssertEqual(recordWhileAcknowledgementIsHeld?.outstandingAcknowledgements, 1)

        // The detached timeout job already woke, but its actor callback has not been
        // delivered. Final acceptance invalidates the identity before this callback resumes.
        await releaseTimeoutWake.signal()
        let timeoutWasStillCurrent = await timeoutIdentityCheck.wait()
        XCTAssertFalse(timeoutWasStillCurrent)
        let recordAfterLateTimeoutDelivery = await session.postAuthRequestRecordSnapshotForTesting(messageId: header.messageId)
        XCTAssertEqual(recordAfterLateTimeoutDelivery?.send, .fullySent)
        XCTAssertEqual(recordAfterLateTimeoutDelivery?.wire, .finalAccepted)
        let closedAfterLateTimeoutDelivery = await session.isTransportClosedForTesting()
        XCTAssertFalse(closedAfterLateTimeoutDelivery)

        await releaseCreditGrant.signal()
        await recordReaped.wait()
        let remainingRecords = await session.activePostAuthRequestRecordCountForTesting()
        let remainingLedger = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(remainingRecords, 0)
        XCTAssertNil(remainingLedger)
        await session.setCleanupTimeoutDeliveryHooksForTesting(onWake: nil, onIdentityCheck: nil)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        await session.setActivePostAuthRequestRecordReapedHookForTesting(nil)
        await session.closeTransportAndWait(cause: "final_invalidates_cleanup_timeout")
    }

    func testSoftExpiredFileOwnersAreRemovedWhenTheirFinalsArrive() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            cleanupTimeout: .seconds(5),
            sessionTime: clock.source,
            cleanupTimeoutSleeper: { try await clock.source.sleep($0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 400)

        for iteration in 0..<8 {
            let catchEntered = SMBActivationEvent()
            let releaseCatch = SMBActivationUncancelledGate()
            await session.setCleanupFileCloseCatchHookForTesting { _ in
                catchEntered.signal()
                await releaseCatch.wait()
            }
            let fileId = [UInt8](repeating: UInt8(iteration + 1), count: 16)
            let close = Task { try await session.closeCreatedHandle(treeId: 0xA, fileId: fileId) }
            try await withHangGuard("File CLOSE \(iteration) is sent") {
                try await transport.waitForSendCount(iteration + 1)
            }
            let packet = try XCTUnwrap(transport.sentPackets.last)
            let header = try SMB2Header.decode(packet)
            transport.releaseNextSend(command: SMB2Commands.close)
            try await withHangGuard("File CLOSE \(iteration) owner completes") {
                await session.waitForRequestSentCountForTesting(atLeast: iteration + 1)
            }
            try await withHangGuard("File CLOSE \(iteration) soft timer is registered") {
                await clock.waitForSleepCount(atLeast: iteration * 2 + 1)
            }

            clock.advance(by: .seconds(5), resumeDueSleeps: true)
            await catchEntered.wait()
            let dispatchBase = await session.receivedPacketDispatchCountForTesting()
            try transport.enqueueResponse(try statusResponse(
                command: SMB2Commands.close,
                messageId: header.messageId,
                sessionId: header.sessionId,
                treeId: header.treeId,
                credits: 1
            ))
            try await withHangGuard("File CLOSE \(iteration) final settles while its timeout catch is paused") {
                await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchBase + 1)
            }
            let ledgerAfterFinal = await session.cleanupAttemptStateForTesting(fileId: fileId)
            let expiredOwnersAfterFinal = await session.softExpiredCleanupOwnerCountForTesting()
            XCTAssertNil(ledgerAfterFinal)
            XCTAssertEqual(expiredOwnersAfterFinal, 0, "settled File owners do not accumulate across CLOSE attempts")

            await releaseCatch.signal()
            do {
                try await close.value
                XCTFail("the soft cleanup deadline should be reported to the original caller")
            } catch SMBTransportError.timedOut {
            }
        }
        await session.setCleanupFileCloseCatchHookForTesting(nil)
        await session.closeTransportAndWait(cause: "soft_expired_file_owner_reclamation")
    }

    func testLateFileCloseCatchCannotRetireANewerAttemptForTheSameFileId() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let timeoutSleeper = ManualSMBSleeper()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            cleanupTimeout: .seconds(5),
            sessionTime: clock.source,
            cleanupTimeoutSleeper: { try await timeoutSleeper.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 500)
        let catchEntered = SMBActivationEvent()
        let releaseCatch = SMBActivationUncancelledGate()
        await session.setCleanupFileCloseCatchHookForTesting { _ in
            catchEntered.signal()
            await releaseCatch.wait()
        }
        let fileId = [UInt8](repeating: 0x9D, count: 16)
        let closeA = Task { try await session.closeCreatedHandle(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("CLOSE A is sent") { try await transport.waitForSendCount(1) }
        let packetA = try XCTUnwrap(transport.sentPackets.first)
        let headerA = try SMB2Header.decode(packetA)
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("CLOSE A full-send is observed") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("CLOSE A soft timer registers") {
            try await timeoutSleeper.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(60),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }

        clock.advance(by: .seconds(5), resumeDueSleeps: false)
        XCTAssertTrue(timeoutSleeper.fireNext())
        await catchEntered.wait()
        let dispatchBase = await session.receivedPacketDispatchCountForTesting()
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: headerA.messageId,
            sessionId: headerA.sessionId,
            treeId: headerA.treeId,
            credits: 1
        ))
        try await withHangGuard("CLOSE A final removes its attempt before the paused catch resumes") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchBase + 1)
        }
        let ledgerAfterA = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertNil(ledgerAfterA)

        let closeB = Task { try await session.closeCreatedHandle(treeId: 0xA, fileId: fileId) }
        try await withHangGuard("CLOSE B starts a new owner for the same FileId") {
            try await transport.waitForSendCount(2)
        }
        let headerB = try SMB2Header.decode(try XCTUnwrap(transport.sentPackets.last))
        let ledgerOwnedByB = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(ledgerOwnedByB, "sending")

        await releaseCatch.signal()
        do {
            try await closeA.value
            XCTFail("CLOSE A's soft deadline should still be returned")
        } catch SMBTransportError.timedOut {
        }
        let ledgerAfterLateCatch = await session.cleanupAttemptStateForTesting(fileId: fileId)
        XCTAssertEqual(ledgerAfterLateCatch, "sending", "the owner-matched transition leaves CLOSE B intact")
        let closedAfterLateCatch = await session.isTransportClosedForTesting()
        XCTAssertFalse(closedAfterLateCatch)

        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("CLOSE B full-send is observed") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: headerB.messageId,
            sessionId: headerB.sessionId,
            treeId: headerB.treeId,
            credits: 0
        ))
        try await closeB.value
        await session.setCleanupFileCloseCatchHookForTesting(nil)
        await session.closeTransportAndWait(cause: "late_file_close_catch_owner_guard")
    }

    func testCleanupFinalAtExactHardDeadlineIsTerminal() async throws {
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 1,
            clock: clock,
            requestTimeout: .seconds(3)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
        let close = Task {
            await session.bestEffortClose(
                treeId: 0xA,
                fileId: [UInt8](repeating: 0xD4, count: 16)
            )
        }
        try await withHangGuard("cleanup CLOSE reaches transport") {
            try await transport.waitForSendCount(1)
        }
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("cleanup CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await withHangGuard("cleanup soft timer is registered") {
            await clock.waitForSleepCount(atLeast: 1)
        }
        clock.advance(by: .seconds(5), resumeDueSleeps: true)
        try await withHangGuard("soft timeout returns to best-effort caller") { await close.value }
        try await withHangGuard("fixed hard timer uses the remaining request timeout") {
            await clock.waitForSleepCount(atLeast: 2)
        }

        clock.advance(by: .seconds(3), resumeDueSleeps: false)
        let dispatchBase = await session.receivedPacketDispatchCountForTesting()
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: 100,
            sessionId: 1,
            treeId: 0xA,
            credits: 0
        ))
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchBase + 1)
        let closed = await session.isTransportClosedForTesting()
        let pending = await session.wirePendingRecordCountForTesting()
        XCTAssertTrue(closed)
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "cleanup_hard_boundary_test_complete")
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
        requestTimeout: Duration? = nil,
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
            requestTimeout: requestTimeout,
            wireDrainGrace: wireDrainGrace,
            sessionTime: clock?.source ?? .production()
        )
    }

#if DEBUG
    private enum M3FileTransferOperation: Sendable {
        case read
        case write
    }

    private func assertM3FileIdTransferRefusal(operation: M3FileTransferOperation) async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_300)
        let fileA = [UInt8](repeating: 0xA1, count: 16)

        let blocker = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("File refusal blocker holds the sender") {
            try await transport.waitForSendCount(1)
        }
        let transfer: Task<Void, Error>
        switch operation {
        case .read:
            transfer = Task {
                _ = try await session.readTransferThroughPipelineForTesting(
                    treeId: 0xA,
                    fileId: fileA,
                    length: 1
                )
            }
        case .write:
            transfer = Task {
                try await session.write(treeId: 0xA, fileId: fileA, data: [0x41])
            }
        }
        try await withHangGuard("File A transfer queues before cleanup intent") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }

        let close = Task { await session.bestEffortClose(treeId: 0xA, fileId: fileA) }
        let refusalCompleted: Bool
        do {
            try await withHangGuard("File A transfer receives its local refusal") {
                try await transfer.value
            }
            XCTFail("File A transfer unexpectedly continued through CLOSE admission")
            refusalCompleted = false
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("SMB FileId is unresolved after CLOSE"))
            refusalCompleted = true
        } catch {
            XCTFail("File A transfer returned an unexpected error: \(error)")
            refusalCompleted = false
        }
        if !refusalCompleted {
            await session.closeTransportAndWait(cause: "m3_file_transfer_refusal_mutation_cleanup")
            try await withHangGuard("mutated File transfer exits after cleanup") { _ = await transfer.result }
            try await withHangGuard("mutated File CLOSE exits after cleanup") { await close.value }
            try await withHangGuard("mutated File blocker exits after cleanup") { _ = await blocker.result }
            return
        }

        let sessionOpenAfterRefusal = !(await session.isTransportClosedForTesting())
        XCTAssertTrue(sessionOpenAfterRefusal, "File refusal must not terminalize the session")
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("File refusal blocker full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let blockerHeader = try SMB2Header.decode(transport.sentPackets[0])
        try transport.enqueueResponse(try echoResponse(
            messageId: blockerHeader.messageId,
            sessionId: 1,
            credits: 1,
            treeId: 0xA
        ))
        try await withHangGuard("File refusal blocker final") { try await blocker.value }

        try await withHangGuard("File A cleanup CLOSE reaches the transport") {
            try await transport.waitForSendCount(2)
        }
        let closeHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(closeHeader.command, SMB2Commands.close)
        transport.releaseNextSend(command: SMB2Commands.close)
        try await withHangGuard("File A cleanup CLOSE full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.close,
            messageId: closeHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("File A cleanup CLOSE final") { await close.value }

        let fileB = [UInt8](repeating: 0xB2, count: 16)
        let followingSameTree = Task { try await session.flushThroughSenderLoopForTesting(treeId: 0xA, fileId: fileB) }
        try await withHangGuard("File B on the same Tree reaches the transport") {
            try await transport.waitForSendCount(3)
        }
        let fileBHeader = try SMB2Header.decode(transport.sentPackets[2])
        XCTAssertEqual(fileBHeader.command, SMB2Commands.flush)
        XCTAssertEqual(fileBHeader.treeId, 0xA)
        transport.releaseNextSend(command: SMB2Commands.flush)
        try await withHangGuard("File B full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 3)
        }
        try transport.enqueueResponse(try statusResponse(
            command: SMB2Commands.flush,
            messageId: fileBHeader.messageId,
            sessionId: 1,
            treeId: 0xA,
            credits: 1
        ))
        try await withHangGuard("File B on the same Tree completes") { try await followingSameTree.value }

        let followingOtherTree = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xB) }
        try await withHangGuard("request on another Tree reaches the transport") {
            try await transport.waitForSendCount(4)
        }
        let otherTreeHeader = try SMB2Header.decode(transport.sentPackets[3])
        XCTAssertEqual(otherTreeHeader.command, SMB2Commands.echo)
        XCTAssertEqual(otherTreeHeader.treeId, 0xB)
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("other Tree request full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 4)
        }
        try transport.enqueueResponse(try echoResponse(
            messageId: otherTreeHeader.messageId,
            sessionId: 1,
            credits: 1,
            treeId: 0xB
        ))
        try await withHangGuard("other Tree request completes") { try await followingOtherTree.value }

        let commands = try transport.sentPackets.map { try SMB2Header.decode($0).command }
        let sessionClosed = await session.isTransportClosedForTesting()
        let records = await session.activePostAuthRequestRecordCountForTesting()
        let transfers = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(commands, [
            SMB2Commands.echo,
            SMB2Commands.close,
            SMB2Commands.flush,
            SMB2Commands.echo
        ])
        XCTAssertFalse(sessionClosed)
        XCTAssertEqual(records, 0)
        XCTAssertEqual(transfers.readTransfers, 0)
        XCTAssertEqual(transfers.writeTransfers, 0)
        await session.closeTransportAndWait(cause: "m3_file_transfer_refusal_test")
    }

    private struct M3CancelledWatch {
        let transport: SMBActivationEventTransport
        let clock: SMBActivationTestClock
        let session: SMBSession
        let notifyHeader: SMB2Header
        let watch: Task<Void, Never>
        let caughtCancellation: SMBActivationRace
    }

    /// Mirrors the public `do { op } catch { bestEffortClose }` shape (`withChangeNotifications` by
    /// default): the catch sends CLOSE for the FileId. Returns once the cancelled caller is waiting
    /// for its own wire owner,
    /// and fails if CLOSE reaches the wire first.
    private func startM3CancelledWatch(
        firstMessageId: UInt64,
        command: UInt16 = SMB2Commands.changeNotify,
        operation: @escaping @Sendable (SMBSession, [UInt8]) async throws -> Void = { session, fileId in
            try await session.changeNotify(
                treeId: 0xA,
                fileId: fileId,
                filter: .default,
                watchTree: false,
                onChange: { _ in }
            )
        }
    ) async throws -> M3CancelledWatch {
        let name = command == SMB2Commands.flush ? "FLUSH" : "CHANGE_NOTIFY"
        let transport = SMBActivationEventTransport()
        let clock = SMBActivationTestClock()
        let session = makeSession(
            transport: transport,
            initialCredits: 2,
            clock: clock,
            wireDrainGrace: .seconds(10)
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: firstMessageId)
        let fileId = [UInt8](repeating: 0xC3, count: 16)
        let caughtCancellation = SMBActivationRace()
        let watch = Task {
            do {
                try await operation(session, fileId)
                caughtCancellation.finish(false)
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            } catch is CancellationError {
                caughtCancellation.finish(true)
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            } catch {
                caughtCancellation.finish(false)
                await session.bestEffortClose(treeId: 0xA, fileId: fileId)
            }
        }

        try await withHangGuard("FileId request reaches transport") {
            try await transport.waitForSendCount(1)
        }
        let notifyHeader = try SMB2Header.decode(transport.sentPackets[0])
        XCTAssertEqual(notifyHeader.command, command)
        transport.releaseNextSend(command: command)
        try await withHangGuard("\(name) full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        watch.cancel()
        try await withHangGuard("\(name) cancellation schedules CANCEL") {
            try await transport.waitForSendCount(2)
        }
        let cancelHeader = try SMB2Header.decode(transport.sentPackets[1])
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, notifyHeader.messageId)
        transport.releaseNextSend(command: SMB2Commands.cancel)
        try await withHangGuard("\(name) CANCEL full-send") {
            await session.waitForSenderFrameCountForTesting(atLeast: 2)
        }
        try await withHangGuard("cancelled \(name) arms its existing fixed drain deadline") {
            await clock.waitForSleepCount(atLeast: 1)
        }

        let closeBoundaryRace = SMBActivationRace()
        let ownerWaitObserver = Task {
            await session.waitForRequestReclaimWaiterCountForTesting(atLeast: 1)
            closeBoundaryRace.finish(true)
        }
        let prematureCloseObserver = Task {
            do {
                // Closing the transport also wakes this waiter, so only a real third send counts.
                try await transport.waitForSendCount(3)
                if transport.sentPackets.count >= 3 { closeBoundaryRace.finish(false) }
            } catch {
            }
        }
        let ownerWaitWon = try await withHangGuard("cancelled \(name) caller waits or its CLOSE is observed") {
            await closeBoundaryRace.wait()
        }
        ownerWaitObserver.cancel()
        prematureCloseObserver.cancel()
        try await withHangGuard("\(name) owner-wait observer exits") { await ownerWaitObserver.value }
        try await withHangGuard("\(name) premature CLOSE observer exits") { await prematureCloseObserver.value }
        XCTAssertTrue(ownerWaitWon, "the cancelled \(name) caller must wait for its wire owner before CLOSE")
        return M3CancelledWatch(
            transport: transport,
            clock: clock,
            session: session,
            notifyHeader: notifyHeader,
            watch: watch,
            caughtCancellation: caughtCancellation
        )
    }

    private func assertM3FileIdDescriptorCodecFault(truncatePacket: Bool) async throws {
        let transport = SMBActivationEventTransport()
        let session = makeSession(transport: transport, initialCredits: 2)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1_400)
        let fileId = [UInt8](repeating: 0xA1, count: 16)
        await session.setPostAuthPacketMutationHookForTesting { command, packet in
            guard command == SMB2Commands.read else { return packet }
            if truncatePacket {
                return Array(packet.prefix(SMB2Header.encodedSize + 8))
            }
            var changed = packet
            changed[SMB2Header.encodedSize + 16] ^= 0x01
            return changed
        }

        let blocker = Task { try await session.echoThroughSenderLoopForTesting(treeId: 0xA) }
        try await withHangGuard("codec fault blocker holds the sender") {
            try await transport.waitForSendCount(1)
        }
        let read = Task {
            try await session.readTransferThroughPipelineForTesting(
                treeId: 0xA,
                fileId: fileId,
                length: 1
            )
        }
        try await withHangGuard("File A READ queues before descriptor mutation") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 1)
        }
        transport.releaseNextSend(command: SMB2Commands.echo)
        try await withHangGuard("codec fault blocker full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }

        do {
            _ = try await withHangGuard("descriptor codec fault returns") { try await read.value }
            XCTFail("mutated FileId descriptor unexpectedly passed final admission")
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("post-auth request FileId changed before commit"))
        } catch {
            XCTFail("FileId descriptor returned an unexpected error: \(error)")
        }
        let sessionTerminalBeforeCleanup = await session.isTransportClosedForTesting()
        let nextMessageIdBeforeCleanup = await session.nextMessageIdForTesting()
        XCTAssertTrue(sessionTerminalBeforeCleanup, "descriptor and codec faults must use the existing terminal policy")
        XCTAssertEqual(nextMessageIdBeforeCleanup, 1_401, "a malformed descriptor must not commit a MessageId")
        await session.closeTransportAndWait(cause: "m3_file_descriptor_codec_fault_test")
        try await withHangGuard("codec fault blocker exits after terminal cleanup") { _ = await blocker.result }
    }
#endif

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

    private func echoResponse(messageId: UInt64, sessionId: UInt64, credits: UInt16, treeId: UInt32 = 0) throws -> [UInt8] {
        var packet = try SMB2Header(
            command: SMB2Commands.echo,
            credits: credits,
            flags: 0x0000_0001,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [4, 0, 0, 0])
        return packet
    }

    private func readResponse(
        payload: [UInt8],
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        credits: UInt16
    ) throws -> [UInt8] {
        var packet = try SMB2Header(
            command: SMB2Commands.read,
            credits: credits,
            flags: 0x0000_0001,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [17, 0, 80, 0])
        let payloadLength = UInt32(payload.count)
        packet.append(contentsOf: [
            UInt8(truncatingIfNeeded: payloadLength),
            UInt8(truncatingIfNeeded: payloadLength >> 8),
            UInt8(truncatingIfNeeded: payloadLength >> 16),
            UInt8(truncatingIfNeeded: payloadLength >> 24)
        ])
        packet.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 0])
        packet.append(contentsOf: payload)
        return packet
    }

    private func changeNotifyResponse(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        credits: UInt16
    ) throws -> [UInt8] {
        var packet = try SMB2Header(
            command: SMB2Commands.changeNotify,
            credits: credits,
            flags: 0x0000_0001,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet.append(contentsOf: [9, 0, 64, 0, 0, 0, 0, 0])
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

private final class SMBM3OwnershipLog: @unchecked Sendable {
    struct Receipt: Equatable {
        let transferIdentifier: UInt64
        let complete: Bool
    }

    private let lock = NSLock()
    private var snapshots: [SMBTransferRequestOwnershipSnapshot] = []

    func append(_ snapshot: SMBTransferRequestOwnershipSnapshot) {
        lock.withLock { snapshots.append(snapshot) }
    }

    var receipts: [Receipt] {
        lock.withLock {
            snapshots.compactMap { snapshot in
                guard snapshot.retirementReceiptIdentifier != nil else { return nil }
                return Receipt(
                    transferIdentifier: snapshot.transferIdentifier,
                    complete: snapshot.retirementReceiptComplete
                )
            }
        }
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

private actor SMBActivationUncancelledGate {
    private var signaled = false
    private var continuation: CheckedContinuation<Void, Never>?

    func wait() async {
        if signaled { return }
        await withCheckedContinuation { continuation in
            if signaled {
                continuation.resume()
            } else {
                self.continuation = continuation
            }
        }
    }

    func signal() {
        guard !signaled else { return }
        signaled = true
        continuation?.resume()
        continuation = nil
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
    private var nowCount = 0
    private var countWaiters: [CountWaiter] = []

    var sleepCallCount: Int { lock.withLock { sleepCount } }
    var nowCallCount: Int { lock.withLock { nowCount } }

    var source: SMBSessionMonotonicTime {
        SMBSessionMonotonicTime(
            now: {
                self.lock.withLock {
                    self.nowCount += 1
                    return self.instant
                }
            },
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
        let command: UInt16
        if packet.starts(with: [0xfd, 0x53, 0x4d, 0x42]) {
            command = UInt16.max
        } else {
            command = try SMB2Header.decode(packet).command
        }
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
                        command: command,
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
