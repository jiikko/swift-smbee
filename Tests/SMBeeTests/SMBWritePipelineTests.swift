import Foundation
import XCTest
@testable import SMBee

final class SMBWritePipelineTests: XCTestCase {
    private let chunkSize = 1_048_576

    func testTransferRefundPumpUsesOneStructuredTaskGroupCoordinator() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: projectRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift"),
            encoding: .utf8
        )
        let pumpStart = try XCTUnwrap(source.range(of: "private func startTransferRetirementEffectPumpIfNeeded()"))
        let pumpEnd = try XCTUnwrap(
            source.range(of: "fileprivate func beginWriteTransfer(", range: pumpStart.upperBound..<source.endIndex)
        )
        let pumpSource = source[pumpStart.lowerBound..<pumpEnd.lowerBound]
        let taskPattern = try NSRegularExpression(
            pattern: #"\bTask(?:\s*<[^>]+>)?(?:\s*\.\s*detached)?\s*(?:\(|\{)"#
        )
        let taskCount = taskPattern.numberOfMatches(
            in: String(pumpSource),
            range: NSRange(location: 0, length: (String(pumpSource) as NSString).length)
        )
        XCTAssertEqual(taskCount, 1, "refund effects must be structured children of one pump Task")
        XCTAssertTrue(pumpSource.contains("withTaskGroup(of: Void.self)"))
        XCTAssertTrue(pumpSource.contains("group.addTask"))
        XCTAssertTrue(
            pumpSource.contains("currently running retirement effects"),
            "document that live child Task count is bounded by the active effect count"
        )
    }

    func testTerminalJoinWaitsForGatedTransferRefundEffect() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 8)
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)

        let senderAtPrecommit = SMBContinuationCountBarrier()
        let releaseSender = SMBAsyncCallbackSuspensionGate()
        let refundStarted = SMBContinuationCountBarrier()
        let releaseRefund = SMBAsyncCallbackSuspensionGate()
        let terminalJoinCompleted = SMBContinuationCountBarrier()
        defer {
            releaseSender.release()
            releaseRefund.release()
            transport.failConnection()
        }

        await session.setSenderPrecommitAdmissionHookForTesting { command in
            guard command == SMB2Commands.write else { return }
            senderAtPrecommit.signal()
            await releaseSender.suspend()
        }
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            guard case .refundPending = point else { return }
            refundStarted.signal()
            await releaseRefund.suspend()
        }
        await session.setTerminalJoinCompletedHookForTesting {
            terminalJoinCompleted.signal()
        }

        let write = Task {
            try await session.write(treeId: 1, fileId: Array(repeating: 0x61, count: 16), data: [0x41])
        }
        try await smbIssue102AwaitWithTimeout("WRITE reaches the precommit gate before refund retirement") {
            try await senderAtPrecommit.waitForCount(1)
        }
        write.cancel()
        try await smbIssue102AwaitWithTimeout("cancelled WRITE refund enters its gate") {
            try await refundStarted.waitForCount(1)
        }

        let terminalClose = Task {
            await session.closeTransportAndWait(cause: "gated_refund_terminal_join_test")
        }
        try await smbIssue102AwaitWithTimeout("terminal close starts while refund effect is gated") {
            try await transport.waitForCloseCount(1)
        }
        releaseSender.release()

        do {
            try await smbIssue102AwaitWithTimeout(
                "terminal join must wait for the gated refund effect",
                timeout: .milliseconds(250)
            ) {
                await terminalClose.value
            }
            XCTFail("terminal join completed before the gated refund effect")
        } catch is SMBIssue102WaitTimeout {
            // The terminal close stays joined to the refund effect until its gate opens.
        }

        releaseRefund.release()
        try await smbIssue102AwaitWithTimeout("terminal close joins after the refund effect finishes") {
            await terminalClose.value
        }
        _ = try await smbIssue102AwaitWithTimeout("cancelled WRITE exits after terminal join") {
            do {
                try await write.value
                return false
            } catch {
                return true
            }
        }
        XCTAssertGreaterThanOrEqual(terminalJoinCompleted.currentCount, 1)
        await session.setSenderPrecommitAdmissionHookForTesting(nil)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
        await session.setTerminalJoinCompletedHookForTesting(nil)
    }

    func testAcknowledgedPrefixSurvivesRetirementDuringCreditWait() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 3)
        XCTAssertNotEqual(
            Array(data[..<chunkSize]),
            Array(data[chunkSize..<(chunkSize * 2)]),
            "adjacent 1 MiB chunks must have different payloads"
        )
        let progress = SMBWritePipelineProgressCollector()
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "retirement-credit-wait.bin",
                data: data,
                onProgress: { progress.append($0.bytesTransferred) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 17)
        let first = try await waitForWrite(transport, offset: 0)
        let second = try await waitForWrite(transport, offset: UInt64(chunkSize))

        try transport.respond(to: first, credits: 16)
        let thirdOffset = UInt64(chunkSize) + 65_536
        let third = try await waitForWrite(transport, offset: thirdOffset)
        try await waitForProgress(progress, count: 1, label: "first ACK retirement after the later commit")
        XCTAssertEqual(progress.values.last, UInt64(chunkSize))
        try transport.respond(to: second, credits: 1)
        try transport.respond(to: third, credits: 16)
        var nextOffset = UInt64(first.length) + UInt64(second.length) + UInt64(third.length)
        while nextOffset < UInt64(data.count) {
            let request = try await waitForWrite(transport, offset: nextOffset)
            try transport.respond(to: request, credits: 16)
            nextOffset += UInt64(request.length)
        }

        try await smbIssue102AwaitWithTimeout("ACK retirement during a later credit wait") {
            try await operation.value
        }
        XCTAssertEqual(progress.values.last, UInt64(data.count))
        XCTAssertTrue(transport.sentCommands.contains(SMB2Commands.flush))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_retirement_credit_wait_test_complete")
    }

    func testSupplierWaitsForCreditBeforeChoosingTheNextWriteSize() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 2)
        let supplier = SMBWritePipelineChunkSource(data: data)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "credit-sized-supplier.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { supplier.nextChunk(maxLength: $0) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 16)
        let first = try await waitForWrite(transport, offset: 0)
        XCTAssertEqual(first.length, UInt32(chunkSize))

        try transport.respond(to: first, credits: 16)
        let second = try await waitForWrite(transport, offset: UInt64(chunkSize))
        XCTAssertEqual(
            second.length,
            UInt32(chunkSize),
            "the supplier should see the full replenished credit window before choosing its next chunk"
        )
        try transport.respond(to: second, credits: 16)
        try await waitForSupplierCalls(supplier, count: 3)
        try await smbIssue102AwaitWithTimeout("credit-aware supplier WRITE completion") {
            try await operation.value
        }

        XCTAssertEqual(supplier.requestedSizes, [chunkSize, chunkSize, chunkSize])
        XCTAssertEqual(transport.writeRequests.map(\.length), [UInt32(chunkSize), UInt32(chunkSize)])
        XCTAssertEqual(transport.writeRequests.flatMap(\.data), data)
    }

    func testZeroCreditWithNoCommittedWriteStillCallsSupplier() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        let calls = SMBWritePipelineCounter()
        let ownershipSnapshots = SMBTransferOwnershipRecorder()
        let data = patternedBytes(count: 65_536)
        defer { transport.failConnection() }

        let create = Task {
            try await session.create(
                treeId: 1,
                request: .upload(path: "zero-credit-supplier-throw.bin", overwrite: true)
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 1)
        let fileId = try await smbIssue102AwaitWithTimeout("zero-credit test CREATE") { try await create.value }
        await session.setTransferRequestOwnershipHookForTesting { snapshot in
            ownershipSnapshots.append(snapshot)
        }

        let operation = Task {
            try await session.write(
                treeId: 1,
                fileId: fileId,
                offset: 0,
                nextChunk: { _ in
                    if calls.increment() == 1 { return data }
                    throw SMBWritePipelineInjectedFailure.supplier
                }
            )
        }
        let first = try await waitForWrite(transport, offset: 0)
        XCTAssertEqual(first.length, 65_536)
        try await waitForActiveSendTasks(session, label: "zero-credit first WRITE send owner")
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        try transport.respond(to: first, credits: 0)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 1)
        do {
            try await waitForSupplierCalls(calls, count: 2)
        } catch {
            XCTFail("second supplier call did not arrive after the final: \(error)")
            operation.cancel()
            return
        }

        do {
            try await smbIssue102AwaitWithTimeout("zero-credit supplier error") {
                try await operation.value
            }
            XCTFail("supplier error after the last committed WRITE was lost")
        } catch SMBWritePipelineInjectedFailure.supplier {
            // A zero-credit window must not suppress EOF or supplier errors.
        }
        XCTAssertEqual(calls.value, 2)
        XCTAssertEqual(transport.writeRequests.count, 1)
        let noTicketClose = try XCTUnwrap(ownershipSnapshots.first {
            $0.command == SMB2Commands.write && $0.offset == nil
        })
        XCTAssertEqual(noTicketClose.caller, .noWireWork)
        XCTAssertEqual(noTicketClose.send, .neverSubmitted)
        XCTAssertEqual(noTicketClose.wire, .notApplicable)
        XCTAssertEqual(noTicketClose.credit, .notApplicable)
        XCTAssertFalse(noTicketClose.deliveryUnresolved)
        XCTAssertTrue(noTicketClose.slotReleased)
        XCTAssertTrue(noTicketClose.slotVacant)
        XCTAssertNil(noTicketClose.retirementReceiptIdentifier)
        XCTAssertEqual(noTicketClose.retirementRefundsPending, 0)
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        let activeRequestRecords = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRequestRecords, 0, "no-ticket supplier failure reclaims its canonical chunk record")
        let activeIdentities = await session.activeRequestIdentityCountForTesting()
        XCTAssertEqual(activeIdentities, 0)
        await session.setTransferRequestOwnershipHookForTesting(nil)
        await session.closeTransportAndWait(cause: "write_zero_credit_supplier_test_complete")
    }

    func testTransferRefundPumpDispatchesThirdEffectWhileTwoRefundsAreGated() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 8)
        await session.installSenderLoopStateForTesting(sessionId: 0x1122_3344_5566_7788, firstMessageId: 100)
        defer { transport.failConnection() }

        let createA = Task {
            try await session.create(treeId: 1, request: .upload(path: "retirement-a.bin", overwrite: true))
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 8)
        let fileA = try await smbIssue102AwaitWithTimeout("refund pump CREATE A completes") {
            try await createA.value
        }
        let createB = Task {
            try await session.create(treeId: 1, request: .upload(path: "retirement-b.bin", overwrite: true))
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 2)
        try transport.completeCreate(credits: 8)
        let fileB = try await smbIssue102AwaitWithTimeout("refund pump CREATE B completes") {
            try await createB.value
        }
        let createC = Task {
            try await session.create(treeId: 1, request: .upload(path: "retirement-c.bin", overwrite: true))
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 3)
        try transport.completeCreate(credits: 8)
        let fileC = try await smbIssue102AwaitWithTimeout("refund pump CREATE C completes") {
            try await createC.value
        }
        let creditBalanceBeforeTransfers = await session.creditBalanceForTesting()
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: 1)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: 1, treeIdentity: treeIdentity)
        let ownershipSnapshots = SMBTransferOwnershipRecorder()
        await session.setTransferRequestOwnershipHookForTesting { snapshot in
            ownershipSnapshots.append(snapshot)
        }

        let senderAtPrecommit = SMBContinuationCountBarrier()
        let releaseSender = SMBAsyncCallbackSuspensionGate()
        let refundAStarted = SMBContinuationCountBarrier()
        let refundBStarted = SMBContinuationCountBarrier()
        let refundCStarted = SMBContinuationCountBarrier()
        let releaseRefundA = SMBAsyncCallbackSuspensionGate()
        let releaseRefundB = SMBAsyncCallbackSuspensionGate()
        let releaseRefundC = SMBAsyncCallbackSuspensionGate()
        defer {
            releaseSender.release()
            releaseRefundA.release()
            releaseRefundB.release()
            releaseRefundC.release()
        }
        await session.setSenderPrecommitAdmissionHookForTesting { command in
            guard command == SMB2Commands.write else { return }
            senderAtPrecommit.signal()
            await releaseSender.suspend()
        }
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            guard case .refundPending(let charge) = point else { return }
            if charge == 1 {
                refundAStarted.signal()
                await releaseRefundA.suspend()
            } else if charge == 2 {
                refundBStarted.signal()
                await releaseRefundB.suspend()
            } else if charge == 3 {
                refundCStarted.signal()
                await releaseRefundC.suspend()
            }
        }

        let operationACompleted = SMBContinuationCountBarrier()
        let operationA = Task {
            defer { operationACompleted.signal() }
            try await session.write(treeId: 1, fileId: fileA, data: [0x41])
        }
        try await smbIssue102AwaitWithTimeout("WRITE A reaches selected precommit owner") {
            try await senderAtPrecommit.waitForCount(1)
        }
        let operationBCompleted = SMBContinuationCountBarrier()
        let operationB = Task {
            defer { operationBCompleted.signal() }
            try await session.write(treeId: 1, fileId: fileB, data: Array(repeating: 0x42, count: 100_000))
        }
        let operationCCompleted = SMBContinuationCountBarrier()
        let operationC = Task {
            defer { operationCCompleted.signal() }
            try await session.write(treeId: 1, fileId: fileC, data: Array(repeating: 0x43, count: 196_608))
        }
        try await smbIssue102AwaitWithTimeout("two WRITE requests are queued before retirement") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 2)
        }
        let nextMessageIdBeforeRetirement = await session.nextMessageIdForTesting()

        operationA.cancel()
        operationB.cancel()
        operationC.cancel()
        let treeClose = Task { await tree.close() }
        try await smbIssue102AwaitWithTimeout("refund A reaches its keyed gate") {
            try await refundAStarted.waitForCount(1)
        }
        try await smbIssue102AwaitWithTimeout("refund B dispatches while refund A remains gated") {
            try await refundBStarted.waitForCount(1)
        }
        do {
            try await smbIssue102AwaitWithTimeout("third refund dispatches while A and B remain gated") {
                try await refundCStarted.waitForCount(1)
            }
        } catch {
            releaseRefundA.release()
            releaseRefundB.release()
            releaseRefundC.release()
            releaseSender.release()
            try? await smbIssue102AwaitWithTimeout("bounded refund dispatch failure cleanup") {
                await session.closeTransportAndWait(cause: "third_refund_dispatch_red_cleanup")
            }
            try? await smbIssue102AwaitWithTimeout("clear refund test hook after bounded cleanup") {
                await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
            }
            throw error
        }
        let selectedA = try XCTUnwrap(ownershipSnapshots.first {
            $0.command == SMB2Commands.write && $0.packetOwned && $0.reservedCharge == 1
        }, "the sender's selected packet owner is observable before retirement")
        let queuedB = try XCTUnwrap(ownershipSnapshots.first {
            $0.command == SMB2Commands.write
                && $0.identity != selectedA.identity
                && $0.reservedCharge == 2
                && $0.retirementReceiptIdentifier != nil
        }, "queued B has its own canonical request identity")
        let queuedC = try XCTUnwrap(ownershipSnapshots.first {
            $0.command == SMB2Commands.write
                && $0.identity != selectedA.identity
                && $0.identity != queuedB.identity
                && $0.reservedCharge == 3
                && $0.retirementReceiptIdentifier != nil
        }, "queued C has its own canonical request identity")
        let retiredA = try XCTUnwrap(ownershipSnapshots.latest(for: selectedA.identity) {
            !$0.retirementReceiptComplete
        })
        XCTAssertTrue(retiredA.packetOwned, "queue removal and refund dispatch do not return the selected packet")
        XCTAssertGreaterThan(retiredA.retirementRefundsPending, 0)
        let duplicateA = try await smbIssue102AwaitWithTimeout("duplicate Tree/cancellation retirement reuses A's receipt") {
            try await ownershipSnapshots.waitForSnapshot(for: selectedA.identity) {
                $0.duplicateRetirementObserved
            }
        }
        XCTAssertEqual(duplicateA.retirementReceiptIdentifier, retiredA.retirementReceiptIdentifier)
        XCTAssertTrue(duplicateA.packetOwned)
        XCTAssertFalse(duplicateA.retirementReceiptComplete)
        let queueAfterRetirement = await session.senderLoopStatisticsForTesting().queuedRequests
        XCTAssertEqual(queueAfterRetirement, 0, "retirement removes queued B before the sender gate opens")
        let recordsWithBothRefundsHeld = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(
            recordsWithBothRefundsHeld,
            3,
            "all three canonical records stay active while C's refund is dispatched but gated"
        )
        XCTAssertEqual(operationACompleted.currentCount, 0, "A's operation remains joined to its pending receipt")
        XCTAssertEqual(operationBCompleted.currentCount, 0, "B's operation cannot finish before its refund ack")
        XCTAssertEqual(operationCCompleted.currentCount, 0, "C's operation is observed before its independent refund ack")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))

        XCTAssertEqual(operationCCompleted.currentCount, 0, "C remains joined to its own refund acknowledgement")
        XCTAssertFalse(
            ownershipSnapshots.latest(for: selectedA.identity)?.retirementReceiptComplete ?? true,
            "A's receipt remains pending while C acknowledges"
        )
        XCTAssertFalse(
            ownershipSnapshots.latest(for: queuedB.identity)?.retirementReceiptComplete ?? true,
            "B's receipt remains pending while C is dispatched"
        )

        releaseRefundC.release()
        let refundAcknowledgedC = try await smbIssue102AwaitWithTimeout("C acknowledges while A and B remain gated") {
            try await ownershipSnapshots.waitForSnapshot(for: queuedC.identity) {
                $0.retirementReceiptComplete && $0.retirementRefundsPending == 0
            }
        }
        XCTAssertTrue(refundAcknowledgedC.retirementReceiptComplete)
        XCTAssertEqual(refundAcknowledgedC.retirementRefundsPending, 0)
        try await smbIssue102AwaitWithTimeout("C operation completes before either earlier refund is released") {
            try await operationCCompleted.waitForCount(1)
        }
        XCTAssertFalse(ownershipSnapshots.latest(for: selectedA.identity)?.retirementReceiptComplete ?? true)
        XCTAssertFalse(ownershipSnapshots.latest(for: queuedB.identity)?.retirementReceiptComplete ?? true)

        releaseRefundB.release()
        let refundAcknowledgedB = try await smbIssue102AwaitWithTimeout("B's refund ack settles independently of A") {
            try await ownershipSnapshots.waitForSnapshot(for: queuedB.identity) {
                $0.retirementReceiptComplete && $0.retirementRefundsPending == 0
            }
        }
        XCTAssertEqual(refundAcknowledgedB.retirementRefundsPending, 0)
        XCTAssertTrue(
            refundAcknowledgedB.retirementReceiptComplete,
            "B's receipt should close after refund ack: slotReleased=\(refundAcknowledgedB.slotReleased), "
                + "slotVacant=\(refundAcknowledgedB.slotVacant), packetOwned=\(refundAcknowledgedB.packetOwned), "
                + "selectedPrecommitOwned=\(refundAcknowledgedB.selectedPrecommitOwned), "
                + "supplierOwned=\(refundAcknowledgedB.supplierOwned), deliveryOwned=\(refundAcknowledgedB.deliveryOwned), "
                + "outstandingGrantAcks=\(refundAcknowledgedB.outstandingCreditGrantAcknowledgements)"
        )
        XCTAssertTrue(
            ownershipSnapshots.snapshots.contains {
                $0.identity == queuedB.identity && $0.retirementReceiptComplete && $0.retirementRefundsPending == 0
            },
            "the ownership recorder retains B's independently completed receipt snapshot"
        )
        try await smbIssue102AwaitWithTimeout("B completes while A's refund remains gated") {
            try await operationBCompleted.waitForCount(1)
        }
        let recordsWithARefundHeld = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsWithARefundHeld, 1, "B is reclaimed while A's packet owner and refund remain active")
        XCTAssertEqual(operationACompleted.currentCount, 0)

        releaseRefundA.release()
        let refundAcknowledgedWhilePacketOwned = try await smbIssue102AwaitWithTimeout(
            "refund A acknowledges while its selected packet remains owned"
        ) {
            try await ownershipSnapshots.waitForSnapshot(for: selectedA.identity) {
                $0.retirementRefundsPending == 0
            }
        }
        XCTAssertTrue(refundAcknowledgedWhilePacketOwned.packetOwned)
        XCTAssertFalse(
            refundAcknowledgedWhilePacketOwned.retirementReceiptComplete,
            "refund acknowledgement alone cannot close the receipt while the sender owns the packet"
        )
        XCTAssertFalse(refundAcknowledgedWhilePacketOwned.slotReleased)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.treeDisconnect))
        let nextMessageIdBeforeSelectedPacketReturns = await session.nextMessageIdForTesting()
        XCTAssertEqual(nextMessageIdBeforeSelectedPacketReturns, nextMessageIdBeforeRetirement)

        releaseSender.release()
        try await smbIssue102AwaitWithTimeout("retired WRITE send owners exit") {
            await session.waitForActiveSendTasksForTesting()
        }
        let packetReturnedA = try await smbIssue102AwaitWithTimeout("selected packet owner returns to the transition") {
            try await ownershipSnapshots.waitForSnapshot(for: selectedA.identity) {
                !$0.packetOwned
            }
        }
        XCTAssertTrue(packetReturnedA.retirementReceiptComplete)
        XCTAssertTrue(packetReturnedA.slotReleased)
        XCTAssertTrue(transport.writeRequests.isEmpty, "retired A and B never allocate a MessageId or reach the wire")
        try await waitForCommand(transport, SMB2Commands.treeDisconnect, occurrence: 1)
        try transport.completeTreeDisconnect()
        try await smbIssue102AwaitWithTimeout("Tree cleanup joins after the three refunds") {
            await treeClose.value
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled WRITE A finishes after its refund ack") {
                try await operationA.value
            }
            XCTFail("expected WRITE A cancellation")
        } catch is CancellationError {
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled queued WRITE B finishes after its refund ack") {
                try await operationB.value
            }
            XCTFail("expected WRITE B cancellation")
        } catch is CancellationError {
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled queued WRITE C finishes after its refund ack") {
                try await operationC.value
            }
            XCTFail("expected WRITE C cancellation")
        } catch is CancellationError {
        }
        let recordsAfterBothRefunds = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(recordsAfterBothRefunds, 0)
        let creditBalanceAfterRefunds = await session.creditBalanceForTesting()
        XCTAssertEqual(creditBalanceAfterRefunds, creditBalanceBeforeTransfers, "each unsent reservation is refunded once")
        XCTAssertTrue(transport.writeRequests.isEmpty)
        await session.setSenderPrecommitAdmissionHookForTesting(nil)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
        await session.setTransferRequestOwnershipHookForTesting(nil)
        try await smbIssue102AwaitWithTimeout("refund pump test final transport close") {
            await session.closeTransportAndWait(cause: "transfer_refund_three_effect_independence_test_complete")
        }
    }

    func testTreePreparationRefundDispatchesSecondIdentityWhileFirstIsGated() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 0)
        let optionalTreeIdentity = await session.ensureTreeIdentity(treeId: 1)
        let treeIdentity = try XCTUnwrap(optionalTreeIdentity)
        let tree = SMBClientTreeSession(session: session, treeId: 1, treeIdentity: treeIdentity)
        let fileIdSeed = [UInt8](repeating: 0x51, count: 16)
        let fileIdA = [UInt8](repeating: 0x52, count: 16)
        let fileIdB = [UInt8](repeating: 0x53, count: 16)
        let claimAStarted = SMBContinuationCountBarrier()
        let claimBStarted = SMBContinuationCountBarrier()
        let refundAStarted = SMBContinuationCountBarrier()
        let refundBStarted = SMBContinuationCountBarrier()
        let grantIdentities = SMBWritePipelineTransferGrantRecorder()
        let refundDispatches = SMBWritePipelineRefundDispatchRecorder()
        let releaseClaimA = SMBAsyncCallbackSuspensionGate()
        let releaseClaimB = SMBAsyncCallbackSuspensionGate()
        let releaseRefundA = SMBAsyncCallbackSuspensionGate()
        let ownershipSnapshots = SMBTransferOwnershipRecorder()
        var treeClose: Task<Void, Never>?
        var writeA: Task<Void, Error>?
        var writeB: Task<Void, Error>?
        let seedWrite = Task {
            try await session.write(treeId: 1, fileId: fileIdSeed, data: Array(repeating: 0x11, count: 65_536))
        }
        defer {
            releaseClaimA.release()
            releaseClaimB.release()
            releaseRefundA.release()
            transport.failConnection()
        }
        await session.setTransferRequestOwnershipHookForTesting { snapshot in
            ownershipSnapshots.append(snapshot)
        }
        await session.setTransferCreditGrantAcceptanceGateForTesting { identity, charge in
            grantIdentities.record(identity: identity, charge: charge)
            if charge == 1 {
                claimAStarted.signal()
                return Task { await releaseClaimA.suspend() }
            }
            if charge == 2 {
                claimBStarted.signal()
                return Task { await releaseClaimB.suspend() }
            }
            return nil
        }
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            switch point {
            case .grantClaimedBeforeAccept:
                break
            case .refundPending(let charge):
                if refundDispatches.record(charge) == 1 {
                    refundAStarted.signal()
                    await releaseRefundA.suspend()
                } else {
                    refundBStarted.signal()
                }
            }
        }

        var creditBalanceBeforePreparationRefunds: UInt32?
        var testFailure: Error?
        do {
            let seedRequest = try await waitForWrite(transport, offset: 0)
            writeA = Task {
                try await session.write(treeId: 1, fileId: fileIdA, data: Array(repeating: 0x21, count: 65_536))
            }
            try await smbIssue102AwaitWithTimeout("first Tree preparation parks on credit") {
                await session.waitForCreditWaiterCountForTesting(atLeast: 1)
            }
            writeB = Task {
                try await session.write(treeId: 1, fileId: fileIdB, data: Array(repeating: 0x31, count: 131_072))
            }
            try await smbIssue102AwaitWithTimeout("both Tree preparation credit waiters are registered") {
                await session.waitForCreditWaiterCountForTesting(atLeast: 2)
            }
            try transport.respond(to: seedRequest, credits: 3)
            try await smbIssue102AwaitWithTimeout("seed WRITE completes") {
                try await seedWrite.value
            }
            try await smbIssue102AwaitWithTimeout("A's grant claim stops before acceptance") {
                try await claimAStarted.waitForCount(1)
            }
            try await smbIssue102AwaitWithTimeout("B's grant claim stops before acceptance") {
                try await claimBStarted.waitForCount(1)
            }
            creditBalanceBeforePreparationRefunds = await session.creditBalanceForTesting()
            treeClose = Task { await tree.close() }
            try await smbIssue102AwaitWithTimeout("A's Tree preparation refund reaches its gate") {
                try await refundAStarted.waitForCount(1)
            }
            try await smbIssue102AwaitWithTimeout("B's Tree preparation refund dispatches while A is gated") {
                try await refundBStarted.waitForCount(1)
            }

            let charges = refundDispatches.charges
            XCTAssertEqual(charges.count, 2)
            let aCharge = try XCTUnwrap(charges.first)
            let bCharge = try XCTUnwrap(charges.last)
            let aIdentity = try XCTUnwrap(grantIdentities.identity(forCharge: aCharge))
            let bIdentity = try XCTUnwrap(grantIdentities.identity(forCharge: bCharge))
            let aPreparation = try XCTUnwrap(ownershipSnapshots.latest(for: aIdentity))
            let bPreparation = try XCTUnwrap(ownershipSnapshots.latest(for: bIdentity))

            if bCharge == 1 { releaseClaimA.release() } else { releaseClaimB.release() }
            _ = try await smbIssue102AwaitWithTimeout("B preparation refund ack settles under the held A ack") {
                try await ownershipSnapshots.waitForSnapshot(for: bPreparation.identity) {
                    $0.retirementRefundsPending == 0
                }
            }
            let balanceAfterBRefund = await session.creditBalanceForTesting()
            XCTAssertEqual(
                balanceAfterBRefund,
                try XCTUnwrap(creditBalanceBeforePreparationRefunds) + UInt32(bCharge),
                "B's preparation refund restores its charge while A remains gated"
            )
            let bOperation = try XCTUnwrap(bCharge == 1 ? writeA : writeB)
            let bFailed = try await smbIssue102AwaitWithTimeout("B preparation exits while A's refund remains gated") {
                do {
                    try await bOperation.value
                    return false
                } catch {
                    return true
                }
            }
            XCTAssertTrue(bFailed, "Tree refusal should terminate the B preparation")
            XCTAssertGreaterThan(
                ownershipSnapshots.latest(for: aPreparation.identity)?.retirementRefundsPending ?? 0,
                0,
                "A remains independently pending while B settles"
            )

            releaseClaimA.release()
            releaseClaimB.release()
            releaseRefundA.release()
            let refundAcknowledgedA = try await smbIssue102AwaitWithTimeout("A's preparation refund ack settles") {
                try await ownershipSnapshots.waitForSnapshot(for: aPreparation.identity) {
                    $0.retirementRefundsPending == 0
                }
            }
            XCTAssertEqual(refundAcknowledgedA.retirementRefundsPending, 0)
            try await smbIssue102AwaitWithTimeout(
                "Tree preparation TREE_DISCONNECT dispatches after refunds",
                timeout: .seconds(1)
            ) {
                try await transport.waitForCommand(SMB2Commands.treeDisconnect, occurrence: 1)
            }
            try transport.completeTreeDisconnect(credits: 1)
            let treeCloseTask = try XCTUnwrap(treeClose)
            try await smbIssue102AwaitWithTimeout("Tree cleanup joins after both preparation refunds") {
                await treeCloseTask.value
            }
            let balanceAfterBothRefunds = await session.creditBalanceForTesting()
            XCTAssertEqual(
                balanceAfterBothRefunds,
                try XCTUnwrap(creditBalanceBeforePreparationRefunds) + UInt32(aCharge) + UInt32(bCharge),
                "both preparation refunds restore their full charges before terminal close"
            )
        } catch {
            testFailure = error
        }

        releaseClaimA.release()
        releaseClaimB.release()
        releaseRefundA.release()
        transport.failConnection()
        try await smbIssue102AwaitWithTimeout("Tree preparation fixture terminal cleanup") {
            await session.closeTransportAndWait(cause: "tree_preparation_refund_fixture_cleanup")
        }
        try? await smbIssue102AwaitWithTimeout("seed WRITE exits during fixture cleanup") { _ = try? await seedWrite.value }
        if let writeA {
            try? await smbIssue102AwaitWithTimeout("preparation WRITE A exits during fixture cleanup") { _ = try? await writeA.value }
        }
        if let writeB {
            try? await smbIssue102AwaitWithTimeout("preparation WRITE B exits during fixture cleanup") { _ = try? await writeB.value }
        }
        await session.setTransferRequestOwnershipHookForTesting(nil)
        await session.setTransferCreditGrantAcceptanceGateForTesting(nil)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
        if let testFailure { throw testFailure }
    }

    func testNonTransferSendFailureClosesBeforeRefundingCredit() async throws {
        let transport = SMBWriteFailingQueryDirectoryTransport()
        let session = makeSession(transport: transport, credits: 1)
        let calls = SMBWritePipelineCounter()
        let chunk = patternedBytes(count: 65_536)
        defer {
            transport.releaseFailure()
            transport.failConnection()
        }

        let create = Task {
            try await session.create(
                treeId: 1,
                request: .read(path: "send-failure-trigger.bin", directory: false)
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 1)
        let fileId = try await smbIssue102AwaitWithTimeout("send-failure test CREATE") { try await create.value }

        let write = Task(priority: .high) {
            try await session.write(
                treeId: 1,
                fileId: fileId,
                offset: 0,
                nextChunk: { _ in
                    if calls.increment() <= 2 { return chunk }
                    return []
                }
            )
        }
        let first = try await waitForWrite(transport, offset: 0)
        XCTAssertEqual(first.length, 65_536)

        let failingRequest = Task {
            try await session.queryDirectory(treeId: 1, fileId: fileId) { _ in }
        }
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        try transport.respond(to: first, credits: 1)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 1)
        try await smbIssue102AwaitWithTimeout("failed ordinary request reached its send gate") {
            try await transport.waitUntilFailureSend()
        }
        try await waitForSupplierCalls(calls, count: 2)
        await session.waitForCreditWaiterCountForTesting(atLeast: 1)

        transport.releaseFailure()
        do {
            try await smbIssue102AwaitWithTimeout("ordinary request send failure") {
                try await failingRequest.value
            }
            XCTFail("QUERY_DIRECTORY send unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
            // A failed ordinary send terminalizes its generation.
        } catch {
            XCTFail("unexpected ordinary request send error: \(error)")
        }
        do {
            try await smbIssue102AwaitWithTimeout("WRITE joined ordinary send failure") {
                try await write.value
            }
            XCTFail("WRITE unexpectedly survived the terminal send failure")
        } catch SMBTransportError.connectionClosed {
            // The pending transfer observes the same terminal generation.
        } catch {
            XCTFail("unexpected WRITE error after terminal send failure: \(error)")
        }

        XCTAssertEqual(transport.writeRequests.map(\.offset), [0])
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_non_transfer_send_failure_test_complete")
    }

    func testCreditGrantBetweenBalanceReadAndRevisionSnapshotDoesNotLoseWakeup() async throws {
        let transport = SMBWritePipelineCreateCreditTransport()
        let session = makeSession(transport: transport, credits: 1)
        let supplier = SMBWritePipelineChunkSource(data: patternedBytes(count: 196_608))
        let grantGate = SMBContinuationAsyncGate()
        let grantEntered = SMBContinuationCountBarrier()
        defer {
            grantGate.release()
            transport.failConnection()
        }

        let writeCreate = Task {
            try await session.create(
                treeId: 1,
                request: .read(path: "write-target.bin", directory: false)
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        let writeCreateHeader = try XCTUnwrap(transport.createRequest(path: "write-target.bin"))
        try transport.respondToCreate(writeCreateHeader, credits: 4)
        let fileId = try await smbIssue102AwaitWithTimeout("credit-revision WRITE CREATE") { try await writeCreate.value }

        let creditRequest = Task {
            try await session.create(
                treeId: 1,
                request: .read(path: "credit-source.bin", directory: false)
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 2)
        let creditRequestHeader = try XCTUnwrap(transport.createRequest(path: "credit-source.bin"))

        let write = Task {
            try await session.write(
                treeId: 1,
                fileId: fileId,
                offset: 0,
                nextChunk: { maxLength in supplier.nextChunk(maxLength: maxLength) }
            )
        }
        let first = try await waitForWrite(transport, offset: 0)
        XCTAssertEqual(first.length, 196_608)
        try await waitForActiveSendTasks(session, label: "credit-revision first WRITE send owner")
        _ = await session.pendingCountForTesting()
        await session.setCreditGrantActorHookForTesting {
            grantEntered.signal()
            try? await grantGate.suspend(
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }

        try transport.respondToCreate(creditRequestHeader, credits: 1)
        try await smbIssue102AwaitWithTimeout("credit grant reached its deterministic gate") {
            try await grantEntered.waitForCount(1)
        }
        grantGate.release()
        try await waitForSupplierCalls(supplier, count: 2)

        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        try transport.respond(to: first, credits: 1)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 1)
        try await smbIssue102AwaitWithTimeout("credit-revision WRITE completion") {
            try await write.value
        }
        try await smbIssue102AwaitWithTimeout("credit-source CREATE completion") {
            _ = try await creditRequest.value
        }
        XCTAssertEqual(supplier.requestedSizes, [196_608, 65_536])
        XCTAssertEqual(transport.writeRequests.map(\.offset), [0])
        await session.setCreditGrantActorHookForTesting(nil)
        await session.closeTransportAndWait(cause: "write_credit_revision_test_complete")
    }

    func testSupplierWaitDoesNotKeepACompletedWriteOnTheWire() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let virtualTime = SMBWritePipelineVirtualClock()
        let drainSleeper = ManualSMBSleeper()
        let supplierGate = SMBContinuationAsyncGate()
        let supplierCalls = SMBWritePipelineCounter()
        let sessionTime = SMBSessionMonotonicTime(now: { virtualTime.now() }, sleep: { _ in })
        let session = makeSession(
            transport: transport,
            credits: 81,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await drainSleeper.sleep(for: $0) }
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 0)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 2)
        let totalBytes = UInt64(chunkSize * 3)
        defer {
            supplierGate.release()
            drainSleeper.fireNext()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "supplier-drain.bin",
                totalBytes: totalBytes,
                nextChunk: { _ in
                    switch supplierCalls.increment() {
                    case 1:
                        return data
                    case 2:
                        try await Task.detached {
                            try await supplierGate.suspend(
                                timeout: .seconds(60),
                                sleeper: { try await Task.sleep(for: $0) }
                            )
                        }.value
                        return []
                    default:
                        return []
                    }
                }
            )
        }

        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        let first = try await waitForWrite(transport, offset: 0)
        try await smbIssue102AwaitWithTimeout("later supplier entered its uncancellable wait") {
            try await supplierGate.waitUntilSuspended(
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        let second = try await waitForWrite(transport, offset: UInt64(chunkSize))
        try transport.respond(to: first, status: SMB2Status.accessDenied)
        try transport.respond(to: second)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 2)
        try await waitForSleeperCall(drainSleeper, count: 1, label: "WRITE wire-drain deadline")
        try await waitForActiveSendTasks(session, label: "WRITE send owner finished before deadline")

        let nowCallCount = virtualTime.nowCallCount
        virtualTime.advance(by: .seconds(30))
        drainSleeper.fireNext()
        try await smbIssue102AwaitWithTimeout("WRITE drain timer callback observed virtual deadline") {
            try await virtualTime.waitForNowCallCount(nowCallCount + 1)
        }
        _ = await session.pendingCountForTesting()
        XCTAssertEqual(transport.closeCount, 0, "a supplier wait must not trigger a shared session close")

        supplierGate.release()
        do {
            try await smbIssue102AwaitWithTimeout("original WRITE error after supplier returns") {
                try await operation.value
            }
            XCTFail("failed WRITE unexpectedly succeeded")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "WRITE") {
            // The original WRITE failure survives the supplier wait and deadline callback.
        } catch {
            XCTFail("supplier wait replaced the original WRITE error: \(error)")
        }

        let statTask = Task { try await client.stat(path: "after-supplier-drain.bin") }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 2)
        try transport.completeCreate()
        let stat = try await smbIssue102AwaitWithTimeout("shared session remains usable after supplier drain") {
            try await statTask.value
        }
        XCTAssertEqual(stat.size, 1_234)
    }

    func testEarlyWriteFailureStopsAdmissionWhileSendOwnerIsGated() async throws {
        let transport = SMBWritePipelineGatedSendTransport(gatedOffset: UInt64(chunkSize))
        let cleanupSleeper = ManualSMBSleeper()
        let session = makeSession(
            transport: transport,
            credits: 81,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 5)
        let progress = SMBWritePipelineProgressCollector()
        defer {
            transport.releaseGatedSend()
            cleanupSleeper.fireNext()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "early-final-gated-send.bin",
                data: data,
                onProgress: { progress.append($0.bytesTransferred) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        let first = try await waitForWrite(transport, offset: 0)
        let failed = try await waitForWrite(transport, offset: UInt64(chunkSize))
        let third = try await waitForWrite(transport, offset: UInt64(chunkSize * 2))
        let fourth = try await waitForWrite(transport, offset: UInt64(chunkSize * 3))
        try await smbIssue102AwaitWithTimeout("the selected WRITE send remains gated") {
            try await transport.waitUntilGatedSend()
        }

        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        try transport.respond(to: failed, status: SMB2Status.accessDenied)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 1)
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "early-final admission stop drain timer")
        try transport.respond(to: first)
        try transport.respond(to: third)
        try transport.respond(to: fourth)
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCount + 4)
        try await waitForProgress(progress, count: 1, label: "successful prefix retires before gated failure")

        transport.releaseGatedSend()
        do {
            try await smbIssue102AwaitWithTimeout("early WRITE failure after send owner returns") {
                try await operation.value
            }
            XCTFail("failed WRITE unexpectedly succeeded")
        } catch SMBError.accessDenied(status: SMB2Status.accessDenied, operation: "WRITE") {
            // The early final stops admission before its send owner returns.
        }

        XCTAssertEqual(
            transport.writeRequests.map(\.offset),
            [0, UInt64(chunkSize), UInt64(chunkSize * 2), UInt64(chunkSize * 3)]
        )
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
    }

    func testFourWritesStayOutstandingAndReverseResponsesPreserveOffsetData() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 5)
        defer { transport.failConnection() }

        let operation = Task { try await client.upload(path: "file.bin", data: data) }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        try await waitForActiveSendTasks(session, label: "four pipelined WRITE send owners")

        XCTAssertEqual(transport.writeRequests.count, 4, "the four-slot window must hold before any final")
        XCTAssertEqual(transport.writeRequests.map(\.offset), (0..<4).map { UInt64($0 * chunkSize) })
        XCTAssertEqual(transport.writeRequests.map(\.length), Array(repeating: UInt32(chunkSize), count: 4))
        for offset in (0..<4).reversed() {
            try transport.respond(to: try request(at: UInt64(offset * chunkSize), in: transport))
        }
        let fifth = try await waitForWrite(transport, offset: UInt64(chunkSize * 4))
        try transport.respond(to: fifth)
        try await smbIssue102AwaitWithTimeout("five pipelined WRITEs and FLUSH") {
            try await operation.value
        }

        let orderedRequests = transport.writeRequests.sorted { $0.offset < $1.offset }
        XCTAssertEqual(orderedRequests.map(\.header.messageId), [1, 17, 33, 49, 65])
        for request in orderedRequests {
            let start = Int(request.offset)
            let end = start + Int(request.length)
            XCTAssertEqual(request.data, Array(data[start..<end]), "WRITE bytes must match their file offsets")
        }
        XCTAssertTrue(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_pipeline_success_test_complete")
    }

    func testAsyncSupplierReentersSessionAndOversizedChunkSplitsUntilEOF() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 2 + chunkSize / 2)
        let calls = SMBWritePipelineCounter()
        let progress = SMBWritePipelineProgressCollector()
        let supplierEntered = SMBContinuationCountBarrier()
        let supplierCallbackExecution = SMBCallbackExecutionRecorder()
        let progressCallbackExecution = SMBCallbackExecutionRecorder()
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "supplier.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { _ in
                    supplierCallbackExecution.record(on: session.sessionExecutor)
                    let call = calls.increment()
                    if call == 1 {
                        supplierEntered.signal()
                        let stat = try await client.stat(path: "reentrant-stat.bin")
                        guard stat.size == 1_234 else {
                            throw SMBCodecError.invalidValue("unexpected reentrant stat result")
                        }
                        return data
                    }
                    return []
                },
                onProgress: {
                    progressCallbackExecution.record(on: session.sessionExecutor)
                    progress.append($0.bytesTransferred)
                }
            )
        }

        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await smbIssue102AwaitWithTimeout("async supplier entered") {
            try await supplierEntered.waitForCount(1)
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 2)
        try transport.completeCreate()
        _ = try await waitForWrite(transport, offset: 0)
        try await waitForProgress(progress, count: 1, label: "supplier progress before final responses")
        XCTAssertEqual(calls.value, 1, "the supplier is not called again while its array has residual bytes")
        XCTAssertEqual(progress.values.last, UInt64(data.count), "supplier progress reports bytes supplied")

        let requestCount = data.count / 65_536
        for index in 0..<requestCount {
            let request = try await waitForWrite(transport, offset: UInt64(index * 65_536))
            try transport.respond(to: request, credits: 1)
        }
        try await smbIssue102AwaitWithTimeout("oversized async supplier WRITE completion") {
            try await operation.value
        }
        let supplierCallbackContext = try XCTUnwrap(supplierCallbackExecution.observation)
        XCTAssertTrue(supplierCallbackContext.isOnExecutorQueue)
        XCTAssertTrue(supplierCallbackContext.taskExecutorMatches)
        let progressCallbackContext = try XCTUnwrap(progressCallbackExecution.observation)
        XCTAssertFalse(progressCallbackContext.isOnExecutorQueue)
        XCTAssertFalse(progressCallbackContext.taskExecutorMatches)
        XCTAssertEqual(calls.value, 2, "the supplier is called again once for EOF after its array drains")
        let requests = transport.writeRequests.sorted { $0.offset < $1.offset }
        XCTAssertEqual(requests.map(\.offset), (0..<requestCount).map { UInt64($0 * 65_536) })
        XCTAssertEqual(requests.map(\.length), Array(repeating: UInt32(65_536), count: requestCount))
        for request in requests {
            let start = Int(request.offset)
            let end = start + Int(request.length)
            XCTAssertEqual(request.data, Array(data[start..<end]))
        }
        XCTAssertTrue(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        await session.closeTransportAndWait(cause: "write_supplier_success_test_complete")
    }

    func testSynchronousFileSupplierPipelinesAndReportsSuppliedProgress() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 2 + 23)
        let sourceURL = makeScratchURL()
        try FileManager.default.createDirectory(
            at: sourceURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(data).write(to: sourceURL)
        let progress = SMBWritePipelineProgressCollector()
        defer {
            try? FileManager.default.removeItem(at: sourceURL)
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "file-source.bin",
                fileURL: sourceURL,
                onProgress: { progress.append($0.bytesTransferred) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: [0, UInt64(chunkSize), UInt64(chunkSize * 2)])
        // The file source reports once per read, and how many reads it takes depends on the credit
        // hint at each read; wait for the report that reaches the full size.
        try await smbIssue102AwaitWithTimeout("file supplier progress before final responses") {
            try await progress.waitForValue(atLeast: UInt64(data.count))
        }
        XCTAssertEqual(progress.values.last, UInt64(data.count), "file progress reports bytes read from the source")
        for offset in [UInt64(chunkSize * 2), UInt64(chunkSize), 0] {
            try transport.respond(to: request(at: offset, in: transport))
        }
        try await smbIssue102AwaitWithTimeout("sync file supplier WRITE completion") {
            try await operation.value
        }
        let requests = transport.writeRequests.sorted { $0.offset < $1.offset }
        XCTAssertEqual(requests.count, 3)
        for request in requests {
            let start = Int(request.offset)
            let end = start + Int(request.length)
            XCTAssertEqual(request.data, Array(data[start..<end]))
        }
        XCTAssertTrue(transport.sentCommands.contains(SMB2Commands.flush))
        await session.closeTransportAndWait(cause: "write_file_supplier_test_complete")
    }

    func testEarliestOffsetFailureWinsAndOnlyAcknowledgedPrefixProgresses() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let progress = SMBWritePipelineProgressCollector()
        let data = patternedBytes(count: chunkSize * 5)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "failed.bin",
                data: data,
                onProgress: { progress.append($0.bytesTransferred) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        let offsetTwo = try request(at: UInt64(chunkSize * 2), in: transport)
        let offsetOne = try request(at: UInt64(chunkSize), in: transport)
        let offsetZero = try request(at: 0, in: transport)
        let offsetThree = try request(at: UInt64(chunkSize * 3), in: transport)
        try transport.respond(to: offsetTwo, status: SMB2Status.accessDenied)
        try transport.respond(to: offsetOne, status: SMB2Status.objectNameNotFound)
        try transport.respond(to: offsetThree)
        try transport.respond(to: offsetZero)

        do {
            try await smbIssue102AwaitWithTimeout("WRITE offset failure drain") { try await operation.value }
            XCTFail("failed WRITE unexpectedly succeeded")
        } catch let error as SMBError {
            guard case .notFound(status: SMB2Status.objectNameNotFound, operation: "WRITE") = error else {
                return XCTFail("the lowest failing offset should win, got \(error)")
            }
        }

        try await waitForProgress(progress, count: 1, label: "ACK prefix after offset failure")
        XCTAssertEqual(transport.writeRequests.count, 4, "no fifth request may commit after failure")
        XCTAssertEqual(progress.values.last, UInt64(chunkSize), "only the successful prefix advances progress")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_offset_failure_test_complete")
    }

    func testShortWriteStopsAdmissionDrainsAndDoesNotFlush() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let progress = SMBWritePipelineProgressCollector()
        let data = patternedBytes(count: chunkSize * 5)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "short.bin",
                data: data,
                onProgress: { progress.append($0.bytesTransferred) }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        try transport.respond(
            to: request(at: UInt64(chunkSize), in: transport),
            count: UInt32(chunkSize - 1)
        )
        try transport.respond(to: request(at: 0, in: transport))
        try transport.respond(to: request(at: UInt64(chunkSize * 3), in: transport))
        try transport.respond(to: request(at: UInt64(chunkSize * 2), in: transport))

        do {
            try await smbIssue102AwaitWithTimeout("short WRITE drain") { try await operation.value }
            XCTFail("short WRITE unexpectedly succeeded")
        } catch let error as SMBCodecError {
            guard case .invalidValue(let message) = error else {
                return XCTFail("unexpected short WRITE error: \(error)")
            }
            XCTAssertTrue(message.contains("short SMB write"), message)
        }

        try await waitForProgress(progress, count: 1, label: "ACK prefix after short WRITE")
        XCTAssertEqual(transport.writeRequests.count, 4)
        XCTAssertEqual(progress.values.last, UInt64(chunkSize), "short WRITE does not advance the ACK prefix")
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_short_response_test_complete")
    }

    func testSupplierThrowStopsAdmissionDrainsAndReturnsOriginalError() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let calls = SMBWritePipelineCounter()
        let supplierFailure = SMBWritePipelineInjectedFailure.supplier
        let suppliedData = patternedBytes(count: chunkSize * 2)
        let totalBytes = UInt64(chunkSize * 3)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "supplier-failure.bin",
                totalBytes: totalBytes,
                nextChunk: { _ in
                    if calls.increment() == 1 { return suppliedData }
                    throw supplierFailure
                }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        _ = try await waitForWrite(transport, offset: 0)
        _ = try await waitForWrite(transport, offset: UInt64(chunkSize))
        try await waitForSupplierCalls(calls, count: 2)
        try transport.respond(to: request(at: UInt64(chunkSize), in: transport))
        try transport.respond(to: request(at: 0, in: transport))

        do {
            try await smbIssue102AwaitWithTimeout("supplier throw drain") { try await operation.value }
            XCTFail("supplier throw was lost")
        } catch SMBWritePipelineInjectedFailure.supplier {
            // The supplier's original error survives ordered wire drain.
        }
        XCTAssertEqual(transport.writeRequests.count, 2)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_supplier_failure_test_complete")
    }

    func testEarlierWireFailureOutranksLaterSupplierThrow() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let calls = SMBWritePipelineCounter()
        let invocations = SMBWritePipelineCounter()
        let supplierGate = SMBContinuationAsyncGate()
        let supplierEntered = SMBContinuationCountBarrier()
        let testChunkSize = chunkSize
        let suppliedData = patternedBytes(count: testChunkSize * 2)
        defer {
            supplierGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "supplier-offset-order.bin",
                totalBytes: UInt64(testChunkSize * 3),
                nextChunk: { _ in
                    if invocations.increment() == 1 {
                        _ = calls.increment()
                        return suppliedData
                    }
                    supplierEntered.signal()
                    try await supplierGate.suspend(
                        timeout: .seconds(60),
                        sleeper: { try await Task.sleep(for: $0) }
                    )
                    await Task.yield()
                    _ = calls.increment()
                    throw SMBWritePipelineInjectedFailure.supplier
                }
            )
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        _ = try await waitForWrite(transport, offset: 0)
        _ = try await waitForWrite(transport, offset: UInt64(testChunkSize))
        try await smbIssue102AwaitWithTimeout("second supplier callback reached its gate") {
            try await supplierEntered.waitForCount(1)
        }
        supplierGate.release()
        try await waitForSupplierCalls(calls, count: 2)
        XCTAssertEqual(calls.value, 2, "the supplier failure belongs to the next source offset")

        try transport.respond(
            to: request(at: 0, in: transport),
            status: SMB2Status.accessDenied
        )
        try transport.respond(to: request(at: UInt64(testChunkSize), in: transport))
        do {
            try await smbIssue102AwaitWithTimeout("earlier WRITE failure vs supplier throw") {
                try await operation.value
            }
            XCTFail("the supplier or wire failure was lost")
        } catch let error as SMBError {
            guard case .accessDenied(status: SMB2Status.accessDenied, operation: "WRITE") = error else {
                return XCTFail("the earlier wire failure should win, got \(error)")
            }
        }

        XCTAssertEqual(transport.writeRequests.count, 2)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_supplier_offset_order_test_complete")
    }

    func testCallerCancellationDrainsCommittedWritesWithoutNewCommitOrCancel() async throws {
        let ordering = SMBWriteCancelOrderProbe()
        let transport = SMBWritePipelineCancellationTransport(ordering: ordering)
        let cleanupSleeper = ManualSMBSleeper()
        let session = makeSession(
            transport: transport,
            credits: 81,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
        await session.setWriteTransferDrainTimerScheduledHookForTesting {
            ordering.record(.writeDrainTimerScheduled)
        }
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 5)
        defer {
            cleanupSleeper.fireNext()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(path: "cancel.bin", data: data)
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        try await waitForActiveSendTasks(session, label: "cancelled WRITE send owners")
        operation.cancel()
        let firstCancellationEvent = try await smbIssue102AwaitWithTimeout("WRITE cancellation drain or CLOSE") {
            try await ordering.waitForFirstEvent()
        }
        XCTAssertEqual(
            firstCancellationEvent,
            .writeDrainTimerScheduled,
            "the committed WRITE drain starts before upload cleanup sends CLOSE"
        )
        for offset in (0..<4).reversed() {
            try transport.respondAndRecord(to: request(at: UInt64(offset * chunkSize), in: transport))
        }

        do {
            try await smbIssue102AwaitWithTimeout("cancelled WRITE drain completion") { try await operation.value }
            XCTFail("cancelled WRITE unexpectedly succeeded")
        } catch is CancellationError {
            // The committed four requests drain before cancellation is returned.
        }
        let orderingEvents = ordering.events
        let writeResponseIndices = orderingEvents.indices.filter { index in
            if case .writeResponse = orderingEvents[index] { return true }
            return false
        }
        let closeRequestIndex = orderingEvents.firstIndex(of: .closeRequest)
        XCTAssertEqual(writeResponseIndices.count, 4, "all committed WRITE responses were delivered")
        if let closeRequestIndex, let lastWriteResponseIndex = writeResponseIndices.last {
            XCTAssertGreaterThan(
                closeRequestIndex,
                lastWriteResponseIndex,
                "upload cleanup CLOSE waits until all committed WRITEs drain"
            )
        } else {
            XCTFail("expected upload cleanup CLOSE after the committed WRITE responses")
        }
        XCTAssertEqual(transport.writeRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)

        let statTask = Task { try await client.stat(path: "after-cancel.bin") }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 2)
        try transport.completeCreate()
        let stat = try await smbIssue102AwaitWithTimeout("session remains usable after WRITE cancellation") {
            try await statTask.value
        }
        XCTAssertEqual(stat.size, 1_234)
        XCTAssertEqual(transport.closeCount, 0, "a drained caller cancellation keeps the session open")
        await session.closeTransportAndWait(cause: "write_cancellation_test_complete")
    }

    func testOperationDeadlineClosesWhenCommittedWritesCannotDrain() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let virtualTime = SMBWritePipelineVirtualClock()
        let drainSleeper = ManualSMBSleeper()
        let sessionTime = SMBSessionMonotonicTime(now: { virtualTime.now() }, sleep: { _ in })
        let session = makeSession(
            transport: transport,
            credits: 81,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await drainSleeper.sleep(for: $0) }
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 5)
        let deadline = virtualTime.now().advanced(by: .seconds(5))
        let operationContext = SMBOperationContext(now: { virtualTime.now() }, deadline: deadline)
        defer {
            drainSleeper.fireNext()
            transport.failConnection()
        }

        let operation = Task {
            try await SMBOperationDeadline.$operationContext.withValue(operationContext) {
                try await client.upload(path: "deadline.bin", data: data)
            }
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        try await waitForActiveSendTasks(session, label: "deadline WRITE send owners")
        virtualTime.advance(by: .seconds(5))
        try transport.respond(to: request(at: 0, in: transport))
        try await waitForSleeperCall(drainSleeper, count: 1, label: "deadline WRITE drain timer")
        drainSleeper.fireNext()
        try await waitForTransportClose(transport, count: 1, label: "deadline WRITE terminal close")

        do {
            try await smbIssue102AwaitWithTimeout("deadline WRITE terminal join") { try await operation.value }
            XCTFail("deadline WRITE unexpectedly succeeded")
        } catch SMBTransportError.timedOut {
            // The operation deadline outranks the drain timeout.
        } catch {
            XCTFail("unexpected deadline transfer error: \(error)")
        }
        XCTAssertEqual(transport.writeRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_deadline_test_complete")
    }

    func testWriteDrainDeadlineJoinsWireOwnersWhileAsyncSupplierIsSuspended() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let virtualTime = SMBWritePipelineVirtualClock()
        let drainSleeper = SMBKeyedManualSleeper()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { try await drainSleeper.sleep(for: $0) }
        )
        let session = makeSession(
            transport: transport,
            credits: 81,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await drainSleeper.sleep(for: $0) }
        )
        let executorEvents = SMBSessionExecutorObservationRecorder()
        session.sessionExecutor.setExecutionObserverForTesting { executorEvents.append($0) }
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 0)
        let client = SMBClientSession(session: session, treeId: 1)
        let testChunkSize = chunkSize
        let data = patternedBytes(count: testChunkSize * 2)
        let supplierCalls = SMBWritePipelineCounter()
        let supplierEntered = SMBContinuationCountBarrier()
        let supplierGate = SMBAsyncCallbackSuspensionGate()
        let readerJoinStarted = SMBContinuationCountBarrier()
        let terminalJoinCompleted = SMBContinuationCountBarrier()
        let ownershipSnapshots = SMBTransferOwnershipRecorder()
        await session.setTerminalJoinCompletedHookForTesting {
            terminalJoinCompleted.signal()
        }
        await session.setTransferRequestOwnershipHookForTesting { snapshot in
            ownershipSnapshots.append(snapshot)
        }
        await session.setReaderTaskJoinSnapshotHookForTesting { _ in
            readerJoinStarted.signal()
        }
        defer {
            supplierGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "suspended-supplier-drain.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { maximumLength in
                    let call = supplierCalls.increment()
                    if call == 1 {
                        return Array(data.prefix(maximumLength))
                    }
                    if call == 2 {
                        supplierEntered.signal()
                        await supplierGate.suspend()
                        let start = min(testChunkSize, data.count)
                        let end = min(data.count, start + maximumLength)
                        return Array(data[start..<end])
                    }
                    return []
                }
            )
        }

        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 81)
        _ = try await waitForWrite(transport, offset: 0)
        let recordsBeforeCancellation = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertGreaterThan(recordsBeforeCancellation, 0, "the drain oracle must start with live post-auth request records")
        try await smbIssue102AwaitWithTimeout("second WRITE source callback suspends") {
            try await supplierEntered.waitForCount(1)
        }
        operation.cancel()
        try await smbIssue102AwaitWithTimeout("suspended-supplier WRITE drain timer is installed") {
            await drainSleeper.waitUntilSleeping(for: .seconds(30))
        }
        let readersBeforeDeadline = await session.readerTaskCountForTesting()
        XCTAssertGreaterThan(readersBeforeDeadline, 0)

        virtualTime.advance(by: .seconds(30))
        drainSleeper.fire(for: .seconds(30))
        try await smbIssue102AwaitWithTimeout("WRITE drain deadline closes transport while supplier is suspended") {
            try await transport.waitForCloseCount(1)
        }
        try await smbIssue102AwaitWithTimeout("WRITE drain deadline starts reader join") {
            try await readerJoinStarted.waitForCount(1)
        }
        try await smbIssue102AwaitWithTimeout("WRITE terminal join completes while supplier is suspended") {
            try await terminalJoinCompleted.waitForCount(1)
        }
        let activeRecordsAfterJoin = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRecordsAfterJoin, 1, "the supplier's canonical request record remains owned until supplier return")
        let senderTasksAfterJoin = await session.senderTaskCountForTesting()
        let readerTasksAfterJoin = await session.readerTaskCountForTesting()
        let pendingAfterJoin = await session.pendingCountForTesting()
        let wireRecordsAfterJoin = await session.wirePendingRecordCountForTesting()
        let lifecycleAfterJoin = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(senderTasksAfterJoin, 0)
        XCTAssertEqual(readerTasksAfterJoin, 0)
        XCTAssertEqual(pendingAfterJoin, 0)
        XCTAssertEqual(wireRecordsAfterJoin, 0)
        XCTAssertEqual(lifecycleAfterJoin.readTransfers, 0)
        XCTAssertEqual(lifecycleAfterJoin.writeTransfers, 1)
        XCTAssertEqual(lifecycleAfterJoin.pendingReadDecodes, 0)
        XCTAssertEqual(lifecycleAfterJoin.readTimers, 0)
        XCTAssertEqual(lifecycleAfterJoin.writeTimers, 0)
        XCTAssertEqual(lifecycleAfterJoin.supplierLeases, 1)
        XCTAssertEqual(lifecycleAfterJoin.deliveryLeases, 0)
        XCTAssertEqual(lifecycleAfterJoin.slotLeases, 1)
        XCTAssertEqual(lifecycleAfterJoin.wireOperationBarriers, 0)
        let suspendedSupplierOwner = try XCTUnwrap(ownershipSnapshots.first {
            $0.command == SMB2Commands.write && $0.offset == nil && $0.supplierOwned
        }, "terminal join preserves the suspended supplier's external owner")
        XCTAssertTrue(suspendedSupplierOwner.supplierOwned)
        XCTAssertEqual(suspendedSupplierOwner.wire, .sessionTerminal)
        XCTAssertFalse(suspendedSupplierOwner.deliveryOwned)
        XCTAssertFalse(suspendedSupplierOwner.slotReleased)
        let drainWake = try XCTUnwrap(executorEvents.observation(for: .writeTransferDrainTimerWake))
        XCTAssertTrue(drainWake.isOnExecutorQueue)
        XCTAssertTrue(drainWake.taskExecutorMatches)

        supplierGate.release()
        do {
            try await smbIssue102AwaitWithTimeout("cancelled WRITE driver exits after supplier resumes") {
                try await operation.value
            }
            XCTFail("cancelled WRITE unexpectedly succeeded")
        } catch is CancellationError {
        } catch SMBTransportError.timedOut {
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(transport.writeRequests.count, 1, "bytes returned after terminal join must not be enqueued")
        let activeRecordsAfterSupplierReturn = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRecordsAfterSupplierReturn, 0)
        let senderTasksAfterSupplierReturn = await session.senderTaskCountForTesting()
        let readerTasksAfterSupplierReturn = await session.readerTaskCountForTesting()
        let pendingAfterSupplierReturn = await session.pendingCountForTesting()
        let wireRecordsAfterSupplierReturn = await session.wirePendingRecordCountForTesting()
        let lifecycleAfterSupplierReturn = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(senderTasksAfterSupplierReturn, 0)
        XCTAssertEqual(readerTasksAfterSupplierReturn, 0)
        XCTAssertEqual(pendingAfterSupplierReturn, 0)
        XCTAssertEqual(wireRecordsAfterSupplierReturn, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.readTransfers, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.writeTransfers, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.pendingReadDecodes, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.readTimers, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.writeTimers, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.supplierLeases, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.deliveryLeases, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.slotLeases, 0)
        XCTAssertEqual(lifecycleAfterSupplierReturn.wireOperationBarriers, 0)
        await session.setTransferRequestOwnershipHookForTesting(nil)
    }

    func testTransportDisconnectTerminalizesAndJoinsWrites() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: chunkSize * 5)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(path: "disconnect.bin", data: data)
        }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate()
        try await waitForWrites(transport, offsets: (0..<4).map { UInt64($0 * chunkSize) })
        try await waitForActiveSendTasks(session, label: "disconnected WRITE send owners")
        transport.failConnection()
        do {
            try await smbIssue102AwaitWithTimeout("disconnected WRITE terminal join") { try await operation.value }
            XCTFail("disconnected WRITE unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
            // The transport failure wins over the ordinary failures caused by the close.
        } catch {
            XCTFail("unexpected disconnected WRITE error: \(error)")
        }

        XCTAssertEqual(transport.writeRequests.count, 4)
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.flush))
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_disconnect_test_complete")
    }

    func testSingleCreditWritesKeepSerialLengthsAndMessageIds() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 1)
#if DEBUG
        let (executorEvents, executorEventContinuation) = AsyncStream.makeStream(of: SMBSessionExecutorObservation.self)
        session.sessionExecutor.setExecutionObserverForTesting { observation in
            executorEventContinuation.yield(observation)
        }
        let sessionExecutorContext = await session.executionContextForTesting()
#endif
        let client = SMBClientSession(session: session, treeId: 1)
        let data = patternedBytes(count: 130_000)
        defer { transport.failConnection() }

        let operation = Task { try await client.upload(path: "one-credit.bin", data: data) }
        try await waitForCommand(transport, SMB2Commands.create, occurrence: 1)
        try transport.completeCreate(credits: 1)
        _ = try await waitForWrite(transport, offset: 0)
        XCTAssertEqual(transport.writeRequests.count, 1, "one available credit permits one 64 KiB WRITE")
        try transport.respond(to: request(at: 0, in: transport), credits: 1)
        _ = try await waitForWrite(transport, offset: 65_536)
        XCTAssertEqual(transport.writeRequests.count, 2)
        try transport.respond(to: request(at: 65_536, in: transport), credits: 1)
        try await smbIssue102AwaitWithTimeout("single-credit WRITE completion") {
            try await operation.value
        }

        let requests = transport.writeRequests.sorted { $0.offset < $1.offset }
        XCTAssertEqual(requests.map(\.length), [65_536, 64_464])
        XCTAssertEqual(requests.map(\.header.messageId), [1, 2])
        XCTAssertEqual(requests.flatMap(\.data), data)
        XCTAssertTrue(transport.sentCommands.contains(SMB2Commands.flush))
        XCTAssertFalse(transport.sentCommands.contains(SMB2Commands.cancel))
        await session.closeTransportAndWait(cause: "write_single_credit_test_complete")
#if DEBUG
        executorEventContinuation.finish()

        var observations: [SMBSessionExecutorProbePoint: SMBSessionExecutorObservation] = [:]
        for await observation in executorEvents {
            observations[observation.point] = observation
        }
        for point in [SMBSessionExecutorProbePoint.writeDriver, .writeDriverAfterStep] {
            let observation = try XCTUnwrap(observations[point], "missing execution probe for \(point)")
            XCTAssertTrue(observation.isOnExecutorQueue)
            XCTAssertTrue(observation.taskExecutorMatches)
            XCTAssertEqual(observation.executorIdentity, sessionExecutorContext.executorIdentity)
        }
#endif
    }

    private func makeSession(
        transport: SMBWritePipelineScriptTransport,
        credits: UInt32,
        sessionTime: SMBSessionMonotonicTime = .production(),
        cleanupTimeoutSleeper: (@Sendable (Duration) async throws -> Void)? = nil
    ) -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: credits,
            cleanupTimeout: .seconds(30),
            requestTimeout: nil,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: cleanupTimeoutSleeper,
            debugLogger: .environment
        )
    }

    private func waitForCommand(
        _ transport: SMBWritePipelineScriptTransport,
        _ command: UInt16,
        occurrence: Int
    ) async throws {
        try await smbIssue102AwaitWithTimeout("WRITE test command \(command) occurrence \(occurrence)") {
            try await transport.waitForCommand(command, occurrence: occurrence)
        }
    }

    private func waitForWrite(
        _ transport: SMBWritePipelineScriptTransport,
        offset: UInt64
    ) async throws -> SMBWritePipelineScriptTransport.WriteRequest {
        try await smbIssue102AwaitWithTimeout("WRITE at offset \(offset)") {
            try await transport.waitForWrite(atOffset: offset)
        }
    }

    private func waitForWrites(
        _ transport: SMBWritePipelineScriptTransport,
        offsets: [UInt64]
    ) async throws {
        for offset in offsets {
            _ = try await waitForWrite(transport, offset: offset)
        }
    }

    private func waitForActiveSendTasks(_ session: SMBSession, label: String) async throws {
        _ = try await smbIssue102AwaitWithTimeout(label) {
            await session.waitForActiveSendTasksForTesting()
            return true
        }
    }

    private func waitForSupplierCalls(_ supplier: SMBWritePipelineChunkSource, count: Int) async throws {
        try await smbIssue102AwaitWithTimeout("supplier call count \(count)") {
            try await supplier.waitForCallCount(count)
        }
    }

    private func waitForSupplierCalls(_ counter: SMBWritePipelineCounter, count: Int) async throws {
        try await smbIssue102AwaitWithTimeout("supplier callback entered \(count) times") {
            try await counter.waitForCount(count)
        }
    }

    private func waitForSleeperCall(
        _ sleeper: ManualSMBSleeper,
        count: Int,
        label: String
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await sleeper.waitUntilCallCount(
                atLeast: count,
                timeout: .seconds(60),
                sleeper: { try await Task.sleep(for: $0) }
            )
        }
    }

    private func waitForTransportClose(
        _ transport: SMBWritePipelineScriptTransport,
        count: Int,
        label: String
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await transport.waitForCloseCount(count)
        }
    }

    private func waitForProgress(
        _ progress: SMBWritePipelineProgressCollector,
        count: Int,
        label: String
    ) async throws {
        try await smbIssue102AwaitWithTimeout(label) {
            try await progress.waitForCount(count)
        }
    }

    private func request(
        at offset: UInt64,
        in transport: SMBWritePipelineScriptTransport
    ) throws -> SMBWritePipelineScriptTransport.WriteRequest {
        try XCTUnwrap(transport.writeRequests.first { $0.offset == offset }, "missing WRITE at offset \(offset)")
    }

    private func patternedBytes(count: Int) -> [UInt8] {
        (0..<count).map { index in
            let block = index / 65_536
            let offset = index % 65_536
            return UInt8(truncatingIfNeeded: block &* 73 &+ offset &* 31)
        }
    }

    private func makeScratchURL() -> URL {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("tmp", isDirectory: true)
            .appendingPathComponent("write-source-\(UUID().uuidString).bin")
    }
}

private enum SMBWritePipelineInjectedFailure: Error, Sendable {
    case supplier
    case transportSend
}

private final class SMBWriteFailingQueryDirectoryTransport: SMBWritePipelineScriptTransport, @unchecked Sendable {
    private let failureGate = SMBContinuationAsyncGate()
    private let failureEntered = SMBContinuationCountBarrier()

    override func send(_ bytes: [UInt8]) async throws {
        guard bytes.count >= 8,
              Array(bytes[4..<8]) == [0xfe, 0x53, 0x4d, 0x42],
              let header = try? SMB2Header.decode(Array(bytes.dropFirst(4))),
              header.command == SMB2Commands.queryDirectory else {
            try await super.send(bytes)
            return
        }
        try await super.send(bytes)
        failureEntered.signal()
        try await failureGate.suspend(
            timeout: .seconds(60),
            sleeper: { try await Task.sleep(for: $0) }
        )
        throw SMBWritePipelineInjectedFailure.transportSend
    }

    func waitUntilFailureSend() async throws {
        try await failureEntered.waitForCount(1)
    }

    func releaseFailure() {
        failureGate.release()
    }
}

private final class SMBWritePipelineCreateCreditTransport: SMBWritePipelineScriptTransport, @unchecked Sendable {
    private let createLock = NSLock()
    private var createRequestsByPath: [String: SMB2Header] = [:]

    override func send(_ bytes: [UInt8]) async throws {
        if bytes.count >= 8,
           Array(bytes[4..<8]) == [0xfe, 0x53, 0x4d, 0x42],
           let header = try? SMB2Header.decode(Array(bytes.dropFirst(4))),
           header.command == SMB2Commands.create,
           let path = Self.createPath(bytes) {
            createLock.withLock { createRequestsByPath[path] = header }
        }
        try await super.send(bytes)
    }

    func createRequest(path: String) -> SMB2Header? {
        createLock.withLock { createRequestsByPath[path] }
    }

    private static func createPath(_ bytes: [UInt8]) -> String? {
        let packet = Array(bytes.dropFirst(4))
        guard packet.count >= SMB2Header.encodedSize + 56 else { return nil }
        var nameRangeReader = SMBByteReader(bytes: Array(packet[108..<112]))
        guard let offset = try? nameRangeReader.readUInt16LE(),
              let length = try? nameRangeReader.readUInt16LE(),
              Int(offset) + Int(length) <= packet.count,
              length.isMultiple(of: 2) else {
            return nil
        }
        let encodedName = Array(packet[Int(offset)..<(Int(offset) + Int(length))])
        let utf16Units = stride(from: 0, to: encodedName.count, by: 2).map { index in
            UInt16(encodedName[index]) | (UInt16(encodedName[index + 1]) << 8)
        }
        return String(decoding: utf16Units, as: UTF16.self)
    }
}

private final class SMBWritePipelineCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0
    private let callBarrier = SMBContinuationCountBarrier()

    func increment() -> Int {
        let value = lock.withLock {
            storage += 1
            return storage
        }
        callBarrier.signal()
        return value
    }

    var value: Int { lock.withLock { storage } }

    func waitForCount(_ count: Int) async throws {
        try await callBarrier.waitForCount(count)
    }
}

private final class SMBWritePipelineTransferGrantRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt16: SMBRequestIdentity] = [:]

    func record(identity: SMBRequestIdentity, charge: UInt16) {
        lock.withLock { storage[charge] = identity }
    }

    func identity(forCharge charge: UInt16) -> SMBRequestIdentity? {
        lock.withLock { storage[charge] }
    }
}

private final class SMBWritePipelineRefundDispatchRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt16] = []

    func record(_ charge: UInt16) -> Int {
        lock.withLock {
            storage.append(charge)
            return storage.count
        }
    }

    var charges: [UInt16] { lock.withLock { storage } }
}

private final class SMBTransferOwnershipRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBTransferRequestOwnershipSnapshot] = []
    private let snapshotBarrier = SMBContinuationCountBarrier()

    func append(_ snapshot: SMBTransferRequestOwnershipSnapshot) {
        lock.withLock { storage.append(snapshot) }
        snapshotBarrier.signal()
    }

    var snapshots: [SMBTransferRequestOwnershipSnapshot] { lock.withLock { storage } }

    func first(where predicate: (SMBTransferRequestOwnershipSnapshot) -> Bool) -> SMBTransferRequestOwnershipSnapshot? {
        lock.withLock { storage.first(where: predicate) }
    }

    func latest(for identity: SMBRequestIdentity) -> SMBTransferRequestOwnershipSnapshot? {
        lock.withLock { storage.last(where: { $0.identity == identity }) }
    }

    func latest(
        for identity: SMBRequestIdentity,
        where predicate: (SMBTransferRequestOwnershipSnapshot) -> Bool
    ) -> SMBTransferRequestOwnershipSnapshot? {
        lock.withLock { storage.last(where: { $0.identity == identity && predicate($0) }) }
    }

    func waitForSnapshot(
        for identity: SMBRequestIdentity,
        where predicate: @Sendable (SMBTransferRequestOwnershipSnapshot) -> Bool
    ) async throws -> SMBTransferRequestOwnershipSnapshot {
        while true {
            let nextSnapshotCount = snapshotBarrier.currentCount + 1
            if let snapshot = latest(for: identity), predicate(snapshot) {
                return snapshot
            }
            try await snapshotBarrier.waitForCount(nextSnapshotCount)
        }
    }
}

private final class SMBWritePipelineProgressCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt64] = []
    private let progressBarrier = SMBContinuationCountBarrier()

    func append(_ bytesTransferred: UInt64) {
        lock.withLock { storage.append(bytesTransferred) }
        progressBarrier.signal()
    }

    var values: [UInt64] { lock.withLock { storage } }

    func waitForCount(_ count: Int) async throws {
        try await progressBarrier.waitForCount(count)
    }

    /// Waits for a report of at least `target` bytes. The number of reports depends on how the
    /// source is read (credit-sized hints), so tests that care about the final value wait on it.
    func waitForValue(atLeast target: UInt64) async throws {
        while true {
            let snapshot = lock.withLock { storage }
            if let last = snapshot.last, last >= target { return }
            try await progressBarrier.waitForCount(snapshot.count + 1)
        }
    }
}

private final class SMBWritePipelineChunkSource: @unchecked Sendable {
    private let lock = NSLock()
    private let data: [UInt8]
    private var cursor = 0
    private var sizes: [Int] = []
    private let callBarrier = SMBContinuationCountBarrier()

    init(data: [UInt8]) {
        self.data = data
    }

    var requestedSizes: [Int] { lock.withLock { sizes } }

    func nextChunk(maxLength: Int) -> [UInt8] {
        let chunk = lock.withLock { () -> [UInt8] in
            sizes.append(maxLength)
            let length = min(maxLength, data.count - cursor)
            let chunk = Array(data[cursor..<(cursor + length)])
            cursor += length
            return chunk
        }
        callBarrier.signal()
        return chunk
    }

    func waitForCallCount(_ count: Int) async throws {
        try await callBarrier.waitForCount(count)
    }
}

private final class SMBWritePipelineVirtualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    private let nowCallBarrier = SMBContinuationCountBarrier()

    var nowCallCount: Int { nowCallBarrier.currentCount }

    func now() -> ContinuousClock.Instant {
        let current = lock.withLock { instant }
        nowCallBarrier.signal()
        return current
    }

    func advance(by duration: Duration) {
        lock.withLock { instant += duration }
    }

    func waitForNowCallCount(_ count: Int) async throws {
        try await nowCallBarrier.waitForCount(count)
    }
}

private final class SMBWriteCancelOrderProbe: @unchecked Sendable {
    enum Event: Equatable, Sendable {
        case writeDrainTimerScheduled
        case closeRequest
        case writeResponse(UInt64)
    }

    private enum WaiterRegistration {
        case cancelled
        case ready(Event)
        case waiting
    }

    private let lock = NSLock()
    private var eventStorage: [Event] = []
    private var firstEvent: Event?
    private var waiters: [UUID: CheckedContinuation<Event, Error>] = [:]

    var events: [Event] { lock.withLock { eventStorage } }

    func record(_ event: Event) {
        let ready = lock.withLock { () -> [CheckedContinuation<Event, Error>] in
            eventStorage.append(event)
            guard firstEvent == nil else { return [] }
            firstEvent = event
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        ready.forEach { $0.resume(returning: event) }
    }

    func waitForFirstEvent() async throws -> Event {
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let registration = lock.withLock { () -> WaiterRegistration in
                    if Task.isCancelled { return .cancelled }
                    if let firstEvent { return .ready(firstEvent) }
                    waiters[waiterID] = continuation
                    return .waiting
                }
                switch registration {
                case .cancelled:
                    continuation.resume(throwing: CancellationError())
                case .ready(let event):
                    continuation.resume(returning: event)
                case .waiting:
                    break
                }
            }
        } onCancel: {
            self.cancelWaiter(waiterID)
        }
    }

    private func cancelWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { waiters.removeValue(forKey: waiterID) }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class SMBWritePipelineCancellationTransport: SMBWritePipelineScriptTransport, @unchecked Sendable {
    private let ordering: SMBWriteCancelOrderProbe

    init(ordering: SMBWriteCancelOrderProbe) {
        self.ordering = ordering
        super.init()
    }

    override func send(_ bytes: [UInt8]) async throws {
        if bytes.count >= SMB2Header.encodedSize + 4,
           Array(bytes[4..<8]) == [0xfe, 0x53, 0x4d, 0x42],
           let header = try? SMB2Header.decode(Array(bytes.dropFirst(4))),
           header.command == SMB2Commands.close {
            ordering.record(.closeRequest)
        }
        try await super.send(bytes)
    }

    func respondAndRecord(to request: WriteRequest) throws {
        ordering.record(.writeResponse(request.header.messageId))
        try respond(to: request)
    }
}
