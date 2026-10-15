import Foundation
import XCTest
@testable import SMBee

final class SMBTransferM4Tests: XCTestCase {
    private let chunkSize = 1_048_576

#if DEBUG
    func testMixedReadWriteAndOrdinaryRequestsShareTheMIDSequenceAcrossUnsentRetirement() async throws {
        let transport = SMBM4HeaderRecordingTransport()
        let testChunkSize = chunkSize
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let retirementRefunds = SMBM4RefundRecorder()
        let ownership = SMBM4OwnershipRecorder()
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            guard case .refundPending(let charge) = point else { return }
            retirementRefunds.append(charge)
        }
        await session.setTransferRequestOwnershipHookForTesting { ownership.append($0) }
        let firstReadSendEntered = SMBContinuationCountBarrier()
        let releaseFirstReadSend = SMBAsyncCallbackSuspensionGate()
        transport.installAfterReadSendHook { request in
            guard request.offset == 0 else { return }
            firstReadSendEntered.signal()
            await releaseFirstReadSend.suspend()
        }
        defer {
            releaseFirstReadSend.release()
            transport.failConnection()
        }

        let read = Task {
            try await client.read(path: "mixed-read.bin", knownSize: UInt64(testChunkSize * 4))
        }
        try await bounded("mixed READ CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("first mixed READ reaches the transport") {
            try await transport.waitForReadCount(1)
        }
        _ = try await bounded("three later READ tickets are queued behind the gated first send") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 3)
            return true
        }

        let ordinary = Task {
            try await session.queryInfo(treeId: 1, fileId: Array(repeating: 0x44, count: 16))
        }
        _ = try await bounded("ordinary QUERY_INFO queues behind the transfer tickets") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 4)
            return true
        }
        try await bounded("first READ send owner is held after the request reaches the server") {
            try await firstReadSendEntered.waitForCount(1)
        }

        let balanceBeforeShortRead = await session.creditBalanceForTesting()
        let writeData = Array(repeating: UInt8(0xc5), count: chunkSize * 2)
        let write = Task {
            try await session.write(
                treeId: 1,
                fileId: Array(repeating: 0x55, count: 16),
                data: writeData
            )
        }
        // The unchanged success path reaches this state in under 50 ms locally;
        // the 3-second cap is over 60x larger and bounds a READ/WRITE overlap regression.
        let liveTransfers = try await bounded("READ and WRITE windows are simultaneously live") {
            while true {
                try Task.checkCancellation()
                let lifecycle = await session.transferLifecycleCountsForTesting()
                if lifecycle.readTransfers == 1 && lifecycle.writeTransfers == 1 { return lifecycle }
                await Task.yield()
            }
        }
        XCTAssertEqual(liveTransfers.readTransfers, 1)
        XCTAssertEqual(liveTransfers.writeTransfers, 1)
        // The mixed fixture completes in under 50 ms locally; the 3-second cap is over 60x larger.
        let reservedWrite: Bool
        do {
            reservedWrite = try await bounded("WRITE has its own reserved ticket while READ remains live") {
                while ownership.first(where: {
                    $0.command == SMB2Commands.write && $0.reservedCharge > 0
                }) == nil {
                    try Task.checkCancellation()
                    await Task.yield()
                }
                return true
            }
        } catch {
            XCTFail("bounded wait for a WRITE reservation while READ is live failed: \(error)")
            return
        }
        XCTAssertTrue(reservedWrite)
        // Before WRITE starts, the send-gated queue contains the three READ tickets and QUERY_INFO.
        // This command-specific count proves a WRITE transfer ticket was queued before the short READ.
        _ = try await bounded("WRITE ticket is queued before short READ retirement") {
            while await session.queuedTransferRequestCountForTesting(command: SMB2Commands.write) == 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
            return true
        }
        let initialRead = try XCTUnwrap(transport.readRequests.first { $0.offset == 0 })
        try transport.respond(
            to: initialRead,
            payload: Array(repeating: 0xa0, count: chunkSize / 2),
            credits: 16
        )
        _ = try await bounded("short READ retires its queued old-epoch tickets") {
            await session.waitForReadTransfersStoppedForTesting()
            return true
        }
        releaseFirstReadSend.release()

        try await bounded("READ rebase reaches the four-slot window") {
            try await transport.waitForReadCount(5)
        }
        _ = try await bounded("ordinary QUERY_INFO completes between READ epochs") {
            try await ordinary.value
        }
        let lifecycleAfterOrdinary = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(lifecycleAfterOrdinary.readTransfers, 1)
        XCTAssertEqual(lifecycleAfterOrdinary.writeTransfers, 1)
        let rebaseReads = transport.readRequests.filter { $0.offset != 0 }
        XCTAssertEqual(rebaseReads.map(\.offset), [
            UInt64(chunkSize / 2),
            UInt64(chunkSize + chunkSize / 2),
            UInt64(chunkSize * 2 + chunkSize / 2),
            UInt64(chunkSize * 3 + chunkSize / 2)
        ])
        for request in rebaseReads.reversed() {
            let fill: UInt8 = switch request.offset {
            case UInt64(chunkSize / 2): 0xb1
            case UInt64(chunkSize + chunkSize / 2): 0xb2
            case UInt64(chunkSize * 2 + chunkSize / 2): 0xb3
            default: 0xb4
            }
            try transport.respond(
                to: request,
                payload: Array(repeating: fill, count: Int(request.length)),
                credits: 16
            )
        }
        let readBytes = try await bounded("mixed READ completes after offset rebase") {
            try await read.value
        }
        var expectedRead = Array(repeating: UInt8(0xa0), count: chunkSize / 2)
        expectedRead += Array(repeating: UInt8(0xb1), count: chunkSize)
        expectedRead += Array(repeating: UInt8(0xb2), count: chunkSize)
        expectedRead += Array(repeating: UInt8(0xb3), count: chunkSize)
        expectedRead += Array(repeating: UInt8(0xb4), count: chunkSize / 2)
        XCTAssertEqual(readBytes, expectedRead, "short-read rebase must neither duplicate nor skip bytes")
        let lifecycleAfterReadSuccess = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(lifecycleAfterReadSuccess.readTransfers, 0)
        XCTAssertEqual(lifecycleAfterReadSuccess.writeTransfers, 1, "READ completion must leave the overlapping WRITE owner live")
        XCTAssertEqual(transport.closeCount, 0, "READ recovery is observed before session close")

        _ = try await bounded("mixed WRITE requests") {
            _ = try await transport.waitForWrite(atOffset: 0)
            _ = try await transport.waitForWrite(atOffset: UInt64(1_048_576))
            return true
        }
        for request in transport.writeRequests.reversed() {
            try transport.respond(to: request, credits: 16)
        }
        try await bounded("mixed WRITE completes") {
            try await write.value
        }
        // The successful READ/WRITE pair returns in under 50 ms locally; this shared
        // 3-second cap is over 60x larger and observes recovery while the session stays open.
        let recovery = try await waitForRecovery(session, label: "mixed READ/WRITE success recovery")
        XCTAssertEqual(recovery.records, 0)
        XCTAssertEqual(recovery.pending, 0)
        XCTAssertEqual(recovery.lifecycle.readTransfers, 0)
        XCTAssertEqual(recovery.lifecycle.writeTransfers, 0)
        XCTAssertEqual(recovery.lifecycle.slotLeases, 0)
        XCTAssertEqual(recovery.lifecycle.readTimers, 0)
        XCTAssertEqual(recovery.lifecycle.writeTimers, 0)
        XCTAssertEqual(transport.closeCount, 0, "WRITE recovery is observed before session close")
        XCTAssertEqual(retirementRefunds.charges.sorted(), [16, 16, 16], "the three unsent READ reservations are refunded once each")
        let finalCreditBalance = await session.creditBalanceForTesting()
        XCTAssertEqual(
            finalCreditBalance,
            balanceBeforeShortRead + 73,
            "all scripted READ/QUERY_INFO/CLOSE grants and the three 16-credit refunds are reflected while the session stays open"
        )
        await session.setTransferRequestOwnershipHookForTesting(nil)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)

        let headers = transport.outgoingHeaders
        XCTAssertTrue(headers.contains { $0.command == SMB2Commands.queryInfo })
        XCTAssertTrue(headers.contains { $0.command == SMB2Commands.read })
        XCTAssertTrue(headers.contains { $0.command == SMB2Commands.write })
        var nextMessageId: UInt64 = 0
        for header in headers {
            XCTAssertEqual(
                header.messageId,
                nextMessageId,
                "ordinary and transfer requests must share one MID cursor; retired tickets consume no range"
            )
            let independentlyExpectedCharge: UInt16
            switch header.command {
            case SMB2Commands.read:
                let request = try XCTUnwrap(transport.readRequests.first { $0.header.messageId == header.messageId })
                let responseLength = request.offset == 0 ? UInt64(chunkSize / 2) : UInt64(request.length)
                independentlyExpectedCharge = protocolCreditCharge(
                    requestLength: UInt64(request.length),
                    responseLength: responseLength
                )
                XCTAssertEqual(header.creditCharge, independentlyExpectedCharge)
            case SMB2Commands.write:
                let request = try XCTUnwrap(transport.writeRequests.first { $0.header.messageId == header.messageId })
                independentlyExpectedCharge = protocolCreditCharge(
                    requestLength: UInt64(request.length),
                    responseLength: 0
                )
                XCTAssertEqual(header.creditCharge, independentlyExpectedCharge)
            case SMB2Commands.create, SMB2Commands.close, SMB2Commands.queryInfo:
                // These ordinary commands encode CreditCharge as zero; the MID
                // allocator still reserves one MessageId for each request.
                XCTAssertEqual(header.creditCharge, 0)
                independentlyExpectedCharge = 1
            default:
                XCTFail("unexpected command in the mixed MID sequence: \(header.command)")
                independentlyExpectedCharge = 1
            }
            nextMessageId += UInt64(independentlyExpectedCharge)
        }
        let queryInfoHeader = try XCTUnwrap(headers.first { $0.command == SMB2Commands.queryInfo })
        XCTAssertEqual(queryInfoHeader.messageId, 17, "the three unsent old-epoch tickets leave no MID hole")
    }

    func testReadCreditChargeUsesTheSMB2RoundingRuleAtANonIntegralBoundary() async throws {
        let payloadLength = 65_537
        let transport = SMBReadPipelineScriptTransport()
        let session = makeReadSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.read(path: "non-integral-credit-charge.bin", knownSize: UInt64(payloadLength))
        }
        try await bounded("non-integral charge CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("65,537-byte READ is sent") { try await transport.waitForReadCount(1) }

        let firstRequest = try XCTUnwrap(transport.readRequests.first)
        let expectedCharge = protocolCreditCharge(
            requestLength: UInt64(payloadLength),
            responseLength: UInt64(payloadLength)
        )
        XCTAssertEqual(expectedCharge, 2)
        XCTAssertEqual(firstRequest.length, UInt32(payloadLength))
        XCTAssertEqual(firstRequest.header.creditCharge, expectedCharge)

        var bytesResponded = 0
        var nextRequestIndex = 0
        while bytesResponded < payloadLength {
            if nextRequestIndex > 0 {
                let nextReadCount = nextRequestIndex + 1
                _ = try await bounded("non-integral READ rebase") {
                    try await transport.waitForReadCount(nextReadCount)
                    return true
                }
            }
            let request = nextRequestIndex == 0
                ? firstRequest
                : try XCTUnwrap(transport.readRequests.dropFirst(nextRequestIndex).first)
            let responseLength = min(Int(request.length), payloadLength - bytesResponded)
            try transport.respond(
                to: request,
                payload: Array(repeating: 0x9b, count: responseLength),
                credits: 1
            )
            bytesResponded += responseLength
            nextRequestIndex += 1
        }

        let result = try await bounded("non-integral READ completes") { try await operation.value }
        XCTAssertEqual(result.count, payloadLength)
        XCTAssertTrue(result.allSatisfy { $0 == 0x9b })
        let recovered = try await waitForRecovery(session, label: "non-integral READ recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testUnsentRefundUsesTheActualPartialReservationRatherThanItsMaximum() async throws {
        let transport = SMBReadPipelineScriptTransport()
        let session = makeReadSession(transport: transport, credits: 1)
        let client = SMBClientSession(session: session, treeId: 1)
        let testChunkSize = chunkSize
        let refunds = SMBM4RefundRecorder()
        let ownership = SMBM4OwnershipRecorder()
        let firstSendEntered = SMBContinuationCountBarrier()
        let releaseFirstSend = SMBAsyncCallbackSuspensionGate()
        await session.setCleanupCreditRefundInterleavingHookForTesting { point in
            guard case .refundPending(let charge) = point else { return }
            refunds.append(charge)
        }
        await session.setTransferRequestOwnershipHookForTesting { ownership.append($0) }
        transport.installAfterReadSendHook { request in
            guard request.offset == 0 else { return }
            firstSendEntered.signal()
            await releaseFirstSend.suspend()
        }
        defer {
            releaseFirstSend.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.read(path: "partial-reservation-refund.bin", knownSize: UInt64(testChunkSize * 4))
        }
        try await bounded("partial refund CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 56)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("partial refund first READ") { try await transport.waitForReadCount(1) }
        try await bounded("partial refund first READ send gate") {
            try await firstSendEntered.waitForCount(1)
        }
        _ = try await bounded("three later READ tickets are queued") {
            await session.waitForQueuedPostAuthRequestCountForTesting(atLeast: 3)
            return true
        }
        // The unmutated fixture reaches the partial reservation in under 5 ms locally; the 3-second cap is over 600x larger.
        let partialReservation = try await bounded("last queued READ reserves eight of sixteen credits") {
            while true {
                try Task.checkCancellation()
                if let snapshot = ownership.first(where: {
                    $0.command == SMB2Commands.read
                        && $0.reservedCharge == 8
                        && $0.credit == .reserved(maximumCharge: 16)
                }) {
                    return snapshot
                }
                await Task.yield()
            }
        }
        XCTAssertEqual(partialReservation.credit, .reserved(maximumCharge: 16))
        XCTAssertEqual(partialReservation.reservedCharge, 8)
        let balanceBeforeCancellation = await session.creditBalanceForTesting()

        operation.cancel()
        _ = try await bounded("cancel retires the queued READ reservations") {
            await session.waitForReadTransfersStoppedForTesting()
            return true
        }
        releaseFirstSend.release()
        let committedRead = try XCTUnwrap(transport.readRequests.first)
        try transport.respond(
            to: committedRead,
            payload: Array(repeating: 0x7e, count: Int(committedRead.length)),
            credits: 16
        )
        do {
            _ = try await bounded("partial refund cancelled READ exits") { try await operation.value }
            XCTFail("cancelled READ unexpectedly succeeded")
        } catch is CancellationError {
            // The committed READ drains; the three unsent reservations refund their actual amounts.
        }
        let recovered = try await waitForRecovery(session, label: "partial reservation refund recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(refunds.charges.sorted(), [8, 16, 16])
        let balanceAfterCancellation = await session.creditBalanceForTesting()
        XCTAssertEqual(balanceAfterCancellation, balanceBeforeCancellation + 56)
        XCTAssertEqual(transport.closeCount, 0)
        await session.setTransferRequestOwnershipHookForTesting(nil)
        await session.setCleanupCreditRefundInterleavingHookForTesting(nil)
    }

    func testReadCallbackFailureRacingCancellationReleasesItsOwnerOnce() async throws {
        let transport = SMBReadPipelineScriptTransport()
        let testChunkSize = chunkSize
        let session = makeReadSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackEntered = SMBContinuationCountBarrier()
        let callbackGate = SMBAsyncCallbackSuspensionGate()
        let callbackCalls = SMBM4Counter()
        defer {
            callbackGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "callback-cancel.bin", knownSize: UInt64(testChunkSize)) { _ in
                _ = callbackCalls.increment()
                callbackEntered.signal()
                await callbackGate.suspend()
                throw SMBM4InjectedFailure.callback
            }
        }
        try await bounded("callback/cancel READ CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("callback/cancel READ request") { try await transport.waitForReadCount(1) }
        try transport.respond(to: try XCTUnwrap(transport.readRequests.first), payload: Array(repeating: 0x61, count: chunkSize))
        try await bounded("READ callback starts") { try await callbackEntered.waitForCount(1) }

        operation.cancel()
        _ = try await bounded("caller cancellation reaches the READ transfer") {
            await session.waitForReadTransfersStoppedForTesting()
            return true
        }
        callbackGate.release()
        do {
            try await bounded("callback failure/cancel result") { try await operation.value }
            XCTFail("cancelled callback unexpectedly succeeded")
        } catch is CancellationError {
            // Caller cancellation is the existing transfer stop priority.
        }
        XCTAssertEqual(callbackCalls.value, 1)
        let recovered = try await waitForRecovery(session, label: "READ callback/cancel owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.deliveryLeases, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        XCTAssertEqual(recovered.lifecycle.readTimers, 0)
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testReadCallbackFailureBeforeCancellationStillReleasesItsOwnerOnce() async throws {
        let transport = SMBReadPipelineScriptTransport()
        let cleanupSleeper = SMBKeyedManualSleeper()
        let testChunkSize = chunkSize
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 81,
            cleanupTimeout: .seconds(30),
            requestTimeout: nil,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) },
            debugLogger: .environment
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let callbackReturned = SMBContinuationCountBarrier()
        let callbackCalls = SMBM4Counter()
        let timerCancellationGate = SMBM4TimerCancellationGate()
        await session.setReadTransferDrainTimerWillJoinHookForTesting {
            timerCancellationGate.select($0)
        }
        await session.setReadTransferDrainTimerCancellationHookForTesting {
            await timerCancellationGate.holdIfSelected($0)
        }
        defer {
            timerCancellationGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "callback-before-cancel.bin", knownSize: UInt64(testChunkSize * 4)) { _ in
                _ = callbackCalls.increment()
                defer { callbackReturned.signal() }
                throw SMBM4InjectedFailure.callback
            }
        }
        let operationReturned = SMBContinuationCountBarrier()
        let operationCompletion = Task {
            do { try await operation.value } catch {}
            operationReturned.signal()
        }
        try await bounded("callback-first READ CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("callback-first READ window") { try await transport.waitForReadCount(4) }
        let committed = transport.readRequests
        try transport.respond(to: committed[0], payload: Array(repeating: 0x62, count: testChunkSize))
        try await bounded("callback failure returns before cancellation") {
            try await callbackReturned.waitForCount(1)
        }
        // This guarded case completed in 7 ms locally; the 3-second cap is over 400x larger
        // and makes a missing stop transition fail boundedly instead of hanging.
        _ = try await bounded("callback failure is recorded before later cancellation") {
            await session.waitForReadTransfersStoppedForTesting()
            return true
        }
        // The callback-first fixture completes in under 10 ms locally; this 3-second
        // bounded registration wait is over 300x larger and confirms the real timer Task sleeps.
        _ = try await bounded("callback failure registers its production drain timer") {
            while cleanupSleeper.activeSleepCount == 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
            return true
        }

        operation.cancel()
        for request in committed.dropFirst() {
            try transport.respond(to: request, payload: Array(repeating: 0x63, count: testChunkSize))
        }
        _ = try await bounded("READ operation selects its timer Task for join") {
            try await timerCancellationGate.waitUntilSelected()
            return true
        }
        _ = try await bounded("selected timer Task enters its held cancellation hook") {
            try await timerCancellationGate.waitUntilEntered()
            return true
        }
        // The operation returns in under 10 ms after release; this 250 ms cap is over 25x larger.
        // The test hook holds the timer Task itself after its sleeper continuation is resumed.
        do {
            _ = try await smbIssue102AwaitWithTimeout(
                "READ operation waits for the cancelled drain timer Task to exit",
                timeout: .milliseconds(250)
            ) {
                try await operationReturned.waitForCount(1)
                return true
            }
            XCTFail("READ returned before its cancelled drain timer Task exited")
        } catch is SMBIssue102WaitTimeout {
            // The selected timer Task is still suspended until the test releases it.
        }
        timerCancellationGate.release()
        do {
            try await bounded("later cancellation is selected after callback failure") { try await operation.value }
            XCTFail("callback failure/cancel unexpectedly succeeded")
        } catch is CancellationError {
            // Caller cancellation remains the public result even when callback failure stopped admission first.
        }
        _ = try await bounded("timer Task and operation completion observer exit") {
            try await operationReturned.waitForCount(1)
            return true
        }
        await operationCompletion.value
        await session.setReadTransferDrainTimerWillJoinHookForTesting(nil)
        await session.setReadTransferDrainTimerCancellationHookForTesting(nil)
        XCTAssertEqual(callbackCalls.value, 1)
        let recovered = try await waitForRecovery(session, label: "callback-first/cancel owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.deliveryLeases, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        XCTAssertEqual(transport.closeCount, 0)
        XCTAssertEqual(cleanupSleeper.activeSleepCount, 0)
    }

    func testWriteSourceFailureRacingCancellationReleasesItsOwnerOnce() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let sourceEntered = SMBContinuationCountBarrier()
        let sourceGate = SMBAsyncCallbackSuspensionGate()
        let sourceCalls = SMBM4Counter()
        let data = Array(repeating: UInt8(0x72), count: chunkSize * 2)
        defer {
            sourceGate.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.upload(
                path: "source-cancel.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { maximumLength in
                    if sourceCalls.increment() == 1 { return Array(data.prefix(maximumLength)) }
                    sourceEntered.signal()
                    await sourceGate.suspend()
                    throw SMBM4InjectedFailure.source
                }
            )
        }
        try await bounded("source/cancel WRITE CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        let firstWrite = try await bounded("source/cancel first WRITE") {
            try await transport.waitForWrite(atOffset: 0)
        }
        try await bounded("second WRITE source call suspends") { try await sourceEntered.waitForCount(1) }
        operation.cancel()
        _ = try await bounded("caller cancellation reaches the WRITE transfer") {
            await session.waitForWriteTransfersStoppedForTesting()
            return true
        }
        sourceGate.release()
        try transport.respond(to: firstWrite, credits: 16)
        do {
            try await bounded("source failure/cancel result") { try await operation.value }
            XCTFail("cancelled source failure unexpectedly succeeded")
        } catch is CancellationError {
            // Cancellation wins the existing stop-reason priority over the late source error.
        }
        XCTAssertEqual(sourceCalls.value, 2)
        XCTAssertEqual(transport.writeRequests.count, 1, "source bytes returned after stop are not enqueued")
        let recovered = try await waitForRecovery(session, label: "WRITE source/cancel owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.writeTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.supplierLeases, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        XCTAssertEqual(recovered.lifecycle.writeTimers, 0)
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testWriteSourceFailureBeforeCancellationStillReleasesItsOwnerOnce() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let testChunkSize = chunkSize
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let sourceFailureReturned = SMBContinuationCountBarrier()
        let sourceCalls = SMBM4Counter()
        let data = Array(repeating: UInt8(0x73), count: testChunkSize)
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "source-before-cancel.bin",
                totalBytes: UInt64(testChunkSize * 2),
                nextChunk: { _ in
                    guard sourceCalls.increment() == 1 else {
                        defer { sourceFailureReturned.signal() }
                        throw SMBM4InjectedFailure.source
                    }
                    return data
                }
            )
        }
        try await bounded("source-first WRITE CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        let firstWrite = try await bounded("source-first committed WRITE") {
            try await transport.waitForWrite(atOffset: 0)
        }
        try await bounded("source failure returns before cancellation") {
            try await sourceFailureReturned.waitForCount(1)
        }
        // This guarded case completed in 2 ms locally; the 3-second cap is over 1,000x larger
        // and makes a missing stop transition fail boundedly instead of hanging.
        _ = try await bounded("source failure is recorded before later cancellation") {
            await session.waitForWriteTransfersStoppedForTesting()
            return true
        }

        operation.cancel()
        try transport.respond(to: firstWrite, credits: 16)
        do {
            try await bounded("later cancellation is selected after source failure") { try await operation.value }
            XCTFail("source failure/cancel unexpectedly succeeded")
        } catch is CancellationError {
            // Caller cancellation remains the public result even when source failure stopped admission first.
        }
        XCTAssertEqual(sourceCalls.value, 2)
        XCTAssertEqual(transport.writeRequests.count, 1)
        let recovered = try await waitForRecovery(session, label: "source-first/cancel owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.writeTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.supplierLeases, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        XCTAssertEqual(recovered.lifecycle.writeTimers, 0)
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testDuplicateGrantAcknowledgementDoesNotReclaimTheLastLiveRecordTwice() async throws {
        let transport = SMBReadPipelineScriptTransport()
        let testChunkSize = chunkSize
        let session = makeReadSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let sendEntered = SMBContinuationCountBarrier()
        let releaseSend = SMBAsyncCallbackSuspensionGate()
        let grantEntered = SMBContinuationCountBarrier()
        let releaseGrant = SMBAsyncCallbackSuspensionGate()
        let targetMessageId = SMBM4MessageIdBox()
        let ownership = SMBM4OwnershipRecorder()
        await session.setTransferRequestOwnershipHookForTesting { ownership.append($0) }
        await session.setCreditGrantAfterAwaitHookForTesting {
            guard let messageId = targetMessageId.value,
                  let snapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: messageId),
                  snapshot.wire == .finalAccepted,
                  snapshot.outstandingAcknowledgements == 1 else {
                return
            }
            grantEntered.signal()
            await releaseGrant.suspend()
        }
        transport.installAfterReadSendHook { request in
            guard request.offset == 0 else { return }
            sendEntered.signal()
            await releaseSend.suspend()
        }
        defer {
            releaseSend.release()
            releaseGrant.release()
            transport.failConnection()
        }

        let operation = Task {
            try await client.withReadStream(path: "duplicate-grant.bin", knownSize: UInt64(testChunkSize)) { _ in }
        }
        try await bounded("duplicate grant READ CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("duplicate grant READ request") { try await transport.waitForReadCount(1) }
        try await bounded("duplicate grant send owner is active") { try await sendEntered.waitForCount(1) }
        let request = try XCTUnwrap(transport.readRequests.first)
        targetMessageId.store(request.header.messageId)
        try transport.respond(to: request, payload: Array(repeating: 0x81, count: chunkSize), credits: 1)
        try await bounded("final credit grant reaches the acknowledgement gate") {
            try await grantEntered.waitForCount(1)
        }

        let readGrantAtGate = await session.postAuthRequestRecordSnapshotForTesting(
            messageId: request.header.messageId
        )
        let readGrant = try XCTUnwrap(readGrantAtGate)
        XCTAssertEqual(readGrant.wire, .finalAccepted)
        XCTAssertEqual(readGrant.outstandingAcknowledgements, 1)
        let duplicateAcknowledgementApplied = await session.dispatchDuplicateTransferGrantAcknowledgementForTesting(
            messageId: request.header.messageId
        )
        XCTAssertTrue(duplicateAcknowledgementApplied, "the first dispatch consumes the live READ grant; the duplicate is a no-op")
        let afterDuplicateSnapshot = await session.postAuthRequestRecordSnapshotForTesting(
            messageId: request.header.messageId
        )
        let afterDuplicate = try XCTUnwrap(afterDuplicateSnapshot)
        XCTAssertEqual(afterDuplicate.outstandingAcknowledgements, 0, "the same grant owner is acknowledged only once")
        let activeRecordsAfterDuplicate = await session.activePostAuthRequestRecordCountForTesting()
        XCTAssertEqual(activeRecordsAfterDuplicate, 1)
        let identityForMessage = await session.requestIdentityForTesting(messageId: request.header.messageId)
        let identity = try XCTUnwrap(identityForMessage)
        let lastOwnership = try XCTUnwrap(ownership.latest(for: identity))
        XCTAssertEqual(lastOwnership.epochOutstandingOwnerCount, 1, "the held send owner remains the last epoch owner")

        releaseGrant.release()
        releaseSend.release()
        // The guarded success path returned in 4 ms locally; the shared 3-second
        // bound is over two orders of magnitude larger and bounds a lost/duplicate ack.
        try await bounded("duplicate grant READ delivery completes") { try await operation.value }
        let recovered = try await waitForRecovery(session, label: "duplicate grant final owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        await session.setTransferRequestOwnershipHookForTesting(nil)
    }

    func testProductionReadDrainTimerUsesTheFixedDeadlineAfterALateFailure() async throws {
        // The guarded session path completes in under 20 ms locally; the 3-second
        // bounded waits leave more than two orders of magnitude for a missing timer wake.
        let transport = SMBReadPipelineScriptTransport()
        let cleanupSleeper = SMBKeyedManualSleeper()
        let virtualTime = SMBM4VirtualClock()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { try await cleanupSleeper.sleep(for: $0) }
        )
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 81,
            cleanupTimeout: .seconds(5),
            requestTimeout: nil,
            sessionTime: sessionTime,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) },
            debugLogger: .environment
        )
        let client = SMBClientSession(session: session, treeId: 1)
        let terminalJoinCompleted = SMBContinuationCountBarrier()
        await session.setTerminalJoinCompletedHookForTesting {
            terminalJoinCompleted.signal()
        }
        defer { transport.failConnection() }

        let testChunkSize = chunkSize
        let operation = Task {
            try await client.withReadStream(
                path: "production-drain-deadline.bin",
                knownSize: UInt64(testChunkSize * 2)
            ) { _ in }
        }
        try await bounded("production timer READ CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        try await bounded("production timer has two committed READs") {
            try await transport.waitForReadCount(2)
        }

        operation.cancel()
        _ = try await bounded("cancel starts the production READ drain timer") {
            await session.waitForReadTransfersStoppedForTesting()
            return true
        }
        _ = try await bounded("first production deadline timer is registered") {
            while !cleanupSleeper.isSleeping(for: .seconds(5)) {
                try Task.checkCancellation()
                await Task.yield()
            }
            return true
        }

        virtualTime.advance(by: .seconds(1))
        try transport.respond(to: transport.readRequests[0], status: SMB2Status.accessDenied)
        let fixedDeadlineTimerRearmed = try? await bounded("late failure keeps the original D") {
            while !cleanupSleeper.isSleeping(for: .seconds(4)) {
                try Task.checkCancellation()
                await Task.yield()
            }
            return true
        }
        XCTAssertEqual(fixedDeadlineTimerRearmed, true, "at t=1 the same absolute D has four seconds remaining")
        guard fixedDeadlineTimerRearmed == true else {
            transport.failConnection()
            _ = try? await bounded("late-failure fixture operation cleanup") {
                do { try await operation.value } catch { return true }
                return true
            }
            return
        }
        XCTAssertEqual(cleanupSleeper.activeSleepCount(for: .seconds(5)), 0)
        XCTAssertEqual(cleanupSleeper.activeSleepCount(for: .seconds(4)), 1)

        virtualTime.advance(by: .seconds(4))
        cleanupSleeper.fire(for: .seconds(4))
        let closedAtDeadline = try? await bounded("production timer terminalizes exactly at D") {
            try await transport.waitForCloseCount(1)
            return true
        }
        XCTAssertEqual(closedAtDeadline, true, "the real timer callback treats exact D as expired")
        if closedAtDeadline != true { transport.failConnection() }
        _ = try? await bounded("production timer joins its terminal reader") {
            try await terminalJoinCompleted.waitForCount(1)
            return true
        }
        do {
            try await bounded("production deadline READ operation returns") { try await operation.value }
            XCTFail("READ unexpectedly succeeded after its drain deadline")
        } catch {
            // The first stop remains the public cancellation result.
        }
        XCTAssertGreaterThanOrEqual(terminalJoinCompleted.currentCount, 1)
        XCTAssertEqual(transport.closeCount, 1)
        let recovered = try await waitForRecovery(session, label: "production READ timer owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.readTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.readTimers, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
    }

    func testTerminalJoinClearsOrdinaryRequestTimerAndCreditWaiter() async throws {
        let transport = SMBM4BlockingEchoTransport()
        let timeoutSleeper = SMBKeyedManualSleeper()
        let virtualTime = SMBM4VirtualClock()
        let sessionTime = SMBSessionMonotonicTime(
            now: { virtualTime.now() },
            sleep: { try await timeoutSleeper.sleep(for: $0) }
        )
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2,
            requestTimeout: .seconds(30),
            sessionTime: sessionTime,
            requestTimeoutSleeper: { try await timeoutSleeper.sleep(for: $0) },
            debugLogger: .environment
        )
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 100)
        defer {
            transport.releaseEchoSend()
        }

        let firstEcho = Task {
            do {
                try await session.echo()
                return false
            } catch {
                return true
            }
        }
        try await bounded("first ordinary ECHO is sent") {
            try await transport.waitForCommand(SMB2Commands.echo, occurrence: 1)
        }
        _ = try await bounded("ordinary request timeout timer is installed") {
            await timeoutSleeper.waitUntilSleeping(for: .seconds(30))
            return true
        }
        let timeoutTasksBeforeTerminal = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timeoutTasksBeforeTerminal, 1)
        let firstMessageId = try XCTUnwrap(transport.outgoingHeaders.first { $0.command == SMB2Commands.echo }?.messageId)
        let firstTimeoutIdentity = await session.requestTimeoutIdentityForTesting(messageId: firstMessageId)
        XCTAssertNotNil(firstTimeoutIdentity)
        let beforeTerminalSnapshot = await session.postAuthRequestRecordSnapshotForTesting(messageId: firstMessageId)
        let beforeTerminal = try XCTUnwrap(beforeTerminalSnapshot)
        XCTAssertEqual(beforeTerminal.outstandingAcknowledgements, 0)
        transport.blockEchoSend(messageId: firstMessageId + 1)

        let blockedEcho = Task {
            do {
                try await session.echo()
                return false
            } catch {
                return true
            }
        }
        try await bounded("second ordinary ECHO is held in the transport send") {
            try await transport.echoSendEntered.waitForCount(1)
        }
        let echoHeaders = transport.outgoingHeaders.filter { $0.command == SMB2Commands.echo }
        XCTAssertEqual(echoHeaders.count, 2)
        let secondMessageId = try XCTUnwrap(echoHeaders.first { $0.messageId != firstMessageId }?.messageId)

        let creditWaiter = Task {
            do {
                try await session.parkCreditWaiterForTesting(charge: 2)
                return false
            } catch {
                return true
            }
        }
        _ = try await bounded("ordinary request fixture parks a credit waiter") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
            return true
        }
        let terminalJoin = Task {
            await session.closeTransportAndWait(cause: "m4_ordinary_terminal_join")
        }
        try await bounded("ordinary terminal closes the blocked transport") {
            try await transport.waitForCloseCount(1)
        }
        transport.releaseEchoSend()
        _ = try await bounded("ordinary terminal joins timer, sender, reader, and credit waiter") {
            await terminalJoin.value
            return true
        }
        let firstEchoFailed = try await bounded("first ordinary ECHO returns after terminal join") { await firstEcho.value }
        let blockedEchoFailed = try await bounded("blocked ordinary ECHO returns after terminal join") { await blockedEcho.value }
        let creditWaiterFailed = try await bounded("ordinary credit waiter fails at terminal") {
            await creditWaiter.value
        }
        XCTAssertTrue(firstEchoFailed)
        XCTAssertTrue(blockedEchoFailed)
        XCTAssertTrue(creditWaiterFailed)
        let activeRecordsAfterTerminal = await session.activePostAuthRequestRecordCountForTesting()
        let pendingAfterTerminal = await session.pendingCountForTesting()
        let timeoutTasksAfterTerminal = await session.requestTimeoutTaskCountForTesting()
        let creditWaitersAfterTerminal = await session.creditWaiterCountForTesting()
        let recordAfterTerminal = await session.postAuthRequestRecordSnapshotForTesting(messageId: firstMessageId)
        let blockedRecordAfterTerminal = await session.postAuthRequestRecordSnapshotForTesting(messageId: secondMessageId)
        let timerIdentityAfterTerminal = await session.requestTimeoutIdentityForTesting(messageId: firstMessageId)
        XCTAssertEqual(activeRecordsAfterTerminal, 0)
        XCTAssertEqual(pendingAfterTerminal, 0)
        XCTAssertEqual(timeoutTasksAfterTerminal, 0)
        XCTAssertEqual(creditWaitersAfterTerminal, 0)
        XCTAssertNil(recordAfterTerminal)
        XCTAssertNil(blockedRecordAfterTerminal)
        XCTAssertNil(timerIdentityAfterTerminal, "terminal join clears the request timer identity")
    }

    func testSupplierCanReturnBeforeTerminalJoinAndStillReclaimsItsRecord() async throws {
        let transport = SMBWritePipelineScriptTransport()
        let session = makeSession(transport: transport, credits: 81)
        let client = SMBClientSession(session: session, treeId: 1)
        let supplierEntered = SMBContinuationCountBarrier()
        let supplierGate = SMBAsyncCallbackSuspensionGate()
        let supplierCalls = SMBM4Counter()
        let readerExitGate = SMBReaderTaskExitGate()
        let readerJoinStarted = SMBContinuationCountBarrier()
        let terminalJoinCompleted = SMBContinuationCountBarrier()
        await session.setReaderTaskExitHookForTesting { handle in await readerExitGate.hold(handle) }
        await session.setReaderTaskJoinSnapshotHookForTesting { _ in readerJoinStarted.signal() }
        await session.setTerminalJoinCompletedHookForTesting { terminalJoinCompleted.signal() }
        let testChunkSize = chunkSize
        let data = Array(repeating: UInt8(0x93), count: testChunkSize * 2)
        defer {
            supplierGate.release()
            readerExitGate.releaseAll()
        }

        let operation = Task {
            try await client.upload(
                path: "supplier-terminal-order.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { maximumLength in
                    if supplierCalls.increment() == 1 {
                        return Array(data.prefix(maximumLength))
                    }
                    supplierEntered.signal()
                    await supplierGate.suspend()
                    return Array(data.suffix(from: min(testChunkSize, data.count)).prefix(maximumLength))
                }
            )
        }
        try await bounded("supplier terminal ordering CREATE") {
            try await transport.waitForCommand(SMB2Commands.create)
        }
        try transport.completeCreate(credits: 81)
        await session.installSenderLoopStateForTesting(sessionId: 1, firstMessageId: 1)
        _ = try await bounded("supplier terminal ordering first WRITE") {
            try await transport.waitForWrite(atOffset: 0)
        }
        try await bounded("supplier terminal ordering second callback") {
            try await supplierEntered.waitForCount(1)
        }
        let lifecycleWhileSupplierSuspended = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(lifecycleWhileSupplierSuspended.supplierLeases, 1)

        let close = Task { await session.closeTransportAndWait(cause: "m4_supplier_return_before_terminal_join") }
        try await bounded("terminal closes while supplier is suspended") {
            try await transport.waitForCloseCount(1)
        }
        try await bounded("terminal join waits at the held reader exit") {
            try await readerJoinStarted.waitForCount(1)
        }
        XCTAssertEqual(terminalJoinCompleted.currentCount, 0)
        supplierGate.release()
        _ = try await bounded("supplier return is recorded before terminal join") {
            while true {
                try Task.checkCancellation()
                let lifecycle = await session.transferLifecycleCountsForTesting()
                if lifecycle.supplierLeases == 0 { return true }
                await Task.yield()
            }
        }
        let lifecycleAfterSupplierReturn = await session.transferLifecycleCountsForTesting()
        XCTAssertEqual(lifecycleAfterSupplierReturn.supplierLeases, 0)
        XCTAssertEqual(terminalJoinCompleted.currentCount, 0)

        readerExitGate.releaseAll()
        _ = try await bounded("terminal join completes after supplier return") {
            await close.value
            try await terminalJoinCompleted.waitForCount(1)
            return true
        }
        let terminalOperationOutcome = try await bounded("terminal supplier operation exits") {
            do {
                try await operation.value
                return SMBM4TerminalOperationOutcome.succeeded
            } catch SMBTransportError.connectionClosed {
                return .connectionClosed
            } catch is CancellationError {
                return .cancelled
            } catch {
                return .other(String(reflecting: type(of: error)) + ":" + String(describing: error))
            }
        }
        XCTAssertEqual(terminalOperationOutcome, .connectionClosed)
        XCTAssertEqual(transport.writeRequests.count, 1)
        let recovered = try await waitForRecovery(session, label: "supplier return/terminal join owner recovery")
        XCTAssertEqual(recovered.records, 0)
        XCTAssertEqual(recovered.lifecycle.writeTransfers, 0)
        XCTAssertEqual(recovered.lifecycle.supplierLeases, 0)
        XCTAssertEqual(recovered.lifecycle.slotLeases, 0)
        XCTAssertEqual(recovered.lifecycle.writeTimers, 0)
        await session.setReaderTaskExitHookForTesting(nil)
        await session.setReaderTaskJoinSnapshotHookForTesting(nil)
        await session.setTerminalJoinCompletedHookForTesting(nil)
    }
#endif

    func testMIDAllocatorHasOneWireCommitSiteAndNoTransferSpecificCursor() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/SMBee/SMBClient.swift"),
            encoding: .utf8
        )
        let commitCallPattern = try NSRegularExpression(pattern: #"\bcommitNextMessageId\s*\("#)
        let matches = commitCallPattern.matches(
            in: source,
            range: NSRange(location: 0, length: (source as NSString).length)
        )
        XCTAssertEqual(matches.count, 2, "there is one allocator definition and one shared sender commit call")
        XCTAssertFalse(source.contains("nextTransferMessageId"))
        XCTAssertFalse(source.contains("transferMessageIdCursor"))
    }

    func testNoTicketCloseDoesNotCreateReceiptOrStartRetirementPump() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/SMBee/SMBClient.swift"),
            encoding: .utf8
        )
        let closeStart = try XCTUnwrap(source.range(of: "private func closeNoTicketTransferRequest("))
        let closeEnd = try XCTUnwrap(
            source.range(of: "private func closeTransferRetirementReceiptIfReady(", range: closeStart.upperBound..<source.endIndex)
        )
        let body = source[closeStart.lowerBound..<closeEnd.lowerBound]
        XCTAssertFalse(body.contains("SMBRetirementReceipt("))
        XCTAssertFalse(body.contains("Task("))
        XCTAssertFalse(body.contains("startTransferRetirementEffectPumpIfNeeded"))
    }

#if DEBUG
    private func makeSession(transport: SMBWritePipelineScriptTransport, credits: UInt32) -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: credits,
            cleanupTimeout: .seconds(30),
            requestTimeout: nil,
            debugLogger: .environment
        )
    }

    private func makeReadSession(transport: SMBReadPipelineScriptTransport, credits: UInt32) -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: credits,
            cleanupTimeout: .seconds(30),
            requestTimeout: nil,
            debugLogger: .environment
        )
    }

    private func protocolCreditCharge(requestLength: UInt64, responseLength: UInt64) -> UInt16 {
        let maximumLength = max(requestLength, responseLength)
        guard maximumLength > 0 else { return 1 }
        return UInt16((maximumLength - 1) / 65_536 + 1)
    }

    private func bounded<Value: Sendable>(
        _ label: String,
        operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        try await smbIssue102AwaitWithTimeout(label, operation: operation)
    }

    private func waitForRecovery(
        _ session: SMBSession,
        label: String
    ) async throws -> SMBM4RecoverySnapshot {
        try await bounded(label) {
            while true {
                try Task.checkCancellation()
                let records = await session.activePostAuthRequestRecordCountForTesting()
                let pending = await session.pendingCountForTesting()
                let counts = await session.transferLifecycleCountsForTesting()
                if records == 0,
                   pending == 0,
                   counts.readTransfers == 0,
                   counts.writeTransfers == 0,
                   counts.slotLeases == 0,
                   counts.readTimers == 0,
                   counts.writeTimers == 0,
                   counts.supplierLeases == 0,
                   counts.deliveryLeases == 0 {
                    return SMBM4RecoverySnapshot(
                        records: records,
                        pending: pending,
                        lifecycle: SMBM4LifecycleSnapshot(
                            readTransfers: counts.readTransfers,
                            writeTransfers: counts.writeTransfers,
                            readTimers: counts.readTimers,
                            writeTimers: counts.writeTimers,
                            supplierLeases: counts.supplierLeases,
                            deliveryLeases: counts.deliveryLeases,
                            slotLeases: counts.slotLeases
                        )
                    )
                }
                await Task.yield()
            }
        }
    }
#endif
}

#if DEBUG
private enum SMBM4InjectedFailure: Error {
    case callback
    case source
}

private final class SMBM4VirtualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now

    func now() -> ContinuousClock.Instant {
        lock.withLock { instant }
    }

    func advance(by duration: Duration) {
        lock.withLock { instant = instant.advanced(by: duration) }
    }
}

private final class SMBM4MessageIdBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue: UInt64?

    var value: UInt64? { lock.withLock { storedValue } }

    func store(_ value: UInt64) {
        lock.withLock { storedValue = value }
    }
}

private struct SMBM4RecoverySnapshot: Sendable {
    let records: Int
    let pending: Int
    let lifecycle: SMBM4LifecycleSnapshot
}

private struct SMBM4LifecycleSnapshot: Sendable {
    let readTransfers: Int
    let writeTransfers: Int
    let readTimers: Int
    let writeTimers: Int
    let supplierLeases: Int
    let deliveryLeases: Int
    let slotLeases: Int
}

#endif

private class SMBM4HeaderRecordingTransport: SMBWritePipelineScriptTransport, @unchecked Sendable {
    private let headerLock = NSLock()
    private var headerStorage: [SMB2Header] = []

    override func send(_ bytes: [UInt8]) async throws {
        if let packet = try smbM4PacketInDirectTCPStream(bytes) {
            let header = try SMB2Header.decode(packet)
            headerLock.withLock { headerStorage.append(header) }
        }
        try await super.send(bytes)
    }

    var outgoingHeaders: [SMB2Header] {
        headerLock.withLock { headerStorage }
    }
}

private final class SMBM4BlockingEchoTransport: SMBM4HeaderRecordingTransport, @unchecked Sendable {
    let echoSendEntered = SMBContinuationCountBarrier()
    private let echoSendGate = SMBAsyncCallbackSuspensionGate()
    private let blockedEchoMessageIdLock = NSLock()
    private var blockedEchoMessageIdStorage: UInt64?

    func blockEchoSend(messageId: UInt64) {
        blockedEchoMessageIdLock.withLock { blockedEchoMessageIdStorage = messageId }
    }

    override func send(_ bytes: [UInt8]) async throws {
        if let packet = try smbM4PacketInDirectTCPStream(bytes),
           let header = try? SMB2Header.decode(packet),
           header.command == SMB2Commands.echo {
            try await super.send(bytes)
            let shouldBlock = blockedEchoMessageIdLock.withLock {
                header.messageId == blockedEchoMessageIdStorage
            }
            if shouldBlock {
                echoSendEntered.signal()
                await echoSendGate.suspend()
                try Task.checkCancellation()
            }
        } else {
            try await super.send(bytes)
        }
    }

    func releaseEchoSend() {
        echoSendGate.release()
    }
}

private func smbM4PacketInDirectTCPStream(_ bytes: [UInt8]) throws -> [UInt8]? {
    guard bytes.count >= 68,
          Array(bytes[4..<8]) == [0xfe, 0x53, 0x4d, 0x42]
    else {
        return nil
    }
    let payloadLength = try DirectTCPFraming.length(from: Array(bytes.prefix(4)))
    guard payloadLength == bytes.count - 4 else { return nil }
    return Array(bytes.dropFirst(4))
}

private final class SMBM4Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var countStorage = 0

    @discardableResult
    func increment() -> Int {
        lock.withLock {
            countStorage += 1
            return countStorage
        }
    }

    var value: Int { lock.withLock { countStorage } }
}

#if DEBUG
private enum SMBM4TerminalOperationOutcome: Equatable, Sendable {
    case succeeded
    case connectionClosed
    case cancelled
    case other(String)
}

private final class SMBM4RefundRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var chargesStorage: [UInt16] = []

    func append(_ charge: UInt16) {
        lock.withLock { chargesStorage.append(charge) }
    }

    var charges: [UInt16] { lock.withLock { chargesStorage } }
}

private final class SMBM4TimerCancellationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var selectedIdentities = Set<UUID>()
    private let selected = SMBContinuationCountBarrier()
    private let entered = SMBContinuationCountBarrier()
    private let releaseGate = SMBAsyncCallbackSuspensionGate()

    func select(_ identity: UUID) {
        _ = lock.withLock { selectedIdentities.insert(identity) }
        selected.signal()
    }

    func holdIfSelected(_ identity: UUID) async {
        let shouldHold = lock.withLock { selectedIdentities.contains(identity) }
        guard shouldHold else { return }
        entered.signal()
        await releaseGate.suspend()
    }

    func waitUntilSelected() async throws {
        try await selected.waitForCount(1)
    }

    func waitUntilEntered() async throws {
        try await entered.waitForCount(1)
    }

    func release() {
        releaseGate.release()
    }
}
#endif

#if DEBUG
private final class SMBM4OwnershipRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var snapshots: [SMBTransferRequestOwnershipSnapshot] = []
    private let changed = SMBContinuationCountBarrier()

    func append(_ snapshot: SMBTransferRequestOwnershipSnapshot) {
        lock.withLock { snapshots.append(snapshot) }
        changed.signal()
    }

    func latest(for identity: SMBRequestIdentity) -> SMBTransferRequestOwnershipSnapshot? {
        lock.withLock { snapshots.last { $0.identity == identity } }
    }

    func first(where predicate: (SMBTransferRequestOwnershipSnapshot) -> Bool) -> SMBTransferRequestOwnershipSnapshot? {
        lock.withLock { snapshots.first(where: predicate) }
    }
}
#endif
