import Foundation
import XCTest
@testable import SMBee

final class SMBWritePipelineTests: XCTestCase {
    private let chunkSize = 1_048_576

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
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(pending, 0)
        await session.closeTransportAndWait(cause: "write_zero_credit_supplier_test_complete")
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

        let failingRequest = Task(priority: .background) {
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

        let write = Task(priority: .background) {
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
        defer { transport.failConnection() }

        let operation = Task {
            try await client.upload(
                path: "supplier.bin",
                totalBytes: UInt64(data.count),
                nextChunk: { _ in
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
                onProgress: { progress.append($0.bytesTransferred) }
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
        try await waitForProgress(progress, count: 1, label: "file supplier progress before final responses")
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
        let transport = SMBWritePipelineScriptTransport()
        let cleanupSleeper = ManualSMBSleeper()
        let session = makeSession(
            transport: transport,
            credits: 81,
            cleanupTimeoutSleeper: { try await cleanupSleeper.sleep(for: $0) }
        )
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
        try await waitForSleeperCall(cleanupSleeper, count: 1, label: "cancelled WRITE drain timer")
        for offset in (0..<4).reversed() {
            try transport.respond(to: request(at: UInt64(offset * chunkSize), in: transport))
        }

        do {
            try await smbIssue102AwaitWithTimeout("cancelled WRITE drain completion") { try await operation.value }
            XCTFail("cancelled WRITE unexpectedly succeeded")
        } catch is CancellationError {
            // The committed four requests drain before cancellation is returned.
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
