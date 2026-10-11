import Foundation
import XCTest
@testable import SMBee

private actor SMBPreparationTestEvents {
    private var counts: [String: Int] = [:]
    private var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]
    private var anyWaiters: [([String], CheckedContinuation<String, Never>)] = []

    func record(_ name: String) {
        counts[name, default: 0] += 1
        let parked = waiters.removeValue(forKey: name) ?? []
        parked.forEach { $0.resume() }
        var retained: [([String], CheckedContinuation<String, Never>)] = []
        for (names, continuation) in anyWaiters {
            if names.contains(name) {
                continuation.resume(returning: name)
            } else {
                retained.append((names, continuation))
            }
        }
        anyWaiters = retained
    }

    func waitFor(_ name: String) async {
        if count(name) > 0 { return }
        await withCheckedContinuation { continuation in
            if count(name) > 0 {
                continuation.resume()
            } else {
                waiters[name, default: []].append(continuation)
            }
        }
    }

    func waitForAny(_ names: [String]) async -> String {
        for name in names where count(name) > 0 {
            return name
        }
        return await withCheckedContinuation { continuation in
            for name in names where count(name) > 0 {
                continuation.resume(returning: name)
                return
            }
            anyWaiters.append((names, continuation))
        }
    }

    func count(_ name: String) -> Int { counts[name, default: 0] }
}

private actor SMBPreparationTestGate {
    private let events: SMBPreparationTestEvents
    private let enteredName: String
    private var opened = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(events: SMBPreparationTestEvents, enteredName: String) {
        self.events = events
        self.enteredName = enteredName
    }

    func pause() async {
        await events.record(enteredName)
        if opened { return }
        await withCheckedContinuation { continuation in
            if opened {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }

    func open() {
        opened = true
        let parked = waiters
        waiters.removeAll()
        parked.forEach { $0.resume() }
    }
}

final class SMBCleanupPreparationTests: XCTestCase {
    func testResourceIdentityDeadlinesAndFiniteHardBound() {
        let session = UUID()
        let treeA = SMBTreeIdentity(sessionInstance: session, generation: 4, treeId: 0, incarnationSequence: 1)
        let treeB = SMBTreeIdentity(sessionInstance: session, generation: 4, treeId: 8, incarnationSequence: 2)
        let fileBytes = Array(repeating: UInt8(0x2A), count: 16)
        let fileA = SMBScopedFileIdLedgerKey(bytes: fileBytes, treeIdentity: treeA)
        let fileB = SMBScopedFileIdLedgerKey(bytes: fileBytes, treeIdentity: treeB)

        XCTAssertNotEqual(fileA, fileB, "the same FileId in different Tree incarnations has separate ledger keys")
        let unscopedBits = fileBytes.withUnsafeBytes { rawBytes in
            (
                rawBytes.loadUnaligned(fromByteOffset: 0, as: UInt64.self),
                rawBytes.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
            )
        }
        XCTAssertEqual(fileA.firstWord, unscopedBits.0)
        XCTAssertEqual(fileA.secondWord, unscopedBits.1)
        XCTAssertEqual(SMBCleanupResource.file(tree: treeA, file: fileA), .file(tree: treeA, file: fileA))
        XCTAssertNotEqual(SMBCleanupResource.tree(treeA), .tree(treeB))

        let now = ContinuousClock.now
        let deadlines = SMBCleanupDeadlines(intentAt: now)
        XCTAssertEqual(deadlines.softAt, now.advanced(by: .seconds(5)))
        XCTAssertEqual(deadlines.hardAt, deadlines.softAt.advanced(by: .seconds(60)))

        let shorterRequest = SMBCleanupDeadlines(intentAt: now, requestTimeout: .seconds(12))
        XCTAssertEqual(shorterRequest.hardAt, deadlines.softAt.advanced(by: .seconds(12)))
        let longerRequest = SMBCleanupDeadlines(intentAt: now, requestTimeout: .seconds(120))
        XCTAssertEqual(longerRequest.hardAt, deadlines.softAt.advanced(by: .seconds(60)))
        let noRequestTimeout = SMBCleanupDeadlines(intentAt: now, requestTimeout: nil)
        XCTAssertEqual(noRequestTimeout.hardAt, deadlines.hardAt)
    }

    func testCleanupDispositionUsesStrictSoftDeadlineForFullSendFinalAndOwner() {
        let intentAt = ContinuousClock().now
        let softAt = intentAt.advanced(by: .seconds(5))
        let hardAt = intentAt.advanced(by: .seconds(20))
        let deadlines = SMBCleanupDeadlines(intentAt: intentAt, softAt: softAt, hardAt: hardAt)
        let boundaries: [(offset: Duration, label: String)] = [
            (.nanoseconds(-1), "D−1ns"),
            (.zero, "D"),
            (.nanoseconds(1), "D+1ns")
        ]

        for boundary in boundaries {
            let fullSendResult = deadlines.disposition(
                for: .softTimeout,
                at: softAt,
                fullSendCompletedAt: softAt.advanced(by: boundary.offset),
                finalAcceptedAt: nil,
                sendOwnerRecoveredAt: nil
            )
            XCTAssertEqual(
                fullSendResult,
                boundary.offset < .zero ? .draining : .terminal,
                "full-send at \(boundary.label)"
            )

            let finalResult = deadlines.disposition(
                for: .finalAccepted,
                at: softAt.advanced(by: boundary.offset),
                fullSendCompletedAt: softAt.advanced(by: .nanoseconds(-1)),
                finalAcceptedAt: nil,
                sendOwnerRecoveredAt: softAt.advanced(by: .nanoseconds(-1))
            )
            XCTAssertEqual(
                finalResult,
                boundary.offset < .zero ? .completedBeforeSoft : .completedAfterSoft,
                "final at \(boundary.label)"
            )

            let ownerResult = deadlines.disposition(
                for: .sendOwnerRecovered,
                at: softAt.advanced(by: boundary.offset),
                fullSendCompletedAt: softAt.advanced(by: .nanoseconds(-1)),
                finalAcceptedAt: softAt.advanced(by: .nanoseconds(-1)),
                sendOwnerRecoveredAt: nil
            )
            XCTAssertEqual(
                ownerResult,
                boundary.offset < .zero ? .completedBeforeSoft : .completedAfterSoft,
                "send owner recovery at \(boundary.label)"
            )
        }
    }

    func testPreparedCleanupOwnerFenceAndSharedRetirementReceipt() async {
        let tree = treeIdentity(id: 0, incarnation: 3)
        let file = SMBScopedFileIdLedgerKey(bytes: Array(repeating: 7, count: 16), treeIdentity: tree)
        let resource = SMBCleanupResource.file(tree: tree, file: file)
        let owner = requestIdentity(sequence: 11)
        let staleOwner = requestIdentity(sequence: 10)
        let deadlines = SMBCleanupDeadlines(intentAt: ContinuousClock.now)
        let ledger = SMBPreparedCleanupLedger()

        let began = await ledger.transitionCleanupLedger(
            resource: resource,
            owner: owner,
            event: .beginIntent(deadlines)
        )
        guard case .changed(.sending(let storedDeadlines)) = began else {
            return XCTFail("intent should enter sending")
        }
        XCTAssertEqual(storedDeadlines, deadlines)

        let stale = await ledger.transitionCleanupLedger(
            resource: resource,
            owner: staleOwner,
            event: .retireUnsent
        )
        guard case .ignoredOwner = stale else { return XCTFail("an old attempt cannot retire a new owner") }
        let stateAfterStaleOwner = await ledger.state(for: resource)
        XCTAssertEqual(stateAfterStaleOwner, .sending(deadlines))

        let first = await ledger.transitionCleanupLedger(resource: resource, owner: owner, event: .retireUnsent)
        guard case .retired(let effect) = first else { return XCTFail("unsent attempt should return an owned retirement effect") }
        XCTAssertEqual(effect.resource, resource)
        XCTAssertEqual(effect.owner, owner)
        let receipt = effect.receipt
        XCTAssertFalse(receipt.isComplete)

        let duplicate = await ledger.transitionCleanupLedger(resource: resource, owner: owner, event: .retireUnsent)
        guard case .alreadyRetired(let sameEffect) = duplicate else {
            return XCTFail("duplicate retirement must reuse the receipt")
        }
        XCTAssertEqual(effect, sameEffect)

        _ = await ledger.transitionCleanupLedger(
            resource: resource,
            owner: owner,
            event: .settleWire(succeeded: false)
        )
        await receipt.wait()
        XCTAssertTrue(receipt.isComplete)
        let retiredState = await ledger.state(for: resource)
        XCTAssertEqual(retiredState, .retiredUnknown)
    }

    func testTreeLifecycleRequiresTheQuarantineOwner() async {
        let tree = treeIdentity(id: 7, incarnation: 2)
        let owner = requestIdentity(sequence: 21)
        let staleOwner = requestIdentity(sequence: 19)
        let lifecycle = SMBTreeLifecycleHarness()

        let quarantine = await lifecycle.transitionTreeLifecycle(tree: tree, owner: owner, event: .beginQuarantine)
        guard case .changed(.quarantined) = quarantine else { return XCTFail("Tree should quarantine") }

        let staleRetirement = await lifecycle.transitionTreeLifecycle(tree: tree, owner: staleOwner, event: .retire)
        guard case .ignoredOwner = staleRetirement else { return XCTFail("a different cleanup owner cannot retire this incarnation") }
        let quarantinedState = await lifecycle.state(for: tree)
        XCTAssertEqual(quarantinedState, .quarantined)

        let retired = await lifecycle.transitionTreeLifecycle(tree: tree, owner: owner, event: .retire)
        guard case .changed(.retired) = retired else { return XCTFail("the owner can retire its Tree") }
        let retiredTreeState = await lifecycle.state(for: tree)
        XCTAssertEqual(retiredTreeState, .retired)
    }

    func testPreparedTreeDisconnectRetirementCarriesItsOwnerAndReceipt() async {
        let tree = treeIdentity(id: 7, incarnation: 3)
        let resource = SMBCleanupResource.tree(tree)
        let owner = requestIdentity(sequence: 22)
        let ledger = SMBPreparedCleanupLedger()
        let deadlines = SMBCleanupDeadlines(intentAt: ContinuousClock.now)

        _ = await ledger.transitionCleanupLedger(resource: resource, owner: owner, event: .beginIntent(deadlines))
        let retirement = await ledger.transitionCleanupLedger(
            resource: resource,
            owner: owner,
            event: .retireUnsent
        )
        guard case .retired(let effect) = retirement else {
            return XCTFail("Tree retirement should carry an effect and receipt")
        }
        XCTAssertEqual(effect.resource, resource)
        XCTAssertEqual(effect.owner, owner)
        XCTAssertFalse(effect.receipt.isComplete)

        let staleSettlement = await ledger.transitionCleanupLedger(
            resource: resource,
            owner: requestIdentity(sequence: 21),
            event: .settleWire(succeeded: false)
        )
        guard case .ignoredOwner = staleSettlement else {
            return XCTFail("an older Tree request cannot settle the retirement receipt")
        }

        _ = await ledger.transitionCleanupLedger(resource: resource, owner: owner, event: .settleWire(succeeded: false))
        await effect.receipt.wait()
        XCTAssertTrue(effect.receipt.isComplete)
    }

    func testTreeScopedCancellationLeavesOtherTreeWaiterAndWindowAlive() async throws {
        let treeA = treeIdentity(id: 3, incarnation: 1)
        let treeB = treeIdentity(id: 4, incarnation: 1)
        let requestA = requestIdentity(sequence: 31)
        let requestB = requestIdentity(sequence: 32)
        let tokenA = SMBTreeCreditCancellationToken(tree: treeA, request: requestA)
        let tokenB = SMBTreeCreditCancellationToken(tree: treeB, request: requestB)
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "prep-tree-cancel")

        let taskA = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: treeA,
                requestIdentity: requestA,
                cancellationToken: tokenA
            )
        }
        await window.waitForPendingWaiterCount(atLeast: 1)
        let taskB = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: treeB,
                requestIdentity: requestB,
                cancellationToken: tokenB
            )
        }
        await window.waitForPendingWaiterCount(atLeast: 2)

        let cancelled = await window.cancelWaiters(
            treeIdentity: treeA,
            requestIdentities: [requestA],
            error: CancellationError()
        )
        XCTAssertEqual(cancelled, 1)
        do {
            _ = try await taskA.value
            XCTFail("Tree A's waiter should be cancelled")
        } catch is CancellationError {
        }

        let pending = await window.pendingWaiterCount
        XCTAssertEqual(pending, 1, "Tree B remains parked in the active window")
        XCTAssertTrue(tokenA.isCancelled)
        _ = await window.grant(1)
        let reservationB = try await taskB.value
        XCTAssertEqual(reservationB, 1)
        let balance = await window.balance
        XCTAssertEqual(balance, 0)
        let remainingWaiters = await window.pendingWaiterCount
        XCTAssertEqual(remainingWaiters, 0)
    }

    func testTreeScopedCancellationKeepsRemainingWaitersInFIFOOrder() async throws {
        let treeA = treeIdentity(id: 20, incarnation: 1)
        let treeB = treeIdentity(id: 21, incarnation: 1)
        let requestA = requestIdentity(sequence: 60)
        let requestB1 = requestIdentity(sequence: 61)
        let requestB2 = requestIdentity(sequence: 62)
        let tokenA = SMBTreeCreditCancellationToken(tree: treeA, request: requestA)
        let tokenB1 = SMBTreeCreditCancellationToken(tree: treeB, request: requestB1)
        let tokenB2 = SMBTreeCreditCancellationToken(tree: treeB, request: requestB2)
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "prep-tree-fifo")
        let events = SMBPreparationTestEvents()
        let hookGate = SMBPreparationTestGate(events: events, enteredName: "first-grant-hook")
        await window.setReservationAcquiredHookForTesting { _ in await hookGate.pause() }

        let taskA = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: treeA,
                requestIdentity: requestA,
                cancellationToken: tokenA
            )
        }
        await window.waitForPendingWaiterCount(atLeast: 1)
        let firstB = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: treeB,
                requestIdentity: requestB1,
                cancellationToken: tokenB1
            )
        }
        await window.waitForPendingWaiterCount(atLeast: 2)
        let secondB = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: treeB,
                requestIdentity: requestB2,
                cancellationToken: tokenB2
            )
        }
        await window.waitForPendingWaiterCount(atLeast: 3)

        _ = await window.cancelWaiters(
            treeIdentity: treeA,
            requestIdentities: [requestA],
            error: CancellationError()
        )
        do {
            _ = try await taskA.value
            XCTFail("Tree A request should be cancelled")
        } catch is CancellationError {
        }
        _ = await window.grant(1)
        await events.waitFor("first-grant-hook")
        let firstWaiterWon = tokenB1.hasClaimedOrAcceptedGrant && !tokenB2.hasClaimedOrAcceptedGrant
        XCTAssertTrue(firstWaiterWon, "cancelling A preserves B's observed registration order")
        await hookGate.open()
        if !firstWaiterWon {
            _ = await window.cancelWaiters(
                treeIdentity: treeB,
                requestIdentities: [requestB1, requestB2],
                error: CancellationError()
            )
            _ = await firstB.result
            _ = await secondB.result
            return
        }
        let firstCharge = try await firstB.value
        XCTAssertEqual(firstCharge, 1)

        _ = await window.grant(1)
        let secondCharge = try await secondB.value
        XCTAssertEqual(secondCharge, 1)
        let remaining = await window.pendingWaiterCount
        XCTAssertEqual(remaining, 0)
    }

    func testCancelAfterGrantBeforeAcknowledgementRefundsExactlyOnce() async throws {
        let tree = treeIdentity(id: 9, incarnation: 5)
        let request = requestIdentity(sequence: 41)
        let token = SMBTreeCreditCancellationToken(tree: tree, request: request)
        let window = SMB2CreditWindow(initialCredits: 1, diagnosticSessionId: "prep-late-grant")
        let events = SMBPreparationTestEvents()
        let hookGate = SMBPreparationTestGate(events: events, enteredName: "reservation-hook")
        await window.setReservationAcquiredHookForTesting { _ in await hookGate.pause() }

        let reservationTask = Task {
            try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: tree,
                requestIdentity: request,
                cancellationToken: token
            )
        }
        await events.waitFor("reservation-hook")

        let cancelledWaiters = await window.cancelWaiters(
            treeIdentity: tree,
            requestIdentities: [request],
            error: CancellationError()
        )
        XCTAssertEqual(cancelledWaiters, 0, "the grant already left the waiter queue")
        let refundedBalance = await window.balance
        XCTAssertEqual(refundedBalance, 1, "the in-flight grant was refunded once")

        await hookGate.open()
        do {
            _ = try await reservationTask.value
            XCTFail("the cancelled grant cannot be delivered to the caller")
        } catch is CancellationError {
        }
        _ = await window.cancelWaiters(
            treeIdentity: tree,
            requestIdentities: [request],
            error: CancellationError()
        )
        let finalBalance = await window.balance
        XCTAssertEqual(finalBalance, 1, "a duplicate cancel cannot refund the same reservation twice")
    }

    func testCancellationTokenHandlesCancelBeforeLateGrantOnce() {
        let tree = treeIdentity(id: 12, incarnation: 1)
        let token = SMBTreeCreditCancellationToken(tree: tree, request: requestIdentity(sequence: 52))

        XCTAssertNil(token.cancel(), "no grant exists when cancellation wins")
        guard case .refundOnce = token.claimGrant(charge: 1) else {
            return XCTFail("a reservation arriving after cancellation must be refunded")
        }
        guard case .rejected = token.claimGrant(charge: 1) else {
            return XCTFail("the same cancellation token cannot settle a second grant")
        }
        XCTAssertFalse(token.acceptGrant())
    }

    func testCancellationBeforeWaiterRegistrationDoesNotPark() async {
        let tree = treeIdentity(id: 12, incarnation: 2)
        let request = requestIdentity(sequence: 53)
        let token = SMBTreeCreditCancellationToken(tree: tree, request: request)
        XCTAssertNil(token.cancel())

        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "prep-cancel-before-register")
        do {
            _ = try await window.reserveUpTo(
                maximumCharge: 1,
                treeIdentity: tree,
                requestIdentity: request,
                cancellationToken: token
            )
            XCTFail("a pre-cancelled reservation must be rejected")
        } catch is CancellationError {
        } catch {
            XCTFail("expected cancellation, got \(error)")
        }

        let pendingWaiterCount = await window.pendingWaiterCount
        let remainingBalance = await window.balance
        XCTAssertEqual(pendingWaiterCount, 0)
        XCTAssertEqual(remainingBalance, 0)
    }

    func testReentrantChildCloseReturnsAfterStartingSharedWorker() async {
        let events = SMBPreparationTestEvents()
        let owner = SMBFacadeOwner(rawValue: 60)
        let session = sessionIdentity(generation: 1)
        let lifecycle = SMBOperationLeaseHarness(
            onWorkerEntryForTesting: { _ in
                if SMBOperationTaskContext.ancestry.isEmpty { await events.record("worker-context-empty") }
                await events.record("worker-entry")
            },
            onBarrierEvaluationForTesting: { _, blocked in
                await events.record(blocked ? "barrier-blocked" : "barrier-clear")
            }
        )
        await lifecycle.registerFacade(owner)
        let lease = await lifecycle.acquire(owner: owner, session: session)
        guard let lease else { return XCTFail("lease admission should start open") }

        let disposition = await SMBOperationTaskContext.withLease(lease) {
            await lifecycle.close(owner: owner) {
                await events.record("cleanup-ran")
                return .success
            }
        }
        guard case .startedOnly = disposition else { return XCTFail("an active callback must not join its close") }
        let barrierEvaluation = await events.waitForAny(["barrier-blocked", "barrier-clear"])
        XCTAssertEqual(barrierEvaluation, "barrier-blocked")
        let closing = await lifecycle.isClosing(owner)
        XCTAssertTrue(closing)
        await assertEventCount(events, "cleanup-ran", 0)

        await lifecycle.release(lease)
        let joined = await lifecycle.close(owner: owner) {
            await events.record("duplicate-cleanup")
            return .failed("must share the first worker")
        }
        guard case .joined(.success) = joined else { return XCTFail("the outside caller joins the existing worker") }
        await assertEventCount(events, "cleanup-ran", 1)
        await assertEventCount(events, "duplicate-cleanup", 0)
        await assertEventCount(events, "worker-entry", 1)
        await assertEventCount(events, "worker-context-empty", 1)
    }

    func testAncestryFindsActiveParentPastExpiredNestedFrame() async {
        let events = SMBPreparationTestEvents()
        let parent = SMBFacadeOwner(rawValue: 70)
        let nested = SMBFacadeOwner(rawValue: 71)
        let sessionP = sessionIdentity(generation: 2)
        let sessionQ = sessionIdentity(generation: 7)
        let lifecycle = SMBOperationLeaseHarness(
            onWorkerEntryForTesting: { _ in await events.record("worker-entry") },
            onBarrierEvaluationForTesting: { _, blocked in
                await events.record(blocked ? "barrier-blocked" : "barrier-clear")
            },
            onCloseDecisionForTesting: { _, shouldJoin in
                await events.record(shouldJoin ? "close-joined" : "close-start-only")
            }
        )
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(nested)
        let parentLease = await lifecycle.acquire(owner: parent, session: sessionP)
        let nestedLease = await lifecycle.acquire(owner: nested, session: sessionQ)
        guard let parentLease, let nestedLease else { return XCTFail("both facade leases should be admitted") }

        let nestedAncestry = await SMBOperationTaskContext.withLease(parentLease) {
            await SMBOperationTaskContext.withLease(nestedLease) {
                let ancestry = SMBOperationTaskContext.ancestry
                await lifecycle.release(nestedLease)
                return ancestry
            }
        }
        let closeTask = Task {
            await SMBOperationTaskContext.$ancestry.withValue(nestedAncestry) {
                await lifecycle.close(owner: parent) {
                    await events.record("parent-cleanup")
                    return .success
                }
            }
        }
        let closeDecision = await events.waitForAny(["close-start-only", "close-joined"])
        XCTAssertEqual(closeDecision, "close-start-only")
        await assertEventCount(events, "close-joined", 0)
        let barrierEvaluation = await events.waitForAny(["barrier-blocked", "barrier-clear"])
        XCTAssertEqual(barrierEvaluation, "barrier-blocked")
        await assertEventCount(events, "parent-cleanup", 0)

        await lifecycle.release(parentLease)
        let disposition = await closeTask.value
        guard case .startedOnly = disposition else {
            return XCTFail("the full ancestry scan finds the active P lease past expired Q")
        }
        let joined = await lifecycle.close(owner: parent) {
            await events.record("duplicate-parent-cleanup")
            return .failed("the first worker must remain shared")
        }
        guard case .joined(.success) = joined else { return XCTFail("the outside close joins after release") }
        await assertEventCount(events, "parent-cleanup", 1)
        await assertEventCount(events, "duplicate-parent-cleanup", 0)
    }

    func testActiveLeaseCallbackDoesNotJoinAnotherFacadeClose() async {
        let callbackOwner = SMBFacadeOwner(rawValue: 75)
        let targetOwner = SMBFacadeOwner(rawValue: 76)
        let lifecycle = SMBOperationLeaseHarness()
        await lifecycle.registerFacade(callbackOwner)
        await lifecycle.registerFacade(targetOwner)
        let lease = await lifecycle.acquire(owner: callbackOwner, session: sessionIdentity(generation: 3))
        guard let lease else { return XCTFail("callback lease should be admitted") }

        let disposition = await SMBOperationTaskContext.withLease(lease) {
            await lifecycle.close(owner: targetOwner) { .success }
        }
        guard case .startedOnly = disposition else {
            return XCTFail("a callback holding any active lease returns after starting another close")
        }
        await lifecycle.release(lease)
    }

    func testCloseWorkerUsesCapturedSessionExecutorPreference() async {
        let events = SMBPreparationTestEvents()
        let owner = SMBFacadeOwner(rawValue: 77)
        let executor = SMBSessionExecutor(label: "SMBee.test.prepared-close")
        let lifecycle = SMBOperationLeaseHarness(
            onWorkerEntryForTesting: { _ in
                let observation = executor.executionContextForTesting(.cleanupCloseTask)
                await events.record(observation.taskExecutorMatches ? "preferred-executor" : "wrong-executor")
            }
        )
        await lifecycle.registerFacade(owner, sessionExecutor: executor)

        let disposition = await lifecycle.close(owner: owner) { .success }
        guard case .joined(.success) = disposition else { return XCTFail("external close joins the worker") }
        await assertEventCount(events, "preferred-executor", 1)
        await assertEventCount(events, "wrong-executor", 0)
    }

    func testCloseWaitsForOperationSetupRetirementAndWireReceiptsAndSharesResult() async {
        let events = SMBPreparationTestEvents()
        let parent = SMBFacadeOwner(rawValue: 80)
        let child = SMBFacadeOwner(rawValue: 81)
        let session = sessionIdentity(generation: 8)
        let lifecycle = SMBOperationLeaseHarness(
            onWorkerEntryForTesting: { _ in
                if SMBOperationTaskContext.ancestry.isEmpty { await events.record("worker-context-empty") }
                await events.record("worker-entry")
            },
            onBarrierEvaluationForTesting: { _, blocked in
                await events.record(blocked ? "barrier-blocked" : "barrier-clear")
            }
        )
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(child, parent: parent)
        let parentLease = await lifecycle.acquire(owner: parent, session: session)
        let childLease = await lifecycle.acquire(
            owner: child,
            session: session,
            tree: treeIdentity(id: 2, incarnation: 1)
        )
        guard let parentLease, let childLease else { return XCTFail("operation leases should be admitted") }
        let setup = await lifecycle.beginBarrier(owner: child, kind: .setup)
        let retirement = await lifecycle.beginBarrier(owner: parent, kind: .retirement)
        let wire = await lifecycle.beginBarrier(owner: child, kind: .wire)

        let firstClose = Task {
            await lifecycle.close(owner: parent) {
                await events.record("cleanup-ran")
                return .success
            }
        }
        await events.waitFor("worker-entry")
        let barrierEvaluation = await events.waitForAny(["barrier-blocked", "barrier-clear"])
        XCTAssertEqual(barrierEvaluation, "barrier-blocked")
        let closing = await lifecycle.isClosing(parent)
        XCTAssertTrue(closing)
        let activeLeasesBeforeRelease = await lifecycle.activeLeaseCount(for: parent)
        XCTAssertEqual(activeLeasesBeforeRelease, 2)
        await assertEventCount(events, "cleanup-ran", 0)
        let rejectedLease = await lifecycle.acquire(owner: parent, session: session)
        XCTAssertNil(rejectedLease, "closing owner rejects new leases")
        let rejectedChildLease = await lifecycle.acquire(owner: child, session: session)
        XCTAssertNil(rejectedChildLease, "a parent close stops admission on its child facades")

        let secondClose = Task {
            await lifecycle.close(owner: parent) {
                await events.record("second-cleanup")
                return .failed("close result must be shared")
            }
        }
        await lifecycle.release(parentLease)
        await lifecycle.release(childLease)
        let activeLeasesAfterRelease = await lifecycle.activeLeaseCount(for: parent)
        XCTAssertEqual(activeLeasesAfterRelease, 0)
        await assertEventCount(events, "cleanup-ran", 0)

        await lifecycle.completeBarrier(setup)
        await lifecycle.completeBarrier(retirement)
        await assertEventCount(events, "cleanup-ran", 0)
        await lifecycle.completeBarrier(wire)

        guard case .joined(.success) = await firstClose.value else { return XCTFail("first close result") }
        guard case .joined(.success) = await secondClose.value else { return XCTFail("concurrent close shares result") }
        await assertEventCount(events, "cleanup-ran", 1)
        await assertEventCount(events, "second-cleanup", 0)
        await assertEventCount(events, "worker-entry", 1)
        await assertEventCount(events, "worker-context-empty", 1)
    }

    func testReparentingFacadeMovesExistingLeaseAndBarrierCounts() async {
        let events = SMBPreparationTestEvents()
        let parent = SMBFacadeOwner(rawValue: 82)
        let child = SMBFacadeOwner(rawValue: 83)
        let newParent = SMBFacadeOwner(rawValue: 86)
        let session = sessionIdentity(generation: 10)
        let lifecycle = SMBOperationLeaseHarness(
            onBarrierEvaluationForTesting: { _, blocked in
                await events.record(blocked ? "parent-blocked" : "parent-clear")
            }
        )
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(newParent)
        await lifecycle.registerFacade(child, parent: parent)
        let lease = await lifecycle.acquire(owner: child, session: session)
        let barrier = await lifecycle.beginBarrier(owner: child, kind: .wire)
        guard let lease else { return XCTFail("child lease should be active before reparenting") }

        let parentLeasesBefore = await lifecycle.activeLeaseCount(for: parent)
        let parentBarriersBefore = await lifecycle.activeBarrierCount(for: parent)
        let newParentLeasesBefore = await lifecycle.activeLeaseCount(for: newParent)
        let newParentBarriersBefore = await lifecycle.activeBarrierCount(for: newParent)
        XCTAssertEqual(parentLeasesBefore, 1)
        XCTAssertEqual(parentBarriersBefore, 1)
        XCTAssertEqual(newParentLeasesBefore, 0)
        XCTAssertEqual(newParentBarriersBefore, 0)

        await lifecycle.registerFacade(child, parent: newParent)
        let parentLeasesAfter = await lifecycle.activeLeaseCount(for: parent)
        let parentBarriersAfter = await lifecycle.activeBarrierCount(for: parent)
        let newParentLeasesAfter = await lifecycle.activeLeaseCount(for: newParent)
        let newParentBarriersAfter = await lifecycle.activeBarrierCount(for: newParent)
        XCTAssertEqual(parentLeasesAfter, 0)
        XCTAssertEqual(parentBarriersAfter, 0)
        XCTAssertEqual(newParentLeasesAfter, 1)
        XCTAssertEqual(newParentBarriersAfter, 1)

        let closeTask = Task {
            await lifecycle.close(owner: newParent) {
                await events.record("parent-cleanup")
                return .success
            }
        }
        let evaluation = await events.waitForAny(["parent-blocked", "parent-clear"])
        XCTAssertEqual(evaluation, "parent-blocked", "existing child ownership moves under the newly registered parent")
        await assertEventCount(events, "parent-cleanup", 0)

        await lifecycle.release(lease)
        await assertEventCount(events, "parent-cleanup", 0, "the child wire barrier remains part of the parent subtree")
        await lifecycle.completeBarrier(barrier)
        guard case .joined(.success) = await closeTask.value else { return XCTFail("parent cleanup should run after both receipts clear") }
        await assertEventCount(events, "parent-cleanup", 1)
    }

    func testReparentingRejectsCycleWithoutChangingLeaseOrBarrierCounts() async {
        let parent = SMBFacadeOwner(rawValue: 90)
        let child = SMBFacadeOwner(rawValue: 91)
        let lifecycle = SMBOperationLeaseHarness()
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(child, parent: parent)
        guard let lease = await lifecycle.acquire(owner: child, session: sessionIdentity(generation: 10)) else {
            return XCTFail("child lease should be active before cycle rejection")
        }
        let barrier = await lifecycle.beginBarrier(owner: child, kind: .wire)

        await lifecycle.registerFacade(parent, parent: child)

        let parentLeases = await lifecycle.activeLeaseCount(for: parent)
        let parentBarriers = await lifecycle.activeBarrierCount(for: parent)
        let childLeases = await lifecycle.activeLeaseCount(for: child)
        let childBarriers = await lifecycle.activeBarrierCount(for: child)
        XCTAssertEqual(parentLeases, 1, "cycle rejection preserves the old parent lease count")
        XCTAssertEqual(parentBarriers, 1, "cycle rejection preserves the old parent barrier count")
        XCTAssertEqual(childLeases, 1, "cycle rejection does not double-count the child lease")
        XCTAssertEqual(childBarriers, 1, "cycle rejection does not double-count the child barrier")

        let countsStayedValid = parentLeases == 1
            && parentBarriers == 1
            && childLeases == 1
            && childBarriers == 1
        if countsStayedValid {
            await lifecycle.release(lease)
            await lifecycle.completeBarrier(barrier)
        }
    }

    func testReparentingWakesOldParentBarrierWaiterAfterCountsMove() async {
        let parent = SMBFacadeOwner(rawValue: 87)
        let child = SMBFacadeOwner(rawValue: 88)
        let newParent = SMBFacadeOwner(rawValue: 89)
        let waiterRegistered = SMBContinuationBooleanLatch()
        let waiterResumed = SMBContinuationCountBarrier()
        let lifecycle = SMBOperationLeaseHarness(
            onBarrierWaiterEventForTesting: { owner, event in
                guard owner == parent else { return }
                switch event {
                case .registered:
                    waiterRegistered.signal(true)
                case .resumed:
                    waiterResumed.signal()
                }
            }
        )
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(newParent)
        await lifecycle.registerFacade(child, parent: parent)
        guard let childLease = await lifecycle.acquire(owner: child, session: sessionIdentity(generation: 10)) else {
            return XCTFail("child lease should be active")
        }
        let childBarrier = await lifecycle.beginBarrier(owner: child, kind: .wire)

        let parentClose = Task {
            await lifecycle.close(owner: parent) { .success }
        }
        let didRegisterWaiter = await waiterRegistered.wait()
        XCTAssertTrue(didRegisterWaiter, "the old parent close has installed its waiter")

        await lifecycle.registerFacade(child, parent: newParent)
        let resumesAfterReparent = waiterResumed.currentCount
        XCTAssertEqual(resumesAfterReparent, 1, "reparenting itself wakes the now-ready old parent")
        if resumesAfterReparent == 0 {
            await lifecycle.expireClose(parent)
        }

        guard case .joined(let outcome) = await parentClose.value else {
            await lifecycle.release(childLease)
            await lifecycle.completeBarrier(childBarrier)
            return XCTFail("old parent close should finish when the child moves away")
        }
        if resumesAfterReparent == 1 {
            XCTAssertEqual(outcome, .success)
        } else {
            XCTAssertEqual(outcome, .failed("operation lease barrier exceeded the cleanup soft deadline"))
        }
        await lifecycle.release(childLease)
        await lifecycle.completeBarrier(childBarrier)
    }

    func testRetiredFacadeKeepsAncestryUntilItsLastLeaseIsReleased() async {
        let parent = SMBFacadeOwner(rawValue: 84)
        let child = SMBFacadeOwner(rawValue: 85)
        let lifecycle = SMBOperationLeaseHarness()
        await lifecycle.registerFacade(parent)
        await lifecycle.registerFacade(child, parent: parent)
        let lease = await lifecycle.acquire(owner: child, session: sessionIdentity(generation: 10))
        guard let lease else { return XCTFail("child lease should be active before retirement") }

        await lifecycle.retireFacade(child)
        let countsWhileLeaseIsActive = await lifecycle.recordCountsForTesting()
        let parentLeasesWhileLeaseIsActive = await lifecycle.activeLeaseCount(for: parent)
        XCTAssertEqual(countsWhileLeaseIsActive.parentRecords, 1)
        XCTAssertEqual(countsWhileLeaseIsActive.retiredFacades, 1)
        XCTAssertEqual(parentLeasesWhileLeaseIsActive, 1)

        await lifecycle.release(lease)
        let countsAfterLastRelease = await lifecycle.recordCountsForTesting()
        let parentLeasesAfterRelease = await lifecycle.activeLeaseCount(for: parent)
        XCTAssertEqual(countsAfterLastRelease.parentRecords, 0)
        XCTAssertEqual(countsAfterLastRelease.retiredFacades, 0)
        XCTAssertEqual(countsAfterLastRelease.leases, 0)
        XCTAssertEqual(parentLeasesAfterRelease, 0)
    }

    func testStaleInheritedAncestryDoesNotSkipCloseJoin() async {
        let events = SMBPreparationTestEvents()
        let gate = SMBPreparationTestGate(events: events, enteredName: "cleanup-entered")
        let owner = SMBFacadeOwner(rawValue: 90)
        let lifecycle = SMBOperationLeaseHarness(
            onWorkerEntryForTesting: { _ in await events.record("worker-entry") },
            onBarrierEvaluationForTesting: { _, blocked in
                await events.record(blocked ? "barrier-blocked" : "barrier-clear")
            }
        )
        await lifecycle.registerFacade(owner)
        let lease = await lifecycle.acquire(owner: owner, session: sessionIdentity(generation: 9))
        guard let lease else { return XCTFail("lease admission should start open") }
        let staleAncestry = await SMBOperationTaskContext.withLease(lease) {
            SMBOperationTaskContext.ancestry
        }
        await lifecycle.release(lease)

        let closeTask = Task {
            await SMBOperationTaskContext.$ancestry.withValue(staleAncestry) {
                let result = await lifecycle.close(owner: owner) {
                    await gate.pause()
                    return .success
                }
                await events.record("close-returned")
                return result
            }
        }
        await events.waitFor("cleanup-entered")
        await assertEventCount(events, "close-returned", 0, "an inactive inherited frame must still join")
        await gate.open()
        guard case .joined(.success) = await closeTask.value else { return XCTFail("stale ancestry should join") }
        await assertEventCount(events, "close-returned", 1)
    }

    func testSourceShapePreparedStateWritesStayInsideTransitions() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = root.appendingPathComponent("Sources/SMBee/SMBCleanupPreparation.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let nsSource = source as NSString
        let mutation = try NSRegularExpression(
            pattern: "entries\\s*\\[[^\\]]*\\]\\s*=(?!=)"
                + "|entries\\.(removeValue|removeAll|updateValue|merge|remove)\\b"
        )
        let matches = mutation.matches(in: source, range: NSRange(location: 0, length: nsSource.length))
        XCTAssertFalse(matches.isEmpty, "the scan must observe prepared ledger writes")

        var transitionRanges: [NSRange] = []
        for signature in ["func transitionCleanupLedger(", "func transitionTreeLifecycle("] {
            let start = nsSource.range(of: signature)
            XCTAssertNotEqual(start.location, NSNotFound, "missing transition function: \(signature)")
            transitionRanges.append(memberRange(containing: start.location, source: source, nsSource: nsSource))
        }
        for match in matches {
            XCTAssertTrue(
                transitionRanges.contains { NSLocationInRange(match.range.location, $0) },
                "prepared cleanup state write escaped its transition at line \(lineNumber(match.range.location, source: source))"
            )
        }
    }

    func testSourceShapeOperationLifecycleWritesStayInsideTransition() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = root.appendingPathComponent("Sources/SMBee/SMBCleanupPreparation.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let nsSource = source as NSString
        let mutation = try NSRegularExpression(
            pattern: "(facadeParents|facadeExecutors|knownFacades|leases|subtreeLeaseCounts|subtreeBarrierCounts|barriers|closing|closeWorkers|barrierWaiters|nextLeaseSequence|nextBarrierSequence)"
                + "\\s*(\\[[^\\]]*\\])?\\s*(=|\\.(insert|remove|removeValue|updateValue|removeAll)\\b|\\+=)"
        )
        let matches = mutation.matches(in: source, range: NSRange(location: 0, length: nsSource.length))
        let start = nsSource.range(of: "private func transitionOperationLifecycle(")
        XCTAssertNotEqual(start.location, NSNotFound)
        let transition = memberRange(containing: start.location, source: source, nsSource: nsSource)
        let outside = matches.filter { !NSLocationInRange($0.range.location, transition) }
        let lines = outside.map { lineNumber($0.range.location, source: source) }
        XCTAssertEqual(lines, [], "operation lifecycle state writes escaped transition at lines \(lines)")
    }

    private func treeIdentity(id: UInt32, incarnation: UInt64) -> SMBTreeIdentity {
        SMBTreeIdentity(
            sessionInstance: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            generation: 1,
            treeId: id,
            incarnationSequence: incarnation
        )
    }

    private func requestIdentity(sequence: UInt64) -> SMBRequestIdentity {
        SMBRequestIdentity(
            sessionInstance: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            generation: 1,
            requestSequence: sequence
        )
    }

    private func sessionIdentity(generation: UInt64) -> SMBSessionIncarnationIdentity {
        SMBSessionIncarnationIdentity(
            sessionInstance: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            generation: generation
        )
    }

    private func memberRange(containing location: Int, source: String, nsSource: NSString) -> NSRange {
        let afterStart = NSRange(location: location, length: nsSource.length - location)
        let nextMember = try? NSRegularExpression(pattern: "\\n    (private |fileprivate |nonisolated )*(func|var|let) ")
            .firstMatch(in: source, range: afterStart)
        let end = nextMember?.range.location ?? nsSource.length
        return NSRange(location: location, length: end - location)
    }

    private func lineNumber(_ location: Int, source: String) -> Int {
        source.prefix(location).filter { $0 == "\n" }.count + 1
    }

    private func assertEventCount(
        _ events: SMBPreparationTestEvents,
        _ event: String,
        _ expected: Int,
        _ message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let actual = await events.count(event)
        XCTAssertEqual(actual, expected, message, file: file, line: line)
    }
}
