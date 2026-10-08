import Foundation
import XCTest
@testable import SMBee

final class SMBTransferWindowTests: XCTestCase {
    func testWindowRejectsFifthSlot() throws {
        let window = SMBTransferWindow(transferIdentifier: 1, direction: .read)
        XCTAssertEqual(SMBTransferWindow.maximumSlotCount, 4)

        for sequence in 1...4 {
            _ = try makeTicket(window, sequence: UInt64(sequence), length: 4)
        }
        XCTAssertNil(window.beginPreparing(candidateLength: 4))
    }

    func testCommitAdvancesRequestFrontierByActualLength() throws {
        let window = SMBTransferWindow(transferIdentifier: 12, direction: .read)
        let firstSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 16))
        let first = try XCTUnwrap(window.commit(
            slotIndex: firstSlot,
            requestIdentity: makeIdentity(1),
            messageID: 1,
            requestedLength: 4,
            at: ContinuousClock.now
        ))
        XCTAssertEqual(first.offset, 0)
        XCTAssertEqual(window.requestFrontier, 4)

        let secondSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 8))
        let second = try XCTUnwrap(window.commit(
            slotIndex: secondSlot,
            requestIdentity: makeIdentity(2),
            messageID: 2,
            requestedLength: 8,
            at: ContinuousClock.now
        ))
        XCTAssertEqual(second.offset, 4)
        XCTAssertEqual(window.requestFrontier, 12)
    }

    func testRevokingPreparingSlotKeepsFrontierAndReturnsSlot() throws {
        let window = SMBTransferWindow(transferIdentifier: 13, direction: .read)
        let slot = try XCTUnwrap(window.beginPreparing(candidateLength: 8))

        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: ContinuousClock.now))
        XCTAssertEqual(window.requestFrontier, 0)
        XCTAssertEqual(window.beginPreparing(candidateLength: 8), slot)
        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: ContinuousClock.now))
    }

    func testPreparingReservationKeepsWireUndrainedUntilRevoked() async throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let window = SMBTransferWindow(transferIdentifier: 130, direction: .read)
        let slot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))
        let credits = SMB2CreditWindow(initialCredits: 2, diagnosticSessionId: "preparing-drain")
        let reservedCharge = try await credits.reserveUpTo(maximumCharge: 1, waitIfUnavailable: false)

        XCTAssertEqual(reservedCharge, 1)
        window.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))
        XCTAssertFalse(window.wireDrained, "a preparing reservation remains unsettled")
        XCTAssertNil(window.wireDrainedAt, "stop must not record the preparing slot as drained")
        XCTAssertTrue(window.drainDeadlineHasWon(at: deadline), "an unsettled reservation reaches the drain deadline")

        let revokedAt = deadline.advanced(by: .milliseconds(1))
        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: revokedAt))
        XCTAssertTrue(window.wireDrained)
        XCTAssertEqual(window.wireDrainedAt, revokedAt, "refund settlement records its own time")
        XCTAssertTrue(window.drainDeadlineHasWon(at: revokedAt), "settlement after the deadline loses the race")
    }

    func testUnreservedSupplierPreparationDoesNotHoldWireDrain() throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let window = SMBTransferWindow(transferIdentifier: 131, direction: .write)
        _ = try XCTUnwrap(window.beginPreparing(candidateLength: 4, countsTowardWireDrain: false))

        window.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))

        XCTAssertTrue(window.wireDrained, "a supplier waiting before credit reservation owns no wire request")
        XCTAssertNil(window.wireDrainedAt, "there was no wire work to drain")
        XCTAssertFalse(window.drainDeadlineHasWon(at: deadline))
    }

    func testSupplierReservationIsIncludedInWriteDrainAfterSupplierReturns() async throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let failureAcceptedAt = start.advanced(by: .milliseconds(10))
        let refundReturnedAt = deadline.advanced(by: .milliseconds(1))
        let window = SMBTransferWindow(transferIdentifier: 135, direction: .write)
        let credits = SMB2CreditWindow(initialCredits: 2, diagnosticSessionId: "write-supplier-reservation")
        let firstSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))
        let firstCharge = try await credits.reserveUpTo(maximumCharge: 1, waitIfUnavailable: false)
        XCTAssertEqual(firstCharge, 1)
        let first = try XCTUnwrap(window.commit(
            slotIndex: firstSlot,
            requestIdentity: makeIdentity(1),
            messageID: 1,
            requestedLength: 4,
            at: start
        ))
        XCTAssertTrue(window.markSendStarted(first))
        XCTAssertTrue(window.markFullySent(first, at: start))
        XCTAssertTrue(window.markSendOwnerFinished(first, at: start))

        let supplierSlot = try XCTUnwrap(
            window.beginPreparing(candidateLength: 4, countsTowardWireDrain: false)
        )
        let suppliedBytes: [UInt8] = [0x41]
        XCTAssertFalse(suppliedBytes.isEmpty)
        window.markPreparingReservationPending(slotIndex: supplierSlot)
        let reservedCharge = try await credits.reserveUpTo(maximumCharge: 1, waitIfUnavailable: false)
        XCTAssertEqual(reservedCharge, 1)

        window.stop(
            for: .offsetFailure(offset: first.offset, error: SMBTransferWindowTestError.serverFailure),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertTrue(window.acceptFinal(
            .failure(error: SMBTransferWindowTestError.serverFailure, isSessionFatal: false),
            for: first,
            at: failureAcceptedAt
        ))

        XCTAssertFalse(window.wireDrained, "a reserved supplier slot is unsettled until its credit is refunded")
        XCTAssertNil(window.wireDrainedAt, "the final response cannot drain an outstanding supplier reservation")
        XCTAssertTrue(window.drainDeadlineHasWon(at: deadline))

        _ = await credits.refund(charge: reservedCharge)
        XCTAssertTrue(window.revokePreparing(slotIndex: supplierSlot, at: refundReturnedAt))
        XCTAssertEqual(window.wireDrainedAt, refundReturnedAt)
        XCTAssertTrue(window.drainDeadlineHasWon(at: refundReturnedAt))
    }

    func testWriteEOFRevocationRecordsOnTimeDrainForStoppedTransfer() throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let firstFinalAt = start.advanced(by: .milliseconds(10))
        let secondFinalAt = start.advanced(by: .milliseconds(20))
        let eofReturnedAt = start.advanced(by: .seconds(4))
        let ownerResumedAt = deadline.advanced(by: .milliseconds(1))
        let window = SMBTransferWindow(transferIdentifier: 136, direction: .write)
        let first = try makeTicket(window, sequence: 1, length: 4)
        let second = try makeTicket(window, sequence: 2, length: 4)
        XCTAssertTrue(window.markSendStarted(first))
        XCTAssertTrue(window.markFullySent(first, at: start))
        XCTAssertTrue(window.markSendOwnerFinished(first, at: start))
        XCTAssertTrue(window.markSendStarted(second))
        XCTAssertTrue(window.markFullySent(second, at: start))
        XCTAssertTrue(window.markSendOwnerFinished(second, at: start))
        let eofSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))

        XCTAssertTrue(window.acceptFinal(.success(payload: []), for: first, at: firstFinalAt))
        XCTAssertTrue(window.acceptFinal(
            .failure(error: SMBTransferWindowTestError.serverFailure, isSessionFatal: false),
            for: second,
            at: secondFinalAt
        ))
        window.stop(
            for: .offsetFailure(offset: second.offset, error: SMBTransferWindowTestError.serverFailure),
            at: secondFinalAt,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertFalse(window.wireDrained, "EOF preparation remains unsettled while the owner evaluates it")

        XCTAssertTrue(window.revokePreparingForSourceEOF(slotIndex: eofSlot, at: eofReturnedAt))
        XCTAssertEqual(window.wireDrainedAt, eofReturnedAt, "EOF retraction must record when the source returned empty")
        XCTAssertFalse(
            window.drainDeadlineHasWon(at: ownerResumedAt),
            "the source EOF completed the drain before the cleanup deadline"
        )
    }

    func testPreparingCycleReplacesEarlierWireDrainTimestamp() throws {
        let start = ContinuousClock.now
        let window = SMBTransferWindow(transferIdentifier: 132, direction: .read)
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        complete(window, ticket: ticket, at: start)
        XCTAssertEqual(window.wireDrainedAt, start)

        let slot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))
        XCTAssertNil(window.wireDrainedAt, "a new preparing reservation invalidates an earlier drain")
        let stoppedAt = start.advanced(by: .seconds(1))
        let deadline = stoppedAt.advanced(by: .seconds(5))
        window.stop(for: .callerCancelled, at: stoppedAt, cleanupTimeout: .seconds(5))
        XCTAssertFalse(window.wireDrained)

        let revokedAt = stoppedAt.advanced(by: .seconds(2))
        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: revokedAt))
        XCTAssertEqual(window.wireDrainedAt, revokedAt)
        XCTAssertFalse(window.drainDeadlineHasWon(at: deadline))
    }

    func testPreparingRevocationUsesTimeAfterRefundForDrainDeadline() throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let finalAcceptedAt = start.advanced(by: .milliseconds(5_050))
        let reservationObservedAt = start.advanced(by: .milliseconds(4_900))
        let refundReturnedAt = start.advanced(by: .milliseconds(5_100))
        let window = SMBTransferWindow(transferIdentifier: 133, direction: .read)
        let readSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))
        let ticket = try XCTUnwrap(window.commit(
            slotIndex: readSlot,
            requestIdentity: makeIdentity(1),
            messageID: 1,
            requestedLength: 4,
            at: start
        ))
        XCTAssertTrue(window.markSendStarted(ticket))
        XCTAssertTrue(window.markFullySent(ticket, at: start))
        XCTAssertTrue(window.markSendOwnerFinished(ticket, at: start))

        let refundSlot = try XCTUnwrap(window.beginPreparing(candidateLength: 4))
        window.stop(
            for: .readBoundary(offset: 0, requestedLength: 4, receivedLength: 1),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(window.drainDeadline, deadline)
        XCTAssertTrue(window.acceptFinal(
            .success(payload: [0x41]),
            for: ticket,
            at: finalAcceptedAt
        ))
        XCTAssertNil(window.wireDrainedAt, "the preparing reservation still owns the wire")

        XCTAssertTrue(window.revokePreparing(slotIndex: refundSlot, at: refundReturnedAt))
        XCTAssertEqual(window.wireDrainedAt, refundReturnedAt)
        XCTAssertTrue(
            window.drainDeadlineHasWon(at: refundReturnedAt),
            "refund completion after the deadline must not be backdated to reservation time"
        )

        let staleTimestampWindow = SMBTransferWindow(transferIdentifier: 134, direction: .read)
        let staleReadSlot = try XCTUnwrap(staleTimestampWindow.beginPreparing(candidateLength: 4))
        let staleTicket = try XCTUnwrap(staleTimestampWindow.commit(
            slotIndex: staleReadSlot,
            requestIdentity: makeIdentity(2),
            messageID: 2,
            requestedLength: 4,
            at: start
        ))
        XCTAssertTrue(staleTimestampWindow.markSendStarted(staleTicket))
        XCTAssertTrue(staleTimestampWindow.markFullySent(staleTicket, at: start))
        XCTAssertTrue(staleTimestampWindow.markSendOwnerFinished(staleTicket, at: start))
        let staleRefundSlot = try XCTUnwrap(staleTimestampWindow.beginPreparing(candidateLength: 4))
        staleTimestampWindow.stop(
            for: .readBoundary(offset: 0, requestedLength: 4, receivedLength: 1),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertTrue(staleTimestampWindow.acceptFinal(
            .success(payload: [0x41]),
            for: staleTicket,
            at: finalAcceptedAt
        ))
        XCTAssertTrue(staleTimestampWindow.revokePreparing(slotIndex: staleRefundSlot, at: reservationObservedAt))
        XCTAssertEqual(staleTimestampWindow.wireDrainedAt, reservationObservedAt)
        XCTAssertFalse(
            staleTimestampWindow.drainDeadlineHasWon(at: refundReturnedAt),
            "the pre-refund timestamp incorrectly makes a late drain look timely"
        )
    }

    func testEmptyWindowStopDoesNotWinDrainDeadline() {
        let deadline = ContinuousClock.now
        let window = SMBTransferWindow(transferIdentifier: 131, direction: .write)

        window.stop(
            for: .operationDeadline,
            at: deadline,
            cleanupTimeout: .seconds(5),
            operationDeadline: deadline
        )

        XCTAssertTrue(window.wireDrained)
        XCTAssertNil(window.wireDrainedAt, "an empty window has no drain event")
        XCTAssertFalse(window.drainDeadlineHasWon(at: deadline))
        XCTAssertFalse(window.drainDeadlineHasWon(at: deadline.advanced(by: .seconds(5))))
    }

    func testFinalBeforeFullSendDoesNotCompleteSlot() throws {
        let window = SMBTransferWindow(transferIdentifier: 2, direction: .read)
        let now = ContinuousClock.now
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertEqual(ticket.slotSequence, 1)
        XCTAssertEqual(ticket.requestIdentity.requestSequence, 1)
        XCTAssertEqual(ticket.messageID, 1)
        XCTAssertTrue(window.markSendStarted(ticket))
        XCTAssertTrue(window.markSendOwnerFinished(ticket, at: now))
        XCTAssertTrue(window.acceptFinal(.success(payload: [1, 2, 3, 4]), for: ticket, at: now))

        XCTAssertFalse(window.wireDrained)
        XCTAssertNil(window.beginNextRetirement())
        XCTAssertTrue(window.markFullySent(ticket, at: now))
        XCTAssertEqual(window.beginNextRetirement()?.ticket, ticket)
    }

    func testSendOwnerMustFinishAfterFullSendAndFinal() throws {
        let window = SMBTransferWindow(transferIdentifier: 3, direction: .read)
        let now = ContinuousClock.now
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertTrue(window.markSendStarted(ticket))
        XCTAssertTrue(window.markFullySent(ticket, at: now))
        XCTAssertTrue(window.acceptFinal(.success(payload: [1, 2, 3, 4]), for: ticket, at: now))

        XCTAssertFalse(window.wireDrained)
        XCTAssertNil(window.beginNextRetirement())
        XCTAssertTrue(window.markSendOwnerFinished(ticket, at: now))
        XCTAssertTrue(window.wireDrained)
        XCTAssertEqual(window.beginNextRetirement()?.ticket, ticket)
    }

    func testPendingReadDecodeDoesNotKeepWireOwnershipOpen() throws {
        let start = ContinuousClock.now
        let window = SMBTransferWindow(transferIdentifier: 31, direction: .read)
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertTrue(window.markSendStarted(ticket))
        XCTAssertTrue(window.markFullySent(ticket, at: start))
        XCTAssertTrue(window.markSendOwnerFinished(ticket, at: start))
        window.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))

        let finalAcceptedAt = start.advanced(by: .seconds(1))
        XCTAssertTrue(window.acceptFinal(.pendingReadDecode, for: ticket, at: finalAcceptedAt))

        XCTAssertTrue(window.wireDrained, "the response is on hand; payload decoding is local work")
        XCTAssertEqual(window.wireDrainedAt, finalAcceptedAt)
        XCTAssertFalse(window.drainDeadlineHasWon(at: start.advanced(by: .seconds(5))))
    }

    func testReadOffsetFailureRetiresWithoutAdvancingDeliveryFrontier() throws {
        let window = SMBTransferWindow(transferIdentifier: 32, direction: .read)
        let now = ContinuousClock.now
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertTrue(window.markSendStarted(ticket))
        XCTAssertTrue(window.markFullySent(ticket, at: now))
        XCTAssertTrue(window.markSendOwnerFinished(ticket, at: now))
        XCTAssertTrue(window.acceptFinal(
            .failure(error: SMBCodecError.truncated, isSessionFatal: false),
            for: ticket,
            at: now
        ))
        window.stop(
            for: .offsetFailure(offset: ticket.offset, error: SMBCodecError.truncated),
            at: now,
            cleanupTimeout: .seconds(5)
        )

        let retirement = try XCTUnwrap(window.beginNextRetirement())
        guard case .failure(let error, let isSessionFatal) = retirement.result else {
            return XCTFail("decode failure must remain a failure through retirement")
        }
        XCTAssertEqual(error as? SMBCodecError, .truncated)
        XCTAssertFalse(isSessionFatal)
        XCTAssertFalse(window.finishRetirement(ticket, advanceFrontier: true))
        XCTAssertEqual(window.retireFrontier, 0, "failed payloads do not become READ delivery")
    }

    func testRetirementWaitsForOffsetOrder() throws {
        let window = SMBTransferWindow(transferIdentifier: 4, direction: .read)
        let first = try makeTicket(window, sequence: 1, length: 4)
        let second = try makeTicket(window, sequence: 2, length: 4)
        let firstPayload: [UInt8] = [0x11, 0x12, 0x13, 0x14]
        let secondPayload: [UInt8] = [0x21, 0x22, 0x23, 0x24]
        complete(window, ticket: second, result: .success(payload: secondPayload))
        XCTAssertNil(window.beginNextRetirement())

        complete(window, ticket: first, result: .success(payload: firstPayload))
        let firstRetirement = try XCTUnwrap(window.beginNextRetirement())
        XCTAssertEqual(firstRetirement.ticket, first)
        XCTAssertEqual(firstRetirement.kind, .deliverRead)
        if case .success(let payload) = firstRetirement.result {
            XCTAssertEqual(payload, firstPayload)
        } else {
            XCTFail("completed success result should be retained until retirement")
        }
        XCTAssertTrue(window.finishRetirement(first, advanceFrontier: true))
        XCTAssertTrue(window.releaseRetiredSlot(first))
        XCTAssertEqual(window.retireFrontier, 4)

        let secondRetirement = try XCTUnwrap(window.beginNextRetirement())
        XCTAssertEqual(secondRetirement.ticket, second)
        if case .success(let payload) = secondRetirement.result {
            XCTAssertEqual(payload, secondPayload)
        } else {
            XCTFail("completed success result should be retained until retirement")
        }
        XCTAssertTrue(window.finishRetirement(second, advanceFrontier: true))
        XCTAssertEqual(window.retireFrontier, 8)
    }

    func testWriteRetirementUsesRetiringState() throws {
        let window = SMBTransferWindow(transferIdentifier: 5, direction: .write)
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        complete(window, ticket: ticket)

        let retirement = try XCTUnwrap(window.beginNextRetirement())
        XCTAssertEqual(retirement.ticket, ticket)
        XCTAssertEqual(retirement.kind, .retireWrite)
        XCTAssertTrue(window.finishRetirement(ticket, advanceFrontier: true))
        XCTAssertTrue(window.releaseRetiredSlot(ticket))
        XCTAssertEqual(window.beginPreparing(candidateLength: 4), ticket.slotIndex)
    }

    func testFailedPrefixCanDiscardLaterCompletedSlotsWithoutAdvancingFrontier() throws {
        let window = SMBTransferWindow(transferIdentifier: 51, direction: .write)
        let first = try makeTicket(window, sequence: 1, length: 4)
        let second = try makeTicket(window, sequence: 2, length: 4)
        let third = try makeTicket(window, sequence: 3, length: 4)
        let now = ContinuousClock.now
        complete(
            window,
            ticket: first,
            result: .failure(error: SMBTransferWindowTestError.serverFailure, isSessionFatal: false),
            at: now
        )
        complete(window, ticket: second, at: now)
        complete(window, ticket: third, at: now)
        window.stop(
            for: .offsetFailure(offset: first.offset, error: SMBTransferWindowTestError.serverFailure),
            at: now,
            cleanupTimeout: .seconds(5)
        )

        let failedPrefix = try XCTUnwrap(window.beginNextRetirement())
        XCTAssertEqual(failedPrefix.ticket, first)
        XCTAssertTrue(window.finishRetirement(first, advanceFrontier: false))
        XCTAssertTrue(window.releaseRetiredSlot(first))
        XCTAssertEqual(window.retireFrontier, 0)
        XCTAssertNil(window.beginNextRetirement(), "later completed slots cannot advance a failed prefix")

        XCTAssertTrue(window.discardCompletedSlot(second))
        XCTAssertTrue(window.releaseRetiredSlot(second))
        XCTAssertTrue(window.discardCompletedSlot(third))
        XCTAssertTrue(window.releaseRetiredSlot(third))
        XCTAssertEqual(window.retireFrontier, 0)
        XCTAssertNil(window.beginNextRetirement())
        XCTAssertFalse(window.releaseRetiredSlot(third), "a discarded slot is released only once")
    }

    func testRetirementPreservesFailureAndSessionFatality() throws {
        let window = SMBTransferWindow(transferIdentifier: 52, direction: .write)
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        complete(
            window,
            ticket: ticket,
            result: .failure(error: SMBTransferWindowTestError.sessionFailure, isSessionFatal: true)
        )

        let retirement = try XCTUnwrap(window.beginNextRetirement())
        guard case .failure(let error, let isSessionFatal) = retirement.result else {
            return XCTFail("failure result must survive completion and retirement")
        }
        XCTAssertEqual(error as? SMBTransferWindowTestError, .sessionFailure)
        XCTAssertTrue(isSessionFatal)
    }

    func testCompletedDeliveringAndRetiringSlotsRemainChargedUntilRelease() throws {
        for direction in [SMBTransferDirection.read, .write] {
            let window = SMBTransferWindow(transferIdentifier: direction == .read ? 53 : 54, direction: direction)
            let tickets = try (1...4).map { sequence in
                try makeTicket(window, sequence: UInt64(sequence), length: 4)
            }
            XCTAssertEqual(window.committedSlotCount, 4)
            for ticket in tickets {
                complete(window, ticket: ticket)
            }
            XCTAssertEqual(window.committedSlotCount, 4, "completed requests remain committed until release")
            XCTAssertNil(window.beginPreparing(candidateLength: 4), "completed requests still own all four slots")

            let retirement = try XCTUnwrap(window.beginNextRetirement())
            XCTAssertEqual(retirement.kind, direction == .read ? .deliverRead : .retireWrite)
            XCTAssertEqual(window.committedSlotCount, 4, "delivery and retirement remain charged")
            XCTAssertNil(window.beginPreparing(candidateLength: 4), "delivery and retirement still own their slot")
            XCTAssertTrue(window.finishRetirement(retirement.ticket, advanceFrontier: true))
            XCTAssertEqual(window.committedSlotCount, 4, "retired storage remains charged until release")
            XCTAssertNil(window.beginPreparing(candidateLength: 4), "retired storage remains charged until release")
            XCTAssertTrue(window.releaseRetiredSlot(retirement.ticket))
            XCTAssertEqual(window.committedSlotCount, 3)
            XCTAssertFalse(window.releaseRetiredSlot(retirement.ticket), "double release must be rejected")
            XCTAssertEqual(window.beginPreparing(candidateLength: 4), retirement.ticket.slotIndex)
        }
    }

    func testPreparingAndCommitEnforceOneMiBPerSlot() throws {
        let window = SMBTransferWindow(transferIdentifier: 55, direction: .write)
        XCTAssertNil(window.beginPreparing(candidateLength: SMBTransferWindow.maximumSlotLength + 1))

        let slot = try XCTUnwrap(window.beginPreparing(candidateLength: SMBTransferWindow.maximumSlotLength))
        XCTAssertNil(window.commit(
            slotIndex: slot,
            requestIdentity: makeIdentity(1),
            messageID: 1,
            requestedLength: SMBTransferWindow.maximumSlotLength + 1,
            at: ContinuousClock.now
        ))
        XCTAssertEqual(window.requestFrontier, 0)
        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: ContinuousClock.now))
    }

    func testStopPreventsPreparedRequestFromCommitting() throws {
        let window = SMBTransferWindow(transferIdentifier: 6, direction: .write)
        let slot = try XCTUnwrap(window.beginPreparing(candidateLength: 8))
        let now = ContinuousClock.now
        window.stop(
            for: .offsetFailure(offset: 0, error: SMBTransferWindowTestError.serverFailure),
            at: now,
            cleanupTimeout: .seconds(5)
        )

        XCTAssertNil(window.commit(
            slotIndex: slot,
            requestIdentity: makeIdentity(1),
            messageID: 1,
            requestedLength: 8,
            at: now
        ))
        XCTAssertNil(window.beginPreparing(candidateLength: 8))
        XCTAssertTrue(window.revokePreparing(slotIndex: slot, at: now))
    }

    func testDrainDeadlineUsesFirstStopAndOnlyShortens() throws {
        let window = SMBTransferWindow(transferIdentifier: 7, direction: .read)
        let start = ContinuousClock.now
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertTrue(window.markSendStarted(ticket))
        let cleanupDeadline = start.advanced(by: .seconds(10))
        window.stop(
            for: .callerCancelled,
            at: start,
            cleanupTimeout: .seconds(10),
            operationDeadline: start.advanced(by: .seconds(30))
        )
        XCTAssertEqual(window.drainDeadline, cleanupDeadline)

        window.stop(
            for: .operationDeadline,
            at: start.advanced(by: .seconds(2)),
            cleanupTimeout: .seconds(100),
            operationDeadline: start.advanced(by: .seconds(12))
        )
        XCTAssertEqual(window.drainDeadline, cleanupDeadline)

        XCTAssertTrue(window.markFullySent(
            ticket,
            responseDeadline: start.advanced(by: .seconds(8)),
            at: start.advanced(by: .seconds(1))
        ))
        XCTAssertEqual(window.drainDeadline, start.advanced(by: .seconds(8)))
        window.shortenDrainDeadline(to: start.advanced(by: .seconds(15)))
        XCTAssertEqual(window.drainDeadline, start.advanced(by: .seconds(8)))
        let shorterDeadline = start.advanced(by: .seconds(4))
        window.shortenDrainDeadline(to: shorterDeadline)
        window.shortenDrainDeadline(to: start.advanced(by: .seconds(6)))
        XCTAssertEqual(window.drainDeadline, shorterDeadline)
    }

    func testDrainDeadlineIncludesOperationAndPreStopResponseDeadlines() throws {
        let start = ContinuousClock.now

        let operationLimited = SMBTransferWindow(transferIdentifier: 71, direction: .read)
        _ = try makeTicket(operationLimited, sequence: 1, length: 4)
        operationLimited.stop(
            for: .callerCancelled,
            at: start,
            cleanupTimeout: .seconds(10),
            operationDeadline: start.advanced(by: .seconds(3))
        )
        XCTAssertEqual(operationLimited.drainDeadline, start.advanced(by: .seconds(3)))

        let responseLimited = SMBTransferWindow(transferIdentifier: 72, direction: .read)
        let ticket = try makeTicket(responseLimited, sequence: 1, length: 4)
        let responseDeadline = start.advanced(by: .seconds(3))
        XCTAssertTrue(responseLimited.markSendStarted(ticket))
        XCTAssertTrue(responseLimited.markFullySent(
            ticket,
            responseDeadline: responseDeadline,
            at: start.advanced(by: .milliseconds(1))
        ))
        responseLimited.stop(
            for: .callerCancelled,
            at: start.advanced(by: .seconds(1)),
            cleanupTimeout: .seconds(10),
            operationDeadline: start.advanced(by: .seconds(30))
        )
        XCTAssertEqual(responseLimited.drainDeadline, responseDeadline)
    }

    func testWireDrainTimestampFixesDeadlineOutcome() throws {
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(5))
        let drainedBefore = deadline.advanced(by: .milliseconds(-1))

        let drainedBeforeStop = SMBTransferWindow(transferIdentifier: 72, direction: .read)
        let alreadyDrainedTicket = try makeTicket(drainedBeforeStop, sequence: 1, length: 4)
        complete(drainedBeforeStop, ticket: alreadyDrainedTicket, at: drainedBefore)
        XCTAssertEqual(drainedBeforeStop.wireDrainedAt, drainedBefore)
        drainedBeforeStop.stop(
            for: .operationDeadline,
            at: deadline.advanced(by: .seconds(1)),
            cleanupTimeout: .seconds(10),
            operationDeadline: deadline
        )
        XCTAssertEqual(drainedBeforeStop.drainDeadline, deadline)
        XCTAssertFalse(drainedBeforeStop.drainDeadlineHasWon(at: deadline.advanced(by: .seconds(1))))

        let onTime = SMBTransferWindow(transferIdentifier: 73, direction: .read)
        let onTimeTicket = try makeTicket(onTime, sequence: 1, length: 4)
        onTime.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))
        complete(onTime, ticket: onTimeTicket, at: drainedBefore)
        XCTAssertEqual(onTime.wireDrainedAt, drainedBefore)
        XCTAssertFalse(onTime.drainDeadlineHasWon(at: deadline.advanced(by: .seconds(1))))
        onTime.stop(
            for: .operationDeadline,
            at: deadline.advanced(by: .seconds(1)),
            cleanupTimeout: .seconds(100)
        )
        XCTAssertEqual(onTime.wireDrainedAt, drainedBefore, "later timer delivery cannot rewrite the drain event")

        let late = SMBTransferWindow(transferIdentifier: 74, direction: .read)
        let lateTicket = try makeTicket(late, sequence: 1, length: 4)
        late.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))
        complete(late, ticket: lateTicket, at: deadline)
        XCTAssertEqual(late.wireDrainedAt, deadline)
        XCTAssertTrue(late.drainDeadlineHasWon(at: deadline), "deadline wins when wire drain equals it")
        XCTAssertTrue(late.drainDeadlineHasWon(at: deadline.advanced(by: .seconds(1))))
    }

    func testShortReadBoundaryOutranksLaterOffsetFailure() {
        let start = ContinuousClock.now
        let window = SMBTransferWindow(transferIdentifier: 75, direction: .read)
        window.stop(
            for: .offsetFailure(offset: 4, error: SMBTransferWindowTestError.laterOffset),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        window.stop(
            for: .readBoundary(offset: 0, requestedLength: 4, receivedLength: 2),
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )

        guard case .readBoundary(let offset, let requested, let received)? = window.selectedStopReason() else {
            return XCTFail("the earlier positive short must be selected over the later remote error")
        }
        XCTAssertEqual(offset, 0)
        XCTAssertEqual(requested, 4)
        XCTAssertEqual(received, 2)
        XCTAssertNil(window.selectedError(), "a positive short is a rebase candidate, not the later error")

        let sameOffsetError = SMBTransferWindow(transferIdentifier: 85, direction: .read)
        sameOffsetError.stop(
            for: .readBoundary(offset: 0, requestedLength: 4, receivedLength: 2),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        sameOffsetError.stop(
            for: .offsetFailure(offset: 0, error: SMBTransferWindowTestError.earlierOffset),
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(sameOffsetError.selectedError() as? SMBTransferWindowTestError, .earlierOffset)

        let fatal = SMBTransferWindow(transferIdentifier: 86, direction: .read)
        fatal.stop(
            for: .readBoundary(offset: 0, requestedLength: 4, receivedLength: 2),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        fatal.stop(
            for: .sessionFailure(SMBTransferWindowTestError.sessionFailure),
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(fatal.selectedError() as? SMBTransferWindowTestError, .sessionFailure)
    }

    func testShortReadRetirementUsesReceivedLengthBeforeDiscardAndRebase() throws {
        let window = SMBTransferWindow(transferIdentifier: 87, direction: .read, startingOffset: 64)
        let short = try makeTicket(window, sequence: 1, length: 8)
        let speculative = try makeTicket(window, sequence: 2, length: 4)
        let now = ContinuousClock.now
        complete(window, ticket: short, result: .success(payload: [1, 2, 3]), at: now)
        complete(window, ticket: speculative, result: .success(payload: [4, 5, 6, 7]), at: now)
        window.stop(
            for: .readBoundary(offset: short.offset, requestedLength: short.requestedLength, receivedLength: 3),
            at: now,
            cleanupTimeout: .seconds(5)
        )

        let retirement = try XCTUnwrap(window.beginNextRetirement())
        XCTAssertEqual(retirement.ticket, short)
        XCTAssertTrue(window.finishRetirement(short, advanceFrontier: true))
        XCTAssertEqual(window.retireFrontier, 67)
        XCTAssertTrue(window.releaseRetiredSlot(short))
        XCTAssertNil(window.beginNextRetirement())
        XCTAssertTrue(window.discardCompletedSlot(speculative))
        XCTAssertTrue(window.releaseRetiredSlot(speculative))
        XCTAssertTrue(window.beginNextEpoch(at: 67))
        XCTAssertEqual(window.requestFrontier, 67)
    }

    func testBeginNextEpochRequiresSelectedPositiveShortAndExactRebaseOffset() {
        let start = ContinuousClock.now
        let short = SMBTransferWindow(transferIdentifier: 76, direction: .read)
        short.stop(
            for: .readBoundary(offset: 64, requestedLength: 8, receivedLength: 3),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertFalse(short.beginNextEpoch(at: 68), "rebase must use offset plus actual received length")
        XCTAssertTrue(short.beginNextEpoch(at: 67))

        let eof = SMBTransferWindow(transferIdentifier: 77, direction: .read)
        eof.stop(
            for: .readBoundary(offset: 64, requestedLength: 8, receivedLength: 0),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertFalse(eof.beginNextEpoch(at: 64), "EOF cannot start a positive-short rebase")

        let ordinaryFailure = SMBTransferWindow(transferIdentifier: 78, direction: .read)
        ordinaryFailure.stop(
            for: .offsetFailure(offset: 64, error: SMBTransferWindowTestError.serverFailure),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        XCTAssertFalse(ordinaryFailure.beginNextEpoch(at: 67))

        for (identifier, higherPriorityReason) in [
            (79, SMBTransferStopReason.callerCancelled),
            (80, SMBTransferStopReason.operationDeadline),
            (81, SMBTransferStopReason.sessionFailure(SMBTransferWindowTestError.sessionFailure))
        ] {
            let window = SMBTransferWindow(transferIdentifier: UInt64(identifier), direction: .read)
            window.stop(for: .readBoundary(offset: 64, requestedLength: 8, receivedLength: 3), at: start, cleanupTimeout: .seconds(5))
            window.stop(for: higherPriorityReason, at: start, cleanupTimeout: .seconds(5))
            XCTAssertFalse(window.beginNextEpoch(at: 67), "cancel, deadline, and fatal stops block rebase")
        }
    }

    func testStopErrorSelectionPriorityAndLowestOffset() {
        let start = ContinuousClock.now
        let window = SMBTransferWindow(transferIdentifier: 8, direction: .write)
        window.stop(
            for: .offsetFailure(offset: 12, error: SMBTransferWindowTestError.laterOffset),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        window.stop(
            for: .offsetFailure(offset: 4, error: SMBTransferWindowTestError.earlierOffset),
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(window.selectedError() as? SMBTransferWindowTestError, .earlierOffset)

        window.stop(
            for: .sessionFailure(SMBTransferWindowTestError.sessionFailure),
            at: start.advanced(by: .milliseconds(2)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(window.selectedError() as? SMBTransferWindowTestError, .sessionFailure)

        window.stop(
            for: .callerCancelled,
            at: start.advanced(by: .milliseconds(3)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertTrue(window.selectedError() is CancellationError)

        let timeoutWindow = SMBTransferWindow(transferIdentifier: 9, direction: .read)
        timeoutWindow.stop(
            for: .sessionFailure(SMBTransferWindowTestError.sessionFailure),
            at: start,
            cleanupTimeout: .seconds(5)
        )
        timeoutWindow.stop(
            for: .operationDeadline,
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(timeoutWindow.selectedError() as? SMBTransportError, .timedOut)
    }

    func testCallerCancellationAndDeadlineUseFirstEventWithDeadlineTieBreak() {
        let start = ContinuousClock.now

        let cancellationFirst = SMBTransferWindow(transferIdentifier: 82, direction: .write)
        cancellationFirst.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))
        cancellationFirst.stop(
            for: .operationDeadline,
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertTrue(cancellationFirst.selectedError() is CancellationError)

        let deadlineFirst = SMBTransferWindow(transferIdentifier: 83, direction: .write)
        deadlineFirst.stop(for: .operationDeadline, at: start, cleanupTimeout: .seconds(5))
        deadlineFirst.stop(
            for: .callerCancelled,
            at: start.advanced(by: .milliseconds(1)),
            cleanupTimeout: .seconds(5)
        )
        XCTAssertEqual(deadlineFirst.selectedError() as? SMBTransportError, .timedOut)

        let sameTime = SMBTransferWindow(transferIdentifier: 84, direction: .write)
        sameTime.stop(for: .callerCancelled, at: start, cleanupTimeout: .seconds(5))
        sameTime.stop(for: .operationDeadline, at: start, cleanupTimeout: .seconds(5))
        XCTAssertEqual(sameTime.selectedError() as? SMBTransportError, .timedOut)
    }

    func testTerminalCloseDrainsOutstandingWireAfterSendOwnersJoin() throws {
        let window = SMBTransferWindow(transferIdentifier: 10, direction: .read)
        let now = ContinuousClock.now
        let ticket = try makeTicket(window, sequence: 1, length: 4)
        XCTAssertFalse(window.wireDrained)

        window.markTerminalClose()

        XCTAssertFalse(window.wireDrained)
        window.markTerminalSendOwnersJoined(at: now)
        XCTAssertTrue(window.wireDrained)
        XCTAssertFalse(window.acceptFinal(.success(payload: [1, 2, 3, 4]), for: ticket, at: now))
        XCTAssertNil(window.beginPreparing(candidateLength: 4))
    }

    func testEachStaleTicketFieldIsRejectedAndCorrectFinalIsRetained() throws {
        let alter: [(SMBTransferTicket) -> SMBTransferTicket] = [
            { replacingTicket($0, transferIdentifier: $0.transferIdentifier + 1) },
            { replacingTicket($0, epoch: $0.epoch + 1) },
            { replacingTicket($0, slotIndex: $0.slotIndex + 1) },
            { replacingTicket($0, slotSequence: $0.slotSequence + 1) },
            { replacingTicket($0, requestIdentity: replacingIdentity($0.requestIdentity, sessionInstance: UUID())) },
            { replacingTicket($0, requestIdentity: replacingIdentity($0.requestIdentity, generation: $0.requestIdentity.generation + 1)) },
            { replacingTicket($0, requestIdentity: replacingIdentity($0.requestIdentity, requestSequence: $0.requestIdentity.requestSequence + 1)) },
            { replacingTicket($0, messageID: $0.messageID + 1) },
            { replacingTicket($0, offset: $0.offset + 1) },
            { replacingTicket($0, requestedLength: $0.requestedLength + 1) }
        ]

        for (index, mutation) in alter.enumerated() {
            let window = SMBTransferWindow(transferIdentifier: 90 + UInt64(index), direction: .read)
            let ticket = try makeTicket(window, sequence: 1, length: 4)
            let staleTicket = mutation(ticket)
            let now = ContinuousClock.now
            XCTAssertTrue(window.markSendStarted(ticket))
            XCTAssertTrue(window.markFullySent(ticket, at: now))
            XCTAssertFalse(window.acceptFinal(.success(payload: [9, 9, 9, 9]), for: staleTicket, at: now))
            XCTAssertTrue(window.acceptFinal(.success(payload: [1, 2, 3, 4]), for: ticket, at: now))
            XCTAssertTrue(window.markSendOwnerFinished(ticket, at: now))

            let retirement = try XCTUnwrap(window.beginNextRetirement())
            guard case .success(let payload) = retirement.result else {
                return XCTFail("valid completion must remain available after stale field \(index)")
            }
            XCTAssertEqual(payload, [1, 2, 3, 4])
        }

        let reused = SMBTransferWindow(transferIdentifier: 110, direction: .read)
        let oldTicket = try makeTicket(reused, sequence: 1, length: 4)
        complete(reused, ticket: oldTicket, result: .success(payload: [1, 1, 1, 1]))
        XCTAssertNotNil(reused.beginNextRetirement())
        XCTAssertTrue(reused.finishRetirement(oldTicket, advanceFrontier: true))
        XCTAssertTrue(reused.releaseRetiredSlot(oldTicket))
        let newTicket = try makeTicket(reused, sequence: 2, length: 4)
        XCTAssertEqual(newTicket.epoch, oldTicket.epoch)
        XCTAssertEqual(newTicket.slotIndex, oldTicket.slotIndex)
        XCTAssertNotEqual(newTicket.slotSequence, oldTicket.slotSequence)
        let now = ContinuousClock.now
        XCTAssertTrue(reused.markSendStarted(newTicket))
        XCTAssertTrue(reused.markFullySent(newTicket, at: now))
        XCTAssertFalse(reused.acceptFinal(.success(payload: [9, 9, 9, 9]), for: oldTicket, at: now))
        XCTAssertTrue(reused.acceptFinal(.success(payload: [2, 2, 2, 2]), for: newTicket, at: now))
        XCTAssertTrue(reused.markSendOwnerFinished(newTicket, at: now))
        let newRetirement = try XCTUnwrap(reused.beginNextRetirement())
        guard case .success(let payload) = newRetirement.result else {
            return XCTFail("same-epoch stale slot completion must leave the current result intact")
        }
        XCTAssertEqual(payload, [2, 2, 2, 2])
    }

    func testNonWaitingCreditReservationUsesAvailableCredits() async throws {
        let credits = SMB2CreditWindow(initialCredits: 3, diagnosticSessionId: "transfer-window")

        let charge = try await credits.reserveUpTo(maximumCharge: 2, waitIfUnavailable: false)

        let balance = await credits.balance
        let waiterCount = await credits.pendingWaiterCount
        XCTAssertEqual(charge, 2)
        XCTAssertEqual(balance, 1)
        XCTAssertEqual(waiterCount, 0)
    }

    func testNonWaitingCreditReservationDoesNotWaitOrBypassFIFOHead() async throws {
        let credits = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "transfer-window")
        let headWaiter = Task {
            try await credits.reserve(charge: 2, messageId: 1, command: SMB2Commands.read)
        }
        try await awaitWithDeadlineHangGuard("FIFO credit waiter registration") {
            await credits.waitForPendingWaiterCount(atLeast: 1)
        }

        _ = await credits.grant(1)
        let probe = Task {
            try await credits.reserveUpTo(maximumCharge: 1, waitIfUnavailable: false)
        }
        let charge: UInt16
        do {
            charge = try await awaitWithDeadlineHangGuard(
                "non-waiting credit reservation probe",
                operation: { () async throws -> UInt16 in try await probe.value }
            )
        } catch {
            probe.cancel()
            headWaiter.cancel()
            await credits.failAllWaiters(error)
            _ = try await awaitWithDeadlineHangGuard("non-waiting probe task cleanup") { await probe.result }
            _ = try await awaitWithDeadlineHangGuard("FIFO head cleanup after probe failure") { await headWaiter.result }
            throw error
        }
        let waitersAfterProbe = await credits.pendingWaiterCount
        let balanceAfterProbe = await credits.balance
        XCTAssertEqual(charge, 0)
        XCTAssertEqual(waitersAfterProbe, 1)
        XCTAssertEqual(balanceAfterProbe, 1)

        _ = await credits.grant(1)
        let remainingBalance = try await awaitWithDeadlineHangGuard("FIFO credit waiter completion") {
            try await headWaiter.value
        }
        _ = try await awaitWithDeadlineHangGuard("non-waiting probe task completion") { try await probe.value }
        let finalWaiterCount = await credits.pendingWaiterCount
        XCTAssertEqual(remainingBalance, 0)
        XCTAssertEqual(finalWaiterCount, 0)
    }

    func testRunContextPropagatesNestedLongShortAndNilTimeouts() async throws {
        let clock = SMBTransferWindowVirtualClock(initial: ContinuousClock.now)
        let time = SMBSessionMonotonicTime(
            now: { clock.now() },
            sleep: { try await clock.sleep(for: $0) }
        )

        let observation = try await awaitWithDeadlineHangGuard("operation run context propagation") {
            try await SMBOperationDeadline.run(
                timeout: .seconds(30),
                time: time,
                sleeper: { try await time.sleep($0) },
                operation: {
                    guard let parent = SMBOperationDeadline.operationContext else {
                        throw SMBTransferWindowTestError.missingOperationContext
                    }
                    let long = try await SMBOperationDeadline.run(
                        timeout: .seconds(9),
                        time: time,
                        sleeper: { try await time.sleep($0) },
                        operation: {
                            SMBOperationDeadline.operationContext?.deadline
                        }
                    )
                    let short = try await SMBOperationDeadline.run(
                        timeout: .seconds(2),
                        time: time,
                        sleeper: { try await time.sleep($0) },
                        operation: {
                            SMBOperationDeadline.operationContext?.deadline
                        }
                    )
                    let inherited = try await SMBOperationDeadline.run(
                        timeout: nil,
                        time: time,
                        sleeper: { try await time.sleep($0) },
                        operation: {
                            await Task { SMBOperationDeadline.operationContext?.deadline }.value
                        }
                    )
                    guard let longDeadline = long,
                          let shortDeadline = short,
                          let nilDeadline = inherited else {
                        throw SMBTransferWindowTestError.missingNestedOperationContext
                    }
                    return SMBTransferWindowDeadlineObservation(
                        parentNow: parent.now(),
                        parentDeadline: parent.deadline,
                        longDeadline: longDeadline,
                        shortDeadline: shortDeadline,
                        nilDeadline: nilDeadline
                    )
                }
            )
        }

        let expectedParent = clock.now().advanced(by: .seconds(30))
        XCTAssertEqual(observation.parentDeadline, expectedParent)
        XCTAssertEqual(observation.longDeadline, min(observation.parentDeadline, observation.parentNow.advanced(by: .seconds(9))))
        XCTAssertEqual(observation.shortDeadline, observation.parentNow.advanced(by: .seconds(2)))
        XCTAssertEqual(observation.nilDeadline, observation.parentDeadline)
    }
}

private enum SMBTransferWindowTestError: Error, Equatable {
    case missingOperationContext
    case missingNestedOperationContext
    case serverFailure
    case sessionFailure
    case earlierOffset
    case laterOffset
}

private struct SMBTransferWindowDeadlineObservation: Sendable {
    let parentNow: ContinuousClock.Instant
    let parentDeadline: ContinuousClock.Instant
    let longDeadline: ContinuousClock.Instant
    let shortDeadline: ContinuousClock.Instant
    let nilDeadline: ContinuousClock.Instant
}

private final class SMBTransferWindowVirtualClock: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var instant: ContinuousClock.Instant
    private var waiters: [Waiter] = []

    init(initial: ContinuousClock.Instant) {
        instant = initial
    }

    func now() -> ContinuousClock.Instant {
        lock.withLock { instant }
    }

    func sleep(for duration: Duration) async throws {
        let id = UUID()
        let deadline = now().advanced(by: duration)
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> Int in
                    guard !Task.isCancelled else { return -1 }
                    guard instant < deadline else { return 1 }
                    waiters.append(Waiter(id: id, deadline: deadline, continuation: continuation))
                    return 0
                }
                if state < 0 { continuation.resume(throwing: CancellationError()) }
                if state > 0 { continuation.resume() }
            }
        } onCancel: {
            self.cancelWaiter(id: id)
        }
    }

    private func cancelWaiter(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private func makeIdentity(_ sequence: UInt64) -> SMBRequestIdentity {
    SMBRequestIdentity(
        sessionInstance: UUID(),
        generation: 1,
        requestSequence: sequence
    )
}

private func replacingIdentity(
    _ identity: SMBRequestIdentity,
    sessionInstance: UUID? = nil,
    generation: UInt64? = nil,
    requestSequence: UInt64? = nil
) -> SMBRequestIdentity {
    SMBRequestIdentity(
        sessionInstance: sessionInstance ?? identity.sessionInstance,
        generation: generation ?? identity.generation,
        requestSequence: requestSequence ?? identity.requestSequence
    )
}

private func replacingTicket(
    _ ticket: SMBTransferTicket,
    transferIdentifier: UInt64? = nil,
    epoch: UInt64? = nil,
    slotIndex: Int? = nil,
    slotSequence: UInt64? = nil,
    requestIdentity: SMBRequestIdentity? = nil,
    messageID: UInt64? = nil,
    offset: UInt64? = nil,
    requestedLength: UInt32? = nil
) -> SMBTransferTicket {
    SMBTransferTicket(
        transferIdentifier: transferIdentifier ?? ticket.transferIdentifier,
        epoch: epoch ?? ticket.epoch,
        slotIndex: slotIndex ?? ticket.slotIndex,
        slotSequence: slotSequence ?? ticket.slotSequence,
        requestIdentity: requestIdentity ?? ticket.requestIdentity,
        messageID: messageID ?? ticket.messageID,
        offset: offset ?? ticket.offset,
        requestedLength: requestedLength ?? ticket.requestedLength
    )
}

private func makeTicket(
    _ window: SMBTransferWindow,
    sequence: UInt64,
    length: UInt32
) throws -> SMBTransferTicket {
    let slotIndex = try XCTUnwrap(window.beginPreparing(candidateLength: length))
    return try XCTUnwrap(window.commit(
        slotIndex: slotIndex,
        requestIdentity: makeIdentity(sequence),
        messageID: sequence,
        requestedLength: length,
        at: ContinuousClock.now
    ))
}

private func complete(
    _ window: SMBTransferWindow,
    ticket: SMBTransferTicket,
    result: SMBTransferFinalResult = .success(payload: []),
    at time: ContinuousClock.Instant = ContinuousClock.now
) {
    XCTAssertTrue(window.markSendStarted(ticket))
    XCTAssertTrue(window.markFullySent(ticket, at: time))
    XCTAssertTrue(window.acceptFinal(result, for: ticket, at: time))
    XCTAssertTrue(window.markSendOwnerFinished(ticket, at: time))
}
