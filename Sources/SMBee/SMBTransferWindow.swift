enum SMBTransferDirection: Equatable, Sendable {
    case read
    case write
}

enum SMBTransferSendPhase: Equatable, Sendable {
    case registered
    case sending
    case fullySent
}

struct SMBTransferTicket: Hashable, Sendable {
    let transferIdentifier: UInt64
    let epoch: UInt64
    let slotIndex: Int
    let slotSequence: UInt64
    let requestIdentity: SMBRequestIdentity
    let messageID: UInt64
    let offset: UInt64
    let requestedLength: UInt32
}

enum SMBTransferFinalResult: @unchecked Sendable {
    case pendingReadDecode
    case success(payload: [UInt8])
    case failure(error: Error, isSessionFatal: Bool)
}

struct SMBTransferRetirement: Sendable {
    let ticket: SMBTransferTicket
    let result: SMBTransferFinalResult
    let kind: SMBTransferRetirementKind
}

enum SMBTransferRetirementKind: Equatable, Sendable {
    case deliverRead
    case retireWrite
}

enum SMBTransferStopReason {
    case callerCancelled
    case operationDeadline
    case sessionFailure(Error)
    case offsetFailure(offset: UInt64, error: Error)
    case readBoundary(offset: UInt64, requestedLength: UInt32, receivedLength: UInt32)
}

/// Synchronous transfer ownership state. The session actor is the only production owner.
final class SMBTransferWindow {
    static let maximumSlotCount = 4
    static let maximumSlotLength: UInt32 = 1_048_576

    private struct Preparation {
        let offset: UInt64
        let candidateLength: UInt32
        let countsTowardWireDrain: Bool
    }

    private enum SlotPhase: Equatable {
        case vacant
        case preparing
        case committed
        case completed
        case delivering
        case retiring
        case retired
    }

    private struct Slot {
        var nextSequence: UInt64 = 0
        var phase: SlotPhase = .vacant
        var preparation: Preparation?
        var ticket: SMBTransferTicket?
        var result: SMBTransferFinalResult?
        var sendPhase: SMBTransferSendPhase?
        var sendOwnerFinished = false
        var responseDeadline: ContinuousClock.Instant?
    }

    private static let allSlotBits = UInt8((1 << maximumSlotCount) - 1)

    private struct StopCandidate {
        let reason: SMBTransferStopReason
        let observedAt: ContinuousClock.Instant
    }

    let transferIdentifier: UInt64
    let direction: SMBTransferDirection
    private(set) var epoch: UInt64 = 0
    private(set) var requestFrontier: UInt64
    private(set) var retireFrontier: UInt64
    private var firstStopTime: ContinuousClock.Instant?
    private(set) var drainDeadline: ContinuousClock.Instant?
    private(set) var wireDrainedAt: ContinuousClock.Instant?
    private var drainDeadlineHasWireWork = false
    private(set) var terminallyClosed = false
    private var terminalSendOwnersJoined = false

    private var admissionStopped = false
    private var slots = Array(repeating: Slot(), count: maximumSlotCount)
    private var vacantSlotBits = allSlotBits
    private var preparingSlotIndex: Int?
    private var committedSlotCountStorage = 0
    private var readyRetirementSlotIndex: Int?
    private var stopCandidates: [StopCandidate] = []

    init(transferIdentifier: UInt64, direction: SMBTransferDirection, startingOffset: UInt64 = 0) {
        self.transferIdentifier = transferIdentifier
        self.direction = direction
        self.requestFrontier = startingOffset
        self.retireFrontier = startingOffset
    }

    var isStopped: Bool {
        admissionStopped || terminallyClosed
    }

    var committedSlotCount: Int {
        committedSlotCountStorage
    }

    var completedTickets: [SMBTransferTicket] {
        slots.compactMap { slot in
            guard slot.phase == .completed else { return nil }
            return slot.ticket
        }
    }

    var hasReadyRetirement: Bool {
        readyRetirementSlotIndex != nil
    }

    func preparingOffsetAndLength(slotIndex: Int) -> (offset: UInt64, candidateLength: UInt32)? {
        guard slots.indices.contains(slotIndex),
              slots[slotIndex].phase == .preparing,
              let preparation = slots[slotIndex].preparation else {
            return nil
        }
        return (preparation.offset, preparation.candidateLength)
    }

    /// Preparing is local ownership only; no MID or pending response exists yet.
    func beginPreparing(candidateLength: UInt32, countsTowardWireDrain: Bool = true) -> Int? {
        guard !isStopped,
              candidateLength > 0,
              candidateLength <= Self.maximumSlotLength,
              preparingSlotIndex == nil,
              vacantSlotBits != 0 else {
            return nil
        }
        let index = vacantSlotBits.trailingZeroBitCount
        let bit = UInt8(1 << index)
        vacantSlotBits &= ~bit
        slots[index].phase = .preparing
        slots[index].preparation = Preparation(
            offset: requestFrontier,
            candidateLength: candidateLength,
            countsTowardWireDrain: countsTowardWireDrain
        )
        preparingSlotIndex = index
        if countsTowardWireDrain { wireDrainedAt = nil }
        return index
    }

    func markPreparingReservationPending(slotIndex: Int) {
        guard slots.indices.contains(slotIndex),
              slots[slotIndex].phase == .preparing,
              let preparation = slots[slotIndex].preparation,
              !preparation.countsTowardWireDrain else {
            return
        }
        slots[slotIndex].preparation = Preparation(
            offset: preparation.offset,
            candidateLength: preparation.candidateLength,
            countsTowardWireDrain: true
        )
        wireDrainedAt = nil
    }

    @discardableResult
    func revokePreparing(slotIndex: Int, at time: ContinuousClock.Instant?) -> Bool {
        guard slots.indices.contains(slotIndex),
              slots[slotIndex].phase == .preparing else {
            return false
        }
        setPhase(.vacant, for: slotIndex)
        slots[slotIndex].preparation = nil
        preparingSlotIndex = nil
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return true
    }

    @discardableResult
    func revokePreparingForSourceEOF(slotIndex: Int, at time: ContinuousClock.Instant) -> Bool {
        revokePreparing(slotIndex: slotIndex, at: time)
    }

    /// Commit advances the request frontier by the actual wire length, not the candidate length.
    func commit(
        slotIndex: Int,
        requestIdentity: SMBRequestIdentity,
        messageID: UInt64,
        requestedLength: UInt32,
        at time: ContinuousClock.Instant?
    ) -> SMBTransferTicket? {
        guard !isStopped,
              slots.indices.contains(slotIndex),
              slots[slotIndex].phase == .preparing,
              let preparation = slots[slotIndex].preparation,
              preparation.offset == requestFrontier,
              requestedLength > 0,
              requestedLength <= Self.maximumSlotLength,
              requestedLength <= preparation.candidateLength,
              slots[slotIndex].nextSequence < UInt64.max else {
            return nil
        }
        let (nextFrontier, overflow) = requestFrontier.addingReportingOverflow(UInt64(requestedLength))
        guard !overflow else { return nil }

        slots[slotIndex].nextSequence += 1
        let ticket = SMBTransferTicket(
            transferIdentifier: transferIdentifier,
            epoch: epoch,
            slotIndex: slotIndex,
            slotSequence: slots[slotIndex].nextSequence,
            requestIdentity: requestIdentity,
            messageID: messageID,
            offset: preparation.offset,
            requestedLength: requestedLength
        )
        slots[slotIndex].preparation = nil
        slots[slotIndex].ticket = ticket
        slots[slotIndex].result = nil
        slots[slotIndex].sendPhase = .registered
        slots[slotIndex].sendOwnerFinished = false
        slots[slotIndex].responseDeadline = nil
        setPhase(.committed, for: slotIndex)
        preparingSlotIndex = nil
        wireDrainedAt = nil
        requestFrontier = nextFrontier
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return ticket
    }

    @discardableResult
    func markSendStarted(_ ticket: SMBTransferTicket) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              slots[index].sendPhase == .registered else {
            return false
        }
        slots[index].sendPhase = .sending
        return true
    }

    @discardableResult
    func markFullySent(
        _ ticket: SMBTransferTicket,
        responseDeadline: ContinuousClock.Instant? = nil,
        at time: ContinuousClock.Instant?
    ) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              slots[index].sendPhase == .sending else {
            return false
        }
        slots[index].sendPhase = .fullySent
        slots[index].responseDeadline = responseDeadline
        if isStopped, let responseDeadline {
            shortenDrainDeadline(to: responseDeadline)
        }
        completeIfReady(slotIndex: index)
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return true
    }

    @discardableResult
    func markSendOwnerFinished(_ ticket: SMBTransferTicket, at time: ContinuousClock.Instant?) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              !slots[index].sendOwnerFinished else {
            return false
        }
        slots[index].sendOwnerFinished = true
        completeIfReady(slotIndex: index)
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return true
    }

    /// A final may arrive before the send callback returns; completion waits for both send facts.
    @discardableResult
    func acceptFinal(
        _ result: SMBTransferFinalResult,
        for ticket: SMBTransferTicket,
        at time: ContinuousClock.Instant?
    ) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              case nil = slots[index].result else {
            return false
        }
        slots[index].result = result
        completeIfReady(slotIndex: index)
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return true
    }

    @discardableResult
    func finishPendingReadDecode(
        _ result: SMBTransferFinalResult,
        for ticket: SMBTransferTicket,
        at time: ContinuousClock.Instant?
    ) -> Bool {
        if case .pendingReadDecode = result { return false }
        guard direction == .read,
              let index = matchingCommittedSlot(for: ticket),
              case .pendingReadDecode? = slots[index].result else {
            return false
        }
        slots[index].result = result
        completeIfReady(slotIndex: index)
        if let time {
            recordWireDrainedIfReady(at: time)
        }
        return true
    }

    func isPendingReadDecode(for ticket: SMBTransferTicket) -> Bool {
        guard direction == .read,
              let index = matchingCommittedSlot(for: ticket),
              case .pendingReadDecode? = slots[index].result else {
            return false
        }
        return true
    }

    /// Starts only the completed request at the retire frontier.
    func beginNextRetirement() -> SMBTransferRetirement? {
        guard let index = readyRetirementSlotIndex,
              slots[index].phase == .completed,
              let ticket = slots[index].ticket,
              let result = slots[index].result else {
            return nil
        }
        readyRetirementSlotIndex = nil
        switch direction {
        case .read:
            setPhase(.delivering, for: index)
        case .write:
            setPhase(.retiring, for: index)
        }
        let kind: SMBTransferRetirementKind = direction == .read ? .deliverRead : .retireWrite
        return SMBTransferRetirement(ticket: ticket, result: result, kind: kind)
    }

    /// Finishes delivery/ACK retirement. Failed callbacks do not advance the ordered prefix.
    @discardableResult
    func finishRetirement(_ ticket: SMBTransferTicket, advanceFrontier: Bool) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              ticket.offset == retireFrontier,
              let result = slots[ticket.slotIndex].result else {
            return false
        }
        let expectedPhase: SlotPhase = direction == .read ? .delivering : .retiring
        guard slots[ticket.slotIndex].phase == expectedPhase,
              slots[ticket.slotIndex].ticket == ticket else {
            return false
        }
        if advanceFrontier {
            let advancedLength: UInt64
            switch (direction, result) {
            case (.read, .success(let payload)):
                advancedLength = UInt64(payload.count)
            case (.write, .success):
                advancedLength = UInt64(ticket.requestedLength)
            case (_, .pendingReadDecode), (_, .failure):
                return false
            }
            let (nextFrontier, overflow) = retireFrontier.addingReportingOverflow(advancedLength)
            guard !overflow else { return false }
            retireFrontier = nextFrontier
        }
        slots[ticket.slotIndex].result = nil
        setPhase(.retired, for: ticket.slotIndex)
        if advanceFrontier {
            refreshReadyRetirementIndex()
        }
        return true
    }

    @discardableResult
    func releaseRetiredSlot(_ ticket: SMBTransferTicket) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              slots[ticket.slotIndex].phase == .retired,
              slots[ticket.slotIndex].ticket == ticket else {
            return false
        }
        clearSlotPayload(at: ticket.slotIndex)
        setPhase(.vacant, for: ticket.slotIndex)
        return true
    }

    /// Discards an out-of-prefix completed request without moving the retirement frontier.
    @discardableResult
    func discardCompletedSlot(_ ticket: SMBTransferTicket) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              ticket.offset > retireFrontier,
              slots[ticket.slotIndex].phase == .completed,
              slots[ticket.slotIndex].ticket == ticket else {
            return false
        }
        slots[ticket.slotIndex].result = nil
        setPhase(.retired, for: ticket.slotIndex)
        return true
    }

    /// Stop paths that outrank ordered delivery may discard any completed slot, including
    /// the current retirement frontier. The owner still releases it exactly once.
    @discardableResult
    func discardCompletedSlotForStop(_ ticket: SMBTransferTicket) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              slots[ticket.slotIndex].phase == .completed,
              slots[ticket.slotIndex].ticket == ticket else {
            return false
        }
        if readyRetirementSlotIndex == ticket.slotIndex {
            readyRetirementSlotIndex = nil
        }
        slots[ticket.slotIndex].result = nil
        setPhase(.retired, for: ticket.slotIndex)
        return true
    }

    /// Once terminal teardown has joined every send owner, no committed slot can receive a
    /// final on this session. Clearing those tickets prevents a dead transfer from retaining
    /// response buffers while preserving stale-ticket rejection through `terminallyClosed`.
    func reclaimSlotsAfterTerminalJoin() {
        guard terminallyClosed, terminalSendOwnersJoined else { return }
        for index in slots.indices {
            clearSlotPayload(at: index)
            setPhase(.vacant, for: index)
        }
        preparingSlotIndex = nil
        readyRetirementSlotIndex = nil
    }

    /// The first stop fixes S + cleanupTimeout; later facts can only shorten that deadline.
    func stop(
        for reason: SMBTransferStopReason,
        at time: ContinuousClock.Instant,
        cleanupTimeout: Duration,
        operationDeadline: ContinuousClock.Instant? = nil
    ) {
        if firstStopTime == nil {
            firstStopTime = time
            drainDeadline = time.advanced(by: cleanupTimeout)
            drainDeadlineHasWireWork = hasUnsettledWireWork
        }
        admissionStopped = true
        insertStopCandidate(StopCandidate(reason: reason, observedAt: time))
        if let operationDeadline {
            shortenDrainDeadline(to: operationDeadline)
        }
        for slot in slots {
            guard slot.phase == .committed,
                  case nil = slot.result,
                  let responseDeadline = slot.responseDeadline else { continue }
            shortenDrainDeadline(to: responseDeadline)
        }
        if drainDeadlineHasWireWork {
            recordWireDrainedIfReady(at: time)
        }
    }

    /// This is also used when a committed send reaches full-send after stop was recorded.
    func shortenDrainDeadline(to deadline: ContinuousClock.Instant) {
        guard firstStopTime != nil else { return }
        guard let currentDeadline = drainDeadline else {
            drainDeadline = deadline
            return
        }
        if deadline < currentDeadline {
            drainDeadline = deadline
        }
    }

    func selectedStopReason() -> SMBTransferStopReason? {
        let callerStops = stopCandidates.filter {
            switch $0.reason {
            case .callerCancelled, .operationDeadline:
                true
            case .sessionFailure, .offsetFailure, .readBoundary:
                false
            }
        }
        if let selected = callerStops.min(by: Self.precedes) {
            return selected.reason
        }

        let sessionFailures = stopCandidates.filter {
            if case .sessionFailure = $0.reason { return true }
            return false
        }
        if let selected = sessionFailures.min(by: Self.precedes) {
            return selected.reason
        }

        let offsetCandidates = stopCandidates.filter {
            switch $0.reason {
            case .offsetFailure, .readBoundary:
                true
            case .callerCancelled, .operationDeadline, .sessionFailure:
                false
            }
        }
        return offsetCandidates.min { left, right in
            let leftOffset = Self.offset(of: left.reason)
            let rightOffset = Self.offset(of: right.reason)
            guard let leftOffset, let rightOffset else { return Self.precedes(left, right) }
            if leftOffset != rightOffset { return leftOffset < rightOffset }
            if case .offsetFailure = left.reason, case .readBoundary = right.reason { return true }
            if case .readBoundary = left.reason, case .offsetFailure = right.reason { return false }
            return Self.precedes(left, right)
        }?.reason
    }

    func selectedError() -> Error? {
        guard let reason = selectedStopReason() else { return nil }
        return switch reason {
        case .callerCancelled:
            CancellationError()
        case .operationDeadline:
            SMBTransportError.timedOut
        case .sessionFailure(let error), .offsetFailure(_, let error):
            error
        case .readBoundary:
            nil
        }
    }

    /// Terminal close only drains wire ownership after every committed send owner has joined.
    func markTerminalClose() {
        terminallyClosed = true
        admissionStopped = true
    }

    func markTerminalSendOwnersJoined(at time: ContinuousClock.Instant) {
        terminalSendOwnersJoined = true
        recordWireDrainedIfReady(at: time)
    }

    var wireDrained: Bool {
        guard !hasPreparingWireWork else { return false }
        return (terminallyClosed && terminalSendOwnersJoined) || !hasUnsettledWireSlot
    }

    /// A deadline wins at equality. The recorded drain fact survives a delayed timer callback.
    func drainDeadlineHasWon(at time: ContinuousClock.Instant) -> Bool {
        guard drainDeadlineHasWireWork,
              let drainDeadline,
              time >= drainDeadline else { return false }
        guard let wireDrainedAt else { return true }
        return wireDrainedAt >= drainDeadline
    }

    /// Starts a fresh epoch after all previous slots have been reclaimed.
    @discardableResult
    func beginNextEpoch(at offset: UInt64) -> Bool {
        guard direction == .read,
              case .readBoundary(let boundaryOffset, let requestedLength, let receivedLength)? = selectedStopReason(),
              receivedLength > 0,
              receivedLength < requestedLength else {
            return false
        }
        let (rebaseOffset, overflow) = boundaryOffset.addingReportingOverflow(UInt64(receivedLength))
        guard !overflow, offset == rebaseOffset else { return false }
        guard !terminallyClosed,
              wireDrained,
              !hasHigherPriorityStopThanReadBoundary,
              vacantSlotBits == Self.allSlotBits,
              epoch < UInt64.max else {
            return false
        }
        epoch += 1
        requestFrontier = offset
        retireFrontier = offset
        firstStopTime = nil
        drainDeadline = nil
        wireDrainedAt = nil
        drainDeadlineHasWireWork = false
        admissionStopped = false
        stopCandidates.removeAll()
        return true
    }

    private func matchingCommittedSlot(for ticket: SMBTransferTicket) -> Int? {
        guard !terminallyClosed,
              ticket.transferIdentifier == transferIdentifier,
              ticket.epoch == epoch,
              slots.indices.contains(ticket.slotIndex),
              slots[ticket.slotIndex].phase == .committed,
              slots[ticket.slotIndex].ticket == ticket else {
            return nil
        }
        return ticket.slotIndex
    }

    private func completeIfReady(slotIndex: Int) {
        guard slots[slotIndex].phase == .committed,
              slots[slotIndex].sendPhase == .fullySent,
              slots[slotIndex].sendOwnerFinished,
              let ticket = slots[slotIndex].ticket,
              let result = slots[slotIndex].result else {
            return
        }
        if case .pendingReadDecode = result { return }
        setPhase(.completed, for: slotIndex)
        if ticket.offset == retireFrontier {
            readyRetirementSlotIndex = slotIndex
        }
    }

    private var hasPreparingWireWork: Bool {
        guard let preparingSlotIndex,
              let preparation = slots[preparingSlotIndex].preparation else {
            return false
        }
        return preparation.countsTowardWireDrain
    }

    private var hasUnsettledWireWork: Bool {
        hasPreparingWireWork || hasUnsettledWireSlot
    }

    private var hasUnsettledWireSlot: Bool {
        slots.contains { slot in
            guard slot.phase == .committed else { return false }
            guard slot.sendPhase == .fullySent, slot.sendOwnerFinished else { return true }
            guard case nil = slot.result else { return false }
            return true
        }
    }

    private func refreshReadyRetirementIndex() {
        readyRetirementSlotIndex = slots.firstIndex { slot in
            slot.phase == .completed && slot.ticket?.offset == retireFrontier
        }
    }

    private func clearSlotPayload(at index: Int) {
        slots[index].preparation = nil
        slots[index].ticket = nil
        slots[index].result = nil
        slots[index].sendPhase = nil
        slots[index].sendOwnerFinished = false
        slots[index].responseDeadline = nil
    }

    private func setPhase(_ phase: SlotPhase, for index: Int) {
        let previousPhase = slots[index].phase
        let slotBit = UInt8(1 << index)
        if previousPhase == .vacant {
            vacantSlotBits &= ~slotBit
        }
        if phase == .vacant {
            vacantSlotBits |= slotBit
        }
        if previousPhase == .preparing, phase == .committed {
            committedSlotCountStorage += 1
        } else if Self.ownsCommittedTicket(previousPhase), phase == .vacant {
            committedSlotCountStorage -= 1
        }
        slots[index].phase = phase
    }

    private static func ownsCommittedTicket(_ phase: SlotPhase) -> Bool {
        switch phase {
        case .committed, .completed, .delivering, .retiring, .retired:
            true
        case .vacant, .preparing:
            false
        }
    }

    private func insertStopCandidate(_ candidate: StopCandidate) {
        switch candidate.reason {
        case .callerCancelled:
            guard !stopCandidates.contains(where: {
                if case .callerCancelled = $0.reason { return true }
                return false
            }) else { return }
        case .operationDeadline:
            guard !stopCandidates.contains(where: {
                if case .operationDeadline = $0.reason { return true }
                return false
            }) else { return }
        case .sessionFailure:
            guard !stopCandidates.contains(where: {
                if case .sessionFailure = $0.reason { return true }
                return false
            }) else { return }
        case .offsetFailure(let offset, _):
            guard !stopCandidates.contains(where: {
                if case .offsetFailure(let existingOffset, _) = $0.reason {
                    return existingOffset == offset
                }
                return false
            }) else { return }
        case .readBoundary(let offset, let requestedLength, let receivedLength):
            guard direction == .read,
                  requestedLength > 0,
                  receivedLength < requestedLength,
                  !stopCandidates.contains(where: {
                      if case .readBoundary(let existingOffset, _, _) = $0.reason {
                          return existingOffset == offset
                      }
                      return false
                  }) else { return }
        }
        stopCandidates.append(candidate)
    }

    private var hasHigherPriorityStopThanReadBoundary: Bool {
        stopCandidates.contains { candidate in
            switch candidate.reason {
            case .callerCancelled, .operationDeadline, .sessionFailure:
                true
            case .offsetFailure, .readBoundary:
                false
            }
        }
    }

    private func recordWireDrainedIfReady(at time: ContinuousClock.Instant) {
        guard firstStopTime == nil || drainDeadlineHasWireWork,
              wireDrainedAt == nil,
              wireDrained else {
            return
        }
        wireDrainedAt = time
    }

    private static func offset(of reason: SMBTransferStopReason) -> UInt64? {
        switch reason {
        case .offsetFailure(let offset, _), .readBoundary(let offset, _, _):
            offset
        case .callerCancelled, .operationDeadline, .sessionFailure:
            nil
        }
    }

    private static func precedes(_ left: StopCandidate, _ right: StopCandidate) -> Bool {
        if left.observedAt != right.observedAt {
            return left.observedAt < right.observedAt
        }
        if case .operationDeadline = left.reason, case .callerCancelled = right.reason {
            return true
        }
        return false
    }
}
