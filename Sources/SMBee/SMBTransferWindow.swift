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

enum SMBTransferFinalResult {
    case success(payload: [UInt8])
    case failure(error: Error, isSessionFatal: Bool)
}

struct SMBTransferRetirement {
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
    }

    private enum WireState {
        case waiting
        case final(SMBTransferFinalResult)
    }

    private struct Committed {
        let ticket: SMBTransferTicket
        var sendPhase: SMBTransferSendPhase
        var wireState: WireState
        var sendOwnerFinished: Bool
        var responseDeadline: ContinuousClock.Instant?
    }

    private enum SlotStorage {
        case vacant
        case preparing(Preparation)
        case committed(Committed)
        case completed(ticket: SMBTransferTicket, result: SMBTransferFinalResult)
        case delivering(ticket: SMBTransferTicket, result: SMBTransferFinalResult)
        case retiring(ticket: SMBTransferTicket, result: SMBTransferFinalResult)
        case retired(SMBTransferTicket)
    }

    private struct Slot {
        var nextSequence: UInt64 = 0
        var storage: SlotStorage = .vacant
    }

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

    /// Preparing is local ownership only; no MID or pending response exists yet.
    func beginPreparing(candidateLength: UInt32) -> Int? {
        guard !isStopped,
              candidateLength > 0,
              candidateLength <= Self.maximumSlotLength,
              !slots.contains(where: { if case .preparing = $0.storage { true } else { false } }),
              let index = slots.firstIndex(where: { if case .vacant = $0.storage { true } else { false } }) else {
            return nil
        }
        slots[index].storage = .preparing(Preparation(
            offset: requestFrontier,
            candidateLength: candidateLength
        ))
        wireDrainedAt = nil
        return index
    }

    @discardableResult
    func revokePreparing(slotIndex: Int, at time: ContinuousClock.Instant) -> Bool {
        guard slots.indices.contains(slotIndex),
              case .preparing = slots[slotIndex].storage else {
            return false
        }
        slots[slotIndex].storage = .vacant
        recordWireDrainedIfReady(at: time)
        return true
    }

    /// Commit advances the request frontier by the actual wire length, not the candidate length.
    func commit(
        slotIndex: Int,
        requestIdentity: SMBRequestIdentity,
        messageID: UInt64,
        requestedLength: UInt32,
        at time: ContinuousClock.Instant
    ) -> SMBTransferTicket? {
        guard !isStopped,
              slots.indices.contains(slotIndex),
              case .preparing(let preparation) = slots[slotIndex].storage,
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
        slots[slotIndex].storage = .committed(Committed(
            ticket: ticket,
            sendPhase: .registered,
            wireState: .waiting,
            sendOwnerFinished: false,
            responseDeadline: nil
        ))
        wireDrainedAt = nil
        requestFrontier = nextFrontier
        recordWireDrainedIfReady(at: time)
        return ticket
    }

    @discardableResult
    func markSendStarted(_ ticket: SMBTransferTicket) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              case .committed(var committed) = slots[index].storage,
              committed.sendPhase == .registered else {
            return false
        }
        committed.sendPhase = .sending
        slots[index].storage = .committed(committed)
        return true
    }

    @discardableResult
    func markFullySent(
        _ ticket: SMBTransferTicket,
        responseDeadline: ContinuousClock.Instant? = nil,
        at time: ContinuousClock.Instant
    ) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              case .committed(var committed) = slots[index].storage,
              committed.sendPhase == .sending else {
            return false
        }
        committed.sendPhase = .fullySent
        committed.responseDeadline = responseDeadline
        slots[index].storage = .committed(committed)
        if isStopped, let responseDeadline {
            shortenDrainDeadline(to: responseDeadline)
        }
        completeIfReady(slotIndex: index)
        recordWireDrainedIfReady(at: time)
        return true
    }

    @discardableResult
    func markSendOwnerFinished(_ ticket: SMBTransferTicket, at time: ContinuousClock.Instant) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              case .committed(var committed) = slots[index].storage,
              !committed.sendOwnerFinished else {
            return false
        }
        committed.sendOwnerFinished = true
        slots[index].storage = .committed(committed)
        completeIfReady(slotIndex: index)
        recordWireDrainedIfReady(at: time)
        return true
    }

    /// A final may arrive before the send callback returns; completion waits for both send facts.
    @discardableResult
    func acceptFinal(
        _ result: SMBTransferFinalResult,
        for ticket: SMBTransferTicket,
        at time: ContinuousClock.Instant
    ) -> Bool {
        guard let index = matchingCommittedSlot(for: ticket),
              case .committed(var committed) = slots[index].storage,
              case .waiting = committed.wireState else {
            return false
        }
        committed.wireState = .final(result)
        slots[index].storage = .committed(committed)
        completeIfReady(slotIndex: index)
        recordWireDrainedIfReady(at: time)
        return true
    }

    /// Starts only the completed request at the retire frontier.
    func beginNextRetirement() -> SMBTransferRetirement? {
        guard let index = slots.firstIndex(where: { slot in
            guard case .completed(let ticket, _) = slot.storage else { return false }
            return ticket.offset == retireFrontier
        }), case .completed(let ticket, let result) = slots[index].storage else {
            return nil
        }
        switch direction {
        case .read:
            slots[index].storage = .delivering(ticket: ticket, result: result)
        case .write:
            slots[index].storage = .retiring(ticket: ticket, result: result)
        }
        let kind: SMBTransferRetirementKind = direction == .read ? .deliverRead : .retireWrite
        return SMBTransferRetirement(ticket: ticket, result: result, kind: kind)
    }

    /// Finishes delivery/ACK retirement. Failed callbacks do not advance the ordered prefix.
    @discardableResult
    func finishRetirement(_ ticket: SMBTransferTicket, advanceFrontier: Bool) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              ticket.offset == retireFrontier else {
            return false
        }
        let result: SMBTransferFinalResult
        switch (direction, slots[ticket.slotIndex].storage) {
        case (.read, .delivering(let current, let currentResult)), (.write, .retiring(let current, let currentResult)):
            guard current == ticket else { return false }
            result = currentResult
        default:
            return false
        }
        if advanceFrontier {
            let advancedLength: UInt64
            switch (direction, result) {
            case (.read, .success(let payload)):
                advancedLength = UInt64(payload.count)
            case (.write, .success):
                advancedLength = UInt64(ticket.requestedLength)
            case (_, .failure):
                return false
            }
            let (nextFrontier, overflow) = retireFrontier.addingReportingOverflow(advancedLength)
            guard !overflow else { return false }
            retireFrontier = nextFrontier
        }
        slots[ticket.slotIndex].storage = .retired(ticket)
        return true
    }

    @discardableResult
    func releaseRetiredSlot(_ ticket: SMBTransferTicket) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              case .retired(let current) = slots[ticket.slotIndex].storage,
              current == ticket else {
            return false
        }
        slots[ticket.slotIndex].storage = .vacant
        return true
    }

    /// Discards an out-of-prefix completed request without moving the retirement frontier.
    @discardableResult
    func discardCompletedSlot(_ ticket: SMBTransferTicket) -> Bool {
        guard slots.indices.contains(ticket.slotIndex),
              ticket.offset > retireFrontier,
              case .completed(let current, _) = slots[ticket.slotIndex].storage,
              current == ticket else {
            return false
        }
        slots[ticket.slotIndex].storage = .retired(ticket)
        return true
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
            guard case .committed(let committed) = slot.storage,
                  case .waiting = committed.wireState,
                  let responseDeadline = committed.responseDeadline else { continue }
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
        guard !hasPreparingSlot else { return false }
        return (terminallyClosed && terminalSendOwnersJoined) || slots.allSatisfy { slot in
            if case .committed = slot.storage { return false }
            return true
        }
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
              slots.allSatisfy({ if case .vacant = $0.storage { true } else { false } }),
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
              case .committed(let committed) = slots[ticket.slotIndex].storage,
              committed.ticket == ticket else {
            return nil
        }
        return ticket.slotIndex
    }

    private func completeIfReady(slotIndex: Int) {
        guard case .committed(let committed) = slots[slotIndex].storage,
              committed.sendPhase == .fullySent,
              committed.sendOwnerFinished,
              case .final(let result) = committed.wireState else {
            return
        }
        slots[slotIndex].storage = .completed(ticket: committed.ticket, result: result)
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

    private var hasPreparingSlot: Bool {
        slots.contains { slot in
            if case .preparing = slot.storage { return true }
            return false
        }
    }

    private var hasUnsettledWireWork: Bool {
        slots.contains { slot in
            switch slot.storage {
            case .preparing, .committed:
                true
            default:
                false
            }
        }
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
