import Foundation

/// Identifies one published TREE_CONNECT incarnation. Numeric TreeIds can be reused, so
/// this value also carries the exact session generation and a session-local sequence.
struct SMBTreeIdentity: Hashable, Sendable {
    let sessionInstance: UUID
    let generation: UInt64
    let treeId: UInt32
    let incarnationSequence: UInt64

    static func == (lhs: SMBTreeIdentity, rhs: SMBTreeIdentity) -> Bool {
        lhs.sessionInstance == rhs.sessionInstance
            && lhs.generation == rhs.generation
            && lhs.treeId == rhs.treeId
            && lhs.incarnationSequence == rhs.incarnationSequence
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(sessionInstance)
        hasher.combine(generation)
        hasher.combine(treeId)
        hasher.combine(incarnationSequence)
    }
}

struct SMBSessionIncarnationIdentity: Hashable, Sendable {
    let sessionInstance: UUID
    let generation: UInt64

    static func == (lhs: SMBSessionIncarnationIdentity, rhs: SMBSessionIncarnationIdentity) -> Bool {
        lhs.sessionInstance == rhs.sessionInstance && lhs.generation == rhs.generation
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(sessionInstance)
        hasher.combine(generation)
    }
}

/// Inline FileId words plus the exact Tree incarnation used by the production cleanup ledger.
struct SMBScopedFileIdLedgerKey: Hashable, Sendable {
    let treeIdentity: SMBTreeIdentity
    let firstWord: UInt64
    let secondWord: UInt64

    init(bytes: [UInt8], treeIdentity: SMBTreeIdentity) {
        precondition(bytes.count == 16, "SMB FileId ledger keys must contain exactly 16 bytes")
        self.treeIdentity = treeIdentity
        (firstWord, secondWord) = bytes.withUnsafeBytes { rawBytes in
            (
                rawBytes.loadUnaligned(fromByteOffset: 0, as: UInt64.self),
                rawBytes.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
            )
        }
    }
}

enum SMBCleanupResource: Hashable, Sendable {
    case file(tree: SMBTreeIdentity, file: SMBScopedFileIdLedgerKey)
    case tree(SMBTreeIdentity)
}

/// Absolute cleanup deadlines are captured when cleanup intent is registered. A request
/// timeout can shorten the hard bound, but nil still leaves the finite hard grace in force.
struct SMBCleanupDeadlines: Sendable, Equatable {
    let intentAt: ContinuousClock.Instant
    let softAt: ContinuousClock.Instant
    let hardAt: ContinuousClock.Instant

    init(
        intentAt: ContinuousClock.Instant,
        softBudget: Duration = .seconds(5),
        hardGrace: Duration = .seconds(60),
        requestTimeout: Duration? = nil
    ) {
        precondition(softBudget >= .zero)
        precondition(hardGrace > .zero)
        if let requestTimeout { precondition(requestTimeout >= .zero) }
        self.intentAt = intentAt
        softAt = intentAt.advanced(by: softBudget)
        hardAt = softAt.advanced(by: min(requestTimeout ?? hardGrace, hardGrace))
    }

    init(intentAt: ContinuousClock.Instant, softAt: ContinuousClock.Instant, hardAt: ContinuousClock.Instant) {
        self.intentAt = intentAt
        self.softAt = softAt
        self.hardAt = hardAt
    }

    func disposition(
        for event: SMBCleanupDeadlineEvent,
        at eventTime: ContinuousClock.Instant,
        fullSendCompletedAt: ContinuousClock.Instant?,
        finalAcceptedAt: ContinuousClock.Instant?,
        sendOwnerRecoveredAt: ContinuousClock.Instant?
    ) -> SMBCleanupDeadlineDisposition {
        var finalAt = finalAcceptedAt
        var ownerAt = sendOwnerRecoveredAt
        switch event {
        case .finalAccepted:
            finalAt = eventTime
        case .sendOwnerRecovered:
            ownerAt = eventTime
        case .softTimeout, .hardTimeout:
            break
        }

        let fullSendWasBeforeSoft: Bool
        if let fullSendCompletedAt {
            fullSendWasBeforeSoft = fullSendCompletedAt < softAt
        } else {
            fullSendWasBeforeSoft = false
        }
        let finalWasBeforeHard: Bool
        if let finalAt {
            finalWasBeforeHard = finalAt < hardAt
        } else {
            finalWasBeforeHard = true
        }
        let ownerWasBeforeHard: Bool
        if let ownerAt {
            ownerWasBeforeHard = ownerAt < hardAt
        } else {
            ownerWasBeforeHard = true
        }

        if let finalAt, finalAt >= hardAt { return .terminal }
        if let ownerAt, ownerAt >= hardAt { return .terminal }
        if case .hardTimeout = event, eventTime >= hardAt,
           !(finalAt != nil && ownerAt != nil && fullSendWasBeforeSoft && finalWasBeforeHard && ownerWasBeforeHard) {
            return .terminal
        }
        guard fullSendWasBeforeSoft else {
            if eventTime >= softAt || eventTime >= hardAt { return .terminal }
            return .beforeSoft
        }
        if let finalAt, let ownerAt {
            if finalAt < softAt && ownerAt < softAt { return .completedBeforeSoft }
            if finalWasBeforeHard && ownerWasBeforeHard { return .completedAfterSoft }
            return .terminal
        }
        if eventTime >= hardAt { return .terminal }
        if eventTime >= softAt { return .draining }
        switch event {
        case .softTimeout, .hardTimeout:
            return .draining
        case .finalAccepted, .sendOwnerRecovered:
            return .beforeSoft
        }
    }
}

enum SMBCleanupDeadlineEvent: Sendable {
    case softTimeout
    case finalAccepted
    case sendOwnerRecovered
    case hardTimeout
}

enum SMBCleanupDeadlineDisposition: Equatable, Sendable {
    case beforeSoft
    case completedBeforeSoft
    case draining
    case completedAfterSoft
    case terminal
}

enum SMBTreeCreditGrantClaim: Sendable {
    case owned
    case refundOnce
    case rejected
}

enum SMBCleanupCreditRefundInterleavingPoint: Sendable {
    case grantClaimedBeforeAccept(charge: UInt16)
    case refundPending(charge: UInt16)
}

/// Short-lived cancel/grant arbitration for one scoped reservation. It is created before
/// entering the credit actor so quarantine can win before a waiter is registered.
final class SMBTreeCreditCancellationToken: @unchecked Sendable {
    private enum State {
        case active
        case cancelled
        case grantPending(UInt16)
        case accepted
        case refundIssued
    }

    private let lock = NSLock()
    private var state: State = .active
    let refundInterleavingHookForTesting:
        (@Sendable (SMBCleanupCreditRefundInterleavingPoint) async -> Void)?
    let tree: SMBTreeIdentity
    let request: SMBRequestIdentity

    init(
        tree: SMBTreeIdentity,
        request: SMBRequestIdentity,
        refundInterleavingHookForTesting:
            (@Sendable (SMBCleanupCreditRefundInterleavingPoint) async -> Void)? = nil
    ) {
        self.tree = tree
        self.request = request
        self.refundInterleavingHookForTesting = refundInterleavingHookForTesting
    }

    var isCancelled: Bool {
        lock.withLock {
            switch state {
            case .cancelled, .refundIssued: return true
            case .active, .grantPending, .accepted: return false
            }
        }
    }

    var hasClaimedOrAcceptedGrant: Bool {
        lock.withLock {
            switch state {
            case .grantPending, .accepted: return true
            case .active, .cancelled, .refundIssued: return false
            }
        }
    }

    func claimGrant(charge: UInt16) -> SMBTreeCreditGrantClaim {
        lock.withLock {
            switch state {
            case .active:
                state = .grantPending(charge)
                return .owned
            case .cancelled:
                state = .refundIssued
                return .refundOnce
            case .grantPending, .accepted, .refundIssued:
                return .rejected
            }
        }
    }

    func acceptGrant() -> Bool {
        lock.withLock {
            guard case .grantPending = state else { return false }
            state = .accepted
            return true
        }
    }

    /// Returns a claimed but not yet delivered grant exactly once. A grant already accepted
    /// by its caller belongs to that caller's later precommit retirement path.
    func cancel() -> UInt16? {
        lock.withLock {
            switch state {
            case .active:
                state = .cancelled
                return nil
            case .grantPending(let charge):
                state = .refundIssued
                return charge
            case .cancelled, .accepted, .refundIssued:
                return nil
            }
        }
    }
}

private final class SMBPreparationReceiptCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var isCompleted = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    var completed: Bool { lock.withLock { isCompleted } }

    func wait() async {
        await withCheckedContinuation { continuation in
            let alreadyCompleted = lock.withLock { () -> Bool in
                if isCompleted { return true }
                waiters.append(continuation)
                return false
            }
            if alreadyCompleted { continuation.resume() }
        }
    }

    func complete() {
        let parked = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            guard !isCompleted else { return [] }
            isCompleted = true
            defer { waiters.removeAll() }
            return waiters
        }
        parked.forEach { $0.resume() }
    }
}

/// Completion handle for a resource retirement effect. Duplicate handles share one
/// completion and retain both the exact resource and the request owner that caused it.
struct SMBResourceRetirementReceipt: Sendable, Equatable {
    let resource: SMBCleanupResource
    let owner: SMBRequestIdentity
    private let receiptID: UUID
    private let completion: SMBPreparationReceiptCompletion

    fileprivate init(
        resource: SMBCleanupResource,
        owner: SMBRequestIdentity,
        completion: SMBPreparationReceiptCompletion
    ) {
        self.resource = resource
        self.owner = owner
        receiptID = UUID()
        self.completion = completion
    }

    var isComplete: Bool { completion.completed }

    func wait() async { await completion.wait() }

    fileprivate func markComplete() { completion.complete() }

    public static func == (lhs: SMBResourceRetirementReceipt, rhs: SMBResourceRetirementReceipt) -> Bool {
        lhs.receiptID == rhs.receiptID
    }
}

struct SMBResourceRetirementEffect: Sendable, Equatable {
    let resource: SMBCleanupResource
    let owner: SMBRequestIdentity
    let receipt: SMBResourceRetirementReceipt
}

enum SMBPreparedCleanupState: Equatable, Sendable {
    case sending(SMBCleanupDeadlines)
    case draining(messageId: UInt64, deadlines: SMBCleanupDeadlines)
    case retiredUnknown
}

enum SMBPreparedCleanupEvent: Sendable {
    case beginIntent(SMBCleanupDeadlines)
    case beginDrain(messageId: UInt64)
    case retireUnsent
    case settleWire(succeeded: Bool)
}

enum SMBPreparedCleanupTransition: Sendable {
    case changed(SMBPreparedCleanupState?)
    case ignoredOwner
    case retired(SMBResourceRetirementEffect)
    case alreadyRetired(SMBResourceRetirementEffect)
    case noChange(SMBPreparedCleanupState?)
}

private struct SMBPreparedCleanupEntry: Sendable {
    let owner: SMBRequestIdentity
    var state: SMBPreparedCleanupState
    var receipt: SMBResourceRetirementReceipt?
}

/// Internal transition harness for the prepared File/Tree cleanup model. Production cleanup
/// continues to use its existing adapter until the atomic activation milestone.
actor SMBPreparedCleanupLedger {
    private var entries: [SMBCleanupResource: SMBPreparedCleanupEntry] = [:]

    func transitionCleanupLedger(
        resource: SMBCleanupResource,
        owner: SMBRequestIdentity,
        event: SMBPreparedCleanupEvent
    ) -> SMBPreparedCleanupTransition {
        let current = entries[resource]
        if let current, current.owner != owner { return .ignoredOwner }

        switch event {
        case .beginIntent(let deadlines):
            guard current == nil else { return .noChange(current?.state) }
            entries[resource] = SMBPreparedCleanupEntry(owner: owner, state: .sending(deadlines), receipt: nil)
            return .changed(.sending(deadlines))
        case .beginDrain(let messageId):
            guard let current else { return .noChange(nil) }
            guard case .sending(let deadlines) = current.state else { return .noChange(current.state) }
            let next = SMBPreparedCleanupState.draining(messageId: messageId, deadlines: deadlines)
            entries[resource] = SMBPreparedCleanupEntry(owner: owner, state: next, receipt: current.receipt)
            return .changed(next)
        case .retireUnsent:
            guard let current else { return .noChange(nil) }
            if let receipt = current.receipt {
                return .alreadyRetired(SMBResourceRetirementEffect(resource: resource, owner: owner, receipt: receipt))
            }
            switch current.state {
            case .sending:
                let receipt = SMBResourceRetirementReceipt(
                    resource: resource,
                    owner: owner,
                    completion: SMBPreparationReceiptCompletion()
                )
                entries[resource] = SMBPreparedCleanupEntry(owner: owner, state: .retiredUnknown, receipt: receipt)
                return .retired(SMBResourceRetirementEffect(resource: resource, owner: owner, receipt: receipt))
            case .draining, .retiredUnknown:
                return .noChange(current.state)
            }
        case .settleWire(let succeeded):
            guard let current else { return .noChange(nil) }
            switch current.state {
            case .sending, .draining:
                if succeeded {
                    entries.removeValue(forKey: resource)
                    current.receipt?.markComplete()
                    return .changed(nil)
                }
                entries[resource] = SMBPreparedCleanupEntry(owner: owner, state: .retiredUnknown, receipt: current.receipt)
                current.receipt?.markComplete()
                return .changed(.retiredUnknown)
            case .retiredUnknown:
                current.receipt?.markComplete()
                return .noChange(.retiredUnknown)
            }
        }
    }

    func state(for resource: SMBCleanupResource) -> SMBPreparedCleanupState? {
        entries[resource]?.state
    }

}

enum SMBTreeLifecycleState: Equatable, Sendable {
    case quarantined
    case retired
    case retiredUnknown
}

enum SMBTreeLifecycleEvent: Sendable {
    case beginQuarantine
    case retire
    case retireUnknown
    case forgetRetired
}

enum SMBTreeLifecycleTransition: Sendable {
    case changed(SMBTreeLifecycleState)
    case ignoredOwner
    case noChange(SMBTreeLifecycleState?)
}

private struct SMBTreeLifecycleEntry: Sendable {
    let owner: SMBRequestIdentity
    var state: SMBTreeLifecycleState
}

actor SMBTreeLifecycleHarness {
    private var entries: [SMBTreeIdentity: SMBTreeLifecycleEntry] = [:]

    func transitionTreeLifecycle(
        tree: SMBTreeIdentity,
        owner: SMBRequestIdentity,
        event: SMBTreeLifecycleEvent
    ) -> SMBTreeLifecycleTransition {
        let current = entries[tree]
        if let current, current.owner != owner { return .ignoredOwner }

        let next: SMBTreeLifecycleState
        switch event {
        case .beginQuarantine:
            guard current == nil else { return .noChange(current?.state) }
            next = .quarantined
        case .retire:
            guard current != nil else { return .noChange(nil) }
            next = .retired
        case .retireUnknown:
            guard current != nil else { return .noChange(nil) }
            next = .retiredUnknown
        case .forgetRetired:
            guard current?.state == .retired else { return .noChange(current?.state) }
            entries.removeValue(forKey: tree)
            return .noChange(nil)
        }
        entries[tree] = SMBTreeLifecycleEntry(owner: owner, state: next)
        return .changed(next)
    }

    func state(for tree: SMBTreeIdentity) -> SMBTreeLifecycleState? { entries[tree]?.state }
}

struct SMBFacadeOwner: Hashable, Sendable {
    let rawValue: UInt64

    static func == (lhs: SMBFacadeOwner, rhs: SMBFacadeOwner) -> Bool {
        lhs.rawValue == rhs.rawValue
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}

enum SMBFacadeOwnerAllocator {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var nextValue: UInt64 = 1

    static func make() -> SMBFacadeOwner {
        lock.withLock {
            let value = nextValue
            nextValue &+= 1
            return SMBFacadeOwner(rawValue: value)
        }
    }
}

struct SMBOperationLeaseID: Hashable, Sendable {
    let owner: SMBFacadeOwner
    let sequence: UInt64
}

struct SMBOperationLease: Hashable, Sendable {
    let id: SMBOperationLeaseID
    let session: SMBSessionIncarnationIdentity
    let tree: SMBTreeIdentity?

    var owner: SMBFacadeOwner { id.owner }
}

struct SMBOperationAncestryFrame: Sendable {
    let owner: SMBFacadeOwner
    let leaseID: SMBOperationLeaseID
}

private final class SMBOperationAncestryNode: @unchecked Sendable {
    let frame: SMBOperationAncestryFrame
    let parent: SMBOperationAncestryNode?

    init(frame: SMBOperationAncestryFrame, parent: SMBOperationAncestryNode?) {
        self.frame = frame
        self.parent = parent
    }
}

struct SMBOperationAncestry: Sendable {
    fileprivate let head: SMBOperationAncestryNode?

    fileprivate init(head: SMBOperationAncestryNode? = nil) { self.head = head }

    func appending(_ lease: SMBOperationLease) -> SMBOperationAncestry {
        SMBOperationAncestry(head: SMBOperationAncestryNode(
            frame: SMBOperationAncestryFrame(owner: lease.owner, leaseID: lease.id),
            parent: head
        ))
    }

    var frames: [SMBOperationAncestryFrame] {
        var result: [SMBOperationAncestryFrame] = []
        var node = head
        while let current = node {
            result.append(current.frame)
            node = current.parent
        }
        return result
    }

    var isEmpty: Bool { head == nil }
}

enum SMBOperationTaskContext {
    @TaskLocal static var ancestry = SMBOperationAncestry()
    private static let activeLeaseLock = NSLock()
    nonisolated(unsafe) private static var activeLeaseIDs: Set<SMBOperationLeaseID> = []

    static func withLease<T: Sendable>(
        _ lease: SMBOperationLease,
        operation: @Sendable () async throws -> T
    ) async rethrows -> T {
        let inserted = activeLeaseLock.withLock { activeLeaseIDs.insert(lease.id).inserted }
        precondition(inserted, "operation lease cannot be active twice")
        defer { _ = activeLeaseLock.withLock { activeLeaseIDs.remove(lease.id) } }
        let ancestry = ancestry.appending(lease)
        return try await $ancestry.withValue(ancestry) {
            try await operation()
        }
    }

    static func hasActiveLease(in ancestry: SMBOperationAncestry = SMBOperationTaskContext.ancestry) -> Bool {
        let ids = ancestry.frames.map(\.leaseID)
        return activeLeaseLock.withLock { ids.contains(where: activeLeaseIDs.contains) }
    }
}

enum SMBOperationBarrierKind: Hashable, Sendable {
    case setup
    case wire
    case retirement
}

struct SMBOperationBarrierReceipt: Hashable, Sendable {
    let owner: SMBFacadeOwner
    let sequence: UInt64
    let kind: SMBOperationBarrierKind
}

enum SMBOperationCloseOutcome: Equatable, Sendable {
    case success
    case failed(String)
}

enum SMBOperationCloseDisposition: Sendable {
    case startedOnly
    case joined(SMBOperationCloseOutcome)
}

private struct SMBOperationLeaseRecord: Sendable {
    let lease: SMBOperationLease
}

private struct SMBOperationBarrierRecord: Sendable {
    let receipt: SMBOperationBarrierReceipt
}

private enum SMBOperationLifecycleEvent {
    case registerFacade(SMBFacadeOwner, parent: SMBFacadeOwner?, sessionExecutor: SMBSessionExecutor?)
    case retireFacade(SMBFacadeOwner)
    case stopAdmission(SMBFacadeOwner)
    case acquire(SMBFacadeOwner, SMBSessionIncarnationIdentity, SMBTreeIdentity?)
    case release(SMBOperationLeaseID)
    case beginBarrier(SMBFacadeOwner, SMBOperationBarrierKind)
    case completeBarrier(SMBOperationBarrierReceipt)
    case pruneRetiredFacades(SMBFacadeOwner)
    case beginClose(
        SMBFacadeOwner,
        SMBOperationAncestry,
        forceStartOnly: Bool,
        joinEvenInsideLease: Bool,
        @Sendable () async -> SMBOperationCloseOutcome
    )
    case waitForBarrier(SMBFacadeOwner, CheckedContinuation<Void, Never>)
    case expireClose(SMBFacadeOwner)
    case resumeReadyBarrierWaiters
}

enum SMBOperationBarrierWaiterEventForTesting: Sendable {
    case registered
    case resumed
}

private enum SMBOperationLifecycleTransition {
    case registered
    case lease(SMBOperationLease?)
    case barrier(SMBOperationBarrierReceipt)
    case close(Task<SMBOperationCloseOutcome, Never>, shouldJoin: Bool)
    case noChange
}

/// Internal harness for P1 close ownership. It models admission, active lease authority,
/// setup/retirement/wire receipts, and one shared detached close worker without changing
/// the public SMBClient close path.
actor SMBOperationLeaseHarness {
    private var facadeParents: [SMBFacadeOwner: SMBFacadeOwner] = [:]
    private var facadeExecutors: [SMBFacadeOwner: SMBSessionExecutor] = [:]
    private var knownFacades: Set<SMBFacadeOwner> = []
    private var leases: [SMBOperationLeaseID: SMBOperationLeaseRecord] = [:]
    private var subtreeLeaseCounts: [SMBFacadeOwner: Int] = [:]
    private var subtreeBarrierCounts: [SMBFacadeOwner: Int] = [:]
    private var barriers: [UInt64: SMBOperationBarrierRecord] = [:]
    private var closing: Set<SMBFacadeOwner> = []
    private var closeWorkers: [SMBFacadeOwner: Task<SMBOperationCloseOutcome, Never>] = [:]
    private var expiredCloses: Set<SMBFacadeOwner> = []
    private var barrierWaiters: [(SMBFacadeOwner, CheckedContinuation<Void, Never>)] = []
    private var nextLeaseSequence: UInt64 = 0
    private var nextBarrierSequence: UInt64 = 0
    private let onWorkerEntryForTesting: @Sendable (SMBFacadeOwner) async -> Void
    private var onBarrierEvaluationForTesting: @Sendable (SMBFacadeOwner, Bool) async -> Void
    private var onBarrierWaiterEventForTesting: @Sendable (SMBFacadeOwner, SMBOperationBarrierWaiterEventForTesting) -> Void
    private let onCloseDecisionForTesting: @Sendable (SMBFacadeOwner, Bool) async -> Void

    init(
        onWorkerEntryForTesting: @escaping @Sendable (SMBFacadeOwner) async -> Void = { _ in },
        onBarrierEvaluationForTesting: @escaping @Sendable (SMBFacadeOwner, Bool) async -> Void = { _, _ in },
        onCloseDecisionForTesting: @escaping @Sendable (SMBFacadeOwner, Bool) async -> Void = { _, _ in },
        onBarrierWaiterEventForTesting: @escaping @Sendable (SMBFacadeOwner, SMBOperationBarrierWaiterEventForTesting) -> Void = { _, _ in }
    ) {
        self.onWorkerEntryForTesting = onWorkerEntryForTesting
        self.onBarrierEvaluationForTesting = onBarrierEvaluationForTesting
        self.onCloseDecisionForTesting = onCloseDecisionForTesting
        self.onBarrierWaiterEventForTesting = onBarrierWaiterEventForTesting
    }

    func registerFacade(
        _ owner: SMBFacadeOwner,
        parent: SMBFacadeOwner? = nil,
        sessionExecutor: SMBSessionExecutor? = nil
    ) {
        _ = transitionOperationLifecycle(.registerFacade(owner, parent: parent, sessionExecutor: sessionExecutor))
    }

    func retireFacade(_ owner: SMBFacadeOwner) {
        _ = transitionOperationLifecycle(.retireFacade(owner))
    }

    func stopAdmission(_ owner: SMBFacadeOwner) {
        _ = transitionOperationLifecycle(.stopAdmission(owner))
    }

    func hasBlockedWork(owner: SMBFacadeOwner) -> Bool {
        isBlocked(owner: owner)
    }

    func recordCountsForTesting() -> (
        facades: Int,
        leases: Int,
        barriers: Int,
        closeWorkers: Int,
        parentRecords: Int,
        executorRecords: Int,
        retiredFacades: Int
    ) {
        (
            knownFacades.count,
            leases.count,
            barriers.count,
            closeWorkers.count,
            facadeParents.count,
            facadeExecutors.count,
            retiredFacades.count
        )
    }

    func acquire(
        owner: SMBFacadeOwner,
        session: SMBSessionIncarnationIdentity,
        tree: SMBTreeIdentity? = nil
    ) -> SMBOperationLease? {
        guard case .lease(let lease) = transitionOperationLifecycle(.acquire(owner, session, tree)) else {
            return nil
        }
        return lease
    }

    func release(_ lease: SMBOperationLease) {
        _ = transitionOperationLifecycle(.release(lease.id))
    }

    func beginBarrier(owner: SMBFacadeOwner, kind: SMBOperationBarrierKind) -> SMBOperationBarrierReceipt {
        guard case .barrier(let receipt) = transitionOperationLifecycle(.beginBarrier(owner, kind)) else {
            preconditionFailure("barrier transition must return a receipt")
        }
        return receipt
    }

    func completeBarrier(_ receipt: SMBOperationBarrierReceipt) {
        _ = transitionOperationLifecycle(.completeBarrier(receipt))
    }

    func setBarrierEvaluationHookForTesting(
        _ hook: @escaping @Sendable (SMBFacadeOwner, Bool) async -> Void
    ) {
        onBarrierEvaluationForTesting = hook
    }

    func close(
        owner: SMBFacadeOwner,
        joinEvenInsideLease: Bool = false,
        cleanup: @escaping @Sendable () async -> SMBOperationCloseOutcome
    ) async -> SMBOperationCloseDisposition {
        let ancestry = SMBOperationTaskContext.ancestry
        let forceStartOnly = !joinEvenInsideLease && SMBOperationTaskContext.hasActiveLease(in: ancestry)
        guard case .close(let worker, let shouldJoin) = transitionOperationLifecycle(
            .beginClose(
                owner,
                ancestry,
                forceStartOnly: forceStartOnly,
                joinEvenInsideLease: joinEvenInsideLease,
                cleanup
            )
        ) else {
            return .startedOnly
        }
        await onCloseDecisionForTesting(owner, shouldJoin)
        guard shouldJoin else { return .startedOnly }
        return .joined(await worker.value)
    }

    func expireClose(_ owner: SMBFacadeOwner) {
        _ = transitionOperationLifecycle(.expireClose(owner))
    }

    func isClosing(_ owner: SMBFacadeOwner) -> Bool { closing.contains(owner) }

    func activeLeaseCount(for owner: SMBFacadeOwner) -> Int {
        subtreeLeaseCounts[owner, default: 0]
    }

    func activeBarrierCount(for owner: SMBFacadeOwner) -> Int {
        subtreeBarrierCounts[owner, default: 0]
    }

    private func transitionOperationLifecycle(_ event: SMBOperationLifecycleEvent) -> SMBOperationLifecycleTransition {
        switch event {
        case .registerFacade(let owner, let parent, let sessionExecutor):
            knownFacades.insert(owner)
            if let parent, facadeParents[owner] != parent, !wouldCreateFacadeCycle(owner: owner, parent: parent) {
                let oldParent = facadeParents[owner]
                let leaseCount = subtreeLeaseCounts[owner, default: 0]
                let barrierCount = subtreeBarrierCounts[owner, default: 0]
                var newAncestors: [SMBFacadeOwner] = []
                var newAncestor: SMBFacadeOwner? = parent
                while let current = newAncestor {
                    newAncestors.append(current)
                    newAncestor = facadeParents[current]
                }
                var oldAncestor = oldParent
                while let current = oldAncestor {
                    oldAncestor = facadeParents[current]
                    if leaseCount > 0 {
                        let updated = subtreeLeaseCounts[current, default: 0] - leaseCount
                        if updated <= 0 {
                            subtreeLeaseCounts.removeValue(forKey: current)
                        } else {
                            subtreeLeaseCounts[current] = updated
                        }
                    }
                    if barrierCount > 0 {
                        let updated = subtreeBarrierCounts[current, default: 0] - barrierCount
                        if updated <= 0 {
                            subtreeBarrierCounts.removeValue(forKey: current)
                        } else {
                            subtreeBarrierCounts[current] = updated
                        }
                    }
                }
                facadeParents[owner] = parent
                for current in newAncestors {
                    if leaseCount > 0 { subtreeLeaseCounts[current, default: 0] += leaseCount }
                    if barrierCount > 0 { subtreeBarrierCounts[current, default: 0] += barrierCount }
                }
                _ = transitionOperationLifecycle(.resumeReadyBarrierWaiters)
            }
            if let sessionExecutor { facadeExecutors[owner] = sessionExecutor }
            return .registered
        case .retireFacade(let owner):
            knownFacades.remove(owner)
            facadeExecutors.removeValue(forKey: owner)
            closing.remove(owner)
            expiredCloses.remove(owner)
            closeWorkers.removeValue(forKey: owner)
            if isReferenced(owner) {
                retiredFacades.insert(owner)
            } else {
                facadeParents.removeValue(forKey: owner)
                retiredFacades.remove(owner)
            }
            return .noChange
        case .stopAdmission(let owner):
            closing.insert(owner)
            return .noChange
        case .acquire(let owner, let session, let tree):
            guard knownFacades.contains(owner), !isAdmissionStopped(owner) else { return .lease(nil) }
            let id = SMBOperationLeaseID(owner: owner, sequence: nextLeaseSequence)
            nextLeaseSequence &+= 1
            let lease = SMBOperationLease(id: id, session: session, tree: tree)
            leases[id] = SMBOperationLeaseRecord(lease: lease)
            var candidate: SMBFacadeOwner? = owner
            while let current = candidate {
                subtreeLeaseCounts[current, default: 0] += 1
                candidate = facadeParents[current]
            }
            return .lease(lease)
        case .release(let id):
            guard let record = leases.removeValue(forKey: id) else { return .noChange }
            var candidate: SMBFacadeOwner? = record.lease.owner
            while let current = candidate {
                candidate = facadeParents[current]
                let count = subtreeLeaseCounts[current, default: 0]
                if count <= 1 {
                    subtreeLeaseCounts.removeValue(forKey: current)
                } else {
                    subtreeLeaseCounts[current] = count - 1
                }
            }
            _ = transitionOperationLifecycle(.pruneRetiredFacades(record.lease.owner))
            _ = transitionOperationLifecycle(.resumeReadyBarrierWaiters)
            return .noChange
        case .beginBarrier(let owner, let kind):
            let receipt = SMBOperationBarrierReceipt(owner: owner, sequence: nextBarrierSequence, kind: kind)
            nextBarrierSequence &+= 1
            barriers[receipt.sequence] = SMBOperationBarrierRecord(receipt: receipt)
            var candidate: SMBFacadeOwner? = owner
            while let current = candidate {
                subtreeBarrierCounts[current, default: 0] += 1
                candidate = facadeParents[current]
            }
            return .barrier(receipt)
        case .completeBarrier(let receipt):
            guard barriers[receipt.sequence]?.receipt == receipt else { return .noChange }
            barriers.removeValue(forKey: receipt.sequence)
            var candidate: SMBFacadeOwner? = receipt.owner
            while let current = candidate {
                candidate = facadeParents[current]
                let count = subtreeBarrierCounts[current, default: 0]
                if count <= 1 {
                    subtreeBarrierCounts.removeValue(forKey: current)
                } else {
                    subtreeBarrierCounts[current] = count - 1
                }
            }
            _ = transitionOperationLifecycle(.pruneRetiredFacades(receipt.owner))
            _ = transitionOperationLifecycle(.resumeReadyBarrierWaiters)
            return .noChange
        case .pruneRetiredFacades(let owner):
            var candidate: SMBFacadeOwner? = owner
            while let current = candidate {
                candidate = facadeParents[current]
                if retiredFacades.contains(current), !isReferenced(current) {
                    retiredFacades.remove(current)
                    facadeParents.removeValue(forKey: current)
                }
            }
            return .noChange
        case .beginClose(let owner, let ancestry, let forceStartOnly, let joinEvenInsideLease, let cleanup):
            closing.insert(owner)
            let worker: Task<SMBOperationCloseOutcome, Never>
            if let existing = closeWorkers[owner] {
                worker = existing
            } else {
                let onWorkerEntry = onWorkerEntryForTesting
                let onBarrierEvaluation = onBarrierEvaluationForTesting
                let executor = facadeExecutors[owner]
                worker = Task.detached(executorPreference: executor) { [self] in
                    await onWorkerEntry(owner)
                    let barrierSatisfied = await waitForBarrier(owner: owner, onEvaluation: onBarrierEvaluation)
                    guard barrierSatisfied else {
                        return .failed("operation lease barrier exceeded the cleanup soft deadline")
                    }
                    return await cleanup()
                }
                closeWorkers[owner] = worker
            }
            return .close(
                worker,
                shouldJoin: joinEvenInsideLease || (!forceStartOnly && !hasActiveLease(in: ancestry))
            )
        case .waitForBarrier(let owner, let continuation):
            if !expiredCloses.contains(owner), isBlocked(owner: owner) {
                barrierWaiters.append((owner, continuation))
                onBarrierWaiterEventForTesting(owner, .registered)
            } else {
                continuation.resume()
            }
            return .noChange
        case .expireClose(let owner):
            expiredCloses.insert(owner)
            let ready = barrierWaiters.filter { $0.0 == owner }
            barrierWaiters.removeAll { $0.0 == owner }
            ready.forEach { $0.1.resume() }
            return .noChange
        case .resumeReadyBarrierWaiters:
            var remaining: [(SMBFacadeOwner, CheckedContinuation<Void, Never>)] = []
            for (owner, continuation) in barrierWaiters {
                if isBlocked(owner: owner) {
                    remaining.append((owner, continuation))
                } else {
                    onBarrierWaiterEventForTesting(owner, .resumed)
                    continuation.resume()
                }
            }
            barrierWaiters = remaining
            return .noChange
        }
    }

    private func waitForBarrier(
        owner: SMBFacadeOwner,
        onEvaluation: @escaping @Sendable (SMBFacadeOwner, Bool) async -> Void
    ) async -> Bool {
        let blocked = isBlocked(owner: owner)
        await onEvaluation(owner, blocked)
        if expiredCloses.contains(owner) { return false }
        if blocked {
            await withCheckedContinuation { continuation in
                _ = transitionOperationLifecycle(.waitForBarrier(owner, continuation))
            }
        }
        return !expiredCloses.contains(owner)
    }

    private func isBlocked(owner: SMBFacadeOwner) -> Bool {
        subtreeLeaseCounts[owner, default: 0] > 0 || subtreeBarrierCounts[owner, default: 0] > 0
    }

    private var retiredFacades: Set<SMBFacadeOwner> = []

    private func wouldCreateFacadeCycle(owner: SMBFacadeOwner, parent: SMBFacadeOwner) -> Bool {
        var candidate: SMBFacadeOwner? = parent
        while let current = candidate {
            if current == owner { return true }
            candidate = facadeParents[current]
        }
        return false
    }

    private func isReferenced(_ owner: SMBFacadeOwner) -> Bool {
        subtreeLeaseCounts[owner, default: 0] > 0 || subtreeBarrierCounts[owner, default: 0] > 0
    }

    private func isAdmissionStopped(_ owner: SMBFacadeOwner) -> Bool {
        var candidate: SMBFacadeOwner? = owner
        while let current = candidate {
            if closing.contains(current) { return true }
            candidate = facadeParents[current]
        }
        return false
    }

    private func hasActiveLease(in ancestry: SMBOperationAncestry) -> Bool {
        ancestry.frames.contains { frame in
            guard let authoritative = leases[frame.leaseID] else { return false }
            return authoritative.lease.owner == frame.owner
        }
    }
}
