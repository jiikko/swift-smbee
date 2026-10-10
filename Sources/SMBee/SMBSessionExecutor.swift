import Dispatch
import Foundation

enum SMBSessionExecutorProbePoint: Hashable, Sendable {
    case sessionActor
    case senderTask
    case sendOwnerTask
    case senderLoop
    case readerTask
    case readerLoop
    case cancellationTask
    case readCancellationTask
    case readCancellationRequested
    case readCancellationApplied
    case writeCancellationTask
    case requestTimeoutWake
    case cleanupTimeoutWake
    case cleanupDrainTimeoutWake
    case wireDrainTimerWake
    case readTransferDrainTimerWake
    case writeTransferDrainTimerWake
    case cleanupCloseTask
    case cleanupTreeDisconnectTask
    case cleanupDisconnectTask
    case terminalizerTask
    case creditFailureTask
    case creditGrantAcknowledgement
    case creditReservationFastPath
    case readDriver
    case readDriverAfterStep
    case readCallback
    case userCallback
    case progressCallback
    case writeDriver
    case writeDriverAfterStep
    case preferredTask
    case ordinaryTask
    case taskGroupChild
    case detachedTask
    case nilPreference
    case explicitActor
    case closeJoin
}

struct SMBSessionExecutorObservation: Equatable, Sendable {
    let point: SMBSessionExecutorProbePoint
    let executorIdentity: UUID
    let isOnExecutorQueue: Bool
    let taskExecutorMatches: Bool
}

/// Session-owned serial execution resource for actor isolation and task preference.
final class SMBSessionExecutor: SerialExecutor, TaskExecutor, @unchecked Sendable {
    private let queue: DispatchQueue
    private let queueIdentity = UUID()
    private let queueIdentityKey = DispatchSpecificKey<UUID>()
#if DEBUG
    private let observerLock = NSLock()
    private var observerForTesting: (@Sendable (SMBSessionExecutorObservation) -> Void)?
#endif

    init(label: String) {
        queue = DispatchQueue(label: label)
        queue.setSpecific(key: queueIdentityKey, value: queueIdentity)
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let unownedJob = UnownedJob(job)
        queue.async { [self] in
            unownedJob.runSynchronously(
                isolatedTo: asUnownedSerialExecutor(),
                taskExecutor: asUnownedTaskExecutor()
            )
        }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }

    func asUnownedTaskExecutor() -> UnownedTaskExecutor {
        UnownedTaskExecutor(ordinary: self)
    }

#if DEBUG
    func setExecutionObserverForTesting(
        _ observer: (@Sendable (SMBSessionExecutorObservation) -> Void)?
    ) {
        observerLock.withLock {
            observerForTesting = observer
        }
    }

    func recordExecutionContextForTesting(_ point: SMBSessionExecutorProbePoint) {
        let observer = observerLock.withLock { observerForTesting }
        guard let observer else { return }
        observer(executionContextForTesting(point))
    }
#else
    @inline(__always)
    func setExecutionObserverForTesting(
        _ observer: (@Sendable (SMBSessionExecutorObservation) -> Void)?
    ) {
        _ = observer
    }

    @inline(__always)
    func recordExecutionContextForTesting(_ point: SMBSessionExecutorProbePoint) {
        _ = point
    }
#endif

    func executionContextForTesting(
        _ point: SMBSessionExecutorProbePoint
    ) -> SMBSessionExecutorObservation {
        let isOnExecutorQueue = DispatchQueue.getSpecific(key: queueIdentityKey) == queueIdentity
        let taskExecutorMatches = withUnsafeCurrentTask { task in
            guard let task, let currentExecutor = task.unownedTaskExecutor else { return false }
            return currentExecutor == asUnownedTaskExecutor()
        }
        return SMBSessionExecutorObservation(
            point: point,
            executorIdentity: queueIdentity,
            isOnExecutorQueue: isOnExecutorQueue,
            taskExecutorMatches: taskExecutorMatches
        )
    }
}
