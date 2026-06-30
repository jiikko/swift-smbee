import Foundation

final class SMBWireTransactionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isLocked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func enter() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if isLocked {
                waiters.append(continuation)
                lock.unlock()
            } else {
                isLocked = true
                lock.unlock()
                continuation.resume()
            }
        }
    }

    func leave() {
        let next: CheckedContinuation<Void, Never>?

        lock.lock()
        if waiters.isEmpty {
            isLocked = false
            next = nil
        } else {
            next = waiters.removeFirst()
        }
        lock.unlock()

        next?.resume()
    }
}
