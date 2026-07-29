import Foundation

/// SMBEE_PERF=1 のときだけ stderr に計測行を出す軽量 perf ロガー (issues/014)。
/// SMBEE_DEBUG (packet dump) とは独立。ホットパス (readChunk / decrypt) から呼ぶため、
/// 環境変数はプロセス起動時に 1 回だけ評価してキャッシュする。
enum SMBPerfLog {
    static let isEnabled = ProcessInfo.processInfo.environment["SMBEE_PERF"] == "1"

    /// Test-seam gate that stays race-free without an atomic (the package still targets
    /// macOS 13, so `Synchronization.Atomic` is unavailable): the only mutable state
    /// (`enabledOverrideStorage` / `testSinkStorage`) is read and written strictly under
    /// `lock`. The lock-free fast path below reads nothing mutable — `isEnabled` and
    /// `isTestProcess` are both immutable `let`s — so production (no XCTest loaded,
    /// SMBEE_PERF unset) never takes the lock and never races. TSan flagged the previous
    /// unguarded `overrideIsSet` flag read as a data race (macos-tsan, 2026-07-29).
    private static let isTestProcess = NSClassFromString("XCTestCase") != nil
    private static let lock = NSLock()
    nonisolated(unsafe) private static var enabledOverrideStorage: Bool?
    nonisolated(unsafe) private static var testSinkStorage: (@Sendable (String) -> Void)?

    nonisolated(unsafe) static var enabledOverride: Bool? {
        get { lock.withLock { enabledOverrideStorage } }
        set { lock.withLock { enabledOverrideStorage = newValue } }
    }

    nonisolated(unsafe) static var testSink: (@Sendable (String) -> Void)? {
        get { lock.withLock { testSinkStorage } }
        set { lock.withLock { testSinkStorage = newValue } }
    }

    static var effectiveIsEnabled: Bool {
        guard isEnabled || isTestProcess else { return false }
        return lock.withLock { enabledOverrideStorage ?? isEnabled }
    }

    static func line(_ message: @autoclosure () -> String) {
        guard isEnabled || isTestProcess else { return }
        lock.lock()
        defer { lock.unlock() }
        guard enabledOverrideStorage ?? isEnabled else { return }
        let value = message()
        if let testSink = testSinkStorage {
            testSink(value)
        } else {
            FileHandle.standardError.write(Data("[smbee-perf] \(value)\n".utf8))
        }
    }

    static func milliseconds(_ duration: Duration) -> String {
        let ms = Double(duration.components.seconds) * 1000
            + Double(duration.components.attoseconds) / 1e15
        return String(format: "%.1f", ms)
    }
}
