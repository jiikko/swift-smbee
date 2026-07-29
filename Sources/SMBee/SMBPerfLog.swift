import Foundation

/// SMBEE_PERF=1 のときだけ stderr に計測行を出す軽量 perf ロガー (issues/014)。
/// SMBEE_DEBUG (packet dump) とは独立。ホットパス (readChunk / decrypt) から呼ぶため、
/// 環境変数はプロセス起動時に 1 回だけ評価してキャッシュする。
enum SMBPerfLog {
    static let isEnabled = ProcessInfo.processInfo.environment["SMBEE_PERF"] == "1"

    /// Test-seam gate that stays race-free without an atomic (the package still targets
    /// macOS 13, so `Synchronization.Atomic` is unavailable): the only mutable state
    /// (`enabledOverrideStorage` / `testSinkStorage`) is read and written strictly under
    /// `lock`, and DEBUG builds always take the lock. RELEASE builds compile the seam out
    /// entirely and read only the immutable `isEnabled`, so production stays lock-free.
    /// Rejected alternatives: an unguarded fast-path flag is a data race (macos-tsan,
    /// 2026-07-29), and `NSClassFromString("XCTestCase")` detection does not work on Linux
    /// (corelibs runtime has no ObjC class lookup — linux-build-test, 2026-07-29).
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
        #if DEBUG
        return lock.withLock { enabledOverrideStorage ?? isEnabled }
        #else
        return isEnabled
        #endif
    }

    static func line(_ message: @autoclosure () -> String) {
        #if DEBUG
        lock.lock()
        let enabled = enabledOverrideStorage ?? isEnabled
        let testSink = testSinkStorage
        lock.unlock()
        guard enabled else { return }
        let value = message()
        if let testSink {
            testSink(value)
        } else {
            FileHandle.standardError.write(Data("[smbee-perf] \(value)\n".utf8))
        }
        #else
        guard isEnabled else { return }
        FileHandle.standardError.write(Data("[smbee-perf] \(message())\n".utf8))
        #endif
    }

    static func milliseconds(_ duration: Duration) -> String {
        let ms = Double(duration.components.seconds) * 1000
            + Double(duration.components.attoseconds) / 1e15
        return String(format: "%.1f", ms)
    }
}
