import XCTest
@testable import SMBee

/// Persistent-session load used to observe first-fault diagnostics around concurrent reads and
/// share enumeration. Connection loss is deliberately observational; other failures are real
/// test failures because they usually indicate a broken harness or an unrelated regression.
final class SMBeeWireStressE2ETests: XCTestCase {
    func testPersistentSessionReadPrefixAndListStress() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_STRESS"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E_STRESS=1 to run wire stress E2E tests")
        }
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let port = try XCTUnwrap(UInt16(environment["SMBEE_E2E_PORT"] ?? "445"))
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let concurrency = max(1, Int(environment["SMBEE_STRESS_CONCURRENCY"] ?? "4") ?? 4)
        let repetitions = max(1, Int(environment["SMBEE_STRESS_REPETITIONS"] ?? "10") ?? 10)
        let prefixLength = max(1, UInt64(environment["SMBEE_STRESS_PREFIX_LENGTH"] ?? "65536") ?? 65536)
        let session = try await SMBee.connect(host: host, port: port, credential: credential, share: share)
        let path = "smbee-wire-stress-\(UUID().uuidString).bin"
        let payload = (0..<Int(max(prefixLength, 65536))).map { UInt8($0 % 251) }
        let counters = StressCounters()

        do {
            try await session.upload(path: path, data: payload)
            for wave in 0..<repetitions {
                if await counters.connectionLossDetected {
                    await counters.abortWaves(count: repetitions - wave)
                    break
                }
                await withTaskGroup(of: Void.self) { group in
                    for _ in 0..<concurrency {
                        group.addTask {
                            await counters.operationStarted()
                            do {
                                _ = try await session.readPrefix(path: path, maxLength: prefixLength)
                            } catch {
                                await counters.record(error: error)
                            }
                        }
                    }
                    group.addTask {
                        await counters.operationStarted()
                        do {
                            _ = try await session.list()
                        } catch {
                            await counters.record(error: error)
                        }
                    }
                }
            }
            try await session.delete(path: path)
            await session.close()
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }

        let summary = await counters.summary
        print("[wire-stress] operations-before-fault=\(summary.operationsBeforeFault) connection-loss=\(summary.connectionLossOccurred) waves-aborted-after-fault=\(summary.wavesAbortedAfterFault)")
        XCTAssertTrue(summary.unexpected.isEmpty, summary.unexpected.joined(separator: "; "))
    }
}

private actor StressCounters {
    private(set) var operations = 0
    private(set) var connectionLosses = 0
    private(set) var operationsBeforeFault = 0
    private(set) var connectionLossOccurred = false
    private(set) var wavesAbortedAfterFault = 0
    private(set) var unexpected: [String] = []

    func operationStarted() { operations += 1 }

    var connectionLossDetected: Bool { connectionLossOccurred }

    func record(error: Error) {
        if error is SMBTransportError {
            if !connectionLossOccurred {
                connectionLossOccurred = true
                operationsBeforeFault = operations
            }
            connectionLosses += 1
        } else if let error = error as? SMBError, case .connectionLost = error {
            if !connectionLossOccurred {
                connectionLossOccurred = true
                operationsBeforeFault = operations
            }
            connectionLosses += 1
        } else {
            unexpected.append("\(String(reflecting: type(of: error))): \(error)")
        }
    }

    func abortWaves(count: Int) {
        wavesAbortedAfterFault += count
    }

    var summary: (operationsBeforeFault: Int, connectionLossOccurred: Bool, wavesAbortedAfterFault: Int, unexpected: [String]) {
        (connectionLossOccurred ? operationsBeforeFault : operations, connectionLossOccurred, wavesAbortedAfterFault, unexpected)
    }
}
