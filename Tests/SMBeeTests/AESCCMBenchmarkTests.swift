import XCTest
@testable import SMBee

/// Env-gated micro-benchmark for issue 075: measures the pure-Swift AES-CCM fallback
/// throughput that gates Linux SMB 3.0.2 encrypted reads. Run with SMBEE_BENCH_CCM=1;
/// it prints CCM_BENCH lines and asserts nothing about speed (measurement only).
final class AESCCMBenchmarkTests: XCTestCase {
    func testAESCCMThroughputMeasurement() throws {
        guard ProcessInfo.processInfo.environment["SMBEE_BENCH_CCM"] == "1" else {
            throw XCTSkip("Set SMBEE_BENCH_CCM=1 to run the AES-CCM micro-benchmark")
        }
        let key = [UInt8](repeating: 0x4b, count: 16)
        let nonce = [UInt8](repeating: 0x6e, count: 11)
        let aad = [UInt8](repeating: 0x61, count: 64)

        // 1 MiB matches the SMB READ chunk clamp; total 8 MiB keeps debug runs bounded.
        let chunkSize = 1 << 20
        let chunkCount = 8
        let plaintext = [UInt8](repeating: 0x70, count: chunkSize)

        let sealed = try AESCCM.seal(
            key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad
        )

        var configuration = "debug"
        #if !DEBUG
        configuration = "release"
        #endif

        let sealStart = ContinuousClock.now
        for _ in 0..<chunkCount {
            _ = try AESCCM.seal(
                key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad
            )
        }
        let sealElapsed = ContinuousClock.now - sealStart

        let openStart = ContinuousClock.now
        for _ in 0..<chunkCount {
            _ = try AESCCM.open(
                key: key,
                nonce: nonce,
                ciphertext: sealed.ciphertext,
                authenticatedData: aad,
                tag: sealed.tag
            )
        }
        let openElapsed = ContinuousClock.now - openStart

        func mibPerSecond(_ elapsed: Duration) -> Double {
            let seconds = Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
            let mib = Double(chunkSize * chunkCount) / Double(1 << 20)
            return mib / seconds
        }
        print("CCM_BENCH config=\(configuration) op=seal bytes=\(chunkSize * chunkCount) " +
            "throughput_mib_s=\(String(format: "%.3f", mibPerSecond(sealElapsed)))")
        print("CCM_BENCH config=\(configuration) op=open bytes=\(chunkSize * chunkCount) " +
            "throughput_mib_s=\(String(format: "%.3f", mibPerSecond(openElapsed)))")
    }
}
