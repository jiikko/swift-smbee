import XCTest
@testable import SMBee

final class SMBTransferRegressionTests: XCTestCase {
    func testEncryptedTransferChunkPlannerReservesTransformOverhead() {
        let overhead = SMB3TransformHeader.encodedSize
        let negotiatedLimit = UInt32(1024 * 1024)
        let readChunk = SMBTransferLimits.negotiatedChunkSize(
            localLimit: SMBSession.localReadChunkLimit,
            negotiatedLimit: negotiatedLimit,
            transformOverhead: overhead
        )
        let writeChunk = SMBTransferLimits.negotiatedChunkSize(
            localLimit: SMBClientSession.localWriteChunkLimit,
            negotiatedLimit: negotiatedLimit,
            transformOverhead: overhead
        )

        XCTAssertEqual(readChunk, 1024 * 1024 - overhead)
        XCTAssertEqual(writeChunk, 1024 * 1024 - overhead)
        XCTAssertLessThanOrEqual(readChunk + overhead, Int(negotiatedLimit))
        XCTAssertLessThanOrEqual(writeChunk + overhead, Int(negotiatedLimit))
    }
}
