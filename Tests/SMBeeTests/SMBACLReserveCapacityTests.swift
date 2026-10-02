import XCTest
@testable import SMBee

final class SMBACLReserveCapacityTests: XCTestCase {
    func testOversizedAceCountReservesOnlyCapacitySupportedByACLBytes() throws {
        var descriptor = [UInt8](repeating: 0, count: 28)
        descriptor[0] = 1
        writeUInt16LE(0x8004, to: &descriptor, at: 2)
        writeUInt32LE(20, to: &descriptor, at: 16)
        descriptor[20] = 2
        writeUInt16LE(8, to: &descriptor, at: 22)
        writeUInt16LE(UInt16.max, to: &descriptor, at: 24)

        var reservedCount: Int?
        XCTAssertThrowsError(
            try SMB2QueryInfo.decodeSecurityDescriptorForTesting(
                descriptor,
                onACLReserveCapacity: { reservedCount = $0 }
            )
        ) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }

        XCTAssertEqual(reservedCount, 0, "an eight-byte ACL cannot contain any ACE headers")
    }
}
