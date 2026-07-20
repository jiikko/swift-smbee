import XCTest
import SMBee

final class SMBeePublicAPITests: XCTestCase {
    func testPublicErrorTaxonomyIsImportableAndSendable() {
        requireSendable(SMBError.self)
        requireSendable(SMBCodecError.self)
        requireSendable(SMBTransportError.self)
    }

    func testURLValidationExposesPublicCodecError() {
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://server")) { error in
            guard case SMBCodecError.invalidValue(let message) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(message, "SMB URL must include a share")
        }
    }

    private func requireSendable<T: Sendable>(_: T.Type) {}
}
