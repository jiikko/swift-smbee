import Foundation
import XCTest
@testable import SMBee

final class SMBVerifySignedConstantTimeTests: XCTestCase {
    private let signingKey = Array(repeating: UInt8(0x6d), count: 16)

    func testVerifySignedAcceptsValidServerSignature() async throws {
        let session = makeSession()
        let packet = try signedPacket()

        try await session.verifySignedForTesting(packet)
    }

    func testVerifySignedRejectsFirstMiddleAndLastSignatureByteChanges() async throws {
        let session = makeSession()
        let signed = try signedPacket()

        for index in [0, 7, 15] {
            var changed = signed
            changed[48 + index] ^= 0x01
            do {
                try await session.verifySignedForTesting(changed)
                XCTFail("expected the signature mutation at byte \(index) to fail")
            } catch {
                XCTAssertEqual(
                    error as? SMBCodecError,
                    .invalidValue("SMB signature verification failed")
                )
            }
        }
    }

    func testVerifySignedCallsTheConstantTimeComparisonPrimitive() throws {
        let sourceFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = sourceFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: repositoryRoot.appendingPathComponent("Sources/SMBee/SMBClient.swift"),
            encoding: .utf8
        )
        let verifierStart = try XCTUnwrap(source.range(of: "private func verifySigned(_ frame:"))
        let verifierEnd = try XCTUnwrap(source.range(of: "private func receiveDecryptedFrame", range: verifierStart.upperBound..<source.endIndex))
        let verifier = source[verifierStart.lowerBound..<verifierEnd.lowerBound]

        XCTAssertTrue(verifier.contains("AESCCM.constantTimeEqual(expected, header.signature)"))
        XCTAssertFalse(verifier.contains("expected == header.signature"))
    }

    private func makeSession() -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: InMemoryTransport(),
            signingKey: signingKey,
            signingRequired: true
        )
    }

    private func signedPacket() throws -> [UInt8] {
        let packet = try SMB2Header(
            command: SMB2Commands.echo,
            messageId: 0x1234,
            treeId: 0x3344,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        return try signedTestPacket(
            packet,
            algorithm: .aesCMAC,
            key: signingKey,
            sender: .server
        )
    }
}
