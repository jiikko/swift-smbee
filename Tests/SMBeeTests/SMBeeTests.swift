import Crypto
import XCTest
@testable import SMBee

final class SMBeeTests: XCTestCase {
    func testVersionIsNotEmpty() {
        XCTAssertFalse(SMBee.version.isEmpty)
    }

    func testSMB2HeaderRoundTrip() throws {
        let header = SMB2Header(
            creditCharge: 7,
            status: 0x1122_3344,
            command: 0,
            credits: 9,
            flags: 0x5566_7788,
            nextCommand: 0,
            messageId: 42,
            treeId: 0xaabb_ccdd,
            sessionId: 0x0102_0304_0506_0708,
            signature: Array(0..<16)
        )

        let encoded = try header.encode()
        XCTAssertEqual(encoded.count, 64)
        XCTAssertEqual(try SMB2Header.decode(encoded), header)
    }

    func testMD4RFC1320Vectors() {
        XCTAssertEqual(hex(MD4.hash([])), "31d6cfe0d16ae931b73c59d7e0c089c0")
        XCTAssertEqual(hex(MD4.hash(Array("a".utf8))), "bde52cb31de33e46245e05fbdbd6fb24")
        XCTAssertEqual(hex(MD4.hash(Array("abc".utf8))), "a448017aaf21d8525fc10ae87aa6729d")
        XCTAssertEqual(hex(MD4.hash(Array("message digest".utf8))), "d9130a8164549fe818874806e1c7014b")
    }

    func testHMACAndSHAUsingSwiftCryptoVectors() {
        let hmacMD5 = HMAC<Insecure.MD5>.authenticationCode(
            for: Array("Hi There".utf8),
            using: SymmetricKey(data: Array(repeating: 0x0b, count: 16))
        )
        XCTAssertEqual(hex(Array(hmacMD5)), "9294727a3638bb1c13f48ef8158bfc9d")

        let hmacSHA256 = SMBCrypto.hmacSHA256(
            key: Array(repeating: 0x0b, count: 20),
            message: Array("Hi There".utf8)
        )
        XCTAssertEqual(
            hex(hmacSHA256),
            "b0344c61d8db38535ca8afceaf0bf12b"
                + "881dc200c9833da726e9376c2e32cff7"
        )

        XCTAssertEqual(
            hex(SMBCrypto.sha512(Array("abc".utf8))),
            "ddaf35a193617abacc417349ae204131"
                + "12e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    func testAESGCMAndGMACNISTVectors() throws {
        let key = Array(repeating: UInt8(0), count: 16)
        let nonce = Array(repeating: UInt8(0), count: 12)
        let gcm = try SMBCrypto.aesGCMSeal(key: key, nonce: nonce, plaintext: [], authenticatedData: [])
        XCTAssertEqual(gcm.ciphertext, [])
        XCTAssertEqual(hex(gcm.tag), "58e2fccefa7e3061367f1d57a4e7455a")

        let gmac = try SMBCrypto.aesGMAC(key: key, nonce: nonce, authenticatedData: [])
        XCTAssertEqual(hex(gmac), "58e2fccefa7e3061367f1d57a4e7455a")
    }

    func testNegotiateRequestRoundTripShape() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )
        let expectedHex =
            "fe534d4240000000000000000000010000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "24000100010000004000000000112233445566778899aabbccddeeff68000000" +
            "03000000110300000100260000000000010020000100aaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000020006000000000002" +
            "00020004000000080004000000000001000200"
        XCTAssertEqual(hex(request), expectedHex)

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMBNegotiateConstants.commandNegotiate)
        XCTAssertEqual(header.messageId, 0)

        var reader = SMBByteReader(bytes: Array(request.dropFirst(64)))
        XCTAssertEqual(try reader.readUInt16LE(), 36)
        XCTAssertEqual(try reader.readUInt16LE(), 1)
        try reader.skip(count: 2 + 2 + 4 + 16)
        XCTAssertEqual(try reader.readUInt32LE(), 104)
        XCTAssertEqual(try reader.readUInt16LE(), 3)
        try reader.skip(count: 2)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect311)
    }

    func testNegotiateRequestContextAlignmentAndCount() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )

        let contextOffset = Int(readUInt32LE(request, at: 64 + 28))
        let contextCount = Int(readUInt16LE(request, at: 64 + 32))
        XCTAssertEqual(contextOffset, 104)
        XCTAssertEqual(contextOffset % 8, 0)
        XCTAssertEqual(contextCount, 3)
        XCTAssertEqual(Array(request[102..<104]), [0, 0])

        var offset = contextOffset
        var contextTypes: [UInt16] = []
        for index in 0..<contextCount {
            XCTAssertEqual(offset % 8, 0)
            let type = readUInt16LE(request, at: offset)
            let length = Int(readUInt16LE(request, at: offset + 2))
            contextTypes.append(type)
            let dataEnd = offset + 8 + length
            let nextOffset: Int
            if index == contextCount - 1 {
                nextOffset = dataEnd
                XCTAssertEqual(dataEnd, request.count)
            } else {
                nextOffset = offset + 8 + ((length + 7) / 8) * 8
                XCTAssertEqual(
                    Array(request[dataEnd..<nextOffset]),
                    Array(repeating: 0, count: nextOffset - dataEnd)
                )
            }
            offset = nextOffset
        }

        XCTAssertEqual(contextTypes, [
            SMBNegotiateConstants.preauthContext,
            SMBNegotiateConstants.encryptionContext,
            SMBNegotiateConstants.signingContext,
        ])
        XCTAssertEqual(offset, request.count)
    }

    func testNegotiateResponseRoundTrip() throws {
        let response = try makeNegotiateResponse()
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertEqual(parsed.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(parsed.cipher, SMBNegotiateConstants.aes128GCM)
        XCTAssertEqual(parsed.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
        XCTAssertEqual(parsed.serverGuid.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
    }

    func testNegotiateResponseRejectsInvalidContextOffset() throws {
        var response = try makeNegotiateResponse()
        writeUInt32LE(128, to: &response, at: 64 + 60)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid NEGOTIATE context offset"))
        }
    }

    func testNegotiateResponseRejectsMalformedContextLength() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(5, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid PREAUTH context length"))
        }
    }

    func testNegotiateResponseRejectsContextPastPacketEnd() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(0xff, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    private func makeNegotiateResponse() throws -> [UInt8] {
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        var body = SMBByteWriter()
        body.writeUInt16LE(65)
        body.writeUInt16LE(SMBNegotiateConstants.signingRequired)
        body.writeUInt16LE(SMBNegotiateConstants.dialect311)
        body.writeUInt16LE(3)
        body.writeBytes(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!.smbWireBytes)
        body.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt64LE(0)
        body.writeUInt64LE(0)
        body.writeUInt16LE(0)
        body.writeUInt16LE(0)
        body.writeUInt32LE(136)
        var packet = header + body.bytes
        packet.append(contentsOf: Array(repeating: 0, count: 136 - packet.count))

        appendContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], to: &packet)
        appendContext(type: SMBNegotiateConstants.encryptionContext, data: [1, 0, 2, 0], to: &packet)
        appendContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], to: &packet)
        return packet
    }

    private func appendContext(type: UInt16, data: [UInt8], to bytes: inout [UInt8]) {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(type)
        writer.writeUInt16LE(UInt16(data.count))
        writer.writeUInt32LE(0)
        writer.writeBytes(data)
        writer.padTo8()
        bytes.append(contentsOf: writer.bytes)
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    }

    private func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
        bytes[offset + 2] = UInt8((value >> 16) & 0xff)
        bytes[offset + 3] = UInt8((value >> 24) & 0xff)
    }
}
