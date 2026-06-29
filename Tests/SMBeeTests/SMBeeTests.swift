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

    func testAESCMACRFC4493Vectors() throws {
        let key = hexBytes("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411"
        )
        XCTAssertEqual(hex(try AES128.encryptBlock(key: key, block: hexBytes("6bc1bee22e409f96e93d7e117393172a"))), "3ad77bb40d7a3660a89ecaf32466ef97")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: [])), "bb1d6929e95937287fa37d129b756746")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: Array(message[0..<16]))), "070a16b46b4d4144f79bdd9dd04a287c")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: message)), "dfa66747de9ae63030ca32611497c827")
        XCTAssertEqual(
            hex(try AESCMAC.authenticationCode(key: key, message: hexBytes(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710"
            ))),
            "51f0bebf7e3b9d92fc49741779363cfe"
        )
    }

    func testNTLMv2KnownVectors() {
        let ntowfv2 = NTLM.ntowfv2(password: "SecREt01", username: "User", domain: "Domain")
        XCTAssertEqual(hex(ntowfv2), "54993fb8ba7bc2d6eacaef6bdc226c49")
        let serverChallenge = hexBytes("0123456789abcdef")
        let blob = hexBytes(
            "01010000000000000090d336b734c301ffffff001122334400000000" +
            "02000c0044004f004d00410049004e00" +
            "01000c00530045005200560045005200" +
            "0400140064006f006d00610069006e002e0063006f006d00" +
            "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00" +
            "0000000000000000"
        )
        XCTAssertEqual(hex(NTLM.ntProofStr(ntowfv2: ntowfv2, serverChallenge: serverChallenge, blob: blob)), "2a8e1bc8a06222ed5301c3fbd2154d0b")
    }

    func testNTLMType1FixedBytesAndSecurityBuffers() {
        let type1 = NTLM.makeType1()

        XCTAssertEqual(type1.count, 40)
        XCTAssertEqual(Array(type1[0..<8]), Array("NTLMSSP\0".utf8))
        XCTAssertEqual(readUInt32LE(type1, at: 8), 1)
        XCTAssertEqual(readUInt32LE(type1, at: 12), NTLM.negotiateFlags)
        XCTAssertEqual(hex(Array(type1[12..<16])), "358288a2")
        XCTAssertEqual(readUInt16LE(type1, at: 16), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 40)
        XCTAssertEqual(hex(Array(type1[32..<40])), "0601b11d0000000f")
    }

    func testNTLMType1DomainAndWorkstationSecurityBuffers() {
        let type1 = NTLM.makeType1(domain: "dom", workstation: "wkst")

        XCTAssertEqual(readUInt16LE(type1, at: 16), 3)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 3)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 4)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 4)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 43)
        XCTAssertEqual(String(decoding: type1[40..<43], as: UTF8.self), "DOM")
        XCTAssertEqual(String(decoding: type1[43..<47], as: UTF8.self), "WKST")
    }

    func testSPNEGONegTokenInitDERStructure() throws {
        let type1 = NTLM.makeType1()
        let token = SPNEGO.wrapNegTokenInit(type1)

        var cursor = 0
        let applicationEnd = try expectDERTag(0x60, in: token, cursor: &cursor)

        let spnegoOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<spnegoOIDEnd]), [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
        cursor = spnegoOIDEnd

        let negTokenInitEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let mechTypesEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let listEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let ntlmOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<ntlmOIDEnd]), [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
        cursor = ntlmOIDEnd
        XCTAssertEqual(cursor, listEnd)
        XCTAssertEqual(cursor, mechTypesEnd)

        let mechTokenEnd = try expectDERTag(0xa2, in: token, cursor: &cursor)
        let octetEnd = try expectDERTag(0x04, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<octetEnd]), type1)
        cursor = octetEnd
        XCTAssertEqual(cursor, mechTokenEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenInitEnd)
        XCTAssertEqual(cursor, applicationEnd)
        XCTAssertEqual(cursor, token.count)
    }

    func testSessionSetupRequestFixedFieldsAndSecurityBuffer() throws {
        let blob = SPNEGO.wrapNegTokenInit(NTLM.makeType1())
        let request = try SMB2SessionSetup.encodeRequest(
            messageId: 7,
            sessionId: 0,
            securityBlob: blob,
            signed: false
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.sessionSetup)
        XCTAssertEqual(header.messageId, 7)
        XCTAssertEqual(header.sessionId, 0)
        XCTAssertEqual(readUInt16LE(request, at: 64), 25)
        XCTAssertEqual(request[66], 0)
        XCTAssertEqual(request[67], 1)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(readUInt32LE(request, at: 72), 0)
        XCTAssertEqual(readUInt16LE(request, at: 76), 88)
        XCTAssertEqual(readUInt16LE(request, at: 78), UInt16(blob.count))
        XCTAssertEqual(readUInt64LE(request, at: 80), 0)
        XCTAssertEqual(Array(request[88..<request.count]), blob)
    }

    func testNegotiateRequestRoundTripShape() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )
        let expectedHex =
            "fe534d4240000000000000000000010000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "24000500010000004000000000112233445566778899aabbccddeeff70000000" +
            "030000000202100200030203110300000100260000000000010020000100aaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000020006000000000002" +
            "00020004000000080004000000000001000200"
        XCTAssertEqual(hex(request), expectedHex)

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMBNegotiateConstants.commandNegotiate)
        XCTAssertEqual(header.messageId, 0)

        var reader = SMBByteReader(bytes: Array(request.dropFirst(64)))
        XCTAssertEqual(try reader.readUInt16LE(), 36)
        XCTAssertEqual(try reader.readUInt16LE(), 5)
        try reader.skip(count: 2 + 2 + 4 + 16)
        XCTAssertEqual(try reader.readUInt32LE(), 112)
        XCTAssertEqual(try reader.readUInt16LE(), 3)
        try reader.skip(count: 2)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect202)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect210)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect300)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect302)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect311)
    }

    func testNegotiateRequestContextAlignmentAndCount() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )

        let contextOffset = Int(readUInt32LE(request, at: 64 + 28))
        let contextCount = Int(readUInt16LE(request, at: 64 + 32))
        XCTAssertEqual(contextOffset, 112)
        XCTAssertEqual(contextOffset % 8, 0)
        XCTAssertEqual(contextCount, 3)
        XCTAssertEqual(Array(request[110..<112]), [0, 0])

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

    func testNegotiateResponseBefore311HasNoContexts() throws {
        let response = try makeNegotiateResponse(
            dialect: SMBNegotiateConstants.dialect300,
            contextCount: 0,
            contextOffset: 0,
            includeContexts: false
        )
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect300)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertNil(parsed.signingAlgorithm)
        XCTAssertNil(parsed.cipher)
        XCTAssertNil(parsed.preauthHashAlgorithm)
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

    private func makeNegotiateResponse(
        dialect: UInt16 = SMBNegotiateConstants.dialect311,
        contextCount: UInt16 = 3,
        contextOffset: UInt32 = 136,
        includeContexts: Bool = true
    ) throws -> [UInt8] {
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        var body = SMBByteWriter()
        body.writeUInt16LE(65)
        body.writeUInt16LE(SMBNegotiateConstants.signingRequired)
        body.writeUInt16LE(dialect)
        body.writeUInt16LE(contextCount)
        body.writeBytes(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!.smbWireBytes)
        body.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt64LE(0)
        body.writeUInt64LE(0)
        body.writeUInt16LE(0)
        body.writeUInt16LE(0)
        body.writeUInt32LE(contextOffset)
        var packet = header + body.bytes
        if includeContexts {
            packet.append(contentsOf: Array(repeating: 0, count: Int(contextOffset) - packet.count))

            appendContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.encryptionContext, data: [1, 0, 2, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], to: &packet)
        }
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

    private func hexBytes(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map {
            let start = value.index(value.startIndex, offsetBy: $0)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
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

    private func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
    }

    private func expectDERTag(_ expectedTag: UInt8, in bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        XCTAssertEqual(bytes[cursor], expectedTag)
        cursor += 1
        let length = try readDERLength(bytes, cursor: &cursor)
        let end = cursor + length
        XCTAssertLessThanOrEqual(end, bytes.count)
        return end
    }

    private func readDERLength(_ bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        let first = bytes[cursor]
        cursor += 1
        if first & 0x80 == 0 {
            return Int(first)
        }
        let byteCount = Int(first & 0x7f)
        XCTAssertGreaterThan(byteCount, 0)
        XCTAssertLessThanOrEqual(byteCount, 2)
        XCTAssertLessThanOrEqual(cursor + byteCount, bytes.count)
        var value = 0
        for _ in 0..<byteCount {
            value = (value << 8) | Int(bytes[cursor])
            cursor += 1
        }
        return value
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
