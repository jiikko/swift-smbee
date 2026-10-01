import Crypto
import Foundation
import XCTest
@testable import SMBee

// Vector source: pyca/cryptography 46.0.7 (OpenSSL), independently of SMBee.
// The temporary generator is kept here because tmp/ is disposable.
// # issue 075: nonce 11 / tag 16 の CCM 固定値を SMBee と独立な実装 (pyca/cryptography = OpenSSL) で作る
// import hashlib, cryptography
// from cryptography.hazmat.primitives.ciphers.aead import AESCCM
// key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
// nonce = bytes.fromhex("101112131415161718191a")
// aad32 = bytes((0x20 + i) & 0xff for i in range(32))
// def pt(n): return bytes((i * 7 + 3) & 0xff for i in range(n))
// print("cryptography", cryptography.__version__)
// for aad_name, aad in (("aad32", aad32), ("aad0", b"")):
//     for n in (0, 1, 15, 16, 17, 32, 33, 4099, 1048593):
//         out = AESCCM(key, tag_length=16).encrypt(nonce, pt(n), aad if aad else None)
//         ct, tag = out[:-16], out[-16:]
//         ctrep = ct.hex() if n <= 33 else "sha256:" + hashlib.sha256(ct).hexdigest()
//         print(f"{aad_name}\tlen={n}\ttag={tag.hex()}\tct={ctrep}")
// The two 8,192-byte-boundary vectors below come from the same script with (aad0, 8176) and (aad32, 8128).

final class AESCCMBackendTests: XCTestCase {
    private struct FixedVector {
        let aadName: String
        let length: Int
        let tag: String
        let ciphertext: String
    }

    private static let fixedVectors = [
        "aad32\tlen=0\ttag=9d87ba17e61320c833a70c92217c4c80\tct=",
        "aad32\tlen=1\ttag=7126664386945ccb10e9ee6d272dec2a\tct=4f",
        "aad32\tlen=15\ttag=390ffd2b0b359d803fe02de47008434f\tct=4f656cc3df9b7c9fb54ea033753dfb",
        "aad32\tlen=16\ttag=5f9ef227d7b8c2f4da9a192f945daab3\tct=4f656cc3df9b7c9fb54ea033753dfbc2",
        "aad32\tlen=17\ttag=e70179d183f637df8b797a51d558e6d4\tct=4f656cc3df9b7c9fb54ea033753dfbc252",
        "aad32\tlen=32\ttag=87676726ea660382e23760b79ab07e13\tct=4f656cc3df9b7c9fb54ea033753dfbc2521259d1c04be74b41f23fc35a360736",
        "aad32\tlen=33\ttag=7a19e2b3f19a95bb125d30dcecab372e\tct=4f656cc3df9b7c9fb54ea033753dfbc2521259d1c04be74b41f23fc35a360736ea",
        "aad32\tlen=4099\ttag=db02ad22f5b356943ba0c76582580e4c\tct=sha256:905131443bf2ce0f246d04fd67ab837b167cff3f3f818eea575030a2a3b10988",
        "aad32\tlen=1048593\ttag=d92e150b73e556ce71175dadd7f72fc5\tct=sha256:2863745bd0438e78f48df19d17321b75d3875efbb4951b94de4f5db3888c8a06",
        "aad0\tlen=0\ttag=fbc611538f7736cb1c9b1c4edd4e2885\tct=",
        "aad0\tlen=1\ttag=b00e2be93598096601edd8b85decb262\tct=4f",
        "aad0\tlen=15\ttag=eb1f74dcef7ac002a6a39e4a41e30252\tct=4f656cc3df9b7c9fb54ea033753dfb",
        "aad0\tlen=16\ttag=a9cd882ed23aae4271c7ad12654241eb\tct=4f656cc3df9b7c9fb54ea033753dfbc2",
        "aad0\tlen=17\ttag=7a3ed5a7599b3c31696ded4e00099a04\tct=4f656cc3df9b7c9fb54ea033753dfbc252",
        "aad0\tlen=32\ttag=485f0ae7ba76d7d4d0070b5ed21cefaa\tct=4f656cc3df9b7c9fb54ea033753dfbc2521259d1c04be74b41f23fc35a360736",
        "aad0\tlen=33\ttag=83c029a00ea1cfa4db636bdf5ed357d0\tct=4f656cc3df9b7c9fb54ea033753dfbc2521259d1c04be74b41f23fc35a360736ea",
        "aad0\tlen=4099\ttag=d74915339461589d9483abd6165e4e5c\tct=sha256:905131443bf2ce0f246d04fd67ab837b167cff3f3f818eea575030a2a3b10988",
        "aad0\tlen=1048593\ttag=08814b5920faefd556b06f3438cc21d8\tct=sha256:2863745bd0438e78f48df19d17321b75d3875efbb4951b94de4f5db3888c8a06",
        // The CBC-MAC input (B_0 + AAD block(s) + payload) ends exactly on the 8,192-byte flush batch boundary.
        "aad0\tlen=8176\ttag=3d7e0285912630563637480949c21c87\tct=sha256:e263dc57d9f06969217d909c9a3484660ec923cd881f3764f2b0a4f6990f4acf",
        "aad32\tlen=8128\ttag=9980d3e7282612ceeba93547f6e4a6bf\tct=sha256:3fed0b50ec961d6f6ef1314f40a6a288e4b59a46ea2e2b245668ab0c8f2f7812"
    ].map { line -> FixedVector in
        let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
        let lengthField = fields[1].dropFirst("len=".count)
        let tagField = fields[2].dropFirst("tag=".count)
        let ciphertextField = fields[3].dropFirst("ct=".count)
        return FixedVector(
            aadName: String(fields[0]),
            length: Int(lengthField)!,
            tag: String(tagField),
            ciphertext: String(ciphertextField)
        )
    }

    func testIndependentFixedVectorsAcrossSelectedAndFallbackBackends() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let nonce = hexBytes("101112131415161718191a")

        for vector in Self.fixedVectors {
            let aad = vector.aadName == "aad32" ? (0..<32).map { UInt8(0x20 + $0) } : []
            let plaintext = (0..<vector.length).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) }
            let expectedTag = hexBytes(vector.tag)
            let expectedCiphertext = vector.ciphertext.hasPrefix("sha256:") ? nil : hexBytes(vector.ciphertext)

            let selected = try AESCCM.seal(
                key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad
            )
            let pure = try AESCCM.sealFallback(
                key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad
            )
            assertFixedVector(
                selected,
                expectedTag: expectedTag,
                expectedCiphertext: expectedCiphertext,
                expectedCiphertextHash: vector.ciphertext,
                label: "public \(vector.aadName) length \(vector.length)"
            )
            assertFixedVector(
                pure,
                expectedTag: expectedTag,
                expectedCiphertext: expectedCiphertext,
                expectedCiphertextHash: vector.ciphertext,
                label: "fallback \(vector.aadName) length \(vector.length)"
            )
            XCTAssertEqual(selected.ciphertext, pure.ciphertext)
            XCTAssertEqual(selected.tag, pure.tag)
            XCTAssertEqual(
                try AESCCM.open(
                    key: key, nonce: nonce, ciphertext: selected.ciphertext, authenticatedData: aad, tag: selected.tag
                ),
                plaintext
            )
            XCTAssertEqual(
                try AESCCM.openFallback(
                    key: key, nonce: nonce, ciphertext: pure.ciphertext, authenticatedData: aad, tag: pure.tag
                ),
                plaintext
            )

            #if canImport(CryptoExtras) && !canImport(CommonCrypto)
            let accelerated = try AESCCMCryptoExtras.sealValidated(
                key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad, tagLength: 16
            )
            assertFixedVector(
                accelerated,
                expectedTag: expectedTag,
                expectedCiphertext: expectedCiphertext,
                expectedCiphertextHash: vector.ciphertext,
                label: "CryptoExtras \(vector.aadName) length \(vector.length)"
            )
            XCTAssertEqual(
                try AESCCMCryptoExtras.openValidated(
                    key: key,
                    nonce: nonce,
                    ciphertext: accelerated.ciphertext,
                    authenticatedData: aad,
                    tag: accelerated.tag
                ),
                plaintext
            )
            #endif
        }
    }

    func testSeededDifferentialSealAndOpenAcrossBoundaries() throws {
        let key = hexBytes("8f0e1d2c3b4a59687766554433221100")
        let payloadLengths = [0, 1, 15, 16, 17, 32, 33]
        let aadLengths = [0, 32, 13]
        let tagLengths = [4, 8, 16]
        let nonceLengths = [11, 7, 9, 13]
        var generator = SeededByteGenerator(state: 0x075c_c0a5_a5f0_0d00)

        for payloadLength in payloadLengths {
            for aadLength in aadLengths {
                for tagLength in tagLengths {
                    for nonceLength in nonceLengths {
                        let nonce = generator.bytes(count: nonceLength)
                        let aad = generator.bytes(count: aadLength)
                        let plaintext = generator.bytes(count: payloadLength)
                        try assertBackendsAgree(
                            key: key,
                            nonce: nonce,
                            plaintext: plaintext,
                            authenticatedData: aad,
                            tagLength: tagLength
                        )
                    }
                }
            }
        }

        for (index, payloadLength) in [65_536, 65_537].enumerated() {
            let aadLength = aadLengths[index]
            let nonceLength = nonceLengths[index + 1]
            let tagLength = tagLengths[index + 1]
            let nonce = generator.bytes(count: nonceLength)
            let aad = generator.bytes(count: aadLength)
            let plaintext = generator.bytes(count: payloadLength)
            try assertBackendsAgree(
                key: key,
                nonce: nonce,
                plaintext: plaintext,
                authenticatedData: aad,
                tagLength: tagLength
            )
        }
    }

    func testModifiedTagsAADAndCiphertextAreRejected() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let nonce = hexBytes("101112131415161718191a")
        let aad = Array(0..<32).map { UInt8($0) }
        let plaintext = Array(0..<65).map { UInt8(truncatingIfNeeded: $0 * 11) }
        let sealed = try AESCCM.seal(key: key, nonce: nonce, plaintext: plaintext, authenticatedData: aad)

        for tagIndex in [0, sealed.tag.count - 1] {
            var changedTag = sealed.tag
            changedTag[tagIndex] ^= 1
            XCTAssertThrowsError(
                try AESCCM.open(
                    key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: aad, tag: changedTag
                )
            )
            XCTAssertThrowsError(
                try AESCCM.openFallback(
                    key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: aad, tag: changedTag
                )
            )
        }

        var changedAAD = aad
        changedAAD[0] ^= 1
        XCTAssertThrowsError(
            try AESCCM.open(
                key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: changedAAD, tag: sealed.tag
            )
        )
        XCTAssertThrowsError(
            try AESCCM.openFallback(
                key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: changedAAD, tag: sealed.tag
            )
        )

        var changedCiphertext = sealed.ciphertext
        changedCiphertext[0] ^= 1
        XCTAssertThrowsError(
            try AESCCM.open(
                key: key, nonce: nonce, ciphertext: changedCiphertext, authenticatedData: aad, tag: sealed.tag
            )
        )
        XCTAssertThrowsError(
            try AESCCM.openFallback(
                key: key, nonce: nonce, ciphertext: changedCiphertext, authenticatedData: aad, tag: sealed.tag
            )
        )
    }

    func testCMACLastBlockCorrectionProducesCBCMAC() throws {
        let key = hexBytes("2b7e151628aed2a6abf7158809cf4f3c")
        let block = [UInt8](repeating: 0, count: 16)
        let l = try AES128.encryptBlock(key: key, block: block)
        let k1 = doubled(l)
        var correctedBlock = block
        for index in 0..<16 { correctedBlock[index] ^= k1[index] }

        let correctedCMAC = try AESCMAC.authenticationCode(key: key, message: correctedBlock)
        let cbcMAC = try AES128.encryptBlock(key: key, block: block)
        let uncorrectedCMAC = try AESCMAC.authenticationCode(key: key, message: block)
        XCTAssertEqual(correctedCMAC, cbcMAC)
        XCTAssertNotEqual(uncorrectedCMAC, cbcMAC)
    }

    func testValidationErrorsAndMessageLengthBoundaries() throws {
        let key = [UInt8](repeating: 0, count: 16)
        let nonce11 = [UInt8](repeating: 0, count: 11)
        let payloadLimit11 = Int(UInt64(1) << 32)
        XCTAssertTrue(AESCCM.isMessageLengthAllowed(payloadLimit11 - 1, nonceLength: 11))
        XCTAssertFalse(AESCCM.isMessageLengthAllowed(payloadLimit11, nonceLength: 11))
        XCTAssertTrue(AESCCM.isMessageLengthAllowed(65_535, nonceLength: 13))
        XCTAssertFalse(AESCCM.isMessageLengthAllowed(65_536, nonceLength: 13))
        XCTAssertTrue(AESCCM.isMessageLengthAllowed(Int.max, nonceLength: 7))
        XCTAssertFalse(AESCCM.isMessageLengthAllowed(-1, nonceLength: 11))

        XCTAssertThrowsError(try AESCCM.seal(
            key: Array(repeating: 0, count: 15), nonce: nonce11, plaintext: [], authenticatedData: []
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM requires a 16-byte key"))
        }
        XCTAssertThrowsError(try AESCCM.seal(
            key: key, nonce: Array(repeating: 0, count: 6), plaintext: [], authenticatedData: []
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM nonce must be 7...13 bytes"))
        }
        XCTAssertThrowsError(try AESCCM.seal(
            key: key, nonce: Array(repeating: 0, count: 14), plaintext: [], authenticatedData: []
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM nonce must be 7...13 bytes"))
        }
        XCTAssertThrowsError(try AESCCM.seal(
            key: key, nonce: nonce11, plaintext: [], authenticatedData: [], tagLength: 5
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM tag length must be even and 4...16 bytes"))
        }
        XCTAssertThrowsError(try AESCCM.open(
            key: key, nonce: nonce11, ciphertext: [], authenticatedData: [], tag: [0, 0, 0]
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM tag length must be even and 4...16 bytes"))
        }
        XCTAssertThrowsError(try AESCCM.validate(
            key: key, nonce: nonce11, tagLength: 16, messageLength: payloadLimit11
        )) {
            XCTAssertEqual($0 as? SMBCodecError, .invalidValue("AES-CCM message too large for nonce length"))
        }
    }

    private func assertBackendsAgree(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        authenticatedData: [UInt8],
        tagLength: Int
    ) throws {
        let selected = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tagLength
        )
        let pure = try AESCCM.sealFallback(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tagLength
        )
        XCTAssertEqual(selected.ciphertext, pure.ciphertext)
        XCTAssertEqual(selected.tag, pure.tag)
        XCTAssertEqual(
            try AESCCM.open(
                key: key,
                nonce: nonce,
                ciphertext: selected.ciphertext,
                authenticatedData: authenticatedData,
                tag: selected.tag
            ),
            plaintext
        )
        XCTAssertEqual(
            try AESCCM.openFallback(
                key: key,
                nonce: nonce,
                ciphertext: selected.ciphertext,
                authenticatedData: authenticatedData,
                tag: selected.tag
            ),
            plaintext
        )
        #if canImport(CryptoExtras) && !canImport(CommonCrypto)
        if nonce.count == 11 {
            let accelerated = try AESCCMCryptoExtras.sealValidated(
                key: key,
                nonce: nonce,
                plaintext: plaintext,
                authenticatedData: authenticatedData,
                tagLength: tagLength
            )
            XCTAssertEqual(accelerated.ciphertext, pure.ciphertext)
            XCTAssertEqual(accelerated.tag, pure.tag)
            XCTAssertEqual(
                try AESCCMCryptoExtras.openValidated(
                    key: key,
                    nonce: nonce,
                    ciphertext: accelerated.ciphertext,
                    authenticatedData: authenticatedData,
                    tag: accelerated.tag
                ),
                plaintext
            )
        }
        #endif
    }

    private func assertFixedVector(
        _ sealed: (ciphertext: [UInt8], tag: [UInt8]),
        expectedTag: [UInt8],
        expectedCiphertext: [UInt8]?,
        expectedCiphertextHash: String,
        label: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(sealed.tag, expectedTag, "\(label) tag", file: file, line: line)
        if let expectedCiphertext {
            XCTAssertEqual(sealed.ciphertext, expectedCiphertext, "\(label) ciphertext", file: file, line: line)
        } else {
            let expectedHash = String(expectedCiphertextHash.dropFirst("sha256:".count))
            XCTAssertEqual(hex(SHA256.hash(data: Data(sealed.ciphertext))), expectedHash, "\(label) ciphertext hash", file: file, line: line)
        }
    }

    private func hexBytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        }
    }

    private func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func doubled(_ input: [UInt8]) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 16)
        var carry: UInt8 = 0
        for index in stride(from: 15, through: 0, by: -1) {
            output[index] = (input[index] &<< 1) | carry
            carry = input[index] >> 7
        }
        if carry != 0 { output[15] ^= 0x87 }
        return output
    }
}

private struct SeededByteGenerator {
    private var state: UInt64

    init(state: UInt64) { self.state = state }

    mutating func bytes(count: Int) -> [UInt8] {
        (0..<count).map { _ in
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return UInt8(truncatingIfNeeded: state >> 24)
        }
    }
}
