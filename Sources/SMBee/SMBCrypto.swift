import Crypto
import Foundation

public enum SMBCrypto {
    public static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: bytes))
    }

    public static func hmacSHA256(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        return Array(authenticationCode)
    }

    public static func aesGCMSeal(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        authenticatedData: [UInt8]
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: authenticatedData
        )
        return (Array(sealedBox.ciphertext), Array(sealedBox.tag))
    }

    public static func aesGMAC(key: [UInt8], nonce: [UInt8], authenticatedData: [UInt8]) throws -> [UInt8] {
        // MS-SMB2 AES-GMAC signing is GCM authentication with zero-length plaintext and the SMB packet as AAD.
        try aesGCMSeal(key: key, nonce: nonce, plaintext: [], authenticatedData: authenticatedData).tag
    }
}
