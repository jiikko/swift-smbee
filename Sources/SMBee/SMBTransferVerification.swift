import Crypto
import Foundation

/// Consumer-visible transfer verification helpers (size is handled by callers via `stat`;
/// this provides content hashing for `--verify hash`).
///
/// Hashing a remote file reads its full content back over the wire, so it costs one extra
/// full transfer. It detects corruption that size comparison cannot.
public enum SMBTransferVerification {
    /// SHA-256 of a remote file, streamed without lifting the file into memory. Hex-encoded.
    public static func remoteSHA256Hex(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws -> String {
        let accumulator = SHA256Accumulator()
        try await SMBee.withReadStream(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: path,
            timeout: timeout
        ) { chunk in
            await accumulator.update(chunk)
        }
        return await accumulator.finalizeHex()
    }

    /// SHA-256 of a local file, streamed in bounded chunks. Hex-encoded.
    public static func localSHA256Hex(fileURL: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            guard let data = try handle.read(upToCount: 1 << 20), !data.isEmpty else { break }
            hasher.update(data: data)
        }
        return hexString(hasher.finalize())
    }

    private static func hexString(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

private actor SHA256Accumulator {
    private var hasher = SHA256()

    func update(_ chunk: [UInt8]) {
        hasher.update(data: Data(chunk))
    }

    func finalizeHex() -> String {
        hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
