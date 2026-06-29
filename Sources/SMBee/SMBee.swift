import Foundation

/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、AES-GCM / HMAC / SHA の計算は swift-crypto に委ねる。
/// MVP の対象サーバは macOS の SMB サーバ (SMBX)、dialect は SMB 3.0.2 / 3.1.1。
public enum SMBee {
    /// ライブラリのバージョン (暫定)。
    public static let version = "0.0.1"

    public static func list(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = ""
    ) async throws -> [SMBDirectoryEntry] {
        try await SMBClient.list(host: host, port: port, share: share, path: path, credential: credential)
    }

    public static func stat(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String
    ) async throws -> SMBFileStat {
        try await SMBClient.stat(host: host, port: port, share: share, path: path, credential: credential)
    }

    public static func read(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        range: SMBReadRange? = nil
    ) async throws -> [UInt8] {
        try await SMBClient.read(host: host, port: port, share: share, path: path, range: range, credential: credential)
    }
}
