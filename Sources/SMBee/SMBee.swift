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

    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String
    ) async throws {
        try await SMBClient.makeDirectory(host: host, port: port, share: share, path: path, credential: credential)
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            data: data,
            overwrite: overwrite,
            credential: credential
        )
    }

    public static func rename(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        replaceIfExists: Bool = false
    ) async throws {
        try await SMBClient.rename(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            replaceIfExists: replaceIfExists,
            credential: credential
        )
    }

    public static func delete(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        directory: Bool = false
    ) async throws {
        try await SMBClient.delete(host: host, port: port, share: share, path: path, directory: directory, credential: credential)
    }
}
