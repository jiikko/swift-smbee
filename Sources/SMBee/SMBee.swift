import Foundation

/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、AES-GCM / HMAC / SHA の計算は swift-crypto に委ねる。
/// MVP の対象サーバは macOS の SMB サーバ (SMBX)、dialect は SMB 3.0.2 / 3.1.1。
public enum SMBee {
    /// ライブラリのバージョン (暫定)。
    public static let version = "0.0.1"

    public static func connect(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String
    ) async throws -> SMBClientSession {
        try await SMBClient.connect(host: host, port: port, share: share, credential: credential)
    }

    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential
    ) async throws -> [SMBShareInfo] {
        try await SMBClient.listShares(host: host, port: port, credential: credential)
    }

    public static func list(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = ""
    ) async throws -> [SMBDirectoryEntry] {
        try await SMBClient.list(host: host, port: port, share: share, path: path, credential: credential)
    }

    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = "",
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await SMBClient.withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            onEntry: onEntry
        )
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

    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        update: SMBFileMetadataUpdate,
        directory: Bool = false
    ) async throws {
        try await SMBClient.updateMetadata(
            host: host,
            port: port,
            share: share,
            path: path,
            update: update,
            directory: directory,
            credential: credential
        )
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

    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await SMBClient.withReadStream(
            host: host,
            port: port,
            share: share,
            path: path,
            range: range,
            credential: credential,
            onChunk: onChunk
        )
    }

    public static func download(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true
    ) async throws {
        try await SMBClient.download(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            credential: credential
        )
    }

    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true
    ) async throws {
        try await SMBClient.downloadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            credential: credential
        )
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

    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true
    ) async throws {
        try await SMBClient.uploadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            credential: credential
        )
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            credential: credential
        )
    }

    public static func copy(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false
    ) async throws {
        try await SMBClient.copy(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            credential: credential
        )
    }

    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false
    ) async throws {
        try await SMBClient.copyDirectory(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
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
        directory: Bool = false,
        recursive: Bool = false
    ) async throws {
        try await SMBClient.delete(
            host: host,
            port: port,
            share: share,
            path: path,
            directory: directory,
            recursive: recursive,
            credential: credential
        )
    }
}
