import Foundation

/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、暗号プリミティブの計算は swift-crypto と in-repo pure-Swift 実装に委ねる。
/// 対象サーバは SMB 3.x サーバ (macOS SMBX / Windows SMB Server / Samba)。
/// 自動 E2E は Samba、手動 smoke は実サーバで確認する。
public enum SMBee {
    /// ライブラリのバージョン (暫定)。
    public static let version = "0.0.1"

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        timeout: Duration? = nil
    ) async throws -> SMBClientSession {
        try await SMBClient.connect(host: host, port: port, share: share, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func connect(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        timeout: Duration? = nil
    ) async throws -> SMBClientSession {
        try await SMBClient.connect(host: host, port: port, share: share, credentialProvider: credentialProvider, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        timeout: Duration? = nil
    ) async throws -> [SMBShareInfo] {
        try await SMBClient.listShares(host: host, port: port, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func list(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = "",
        timeout: Duration? = nil
    ) async throws -> [SMBDirectoryEntry] {
        try await SMBClient.list(host: host, port: port, share: share, path: path, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = "",
        timeout: Duration? = nil,
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await SMBClient.withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credential: credential,
            timeout: timeout,
            onEntry: onEntry
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func stat(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBFileStat {
        try await SMBClient.stat(host: host, port: port, share: share, path: path, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        update: SMBFileMetadataUpdate,
        directory: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.updateMetadata(
            host: host,
            port: port,
            share: share,
            path: path,
            update: update,
            directory: directory,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func read(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        timeout: Duration? = nil
    ) async throws -> [UInt8] {
        try await SMBClient.read(host: host, port: port, share: share, path: path, range: range, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        timeout: Duration? = nil,
        onChunk: @escaping @Sendable ([UInt8]) async throws -> Void
    ) async throws {
        try await SMBClient.withReadStream(
            host: host,
            port: port,
            share: share,
            path: path,
            range: range,
            credential: credential,
            timeout: timeout,
            onChunk: onChunk
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func download(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.download(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.downloadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.makeDirectory(host: host, port: port, share: share, path: path, credential: credential, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            data: data,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.uploadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func copy(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.copy(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.copyDirectory(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func rename(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        fromPath: String,
        toPath: String,
        replaceIfExists: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.rename(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            replaceIfExists: replaceIfExists,
            credential: credential,
            timeout: timeout
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func delete(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.delete(
            host: host,
            port: port,
            share: share,
            path: path,
            directory: directory,
            recursive: recursive,
            credential: credential,
            timeout: timeout
        )
    }
}
