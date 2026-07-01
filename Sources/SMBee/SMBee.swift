import Foundation

/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、暗号プリミティブの計算は swift-crypto と in-repo pure-Swift 実装に委ねる。
/// 対象サーバは SMB 3.x サーバ (macOS SMBX / Windows SMB Server / Samba)。
/// 自動 E2E は Samba、手動 smoke は実サーバで確認する。
// swiftlint:disable:next type_body_length
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

    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider
    ) async throws -> [SMBShareInfo] {
        try await SMBClient.listShares(host: host, port: port, credentialProvider: credentialProvider)
    }

    /// Resolve a DFS namespace path to referral targets. This returns referral
    /// metadata only; reconnecting to a target and rewriting paths is left to callers.
    ///
    /// - Parameter path: DFS path in `\\host\dfsroot\link` form.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func dfsReferral(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBDfsReferralResult {
        try await SMBClient.dfsReferral(host: host, port: port, credential: credential, path: path, timeout: timeout)
    }

    /// Resolve a DFS namespace path to referral targets. This returns referral
    /// metadata only; reconnecting to a target and rewriting paths is left to callers.
    public static func dfsReferral(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        path: String
    ) async throws -> SMBDfsReferralResult {
        try await SMBClient.dfsReferral(host: host, port: port, credentialProvider: credentialProvider, path: path)
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

    public static func list(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String = ""
    ) async throws -> [SMBDirectoryEntry] {
        try await SMBClient.list(host: host, port: port, share: share, path: path, credentialProvider: credentialProvider)
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

    public static func withDirectoryStream(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String = "",
        onEntry: @escaping @Sendable (SMBDirectoryEntry) async throws -> Void
    ) async throws {
        try await SMBClient.withDirectoryStream(
            host: host,
            port: port,
            share: share,
            path: path,
            credentialProvider: credentialProvider,
            onEntry: onEntry
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall watch deadline.
    public static func withChangeNotifications(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String = "",
        filter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        timeout: Duration? = nil,
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        try await SMBClient.withChangeNotifications(
            host: host,
            port: port,
            share: share,
            path: path,
            filter: filter,
            watchTree: watchTree,
            credential: credential,
            timeout: timeout,
            onChange: onChange
        )
    }

    public static func withChangeNotifications(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String = "",
        filter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        onChange: @escaping @Sendable (SMBChangeNotifyEvent) async throws -> Void
    ) async throws {
        try await SMBClient.withChangeNotifications(
            host: host,
            port: port,
            share: share,
            path: path,
            filter: filter,
            watchTree: watchTree,
            credentialProvider: credentialProvider,
            onChange: onChange
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

    public static func stat(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String
    ) async throws -> SMBFileStat {
        try await SMBClient.stat(host: host, port: port, share: share, path: path, credentialProvider: credentialProvider)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func securityInfo(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBSecurityInfo {
        try await SMBClient.securityInfo(host: host, port: port, share: share, path: path, credential: credential, timeout: timeout)
    }

    public static func securityInfo(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBSecurityInfo {
        try await SMBClient.securityInfo(host: host, port: port, share: share, path: path, credentialProvider: credentialProvider, timeout: timeout)
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func volumeInfo(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        timeout: Duration? = nil
    ) async throws -> SMBVolumeInfo {
        try await SMBClient.volumeInfo(host: host, port: port, share: share, credential: credential, timeout: timeout)
    }

    public static func volumeInfo(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String
    ) async throws -> SMBVolumeInfo {
        try await SMBClient.volumeInfo(host: host, port: port, share: share, credentialProvider: credentialProvider)
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

    public static func updateMetadata(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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
        timeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        try await SMBClient.read(host: host, port: port, share: share, path: path, range: range, credential: credential, timeout: timeout, onProgress: onProgress)
    }

    public static func read(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        range: SMBReadRange? = nil
    ) async throws -> [UInt8] {
        try await SMBClient.read(
            host: host,
            port: port,
            share: share,
            path: path,
            range: range,
            credentialProvider: credentialProvider
        )
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
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil,
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
            onProgress: onProgress,
            onChunk: onChunk
        )
    }

    public static func withReadStream(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider,
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
        timeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.download(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout,
            onProgress: onProgress
        )
    }

    public static func download(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String
    ) async throws {
        try await SMBClient.makeDirectory(host: host, port: port, share: share, path: path, credentialProvider: credentialProvider)
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
        timeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            data: data,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout,
            onProgress: onProgress
        )
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func upload(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        fileURL: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            fileURL: fileURL,
            overwrite: overwrite,
            credential: credential,
            timeout: timeout,
            onProgress: onProgress
        )
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        fileURL: URL,
        overwrite: Bool = true,
        timeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            fileURL: fileURL,
            overwrite: overwrite,
            credential: try await credentialProvider(),
            timeout: timeout,
            onProgress: onProgress
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

    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func upload(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func copy(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func rename(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
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

    public static func delete(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
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
            credentialProvider: credentialProvider
        )
    }
}
