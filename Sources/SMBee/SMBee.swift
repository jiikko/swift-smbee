import Foundation

// swiftlint:disable file_length type_body_length
/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、暗号プリミティブの計算はCommonCrypto、swift-crypto、検証用pure-Swift実装に委ねる。
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
        credentialProvider: @escaping SMBCredentialProvider,
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

    /// Resolve SIDs to account names over `IPC$` + `lsarpc` (MS-LSAT LsarLookupSids).
    /// The result matches `sids` positionally; unmapped SIDs are nil.
    public static func lookupSIDs(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        sids: [String],
        timeout: Duration? = nil
    ) async throws -> [SMBResolvedSIDName?] {
        try await SMBClient.lookupSIDs(host: host, port: port, sids: sids, credential: credential, timeout: timeout)
    }

    /// Send an authenticated SMB2 ECHO and return when the server replies.
    ///
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func echo(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.echo(host: host, port: port, share: share, credential: credential, timeout: timeout)
    }

    /// Send an authenticated SMB2 ECHO and return when the server replies.
    public static func echo(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String
    ) async throws {
        try await SMBClient.echo(host: host, port: port, share: share, credentialProvider: credentialProvider)
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

    /// Resolve a DFS path and connect to its first referral target with the same credential.
    /// This follows one namespace hop; use `dfsReferral` for custom target selection.
    public static func connectFollowingDFS(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBClientSession {
        try await SMBClient.connectFollowingDFS(
            host: host, port: port, credential: credential, path: path, timeout: timeout
        )
    }

    public static func resolveDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        timeout: Duration? = nil, maxHops: Int = 8
    ) async throws -> SMBDfsResolvedPath {
        try await SMBClient.resolveDFS(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, maxHops: maxHops
        )
    }

    public static func listFollowingDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        timeout: Duration? = nil, maxHops: Int = 8
    ) async throws -> [SMBDirectoryEntry] {
        try await SMBClient.listFollowingDFS(
            host: host, port: port, credential: credential, path: path,
            timeout: timeout, maxHops: maxHops
        )
    }

    public static func readFollowingDFS(
        host: String, port: UInt16 = 445, credential: SMBCredential, path: String,
        range: SMBReadRange? = nil, timeout: Duration? = nil, maxHops: Int = 8
    ) async throws -> [UInt8] {
        try await SMBClient.readFollowingDFS(
            host: host, port: port, credential: credential, path: path,
            range: range, timeout: timeout, maxHops: maxHops
        )
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

    /// Read reparse point target data without following the target.
    ///
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func readlink(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        timeout: Duration? = nil
    ) async throws -> SMBReparsePoint {
        try await SMBClient.readlink(host: host, port: port, share: share, path: path, credential: credential, timeout: timeout)
    }

    /// Read reparse point target data without following the target.
    public static func readlink(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String
    ) async throws -> SMBReparsePoint {
        try await SMBClient.readlink(host: host, port: port, share: share, path: path, credentialProvider: credentialProvider)
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

    /// Writes the file's DACL (read-modify-write: owner/group are preserved). A structural
    /// lockout guard rejects an empty or deny-only DACL unless `force` is set.
    ///
    /// - Note: The server may normalize the requested access masks. Samba (POSIX-ACL backed)
    ///   maps NT masks to its canonical representation (e.g. a requested `0x00020000` reads back
    ///   as `0x00120089`), so the round-trip is not guaranteed to be mask-exact.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        dacl: [SMBAccessControlEntry],
        force: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.setSecurityInfo(host: host, port: port, share: share, path: path, dacl: dacl, force: force, credential: credential, timeout: timeout)
    }

    /// Write the provided security descriptor components: non-nil owner/group/DACL are set,
    /// nil components are left untouched. Owner/group writes require WRITE_OWNER access;
    /// setting the caller's own SID is the portable case (arbitrary owners need privilege).
    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool = false,
        credential: SMBCredential,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.setSecurityInfo(
            host: host,
            port: port,
            share: share,
            path: path,
            ownerSID: ownerSID,
            groupSID: groupSID,
            dacl: dacl,
            force: force,
            credential: credential,
            timeout: timeout
        )
    }

    public static func setSecurityInfo(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        dacl: [SMBAccessControlEntry],
        force: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.setSecurityInfo(host: host, port: port, share: share, path: path, dacl: dacl, force: force, credentialProvider: credentialProvider, timeout: timeout)
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
        operationTimeout: Duration? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws -> [UInt8] {
        try await SMBClient.read(host: host, port: port, share: share, path: path, range: range, credential: credential, timeout: timeout, operationTimeout: operationTimeout, onProgress: onProgress)
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
        resume: Bool = false,
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
            resume: resume,
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
        overwrite: Bool = true,
        resume: Bool = false
    ) async throws {
        try await SMBClient.download(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            resume: resume,
            credentialProvider: credentialProvider
        )
    }

    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    /// - Parameter atomic: When true, downloads into a hidden sibling staging directory and moves/replaces the
    ///   final destination after the full tree succeeds. This is best-effort local atomicity only: the final
    ///   move/replace is not transactional across filesystems or crashes. `dryRun` creates no staging directory,
    ///   and `skipExisting` and `resume` are ignored because atomic downloads always build a fresh staged tree.
    /// - Parameter resume: When true and `atomic` is false, skips files whose destination size already matches
    ///   the source size. Missing or size-mismatched files are transferred with overwrite enabled. If both
    ///   `resume` and `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not
    ///   byte-level partial-file resume.
    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        atomic: Bool = false,
        timeout: Duration? = nil,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.downloadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            atomic: atomic,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: credential,
            timeout: timeout,
            onAction: onAction,
            onProgress: onProgress
        )
    }

    /// - Parameter atomic: When true, downloads into a hidden sibling staging directory and moves/replaces the
    ///   final destination after the full tree succeeds. This is best-effort local atomicity only: the final
    ///   move/replace is not transactional across filesystems or crashes. `dryRun` creates no staging directory,
    ///   and `skipExisting` and `resume` are ignored because atomic downloads always build a fresh staged tree.
    /// - Parameter resume: When true and `atomic` is false, skips files whose destination size already matches
    ///   the source size. Missing or size-mismatched files are transferred with overwrite enabled. If both
    ///   `resume` and `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not
    ///   byte-level partial-file resume.
    public static func downloadDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        atomic: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.downloadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            atomic: atomic,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credentialProvider: credentialProvider,
            onAction: onAction,
            onProgress: onProgress
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
        resume: Bool = false,
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
            resume: resume,
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
        resume: Bool = false,
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
            resume: resume,
            credential: try await credentialProvider(),
            timeout: timeout,
            onProgress: onProgress
        )
    }

    /// - Parameter resume: When true, skips files whose remote destination size already matches the local source
    ///   size. Missing or size-mismatched files are uploaded with overwrite enabled. If both `resume` and
    ///   `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not byte-level
    ///   partial-file resume.
    /// - Parameter timeout: Socket-level timeout for connect and each recv/send I/O. This is not an overall operation deadline.
    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        credential: SMBCredential,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        timeout: Duration? = nil,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.uploadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: credential,
            timeout: timeout,
            onAction: onAction,
            onProgress: onProgress
        )
    }

    /// - Parameter resume: When true, skips files whose remote destination size already matches the local source
    ///   size. Missing or size-mismatched files are uploaded with overwrite enabled. If both `resume` and
    ///   `skipExisting` are true, `resume` takes precedence. This is size-based skip only, not byte-level
    ///   partial-file resume.
    public static func uploadDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        localDirectory: URL,
        overwrite: Bool = true,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        resume: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil,
        onProgress: (@Sendable (SMBTransferProgress) -> Void)? = nil
    ) async throws {
        try await SMBClient.uploadDirectory(
            host: host,
            port: port,
            share: share,
            path: path,
            localDirectory: localDirectory,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            resume: resume,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credentialProvider: credentialProvider,
            onAction: onAction,
            onProgress: onProgress
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
        resume: Bool = false,
        timeout: Duration? = nil
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            resume: resume,
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
        overwrite: Bool = true,
        resume: Bool = false
    ) async throws {
        try await SMBClient.upload(
            host: host,
            port: port,
            share: share,
            path: path,
            localFile: localFile,
            overwrite: overwrite,
            resume: resume,
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
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        timeout: Duration? = nil,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await SMBClient.copyDirectory(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credential: credential,
            timeout: timeout,
            onAction: onAction
        )
    }

    public static func copyDirectory(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        fromPath: String,
        toPath: String,
        overwrite: Bool = false,
        continueOnError: Bool = false,
        skipExisting: Bool = false,
        dryRun: Bool = false,
        include: [String] = [],
        exclude: [String] = [],
        perFileTimeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await SMBClient.copyDirectory(
            host: host,
            port: port,
            share: share,
            fromPath: fromPath,
            toPath: toPath,
            overwrite: overwrite,
            continueOnError: continueOnError,
            skipExisting: skipExisting,
            dryRun: dryRun,
            include: include,
            exclude: exclude,
            perFileTimeout: perFileTimeout,
            credentialProvider: credentialProvider,
            onAction: onAction
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
        continueOnError: Bool = false,
        dryRun: Bool = false,
        timeout: Duration? = nil,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await SMBClient.delete(
            host: host,
            port: port,
            share: share,
            path: path,
            directory: directory,
            recursive: recursive,
            continueOnError: continueOnError,
            dryRun: dryRun,
            credential: credential,
            timeout: timeout,
            onAction: onAction
        )
    }

    public static func delete(
        host: String,
        port: UInt16 = 445,
        credentialProvider: SMBCredentialProvider,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        continueOnError: Bool = false,
        dryRun: Bool = false,
        onAction: (@Sendable (SMBRecursiveAction) -> Void)? = nil
    ) async throws {
        try await SMBClient.delete(
            host: host,
            port: port,
            share: share,
            path: path,
            directory: directory,
            recursive: recursive,
            continueOnError: continueOnError,
            dryRun: dryRun,
            credentialProvider: credentialProvider,
            onAction: onAction
        )
    }
}
