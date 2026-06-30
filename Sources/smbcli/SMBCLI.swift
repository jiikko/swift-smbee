import ArgumentParser
import Foundation
import SMBee

@main
struct SMBCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smbcli",
        abstract: "🐝 SMBee command-line client",
        version: SMBee.version,
        subcommands: [Probe.self, List.self, Stat.self, Cat.self, Get.self, MakeDirectory.self, Put.self, Copy.self, Move.self, Remove.self]
    )
}

/// `smbcli probe smb://host[:445]` — NEGOTIATE して交渉結果
/// (dialect / signing / encryption) を表示する。最初のマイルストーン。
struct Probe: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Negotiate with an SMB server and print the negotiated dialect/signing/encryption"
    )

    @Argument(help: "smb://host[:445]")
    var url: String

    func run() async throws {
        let endpoint = try SMBURLParser.parseProbeURL(url)
        let result = try await SMBProbe.probe(host: endpoint.host, port: endpoint.port)
        print("dialect: \(formatHex(result.dialect, width: 4))")
        print("signingRequired: \(result.signingRequired)")
        print("signing: \(formatOptionalHex(result.signingAlgorithm, width: 4))")
        print("cipher: \(formatOptionalHex(result.cipher, width: 4))")
        print("preauthHash: \(formatOptionalHex(result.preauthHashAlgorithm, width: 4))")
        print("serverGuid: \(result.serverGuid.uuidString)")
        print("maxTransactSize: \(result.maxTransactSize)")
        print("maxReadSize: \(result.maxReadSize)")
        print("maxWriteSize: \(result.maxWriteSize)")
    }

    private func formatOptionalHex(_ value: UInt16?, width: Int) -> String {
        guard let value else { return "none" }
        return formatHex(value, width: width)
    }

    private func formatHex<T: FixedWidthInteger>(_ value: T, width: Int) -> String {
        "0x" + String(format: "%0\(width)x", Int(value))
    }
}

struct List: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ls", abstract: "List an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        try await SMBee.withDirectoryStream(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path
        ) { entry in
            let kind = entry.isDirectory ? "d" : "-"
            print("\(kind) \(entry.fileSize) \(entry.name)")
        }
    }
}

struct Stat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "stat", abstract: "Stat an SMB path")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        let stat = try await SMBee.stat(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path
        )
        print("size: \(stat.size)")
        print("type: \(stat.isDirectory ? "directory" : "file")")
        if let modifiedTime = stat.modifiedTime {
            print("mtime: \(formatDate(modifiedTime))")
        }
    }
}

struct Cat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "cat", abstract: "Read an SMB file")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "Byte range a-b")
    var range: String?

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, auth: auth)
        // ファイル全体をメモリに lift せず streaming で stdout へ流す (大ファイル対応)。
        let stdout = FileHandle.standardOutput
        try await SMBee.withReadStream(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            range: try range.map(parseRange)
        ) { chunk in
            stdout.write(Data(chunk))
        }
    }
}

struct Get: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "get", abstract: "Download an SMB file")

    @Argument(help: "smb://user@host[:445]/share/path")
    var source: String

    @Argument(help: "Local destination file")
    var destination: String

    @Flag(help: "Fail if the destination exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively download a directory")
    var recursive = false

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        if recursive {
            try await SMBee.downloadDirectory(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localDirectory: URL(fileURLWithPath: destination),
                overwrite: !noOverwrite
            )
            return
        }
        try await SMBee.download(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            localFile: URL(fileURLWithPath: destination),
            overwrite: !noOverwrite
        )
    }
}

struct MakeDirectory: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mkdir", abstract: "Create an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await SMBee.makeDirectory(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path
        )
    }
}

struct Put: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "put", abstract: "Upload a local file to SMB")

    @Argument(help: "Local source file")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/path")
    var destination: String

    @Flag(help: "Fail if the destination exists")
    var noOverwrite = false

    @Flag(name: .shortAndLong, help: "Recursively upload a directory")
    var recursive = false

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeEndpointAndCredential(url: destination, auth: auth)
        if recursive {
            try await SMBee.uploadDirectory(
                host: endpoint.host,
                port: endpoint.port,
                credential: credential,
                share: endpoint.share,
                path: endpoint.path,
                localDirectory: URL(fileURLWithPath: source),
                overwrite: !noOverwrite
            )
            return
        }
        try await SMBee.upload(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            localFile: URL(fileURLWithPath: source),
            overwrite: !noOverwrite
        )
    }
}

struct Move: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mv", abstract: "Rename an SMB path within one share")

    @Argument(help: "smb://user@host[:445]/share/source")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/destination")
    var destination: String

    @Flag(help: "Replace destination if it exists")
    var replace = false

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (from, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        let to = try SMBURLParser.parseReadURL(destination)
        guard from.host == to.host, from.port == to.port, from.username == to.username, from.share == to.share else {
            throw ValidationError("mv source and destination must use the same user, host, port, and share")
        }
        try await SMBee.rename(
            host: from.host,
            port: from.port,
            credential: credential,
            share: from.share,
            fromPath: from.path,
            toPath: to.path,
            replaceIfExists: replace
        )
    }
}

struct Copy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "cp", abstract: "Copy an SMB path within one share")

    @Argument(help: "smb://user@host[:445]/share/source")
    var source: String

    @Argument(help: "smb://user@host[:445]/share/destination")
    var destination: String

    @Flag(help: "Replace destination if it exists")
    var replace = false

    @Flag(name: .shortAndLong, help: "Recursively copy a directory")
    var recursive = false

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (from, credential) = try makeEndpointAndCredential(url: source, auth: auth)
        let to = try SMBURLParser.parseReadURL(destination)
        guard from.host == to.host, from.port == to.port, from.username == to.username, from.share == to.share else {
            throw ValidationError("cp source and destination must use the same user, host, port, and share")
        }
        if recursive {
            try await SMBee.copyDirectory(
                host: from.host,
                port: from.port,
                credential: credential,
                share: from.share,
                fromPath: from.path,
                toPath: to.path,
                overwrite: replace
            )
            return
        }
        try await SMBee.copy(
            host: from.host,
            port: from.port,
            credential: credential,
            share: from.share,
            fromPath: from.path,
            toPath: to.path,
            overwrite: replace
        )
    }
}

struct Remove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "rm", abstract: "Delete an SMB file or empty directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Flag(help: "Open the target as a directory")
    var directory = false

    @Flag(name: .shortAndLong, help: "Recursively delete a non-empty directory")
    var recursive = false

    @OptionGroup
    var auth: AuthOptions

    func run() async throws {
        let (endpoint, credential) = try makeEndpointAndCredential(url: url, auth: auth)
        try await SMBee.delete(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            directory: directory || recursive,
            recursive: recursive
        )
    }
}

struct AuthOptions: ParsableArguments {
    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    @Option(help: "NT hash as 32 hexadecimal characters")
    var ntHash: String?

    @Flag(help: "Read password from standard input")
    var passwordStdin = false
}

private func makeReadEndpointAndCredential(url: String, auth: AuthOptions) throws -> (SMBURLParser.ReadURL, SMBCredential) {
    try makeEndpointAndCredential(url: url, auth: auth)
}

private func makeEndpointAndCredential(url: String, auth: AuthOptions) throws -> (SMBURLParser.ReadURL, SMBCredential) {
    let endpoint = try SMBURLParser.parseReadURL(url)
    guard let username = endpoint.username, !username.isEmpty else {
        throw ValidationError("SMB URL must include a username")
    }
    if let ntHash = try readNTHash(options: auth) {
        guard endpoint.password == nil, !auth.passwordStdin, ProcessInfo.processInfo.environment["SMB_PASSWORD"] == nil else {
            throw ValidationError("Use either an NT hash or a password, not both")
        }
        return (endpoint, try SMBCredential(username: username, ntHash: ntHash, domain: auth.domain))
    }
    guard let password = try endpoint.password ?? readPassword(options: auth) else {
        throw ValidationError("Set SMB_PASSWORD, SMB_NT_HASH, pass --password-stdin/--nt-hash, or include a password in the SMB URL")
    }
    return (endpoint, SMBCredential(username: username, password: password, domain: auth.domain))
}

private func readNTHash(options: AuthOptions) throws -> [UInt8]? {
    guard let value = options.ntHash ?? ProcessInfo.processInfo.environment["SMB_NT_HASH"] else {
        return nil
    }
    return try parseNTHash(value)
}

private func readPassword(options: AuthOptions) throws -> String? {
    if options.passwordStdin {
        guard let password = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) else {
            throw ValidationError("Password from stdin must be valid UTF-8")
        }
        return password.trimmingCharacters(in: CharacterSet(charactersIn: "\r\n"))
    }
    return ProcessInfo.processInfo.environment["SMB_PASSWORD"]
}

private func parseNTHash(_ value: String) throws -> [UInt8] {
    let hex = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard hex.count == 32 else {
        throw ValidationError("NT hash must be 32 hexadecimal characters")
    }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(16)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw ValidationError("NT hash must contain only hexadecimal characters")
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

private func parseRange(_ value: String) throws -> SMBReadRange {
    let parts = value.split(separator: "-", omittingEmptySubsequences: false)
    guard parts.count == 2,
          let start = UInt64(parts[0]),
          let end = UInt64(parts[1]),
          end >= start else {
        throw ValidationError("Range must be in a-b form with b >= a")
    }
    return SMBReadRange(offset: start, length: end - start + 1)
}

private func formatDate(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}
