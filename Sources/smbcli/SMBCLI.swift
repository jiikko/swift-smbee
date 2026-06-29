import ArgumentParser
import Foundation
import SMBee

@main
struct SMBCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smbcli",
        abstract: "🐝 SMBee command-line client",
        version: SMBee.version,
        subcommands: [Probe.self, List.self, Stat.self, Cat.self]
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

    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, domain: domain)
        let entries = try await SMBee.list(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path
        )
        for entry in entries {
            let kind = entry.isDirectory ? "d" : "-"
            print("\(kind) \(entry.fileSize) \(entry.name)")
        }
    }
}

struct Stat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "stat", abstract: "Stat an SMB path")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, domain: domain)
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

    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    func run() async throws {
        let (endpoint, credential) = try makeReadEndpointAndCredential(url: url, domain: domain)
        let data = try await SMBee.read(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path,
            range: try range.map(parseRange)
        )
        FileHandle.standardOutput.write(Data(data))
    }
}

private func makeReadEndpointAndCredential(url: String, domain: String) throws -> (SMBURLParser.ReadURL, SMBCredential) {
    let endpoint = try SMBURLParser.parseReadURL(url)
    guard let username = endpoint.username, !username.isEmpty else {
        throw ValidationError("SMB URL must include a username")
    }
    guard let password = ProcessInfo.processInfo.environment["SMB_PASSWORD"] else {
        throw ValidationError("Set SMB_PASSWORD in the environment")
    }
    return (endpoint, SMBCredential(username: username, password: password, domain: domain))
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
