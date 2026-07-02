import ArgumentParser
import Foundation
import SMBee
@testable import smbcli
import XCTest

final class SMBCLIBatchTests: XCTestCase {
    func testGlobMatchesAsterisk() {
        XCTAssertTrue(globMatches("*.log", "a.log"))
        XCTAssertFalse(globMatches("*.log", "b.txt"))
    }

    func testGlobMatchesQuestionAndCharacterClass() {
        XCTAssertTrue(globMatches("file?.[ch]", "file1.c"))
        XCTAssertTrue(globMatches("file?.[ch]", "fileA.h"))
        XCTAssertFalse(globMatches("file?.[ch]", "file10.c"))
        XCTAssertFalse(globMatches("file?.[ch]", "file1.swift"))
    }

    func testGlobMatchingIsCaseSensitiveWithDefaultFnmatchFlags() {
        XCTAssertTrue(globMatches("*.LOG", "a.LOG"))
        XCTAssertFalse(globMatches("*.LOG", "a.log"))
    }

    func testBatchGlobEntriesExcludesDirectoriesAndExcludePatterns() {
        let entries = [
            SMBDirectoryEntry(name: "a.log", fileSize: 1, isDirectory: false),
            SMBDirectoryEntry(name: "b.log", fileSize: 1, isDirectory: false),
            SMBDirectoryEntry(name: "c.txt", fileSize: 1, isDirectory: false),
            SMBDirectoryEntry(name: "logs.log", fileSize: 0, isDirectory: true),
        ]

        let files = batchGlobEntries(entries, include: "*.log", exclude: ["b.*"])

        XCTAssertEqual(files.map(\.name), ["a.log"])
    }

    func testLocalBatchGlobEntriesExcludesDirectoriesAndExcludePatterns() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        try Data("a".utf8).write(to: directory.appendingPathComponent("a.log"))
        try Data("b".utf8).write(to: directory.appendingPathComponent("b.log"))
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("nested.log"), withIntermediateDirectories: true)

        let files = try localBatchGlobEntries(directory: directory.path, include: "*.log", exclude: ["b.*"])

        XCTAssertEqual(files.map(\.name), ["a.log"])
    }

    func testMGetParsesPositionalsAndFlags() throws {
        let command = try MGet.parse([
            "smb://user@host/share/dir",
            "*.log",
            "/tmp/out",
            "--exclude",
            "debug-*",
            "--exclude",
            "*.bak",
            "--dry-run",
            "--no-overwrite",
        ])

        XCTAssertEqual(command.remoteDirectory, "smb://user@host/share/dir")
        XCTAssertEqual(command.pattern, "*.log")
        XCTAssertEqual(command.localDirectory, "/tmp/out")
        XCTAssertEqual(command.exclude, ["debug-*", "*.bak"])
        XCTAssertTrue(command.dryRun)
        XCTAssertTrue(command.noOverwrite)
    }

    func testMPutParsesPositionalsAndFlags() throws {
        let command = try MPut.parse([
            "/tmp/in",
            "file?.[ch]",
            "smb://user@host/share/dir",
            "--exclude",
            "file9.*",
            "--dry-run",
            "--no-overwrite",
        ])

        XCTAssertEqual(command.localDirectory, "/tmp/in")
        XCTAssertEqual(command.pattern, "file?.[ch]")
        XCTAssertEqual(command.remoteDirectory, "smb://user@host/share/dir")
        XCTAssertEqual(command.exclude, ["file9.*"])
        XCTAssertTrue(command.dryRun)
        XCTAssertTrue(command.noOverwrite)
    }

    func testProbeParsesServerUrlAndCommonFlags() throws {
        let command = try Probe.parse(["smb://host:1445", "--json", "--timeout", "1.25", "--debug"])

        XCTAssertEqual(command.url, "smb://host:1445")
        XCTAssertTrue(command.json)
        XCTAssertEqual(command.transport.timeout, 1.25)
        XCTAssertTrue(command.debug.debug)
    }

    func testPingParsesReadUrlAndAuth() throws {
        let command = try Ping.parse(["smb://user@host/share", "--domain", "WORK", "--timeout", "1.5"])

        XCTAssertEqual(command.url, "smb://user@host/share")
        XCTAssertEqual(command.auth.domain, "WORK")
        XCTAssertEqual(command.transport.timeout, 1.5)
    }

    func testSharesListStatDiskFreeACLAndDfsParseJsonTimeoutAndAuth() throws {
        let shares = try Shares.parse(["smb://user@host", "--domain", "WORK", "--json", "--timeout", "2"])
        XCTAssertEqual(shares.url, "smb://user@host")
        XCTAssertEqual(shares.auth.domain, "WORK")
        XCTAssertTrue(shares.json)
        XCTAssertEqual(shares.transport.timeout, 2)

        let list = try List.parse(["smb://user@host/share/dir", "--json", "--guest"])
        XCTAssertEqual(list.url, "smb://user@host/share/dir")
        XCTAssertTrue(list.json)
        XCTAssertTrue(list.auth.guest)

        let stat = try Stat.parse(["smb://user@host/share/file.txt", "--json"])
        XCTAssertEqual(stat.url, "smb://user@host/share/file.txt")
        XCTAssertTrue(stat.json)

        let readlink = try Readlink.parse(["smb://user@host/share/link", "--json", "--timeout", "3"])
        XCTAssertEqual(readlink.url, "smb://user@host/share/link")
        XCTAssertTrue(readlink.json)
        XCTAssertEqual(readlink.transport.timeout, 3)

        let df = try DiskFree.parse(["smb://user@host/share", "--json"])
        XCTAssertEqual(df.url, "smb://user@host/share")
        XCTAssertTrue(df.json)

        let acl = try ACL.parse(["smb://user@host/share/file.txt", "--json", "--resolve-sids"])
        XCTAssertEqual(acl.url, "smb://user@host/share/file.txt")
        XCTAssertTrue(acl.json)
        XCTAssertTrue(acl.resolveSids)

        let dfs = try Dfs.parse(["smb://user@host/dfsroot/link", "--json"])
        XCTAssertEqual(dfs.url, "smb://user@host/dfsroot/link")
        XCTAssertTrue(dfs.json)

        let watch = try Watch.parse(["smb://user@host/share/dir", "--recursive", "--json"])
        XCTAssertEqual(watch.url, "smb://user@host/share/dir")
        XCTAssertTrue(watch.recursive)
        XCTAssertTrue(watch.json)
    }

    func testCatGetPutMkdirMoveCopyRemoveParsePositionalsAndFlags() throws {
        let cat = try Cat.parse(["smb://user@host/share/file.txt", "--range", "2-9", "--trace-wire"])
        XCTAssertEqual(cat.url, "smb://user@host/share/file.txt")
        XCTAssertEqual(cat.range, "2-9")
        XCTAssertTrue(cat.debug.traceWire)

        let get = try Get.parse(["smb://user@host/share/dir", "/tmp/out", "--recursive", "--no-overwrite", "--progress", "--resume"])
        XCTAssertEqual(get.source, "smb://user@host/share/dir")
        XCTAssertEqual(get.destination, "/tmp/out")
        XCTAssertTrue(get.recursive)
        XCTAssertTrue(get.noOverwrite)
        XCTAssertTrue(get.progress)
        XCTAssertTrue(get.resume)

        let put = try Put.parse(["/tmp/in", "smb://user@host/share/file.txt", "--recursive", "--no-overwrite", "--progress"])
        XCTAssertEqual(put.source, "/tmp/in")
        XCTAssertEqual(put.destination, "smb://user@host/share/file.txt")
        XCTAssertTrue(put.recursive)
        XCTAssertTrue(put.noOverwrite)
        XCTAssertTrue(put.progress)

        let mkdir = try MakeDirectory.parse(["smb://user@host/share/new"])
        XCTAssertEqual(mkdir.url, "smb://user@host/share/new")

        let move = try Move.parse(["smb://user@host/share/old", "smb://user@host/share/new", "--replace"])
        XCTAssertEqual(move.source, "smb://user@host/share/old")
        XCTAssertEqual(move.destination, "smb://user@host/share/new")
        XCTAssertTrue(move.replace)

        let copy = try Copy.parse(["smb://user@host/share/source", "smb://user@host/share/destination", "--replace", "--recursive"])
        XCTAssertEqual(copy.source, "smb://user@host/share/source")
        XCTAssertEqual(copy.destination, "smb://user@host/share/destination")
        XCTAssertTrue(copy.replace)
        XCTAssertTrue(copy.recursive)

        let remove = try Remove.parse(["smb://user@host/share/dead", "--directory", "--recursive"])
        XCTAssertEqual(remove.url, "smb://user@host/share/dead")
        XCTAssertTrue(remove.directory)
        XCTAssertTrue(remove.recursive)
    }
}
