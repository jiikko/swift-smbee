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
}
