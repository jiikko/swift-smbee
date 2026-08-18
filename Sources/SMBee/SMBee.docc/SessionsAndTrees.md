# Sessions and Trees

Reuse authentication while keeping each share scoped and independently closed.

An ``SMBClientSession`` owns the authenticated SMB session and its primary tree.
Its ``SMBClientSession/withTree(share:operation:)`` method temporarily connects
another share on the same authentication session. The child tree is disconnected
when the closure returns or throws, and closing the parent disconnects any tracked
child trees before logging off.

```swift
let session = try await SMBee.connect(
    host: "files.example.com",
    credential: credential,
    share: "public"
)

let publicEntries = try await session.list()
let privateEntries = try await session.withTree(share: "private") { tree in
    try await tree.list(path: "incoming")
}
let shares = try await session.listShares() // Uses a scoped IPC$ tree.

await session.close()
```

Actors serialize session and tree state. Closures and progress callbacks are
`@Sendable`; do not assume they run on the caller's executor.

Handle, tree, and session cleanup uses a bounded internal deadline. If a server does
not answer `CLOSE`, `TREE_DISCONNECT`, or `LOGOFF`, SMBee closes the transport and
invalidates the session rather than retaining an indeterminate server-side resource.
After such a cleanup failure, create a new ``SMBClientSession`` instead of reusing the
old one.

## Resolving canonical names on case-insensitive shares

Windows, macOS, and Samba shares are case-insensitive but case-preserving: opening
`report.txt` succeeds even when the stored entry is `Report.txt`. Neither
``SMBFileStat`` nor the SMB2 CREATE response carries the stored spelling, so a client
that echoes the requested path back to its callers ends up disagreeing with its own
directory listings.

``SMBClientSession/directoryEntry(matching:)`` recovers the stored spelling in a single
round trip by querying the parent directory with the leaf as the QUERY_DIRECTORY search
pattern — no full listing required.

```swift
// The share stores "Report.txt"; the caller only knows "report.txt".
let entry = try await session.directoryEntry(matching: "docs/report.txt")
entry?.name // "Report.txt"

// A pattern that matches nothing returns nil rather than throwing.
let missing = try await session.directoryEntry(matching: "docs/absent.txt")
missing // nil
```

Wildcard metacharacters in the leaf (`*`, `?`) are interpreted by the server, so the
result is filtered down to entries whose name matches the leaf exactly or
case-insensitively. Paths containing `.` or `..` components are rejected.
