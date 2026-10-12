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
`@Sendable`; do not assume they run on the caller's executor. Callback placement,
blocking behavior, and the progress-queue exception are described in
``Callbacks``.

## Watch directories with CHANGE_NOTIFY

`withChangeNotifications` uses a long-poll request: the server may leave it pending
until a change occurs. A finite receive timeout on the default POSIX transport still
applies while SMBee waits for that response. If the connection receives no data before
the timeout (including no `STATUS_PENDING` interim response), the receive fails and
the session is closed. Other operations sharing that session fail with it. The
per-request `requestTimeout` does not bound CHANGE_NOTIFY; long-poll requests are
excluded from that timer.

The public `timeout:` argument configures the transport only when SMBee creates the
default transport. That default is `POSIXSocketTransport` on both macOS and Linux, and
its receive timeout uses the socket's `SO_RCVTIMEO`. If you pass `makeTransport`, that
factory takes precedence and `timeout:` is not passed to it. `NWConnectionTransport`
does not have a receive timeout, while a custom factory can create a POSIX transport
with a finite timeout even when the API's `timeout:` is `nil`.

Keep a watch on a dedicated session with `timeout: nil`, separate from the session used
for ordinary work. Ordinary requests on their own session remain bounded by the default
`requestTimeout` of 60 seconds unless you set it to `nil`.

```swift
let watchSession = try await SMBee.connect(
    host: "files.example.com",
    credential: credential,
    share: "public",
    timeout: nil
)
let workSession = try await SMBee.connect(
    host: "files.example.com",
    credential: credential,
    share: "public"
)

let watchTask = Task {
    try await watchSession.withChangeNotifications(path: "reports") { event in
        if event.requiresRescan {
            // Reconcile the directory contents.
        }
    }
}
let entries = try await workSession.list(path: "reports")
watchTask.cancel()
```

File and scoped Tree cleanup has a soft deadline and a finite hard deadline. The default
soft budget is five seconds; the hard grace is at most sixty seconds and is shortened by
`requestTimeout` when configured. If a cleanup request is still waiting for credit or a
send slot at the soft deadline, SMBee retires it without allocating a MessageId. If the
request was fully sent, the caller receives a timeout while SMBee drains its response
until the fixed hard deadline. A missing response before that hard deadline does not by
itself close the shared transport. Reaching the hard deadline with an unfinished wire
drain does close the session. Explicit session close still performs terminal teardown.

`withTree` reports a scoped cleanup failure when its body succeeded. When both the body
and cleanup fail, it preserves the body error. A ``SMBError/treeUnavailable(treeId:operation:)``
means that the selected Tree is closing or retired; it does not invalidate other Trees on
the shared session and does not trigger automatic reconnect. If `close()` is called from
inside a callback that holds an active operation lease, it starts cleanup and returns
without waiting for that cleanup; calls outside such callbacks wait for the shared cleanup
to finish.

## Resolving canonical names on case-insensitive shares

Windows, macOS, and Samba shares are case-insensitive but case-preserving: opening
`report.txt` succeeds even when the stored entry is `Report.txt`. Neither
``SMBFileStat`` nor the SMB2 CREATE response carries the stored spelling, so a client
that echoes the requested path back to its callers ends up disagreeing with its own
directory listings.

``SMBClientSession/directoryEntry(matching:)`` recovers the stored spelling with a single
QUERY_DIRECTORY against the parent directory, using the leaf as the search pattern — no
full listing required. (The call still opens and closes the parent handle, so it costs
the same three commands as a plain `stat`.)

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
