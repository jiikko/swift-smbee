# smbcli JSON output

`smbcli` keeps stdout machine-readable when `--json` is supported. Diagnostics
and progress remain on stderr unless a command documents otherwise. With
`--json`, errors are emitted to stderr as a structured JSON object before the
process exits with the same non-zero exit code.

Commands with stable JSON output:

- `probe --json`
- `ls --json`
- `shares --json`
- `stat --json`
- `readlink --json`
- `df --json`
- `acl --json`
- `dfs --json`
- `watch --json`

`watch --json` prints newline-delimited JSON. Each line is either a `changes`
event with file change entries or an `overflow` event with `rescanRequired`.

Mutating commands with stable success JSON output:

- `mkdir`
- `put`
- `get`
- `cp`
- `mv`
- `rm`
- `setacl`

Recursive runs (`get -r` / `put -r` / `cp -r` / `rm -r`) with `--json` print
each action as newline-delimited JSON on stdout, followed by the success
object (suppressed for `--dry-run`, where the NDJSON lines are the plan):

```json
{"action":"download","path":"dir\\file.txt"}
```

Success output shape:

```json
{"command":"put","ok":true,"path":"dir\\file.txt"}
```

Error output shape:

```json
{"category":"smb","error":"notFound(status: 3221225524, operation: \"CREATE\")","exitCode":4,"ok":false}
```

`category` is `smb`, `usage`, or `other`. `exitCode` matches the process exit
status.
