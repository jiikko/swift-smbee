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
- `sparse --query --json`
- `mget --json`
- `mput --json`

`stat --json` includes the server-reported `allocationSize` when available.

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
- `lock`

`sparse --query --json` emits an array of `{offset,length}` ranges. `lock` emits
the standard success object after the lock is acquired and released.

Recursive runs (`get -r` / `put -r` / `cp -r` / `rm -r`) with `--json` print
each action as newline-delimited JSON on stdout, followed by the success
object (suppressed for `--dry-run`, where the NDJSON lines are the plan):

```json
{"action":"download","path":"dir\\file.txt"}
```

Batch runs (`mget` / `mput`) with `--json` also print newline-delimited JSON:
one `{action,source,destination}` object for each downloaded, uploaded, planned,
or skipped item, followed by one summary object. The summary has
`command`, `action` (`planned`, `downloaded`, or `uploaded`), `count`,
`skipped`, `dryRun`, and `ok`. For example:

```json
{"action":"upload","source":"/tmp/in/a.txt","destination":"dir\\a.txt"}
{"command":"mput","action":"uploaded","count":1,"skipped":0,"dryRun":false,"ok":true}
```

`mget` and `mput` deliberately have no interactive confirmation prompt: this
keeps stdin usable in scripts. Use `--dry-run` to review the exact transfer
plan before running a mutating batch command; it emits the same action records
with a `planned` summary and makes no file changes.

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
