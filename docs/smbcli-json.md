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

## Compatibility and update policy

JSON and NDJSON described in this document are a source-level CLI contract for the
0.x series. There is no numeric `schemaVersion` field: record kinds already have stable
discriminators (`event`, `action`, or `command`), and adding a version field to every
existing object would itself change consumers' exact-shape expectations.

Within 0.x:

- existing keys, value types, and NDJSON record order are not removed or renamed;
- new optional keys or new discriminator values may be added;
- consumers should ignore unknown keys and handle unknown discriminator values;
- a required-key or type change needs a documented migration and a release note;
- human-readable text in `error` is diagnostic and must not be parsed as a stable enum.

Every JSON output change updates these items in the same commit:

1. the encoder or CLI emission site;
2. an exact-shape unit regression in `SMBCLIOutputTests`, `SMBCLIHelperTests`, or
   `SMBCLIBatchTests`;
3. this document, including NDJSON ordering when applicable;
4. the relevant Samba CLI smoke assertion for externally visible command output.

This checklist is the schema-change gate until a separately versioned schema is needed.
