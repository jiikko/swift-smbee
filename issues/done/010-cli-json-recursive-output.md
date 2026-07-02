# smbcli `--json` × recursive 出力の汚染・欠落

- 種別: bug (CLI machine-readable output)
- 発見: 2026-07-03 サブエージェントレビュー → main agent で code 裏取り済み。codex レビューは usage limit のため未実施 (要: 後日 codex-review)

## 症状

1. `writeRecursiveAction` (`Sources/smbcli/SMBCLI.swift` の `func writeRecursiveAction`) は
   `--json` 指定に関係なく plain-text の action 行 (`download <path>` 等) を **stdout** に書く。
   `cp -r --json` は最後に JSON success object を出すが、stdout は text/JSON 混在になり
   機械 parse が壊れる。
2. `get -r --json` / `put -r --json` の recursive 分岐は JSON success object を**一切出さずに
   return する**（非 recursive 分岐と `cp -r` は出す）。フラグが黙って無視される。
3. `--continue-on-error` の部分失敗は最後に `recursiveOperationIncomplete` を throw するが、
   (2) と合わせると recursive get/put の JSON consumer には成功/部分失敗の安定 signal が無い。

## 対応 (2026-07-03 完了)

- `--json` 時は recursive action 行を NDJSON (`{"action":...,"path":...}`) として stdout に出力
  (`recursiveActionLine`)。`watch --json` と同じ NDJSON 方針。
- `get -r --json` / `put -r --json` も成功時に success object を出す (`cp -r` と同一)。
  dry-run では NDJSON の plan のみで success object は出さない。
- 部分失敗 (`--continue-on-error`) は既存の structured stderr error object + exit code が signal。
- `docs/smbcli-json.md` 更新、unit (`testRecursiveActionLineFormats`) 追加。
- なお `--resume`×`--skip-existing` 等のフラグ相互作用ガードは対象外のまま (必要なら別 issue)。

## 対応方針（案・当初）

- `--json` 時は action 行を stderr へ逃がすか、`watch --json` と同様 NDJSON
  (`{"action":"download","path":...}`) として stdout に統一する。docs/smbcli-json.md の
  「mutating command は exit status を安定 signal とする」方針との整合を先に決める。
- recursive get/put にも `cp -r` と同じ成功 object を出す。
- 部分失敗時は `ok=false` の structured stderr object（既存の error 出力形式）に
  failures の件数を含める。

## 関連

- `docs/smbcli-json.md` / todo2 P2-5 (CLI JSON parity)
- `--resume` + `--skip-existing` / `--no-overwrite` + `--resume` のフラグ相互作用に
  ValidationError ガードが無い点も同じ CLI surface の整理対象（`--verify`+`--dry-run` には
  ガードがある）。
