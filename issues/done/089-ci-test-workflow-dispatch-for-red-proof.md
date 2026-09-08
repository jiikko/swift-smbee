# 089 ci: test.yml に workflow_dispatch を足して「赤の実証」に意図的な赤 commit を使わないようにする

- 種別: ci
- 起票: 2026-09-08 (retro [`084`](084-retro-audit-analyzer-rules-2026-08-27.md) 項目 5 の切り出し)
- 状態: **open**
- 関連: `.github/workflows/test.yml` / `.github/workflows/wire-stress-e2e.yml` (`workflow_dispatch` の先例) /
  [`083`](083-ci-swiftlint-analyzer-unused-declaration.md)

## 問題

新設した検査が **CI で本当に落ちるか**を実証するには、その検査が守っている修正を revert して
CI を赤にして見せる必要がある (グローバルルール `verify-execution-not-just-exit-code.md` の
「新設した検査が CI で走っているか、同じ commit で確認する」)。

2026-08-27 の issue 083 (swiftlint analyzer rules) では、この実証を
**master に意図的な赤 commit を積む**形で行った (ユーザー選択)。履歴に
`0cfccc9 test(ci): [意図的に赤] issue 082 の削除を一時 revert して swiftlint analyze の red を実証する` が残る。

赤 commit を master に積むと:

- `git bisect` / `git log` を読む人が「本当に壊れていた時期」と区別できない。
- 直後の revert commit とペアで読まないと意味が取れない。
- 連続 push になるため、`cancel-in-progress` で前の run が消える
  (CLAUDE.md「push後のCI確認」の注記の原因でもある)。

## 対応案

`.github/workflows/test.yml` に `workflow_dispatch` を足す (`ref` を指定して任意の commit / branch で
起動できるようにする)。`wire-stress-e2e.yml:5-6` が既に `workflow_dispatch` を持っているので同形でよい。

これで「赤の実証」は次の形になる:

1. 実証用の変更をローカルの一時ブランチに commit して push (master には積まない)。
2. `gh workflow run test.yml --ref <その branch>` で起動し、赤を確認して run URL を issue に残す。
3. ブランチを削除する。

## 完了条件

- `test.yml` に `workflow_dispatch` があり、**master 以外の ref を指定して起動できることを 1 回実際に確認**する
  (起動して run URL を残す。設定を足しただけでは「起動できる」の証拠にならない)。
- 「赤の実証」の手順を CLAUDE.md か `docs/testing.md` のどちらかに 1 行足す
  (道具を足したら入口も更新する)。

## スコープ外

- 他の workflow (`e2e.yml` / `performance.yml`) への `workflow_dispatch` 追加。
  必要になった時点で同じ形を足す。

## 対応 (2026-09-08) — 実装済み / dispatch の実測待ち

### 変更

| ファイル | 変更 |
|---|---|
| `.github/workflows/test.yml` | `on:` に `workflow_dispatch:` を追加 (`concurrency` は変更なし) |
| `docs/testing.md` | 「Test workflow の手動起動（red の実証）」節を追加 |

### 実測 (変更前・2026-09-08)

```
$ gh workflow run test.yml --ref master
rc=1
stderr: could not create workflow dispatch event: HTTP 422:
        Workflow does not have 'workflow_dispatch' trigger
```

この 422 が「変更前は trigger が live でない」ことの証拠。push 後に同じコマンドが通ることを
確認して、両側で挟む。

### 完了条件の変更 (スコープの縮小・明示)

起票時の完了条件は「**master 以外の ref** を指定して起動できることを 1 回実際に確認」だったが、
これは**一時ブランチの新規作成**を要求する。ブランチ作成はユーザーの領分
(グローバルルール `no-unauthorized-branch-switch.md`) なので、次の形に縮める:

- master への dispatch が起動できることを実測する (run URL を残す)。
- **既存の** remote branch (`agent/issues-018-029` / `claude/kerberos-finder-auth-5pjrgn` /
  `copilot/update-node-version` / `feature/smbclient-backlog`) を `--ref` に指定して、
  非 master ref への dispatch の可否を実測して記録する。ブランチは作らない。
- 実際の「赤の実証」でブランチが要るときは、その時点でユーザーに確認する。

### 設計判断: `concurrency` は触らない

master へ dispatch すると `concurrency: test-${{ github.ref }}` により進行中の push run を
cancel する。しかし red-proof の想定利用は**非 master ref への dispatch** なので、この衝突は
通常発火しない。`group` に `github.event_name` を足す変更は入れず、caveat を doc に 1 行書くに留めた。

### 残タスク

- [ ] push 後に `gh workflow run test.yml --ref master` の rc/stdout/stderr を分けて実測し run URL を記録
- [ ] 既存 remote branch への dispatch 可否を実測し、制約が判明したら `docs/testing.md` に追記

### 実測 (2026-09-08・push 後)

stdout / stderr / rc を分けて採った。

| ref | rc | stderr |
|---|---:|---|
| `master` | **0** | (なし) |
| `feature/smbclient-backlog` (既存 branch) | 1 | `HTTP 422: Workflow does not have 'workflow_dispatch' trigger` |

- 起動した run: https://github.com/jiikko/swift-smbee/actions/runs/34195579546 (master / `2bb7c598`)
  — **conclusion=success で完走**した (起動できただけでなく、dispatch 経由の run が通ることまで確認)。
- 変更前の master は同じ 422 で拒否されていたので、**前後で挟んで trigger が live になったことを確認**した。

**判明した制約 (docs/testing.md に反映済み)**: `--ref` に指定する **ref 側の `test.yml` にも
`workflow_dispatch` が要る**。trigger の登録は default branch にある必要があるが、実行されるのは
指定 ref のファイルなので、両方に無いと拒否される。したがって赤の実証用のブランチは
**`workflow_dispatch` を持つ master から切る**必要がある (今後は満たされる)。

### 完了条件の達成状況

- [x] `test.yml` に `workflow_dispatch` があり、**起動できることを実際に確認**した (run URL 上記)
- [x] 非 master ref への dispatch 可否を実測し、制約を `docs/testing.md` に記録した
- [x] 「赤の実証」の手順を `docs/testing.md` に足した

状態: **done**
