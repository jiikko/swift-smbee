# 076 refactor: 4GiB 境界 E2E の sentinel 定数の 3 箇所同期を整理する

状態: **open**
起票: 2026-07-31
関連: `Tests/SMBeeTests/SMBeeE2ETests.swift`（`testReadRangesAround4GiBBoundary` の定数） /
`bin/e2e/container-samba.sh` / `test/e2e/start-samba-ci.sh`（fixture 作成の dd 引数） /
`issues/075-perf-linux-aes-ccm-pure-swift-throughput.md`（この検証を導入した経緯）

## 問題

commit `2de6519` で導入した 4GiB 境界横断 E2E の fixture 契約が、次の 3 箇所に
手動同期のリテラルとして重複している:

1. `Tests/SMBeeTests/SMBeeE2ETests.swift` の `testReadRangesAround4GiBBoundary` 内の定数
   （`sentinelOffset` 4295016448 / `sentinel2Offset` 4295954432 は 10 進、
   `sentinelByte` 0xA5 / `sentinel2Byte` 0x5A は 16 進、`sentinelLength` 4096）
2. `bin/e2e/container-samba.sh` の `dd ... seek=1048588` / `seek=1048817`
   （seek は 4096-byte block 単位、byte 値は tr の octal `\245` / `\132`）
3. `test/e2e/start-samba-ci.sh` の同形 2 行

**壊れ方の性質は値によって異なる**（2026-07-31 codex レビューで訂正）:

- sentinel の offset / byte / length は、片側だけ変更すると点読みまたは stream 照合が
  即 fail するため、サイレントには壊れない。
- **fixture サイズ（truncate の 4296998912）は即 fail 保証の対象外**。テストのサイズ検証は
  `XCTAssertGreaterThanOrEqual` で、必要最小 4296998911 bytes 以上なら通る。Swift 側の
  4296998912 はコメントにしか存在しない。サイズだけの drift は検出されない
  （最小値を割った場合のみ fail）。

表現形式が 3 種類（Swift リテラル / dd の block seek / tr の octal）に分かれており、
変更時に換算ミスと修正往復を誘発する。

## 制約（対応案の選定時に守ること）

- **producer（fixture 生成）と test oracle（期待値）を完全に同一 spec から導出すると
  独立検証が消える**。特に第 2 sentinel は「最初の ~1MiB chunk より後の READ offset の
  wrap 検出」が存在理由だが、テストは現在「crossing range に収まること」しか assert して
  いない。生成位置と期待位置が同時に追従する形にすると、第 2 sentinel を誤って最初の
  chunk 内へ動かしても偽 green になる。テスト期待値まで共有するなら、
  `sentinel2Offset >= crossingRange.offset + 1MiB`（local read chunk cap）を独立の
  invariant として assert に追加することが前提条件。
- スクリプト共通化は host/container 境界を跨ぐ。どちらのスクリプトも fixture 作成を
  `bash -lc '...'`（single-quote 引数）でコンテナ内へ渡しており、host で source した
  関数はコンテナ内に届かない（文字列生成関数にする、bind mount して container 内で
  source する等の設計が要る）。
- CI は `start-samba-ci.sh`（fixture 作成）と Swift テスト実行が別 step・別コンテナ
  （`test/e2e/run-swift-in-container.sh` は `DOCKER_RUN_ENV` に列挙した env だけ転送）。
  env 経由で契約を渡す案は `$GITHUB_ENV` / workflow `env` / `DOCKER_RUN_ENV` の配線が必要。

## 対応方針

trigger 待ちでよい（先回りの分解はしない）: **次に sentinel 配置・fixture サイズを変更する
必要が生じた時**、または fixture を使う E2E がもう 1 本増えた時に着手する。
着手時の推奨スコープは「fixture スクリプト 2 本の生成処理の共通化」（安全に単一ソース化
できるのはここ）。テスト期待値との共有まで踏み込む場合は上記 invariant 追加を前提とする。

## 完了条件

以下のいずれか:

- fixture スクリプト 2 本の sentinel/サイズ生成が 1 箇所から導出され、
  `bin/e2e/container-samba.sh` と CI E2E の両方で `testReadRangesAround4GiBBoundary` が green。
  （テスト期待値まで共有した場合は第 2 sentinel の chunk 境界 invariant assert を含むこと）
- または「現状維持（コメント契約 + 即 fail 性質で運用）」を選び、その理由を
  コード近傍コメントに残して close する。

---

## 対応 (2026-09-08) — 完了

**選んだ道**: 完了条件の 1 つ目「fixture スクリプト 2 本の生成処理の共通化」。
テスト期待値 (Swift 側の定数) は**共有しない**ので、issue が前提条件としていた
`sentinel2Offset >= crossingRange.offset + 1MiB` の invariant 追加は不要 (下記「却下した指摘」参照)。

### やったこと

- **`test/e2e/container-init.sh` を新設**し、`bin/e2e/container-samba.sh` (Apple container / macOS) と
  `test/e2e/start-samba-ci.sh` (docker / CI) が inline で重複して持っていた container init payload
  (apt install → smb.conf 配置 → 共有/ユーザ/DFS link → **4GiB fixture** → `exec smbd`) を丸ごと移した。
  両者は `bash -lc "$(<file)"` で読む (bind mount は docker と Apple container で mount 意味論を
  二重に合わせる必要が出るため採らない)。
- 読み込みを guard: 存在・可読・非空・**行頭の実コマンドとして `exec smbd` を含む**。
  🚨 **脅威モデルは「空 / 途中で切れた / 古い断片」の検出**であって、意図的に細工した payload の
  防御ではない (ファイルを編集できる人は何でも実行できる)。この線引きは guard の直近コメントにも書いた。
- `test/e2e/start-samba-ci.sh` の repo root 解決を `${PWD}` から `SCRIPT_DIR`/`REPO_ROOT` へ直した
  (サブディレクトリから呼ぶと壊れる既存の穴)。併せて `unset CDPATH` を追加。
- **絶対パスの `SAMBA_CONFIG`** が `${REPO_ROOT}/${SAMBA_CONFIG}` で壊れる既存の穴を両スクリプトで直した
  (今回まさにその行を触ったため)。
- **Swift 側に fixture サイズの独立 assert を追加** (`XCTAssertEqual(stat.size, 4_296_998_912)`)。
  issue 本文が「fixture サイズの drift は検出されない」と書いていた穴を塞ぐ。
  期待値は **script から導出せず Swift 側に手書き**のまま = producer と oracle の独立性は保つ。
  判定は「`SMBEE_E2E_LARGE_PATH` が未設定か」ではなく「**解決された path が既定の fixture 名か**」
  (既定名を明示的に渡して size 検査を回避できてしまうため)。
- `docs/testing.md` に正本ファイルの入口を 1 行追加。

### 結果 (実測)

| 検証 | 結果 |
|---|---|
| 抽出前後の payload diff | 差分は**コメント 2 行と `mkdir` の 1 行/2 行だけ** (機能は完全一致) |
| `bash -n` / `shellcheck` (launcher 2 本) | pass |
| `swift build` / `swift test --skip SMBeeE2ETests` | **445 tests / 0 failures** |
| ローカル E2E (`bin/e2e/container-samba.sh`, Apple container) | `testReadRangesAround4GiBBoundary` **green (1 test executed)** |
| 絶対パス `SAMBA_CONFIG` での E2E | **green (1 test executed)** |
| guard: ファイル不在 / 空 / `# exec smbd` のコメントのみ | いずれも **exit 1 + 明示メッセージ** |

### ミューテーション検証 (fresh container・exact filter・1 test executed を確認)

| 変異 | 結果 |
|---|---|
| `seek=1048817` → `1048818` (第 2 sentinel の位置) | **red** (`second sentinel read did not return the fixture bytes`) |
| `truncate -s 4296998912` → `...911` (fixture サイズ) | **red** (新設した exact assert) |
| 上に加えて `SMBEE_E2E_LARGE_PATH=large-4gib-plus.bin` (既定名で opt-out を試みる) | **red** (判定を「解決 path が既定名か」に直した効果) |

### 却下した指摘とその理由 (次の監査が再生成しないため)

codex の敵対レビュー 2 lens (挙動を壊す / false green) と設計レビュー 1 本の指摘のうち、採らなかったもの:

- **`start-samba-ci.sh` を symlink / `bash <(...)` 経由で起動すると `REPO_ROOT` が `/` になる**
  — 旧 `${PWD}` からの回帰だが、config / init の存在検査で**大声で失敗する**ので誤った container は
  上がらない。symlink 解決の boilerplate より前提のコメントを残す方を選んだ (該当箇所に記載)。
- **full-read の `testReadStreamCountsFileLargerThan4GiB` は sentinel を検証しない** — 本変更以前からの
  性質。あのテストは byte 数の通し検証が目的で env gate 付き。
- **filter / skip 指定で fixture 検証なしに launcher が成功する** — E2E ハーネスの既存の性質で、
  本変更が作った穴ではない。脅威モデルは「boundary test が走ったときに drift を捕まえる」こと。
- **fixture の「全ゼロ sparse」契約より狭い範囲しか読んでいない / sparse 性が assert されていない**
  — 既存の性質。sparse は fixture 作成が安いことの理由であって検証対象ではない。
- **`smb encrypt = required` を落としても probe test は気づかない** — 本変更と無関係 (smb.conf profile の話)。
- **テスト期待値まで共有する案** — issue 本文の制約どおり採らない (producer と oracle の独立検証が消える)。
  その旨を Swift 定数の近傍コメントに書いた。

### 未確認リスク

- payload が CRLF / UTF-8 BOM で保存されると `bash -lc` 内で失敗する。現物は LF-only で、
  repo は macOS / Linux のみなのでコードは足していない。
- CI E2E (docker / Linux) での green は**未確認** (push 後に確認する)。

### 完了条件の充足

- [x] fixture スクリプト 2 本の sentinel / サイズ生成が 1 箇所から導出される
- [x] `bin/e2e/container-samba.sh` で `testReadRangesAround4GiBBoundary` が green
- [ ] CI E2E で green — **push 後に確認する**
