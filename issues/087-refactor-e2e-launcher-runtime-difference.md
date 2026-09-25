# 087 refactor: E2E launcher 2 本に残った重複を runtime 固有部分だけに切り詰める

- 種別: refactor (予防的。現時点で failing なものは無い)
- 起票: 2026-09-08
- 状態: **open / trigger 待ち**
- 関連: [`done/076`](done/076-refactor-e2e-sentinel-constants-single-source.md) (container init の単一ソース化。本 issue の発端であり、
  「host/container 境界を跨ぐ共通化の難しさ」の整理もここにある) /
  `bin/e2e/container-samba.sh` (Apple container / macOS) / `test/e2e/start-samba-ci.sh` (docker / CI) /
  `test/e2e/container-init.sh` (076 で作った共通 init) / `bin/ci/test-performance-scripts` (shell test の先例)

## 問題

issue 076 で **container 内で実行される init 本文**は 1 箇所 (`test/e2e/container-init.sh`) に寄せた。
しかし **host 側の launcher 2 本**には重複が残っている。

### 同一実装 (一字一句同じ)

**実測 (2026-09-08)**: `bin/e2e/container-samba.sh:43-67` と `test/e2e/start-samba-ci.sh:26-50` は
`diff` で差分ゼロ。内訳は「絶対/相対 path の解決」+「container init の読み込みと 4 段の guard」。

- 数え方 (自分で計測): `:43-67` の範囲は **1 コピーあたり 25 physical / 24 nonblank /
  20 non-comment 行**。2 本の合計では 50 / 48 / 40 行で、共通化で消えるのは 1 コピー分。
  config 存在検査 (下記「同一契約」) を含めると 1 コピー約 30 行。
- 他にも一字一句同じもの: `unset CDPATH` (`container-samba.sh:2` / `start-samba-ci.sh:2`)、
  `SCRIPT_DIR` / `REPO_ROOT` の解決と repo root への `cd` (`:5-6,22` / `:11-13`)、
  `-v "${SAMBA_CONFIG_PATH}:/tmp/smbee-smb.conf:ro"` と
  `bash -lc "${CONTAINER_INIT}"` の payload 受け渡し (`:90-93` / `:57-60`)。

### 同一契約だが実装が違う

| 項目 | `container-samba.sh` | `start-samba-ci.sh` |
|---|---|---|
| config 存在検査 | `printf` (`:38-41`) | `echo` (`:21-24`) |
| readiness の **envelope** (120 回 retry / 1 秒 sleep / timeout) | `:95-104` | `:62-68` |
| 既存 container の強制削除 | `container rm -f` (`:87`) | `docker rm -f` (`:55`) |
| 失敗時の logs 出力 | `container logs ... \| tail -n 120` (`:108-109`) | `docker logs` (`:70-71`) |

### runtime 固有 (共通化の対象外)

- readiness の **predicate**: local は port open **かつ** `container logs` に `waiting for connections`
  (`:96-98`)、CI は `/dev/tcp` の open だけ (`:63`)。
- teardown の lifecycle: local は `EXIT` trap + `SMBEE_E2E_KEEP_CONTAINER` (`:78-87`)、
  CI は workflow の `samba-teardown` action が `if: always()` で行う
  (`.github/actions/samba-teardown/action.yml:10-15`)。
- container 起動コマンドと `-p` の書式、Apple container 固有の前処理
  (`container system status` / `container system start`)。
- local だけが持つもの: port validation (`:33-36`)、probe / API / CLI smoke の実行 (`:121-150`)。
  CI 側はこれを workflow へ委譲する (`.github/workflows/e2e.yml:75-95`)。

## なぜ issue にするか (予防的な保守コスト)

076 の敵対レビューが見つけた **「絶対パスの `SAMBA_CONFIG` に repo root を前置してしまう」問題は、
2 本の launcher に同じ形で存在し、076 で両方に同じ修正を当てた**。
このバグ自体は解決済みで、これは**現在の障害ではなく再発防止の根拠**である。
同一実装の block が 2 本ある限り、この形の変更は 2 箇所を揃えて直す必要が残る。

一方これは「行数が多いから分ける」類ではなく、**共通化で複雑性が実際に下がるか**は自明ではない
(判断基準はグローバルの refactor ルール「複雑性が実際に下がるかで判断する」に従う):

- 寄せて消えるのは 1 コピー分の 25〜30 行。
- readiness の predicate と teardown lifecycle は runtime 依存が強く、
  無理に寄せると「差分を吸収するための分岐」が新しい複雑性になる。
- host/container 境界を跨ぐ共通化の難しさは 076 の本文が整理している。

## 対応方針 — trigger 待ち (先回りの分解はしない)

**次のどれかが起きたら着手する**:

1. **独立した Samba 起動スクリプトが 3 本目になったとき**
   (別 container runtime / 別 CI provider の launcher。**profile が増えることは trigger ではない** —
   `bin/e2e/smoke-all:20-37` も CI matrix も既存の launcher 2 本を使い回すだけ)。
2. **上記「同一実装」の block、または config / init の契約を次に変更するとき**。
   2 箇所を揃えて直す作業が発生した時点で、そのまま共通化に倒す。
3. 同型のバグがもう 1 回見つかったとき (人の発見待ちなので、これ単独を trigger にはしない)。

着手時の推奨スコープ:

- **寄せる**: 「同一実装」の 25 行 (config path 解決 + init 読み込みと guard。config 存在検査を含めれば約 30 行) と、
  readiness の **retry envelope** (predicate は callback で launcher 側に残す)。
- **残す**: readiness predicate、teardown lifecycle、runtime 固有の起動・前処理。

## 完了条件

以下のいずれか。

- 上記「寄せる」対象が 1 箇所 (`test/e2e/launcher-common.sh` 等) から source され、次を満たす。
  - **CI E2E で `testReadRangesAround4GiBBoundary` が実行され passed になること**を機械判定する。
    「workflow が success」だけでは不十分 —
    `Tests/SMBeeTests/SMBeeE2ETests.swift:664-667` は `SMBEE_E2E` 未設定で `XCTSkip` し、
    `.github/workflows/e2e.yml:75-95` は `swift test` の終了コードしか見ないため、
    **skip / 対象テスト 0 件は現状 green に見える**。exact filter で回し、
    `Test Case '...testReadRangesAround4GiBBoundary' passed` の出力と実行件数 1 を確認する
    (`wire-stress-e2e.yml:50-58` の skip 検出パターンが先例)。
  - Apple container 側 (`bin/e2e/container-samba.sh`) の green は **CI gate ではなく別の証跡**として残す
    (macOS ローカル専用で、CI から機械判定できないため)。
  - 切り出した関数の**回帰テストを `bin/ci/test-e2e-launchers` として新設**し
    (`bin/ci/test-performance-scripts` が stub + 一時ディレクトリ構成の先例)、
    **どの workflow の step から実行されるかまで配線して完了条件に書く**。
    現状 `bin/ci/test-performance-scripts:190-212` は launcher を検査対象にしていない。
    検査項目: 絶対パス `SAMBA_CONFIG` / 相対パス / init ファイル不在 / 空 / `exec smbd` 欠落。
- または「現状維持 (2 本に同一実装を残す)」を選び、その理由を両 launcher の該当箇所に
  コメントで残して close する。

## スコープ外

- container init 本文の共通化 — 076 で完了済み。
- **readiness predicate** と **teardown lifecycle** の共通化 — runtime 依存が強い。
  retry envelope だけは上記「寄せる」に含める。
- E2E ハーネス全体の「filter / skip で fixture 検証を飛ばせる」性質 — 076 で
  却下理由つきで記録済み (`issues/done/076-...` の「却下した指摘とその理由」)。
  ただし完了条件の 1 つ目はこの性質を前提に「実行されたことの機械判定」を要求する。

## 進捗 (2026-09-25)

ユーザー指示で trigger 待ちを解除して着手した。完了条件の 1 つ目 (共通化) を採った。

- **共通化**: `test/e2e/launcher-common.sh` を新設し、両 launcher が source する。
  寄せたのは `smbee_e2e_resolve_samba_config` (config 存在検査 + 絶対/相対 path 解決)、
  `smbee_e2e_load_container_init` (init 読み込み + 4 段の guard)、`smbee_e2e_wait_until_ready`
  (120 回 / 1 秒の retry envelope + 最後に 1 回判定。predicate と進捗表示は callback)。
  predicate・teardown・起動コマンド・Apple container の前処理は各 launcher に残した。
- **挙動差** (意図したもの): CI launcher の config 不在メッセージが `Samba config not found:` →
  `Missing Samba config:` (旧文言への依存は grep で 0 件)。CI launcher の readiness 判定が
  最後の 1 回ぶん増えて最大 121 回 (ローカルは元から 121 回)。
- **回帰テスト**: `bin/ci/test-e2e-launchers` (24 シナリオ。docker / container / nc / sleep / swift を
  fake に置き、launcher をスクラッチの repo tree へコピーして走らせる)。検査項目: 絶対 / 相対
  `SAMBA_CONFIG`、config 不在、init 不在 / 空 / `exec smbd` 欠落、retry の回数と間隔、両 launcher の
  `run` の argv、ローカルの EXIT trap teardown、ローカルの readiness がログ行を要求すること。
  **配線**: `.github/workflows/test.yml` の job `e2e-launchers` (paths filter 無し)。
- **CI の「実行された」判定**: `bin/ci/require-xctest-passed` を新設し、`e2e.yml` の full scope
  (matrix `required_test`) で `SMBeeE2ETests.testReadRangesAround4GiBBoundary` が passed 1 回・
  skipped 0 回であることを判定する。full scope で `required_test` が空なら step を失敗させる
  (matrix の typo で gate が黙って外れるのを防ぐ)。書式は Linux XCTest (`Test Case 'Class.method' passed (…)`)
  で、run 34239055805 の実ログで確認した。
- **変異検証**: 21 変異すべてが狙った scenario で red (path 前置の復活 / 各 guard の除去 / retry 60 回 /
  間隔 2 秒 / 最終判定の除去 / tick の除去 / 両 launcher の `-v` を旧式へ / `|| exit 1` → `|| true` /
  ローカル readiness を port のみに / EXIT trap 除去 / gate の 1 回以上化・skip 検査除去・status 無視)。
  途中で見つけた偽の緑: (1) `||` の中で呼ばれる fake `sleep` 内の assert は errexit も ERR trap も効かず
  拾われなかった → 記録して外で比較する形へ。(2) config 不在の `|| exit 1` を外しても `set -u` が
  後で落として同じ rc になる → guard の後に runtime (docker / container) が 1 回も呼ばれていないことを
  assert する形にした。最初は stderr の `unbound variable` を grep したが、この Mac の bash は日本語で出すため
  偽の緑になった (観測で確認)。文言に依存しない形へ置き換えた (2 周目の P3-1)。
- **Apple container 側の証跡** (CI gate ではない): 2026-09-25 に `bin/e2e/container-samba.sh` を既定 profile で
  実行し rc=0。`testReadRangesAround4GiBBoundary` は passed (macOS 書式
  `-[SMBeeTests.SMBeeE2ETests testReadRangesAround4GiBBoundary]`)。
- **敵対レビュー**: 1 周目は P1 なし / P2 1 件 (間隔 assert が効かない) / P3 3 件。
  P2・P3-1 (ローカル側の bad init と両側の config 不在のシナリオ不足)・P3-2 (gate が黙って外れる) は対応した。
  P3-3 は上記「挙動差」で、害なしとして記録のみ。
  2 周目は P1/P2 なし。P3-1 (上記の文言依存) は対応した。P3-2「e2e.yml の SCOPE 判定は機械検査されていない」は、
  YAML 内の判定で実害は `scope: full` を改名したときだけなので受容した (検出できるかは未確認。改名時に見直す)。
  最後の修正は新しい判定を足しておらず、変異 (`LANG=ja_JP.UTF-8` 下で 21/21 red) で直接確かめたので周回を閉じた。
