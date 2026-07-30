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
