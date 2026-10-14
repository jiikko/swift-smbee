# 112 (chore): x86_64 Linux を実質サポート対象外にする（段階的に外す）

起票日: 2026-10-14

## 概要

SMBee を使うのは arm の Mac だけなので、x86_64 Linux を実質サポート対象外にする（ユーザー判断、2026-10-14）。
コードや記述は一気には消さず、段階的に外す。

- **今後、x86_64 のための新しい実装・修正はしない**。x86_64 でだけ起きる不具合・性能の退行は直さない
- 既存のコードはそのまま残す（x86_64 に固有のコードはもともと無い。Linux 対応は arm64 で続ける）
- CI では x86_64 を確認しない

## 経緯

issue 106 Commit 5（M1+M2）の性能の退行が、CI の x86 の gate でだけ大きく出た（x86 で read −14.7% / user CPU +22.7%、arm64 の手元で −11.5% / +12.9%）。
x86 の gate に余裕を作るための最適化（slot table、正常系の遷移をまとめる）は効果が小さく、利用しない環境のために設計を曲げる価値が無いと判断した。

CI で Linux を使うのは Samba の E2E を Docker で動かすためで（macOS の runner では Docker が使えない）、x86 である必要は無かった。

## やったこと

- commit `ci: Linux の job を ubuntu-24.04-arm に移し、x86_64 Linux のサポートを段階的に外す`:
  `.github/workflows/` の `runs-on: ubuntu-latest` 15 か所をすべて `ubuntu-24.04-arm` にした（test / e2e / performance / samba-compat / wire-stress-e2e / network-performance-study / issues）。
  README の「対応環境」に方針を書き（正本）、`docs/testing.md` の runner 名を合わせた
- 確かめたこと: workflow・`test/e2e`・`bin/ci` に x86 に固定した設定は無い。Swift の image の digest（`.swift-image-digest`）は multi-arch で、手元の arm64 container でも同じ digest が動く。
  性能の cache の key は `runner.arch` を含むので、x86 の cache と混ざらない

## 残り

- [ ] arm64 の runner で Test / E2E / Performance が通ることを、上の commit の CI（`bin/ci/verify-agent-push`）で確かめる
- [ ] `docs/performance-resource-baseline.md` の `Linux/X64` は過去の計測の条件の記録なので残す。arm64 の runner の baseline は、次に baseline を取り直すときに足す
- [ ] `bin/ci/test-performance-scripts` の fixture にある `Linux 6.8.0 x86_64` は文字列の fixture で、判定に影響しないので触らない

## 再評価の trigger

x86_64 Linux で SMBee を使う consumer が現れたら、CI に x86 の job を戻すかを判断し直す。
