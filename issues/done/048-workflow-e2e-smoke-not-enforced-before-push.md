# 048 workflow: production wire 変更の push 前 E2E smoke がルールだけで強制されていない

- 種別: workflow / regression prevention
- 重要度: medium
- 状態: open
- 関連: `CLAUDE.md`「実装を変更したら smoke E2E を回す」, `bin/e2e/container-samba.sh`,
  2026-07-11 の CI 障害 (9f6745c: QUERY_DIRECTORY 拡大 / 91026d2: 署名必須の誤適用)

## 問題

CLAUDE.md は「production の wire 挙動を変更したらローカルで container Samba E2E smoke を実行する」と
定めているが、強制する仕組みがない。実際に 9f6745c (QUERY_DIRECTORY の出力バッファ拡大に CreditCharge が
追随せず実サーバが INVALID_PARAMETER) と 91026d2 (暗号化セッションの AEAD 保護応答に署名必須を誤適用) は
ローカル smoke を踏まずに master へ push され、CI の E2E workflow (samba-compat.yml) が初検出になった。

unit テストは InMemoryTransport + synthetic frame の round-trip なので、この 2 種の退行は構造的に
unit では検出できない。なお CI 側は既に 3 プロファイル (smb302-encrypted-required /
smb311-signing-required / smb311-encrypted-required) を回しており検出能力は十分。**穴は
「master に乗る前のローカル検証が任意」であること**に限られる (2 退行は別々のプロファイルでしか
顕在化しなかったため、ローカル smoke も既定 1 プロファイルでは不足する)。

## 影響

- master が赤いまま後続コミットが積まれ、原因コミットの特定と修正が遅れる。
- 「ルールはあるが踏まれない」状態が常態化する。

## 対応方針

1. ローカル 2 プロファイル一括 smoke ターゲット (`bin/e2e/smoke-all`: 既定
   `smb302-encrypted-required` + `smb311-signing-required`) を追加し、成功時に
   「検証済み commit hash」マーカー (`./tmp/e2e-verified-<sha>`) を残す。
2. pre-push フックを `bin/hooks/pre-push` としてリポジトリ管理し、`core.hooksPath` を設定する
   セットアップターゲット (`make setup-hooks` 等) を用意する。フックは push 対象 diff に
   `Sources/SMBee/` が含まれる場合にマーカーを照合し、無ければ push を拒否する。
   注意: `.git/hooks/` 直置きは clone 後に自動有効化されないため採らない。
   セットアップ手順は CLAUDE.md / README に明記する (未セットアップ環境では従来どおり CI が最終防衛線)。
3. 緊急用の明示スキップ (`SMBEE_SKIP_E2E_GATE=1 git push`) を用意し、スキップ時は stderr に警告を出す。
