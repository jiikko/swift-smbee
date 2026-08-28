# 085 retro: resource-performance job の live download 依存を codex-drive で直した (2026-08-28)

状態: **open**
起票: 2026-08-28
種別: `retro`

## 何をやったか

- 失敗 run 33056637791 (docs のみの commit で赤) を観測 → 真因は「reference build が毎 run GitHub から
  SwiftLint binary (75 MB) を live download し、transient な 13 KB 応答 → SwiftPM の retry が cache path に
  直接書けず `already exists` で fatal」。SwiftPM のソースと手元実験 (不正 archive は evict されない /
  artifact は 0600 で書かれる) で裏取り
- codex-drive (軽量パス): D1 設計 1 本 → Claude 検閲 → D3 敵対 1 本 (9 件中 4 件採用) → 承認 → codex 実装 →
  Claude 検証 (テスト / shellcheck / 変異 4 本) → 敵対レビュー 1 本 (6 件中 2 件採用、Claude が直接修正) →
  commit 68ab66d → CI で prewarm 1 回 + 計測中 download 0 件 + cache 保存を確認

## 反省と気づき

1. **WebFetch の要約を「外部事実」として書いたが、手元実験で否定された** (SwiftPM `main` の evict 挙動 → 6.3.3 では
   不正 archive が残る)。ソース要約は仮説であり、手元で再現できる実験が 1 本あれば数分で確定した。
   → 切り出し先: `measure-external-cli-streams-separately.md` か新規 rule 候補「外部ソースの要約は実験で裏取りしてから
   設計の前提にする」。要否はユーザー判断
2. **自分の変更 (期待 argv に 2 要素追加) の off-by-one で baseline を赤にし、赤い baseline 上で変異を当てて
   「red」を読んだ**。`mutation-verify-new-tests.md` の手順 0 (baseline green を先に測る) を踏んでいれば
   1 往復で済んだ。→ 却下 (既存 rule どおり。今回は次の往復で自分で気づいた)
3. **敵対レビューの「LOG_FILE が無いと grep の status 2 が if に吸われて素通り」は自分では見つけていなかった**。
   `verify-execution-not-just-exit-code.md` の「沈黙 = 成功にしない」の典型で、検査を新設したときの異常系
   (対象 0 件) を自分で作っていなかった。→ 却下 (`adversarial-review-own-safeguards.md` の表そのもの。
   rule は既にあり、今回は red team が拾った = 仕組みが機能した)
4. **prewarm の retry/purge は docker stub では実行されず、テストが書けていない**。inner bash を分離して
   fake `swift` で走らせる harness は D3/敵対レビューの両方が提案した。頻度 (transient 失敗) を見てから判断。
   → 切り出し先: 新規 issue 候補「run-resource-performance の inner script を分離して retry/purge をテスト可能にする」。
   要否はユーザー判断
5. **cold cache の初回露出は残る** (prewarm 3 回が全部外れると落ちる)。actions/cache は success 時のみ保存なので
   汚染は永続化しないが、「落ちたら rerun」の運用は残る。→ 観測ポイントとして残す (issue 化は再発してから)

## 残課題

- [x] 次の master push の Performance run で `Downloading binary artifact` が 0 件 (warm cache) であることの確認
      → run 33150668326 (29782ab) で確認: download 0 件、reference の prewarm は `Fetching binary artifact ... from cache`
- [ ] 上記 1 / 4 の切り出し要否の判断 (ユーザー)
