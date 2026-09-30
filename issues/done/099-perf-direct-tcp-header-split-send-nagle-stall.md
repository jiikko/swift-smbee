# 099 perf: direct TCP の frame header を別の send() で送るため、往復ごとに Nagle と遅延 ACK で約 40 ms 待つ

起票日: 2026-09-30
親: [097](097-perf-samba-real-transfer-measurement.md)（実 Samba 転送の分解測定。この issue は 097 の「client 側の単一候補が
wall の 10% 以上」に当たる）
関連: `Sources/SMBee/POSIXSocketTransport.swift`（`sendBlocking` / `enqueueSend`）/ `Sources/SMBee/DirectTCPFraming.swift`
（`segments`）/ commit `0709833 perf(transport): send direct TCP frames as segments`

## 概要

`POSIXSocketTransport.sendBlocking` は `send(_ segments:)` で受けた segment を **1 つずつ別の `send()` で**書く。
`DirectTCPFraming.segments` は frame を `[4 byte の direct-TCP header] + payload` に分けるので、どの request も
**4 byte だけの `send()` の直後に本体の `send()`** になる。Nagle が有効（`TCP_NODELAY` 未設定）なので、2 つ目の
`send()` は 1 つ目の ACK を待ち、server は遅延 ACK（Linux の最小値は約 40 ms）で待ってから ACK する、という相互作用で
**SMB の往復ごとに数十 ms の待ちが乗っている**と考えられる。下の A/B で待ち時間の大半が消えることは実測したが、
各往復の内訳（どの frame で何 ms 待ったか）は packet capture を取っていないので未観測。この分割は 2026-07-23 の
`0709833`（copy を 1 本減らす perf 変更）で入った（現行の `sendBlocking` のループの形はその後に変わっているが、segment ごとに
writer を呼ぶ点は同じ）。

## 実測（issue 097 の study、GitHub-hosted ubuntu-latest、Samba 4.19.5、同一 host の docker、10 invocation の median）

- 1 MiB の read / write は、CMAC / GMAC / GCM の 3 profile で **約 166〜168 ms / 126〜131 ms** に揃い、client CPU ÷ wall は
  0.02〜0.03、Samba container の CPU ÷ wall も 0.02〜0.06。どちらも暇で、待っている
  （run [36682108096](https://github.com/jiikko/swift-smbee/actions/runs/36682108096)）。CCM の smb302-encrypted-required は
  206.8 / 196.3 ms で、client CPU が約 41 ms 乗っている
- この計測の read は CREATE / QUERY_INFO / READ / CLOSE（`knownSize` 無し。JSONL の `read_commands` は 1 MiB で 1、64 MiB で 64）、
  write は CREATE / WRITE / FLUSH / CLOSE（`send_calls` 4）。1 往復あたりに直すと read 約 42 ms、write 約 33 ms で、遅延 ACK の
  最小値（約 40 ms）と桁が合う。CLOSE を待つかどうか等で 1 往復の数え方は変わるので、ここは桁の一致までしか言わない
- 64 MiB の read は READ 64 本（実測）で 21.7 MiB/s（READ 1 本あたり約 46 ms）。write は複数の WRITE を
  同時に出すので影響が薄い（107〜150 MiB/s）
- **`TCP_NODELAY` の A/B**（HEAD と、connect 直後に `TCP_NODELAY` を立てた HEAD。同じ runner で ABBA、各 10 invocation、
  run [36682119995](https://github.com/jiikko/swift-smbee/actions/runs/36682119995)。判定は 097 の 3×MAD かつ 5%）:

| Profile | Size | Metric | current median / MAD | nodelay median / MAD | Change |
|---|---:|---|---:|---:|---:|
| smb302-signing-required | 1 MiB | read wall_ms | 168.084 / 0.249 | 5.791 / 0.066 | -96.6% |
| smb302-signing-required | 1 MiB | write wall_ms | 129.209 / 0.114 | 6.636 / 0.189 | -94.9% |
| smb302-signing-required | 64 MiB | read throughput MiB/s | 21.599 / 0.010 | 259.549 / 0.388 | +1101.7% |
| smb302-signing-required | 64 MiB | write throughput MiB/s | 163.618 / 0.292 | 238.574 / 0.890 | +45.8% |
| smb302-encrypted-required | 1 MiB | read wall_ms | 237.085 / 0.223 | 74.033 / 0.582 | -68.8% |
| smb302-encrypted-required | 1 MiB | write wall_ms | 197.181 / 0.465 | 75.101 / 0.876 | -61.9% |
| smb302-encrypted-required | 64 MiB | read throughput MiB/s | 8.759 / 0.014 | 14.049 / 0.072 | +60.4% |
| smb302-encrypted-required | 64 MiB | write throughput MiB/s | 13.590 / 0.042 | 13.984 / 0.063 | within noise（CCM の CPU 律速。075） |

  client CPU はどの行もほぼ変わらない（-0.1〜-17%）ので、減ったのは待ち時間だけ。
- 分割前の実装は 1 回の `send()` で frame を送っていた。097 の 060 A/B（`e91809a` = 分割前 + issue 098 の backport、
  `smb302-signing-required`）は 1 MiB read が **13.389 ms** で、同じ profile の HEAD（168.020 ms）より 1 桁速い
  （run [36682114125](https://github.com/jiikko/swift-smbee/actions/runs/36682114125)）。251 commit 離れた比較なので、これ単独では
  原因を 0709833 に帰属させない。帰属の根拠は上の A/B とコードの読み（`sendBlocking` の `for segment in segments` ループ）
- smb311 の 2 profile は A/B を取っていないが、1 MiB の固定遅延（166 / 126 ms）が 302 と同じ形なので同じ原因と推定（未検証）
- macOS の手元（Apple container）では 1 MiB が 5〜19 ms で、この待ちは見えない。GitHub-hosted の Linux runner では出る。
  OS による違いの原因（遅延 ACK の実装差など）は未確認。**手元の smoke では気づけない**のが実害

## 対応方針（案。実装時に決める）

1. **1 frame を 1 回の syscall で書く**: segment を `writev` / `sendmsg`（iovec）でまとめて書く。0709833 の目的（payload の
   copy を 1 本減らす）を保ったまま、header だけの小さな send を無くせる。部分書き込み・EINTR・cancel の扱い
   （`sendBlocking` の現在の契約）を iovec の進め方に移す必要がある
2. **`TCP_NODELAY` を立てる**: SMB は request / response の往復が主体で、Nagle による合体の利点は小さいと考えられる。
   上の A/B はこれ単独の効果。Windows / macOS の SMB client が既定で NODELAY を使うかは**未確認**
   （採否の根拠にするなら一次資料を引く）
3. 1 と 2 は独立に効く。2 だけでも A/B で待ちは消えている。1 は syscall 数も減らすが、効果は未測定。
   どちらを採るか（両方か）は実装時に A/B で決める

守るべきこと: `sendBlocking` の cancel / poison / 部分書き込みの契約（コメントに記述がある）を崩さない。`SMBTransport` の
「1 回の send 呼び出しの bytes は他の呼び出しと混ざらない」契約も同じ。

## 退行を守るテスト

- unit: 1 frame（header + payload）の `send(_ segments:)` が writer / syscall を**1 回**しか呼ばないことを、fake writer の
  呼び出し回数で固定する（今の実装に当てると 2 回で red になるはず）。`TCP_NODELAY` を採るなら、connect 後の
  `setsockopt` を syscall hook で観測する
- 実転送: `network-performance-study.yml` の `profiles` を 1 回回し、1 MiB の wall が 40 ms × 往復数の水準から外れることを
  見る（097 の表と比べる）。常設の `samba-network-performance` の 1 MiB read / write（現在 p50 約 241 / 200 ms。CCM）も下がるはず

## 受け入れ条件

- [x] 1 frame が 1 回の syscall で書かれる（または `TCP_NODELAY` が立つ）ことを unit で固定し、今の実装に戻す変異で red を確認（TCP_NODELAY を採用。変異 5 本すべて red）
- [x] `network-performance-study.yml` の profiles（1・64 MiB × 10 invocation）で、4 profile の 1 MiB wall と 64 MiB read が
  097 の表から「差あり」で改善していることを run URL つきで記録（run をまたぐと runner の CPU が違って比べられないので、修正前の commit と同じ runner で
  ABBA に比べる fix-ab で測った。下の「実転送の A/B」）
- [x] `make smoke` と CI（`bin/ci/verify-agent-push`）が green。Performance の regression gate を通る

## 進捗

- 2026-09-30: issue 097 の study で検出して起票。codex の反証レビューで、write の往復数（FLUSH の数え漏れ）・
  3 profile と CCM の値の混同・「Linux だけ」「各往復に 40 ms」の言い過ぎ・NODELAY 単独の効果についての根拠の無い推論を
  指摘され、実測（JSONL の command 数・`send_calls`）に合わせて直した。
- 2026-09-30: codex-drive で着手（下の「対応」節）。

## 対応（2026-09-30、codex-drive）

### 設計

- D1（codex の独立 4 案）は「TCP_NODELAY だけ」（A）と「TCP_NODELAY + vectored `sendmsg`」（B / C / D）に分かれた。**A を採った**。
  A の効果は 097 の nodelay arm で実測済み（send の分け方は今のまま NODELAY を立てた全体の効果）。`sendmsg` は効果が未測定で、
  writer seam・部分書き込み / EINTR / cancel / poison の fake・`msghdr` の Linux / Darwin 差の作り替えのリスクに見合わない
- D3（codex の敵対 1 本）: 不変条件を破る経路は無し。**「setsockopt が失敗した候補を落とす（fail-closed）と、全候補で失敗する環境では TCP は
  繋がるのに SMB が繋がらない。EAGAIN 系は `socketError` で `.timedOut` になり候補ループを止める」**を指摘 → **fail-soft に決めた（ユーザー承認）**:
  TCP_NODELAY は性能の option なので、設定に失敗しても接続は続け、`SMBEE_DEBUG=1` のときだけ stderr に 1 行出す
- `sendmsg` を後で測る条件（D3 で挙がった）: 小さな要求が大量に続く workload と、3 segment の暗号化 frame。NODELAY と NODELAY + sendmsg を比べる

### 実装

- `perf(transport): issue 099 — 接続直後に TCP_NODELAY を立て、往復ごとの Nagle と遅延 ACK の待ちを消す`:
  `POSIXSocketTransport.connectInstalledCandidate` で `connectSocket` の後・`applySocketTimeoutIfNeeded` と昇格の前に
  `applyTCPNoDelayIfNeeded`（既存の `syscalls.setSocketOption` seam。失敗は throw しない）。送信経路・writer seam・`DirectTCPFraming` は不変。
  commit の題の「消す」は、setsockopt が成功したときの話（fail-soft で失敗した接続では待ちが残りうる）
- `ci(perf): issue 099 — study workflow に修正前の commit と比べる fix-ab 実験を足す`（受け入れ条件の実転送 A/B 用）

### 検証（ここまで）

- unit 481 本 green（新規 2 本を含む）、Linux（swift:6.2 container）build green、`make lint-analyze` 0 violations、`make smoke` green
  （`Sources/SMBee` tree `aec093b`）
- 変異 4 本すべて red: 呼び出しを消す / fail-closed に戻す / 値を 0 にする / timeout 設定の後に回す
- 敵対レビュー（codex、2 lens）: production は壊せなかった。テストの穴として「connect の即時成功経路を通っていない」
  「『昇格前』を実際の昇格点ではなく connect の戻りで見ている」を指摘 → テスト強化中。**実際の昇格点との順序は、production に test 専用の
  状態を足さない限り観測できないので pin しない**（R5）
- 未確認リスク: `NWConnectionTransport`（macOS app の経路）の `.tcp` の noDelay 既定値と frame 間の Nagle / kernel 上の実効値と packet 数
  （unit では見えない。実転送の fix-ab で見る）

### 変異検証（テスト強化の後）

`test(transport): issue 099 — TCP_NODELAY の設定を connect の即時成功経路でも固定し、昇格の順序は pin しないと明記する` の後、使い捨て worktree で 5 本:
呼び出しを消す / fail-closed に戻す / 値を 0 にする / timeout 設定の後に回す / poll 成功の分岐でだけ設定する（connect の即時成功で未設定になる）。
5 本とも red（最後の 1 本は `testPOSIXConnectErrnoTransitionsUsePollWithoutReissuingConnect` の即時成功ケースが捕まえた）。
敵対レビューの後の修正はテストだけで判定ロジックを足しておらず、各修正を変異で直接確かめたので、敵対レビューは 1 ラウンドで閉じた。

### 実転送の A/B（fix-ab、run [36701434912](https://github.com/jiikko/swift-smbee/actions/runs/36701434912)）

修正前（`e3b678f`）と修正後（`3f5f0d7`）を同じ runner で ABBA、各 10 invocation（1・64 MiB、warmup 2、sample 5）。1,600 sample すべてで size 一致・
SHA-256 照合 640 件が通った。判定は 097 の 3×MAD かつ 5%。

| Profile | 1 MiB read wall | 1 MiB write wall | 64 MiB read | 64 MiB write |
|---|---:|---:|---:|---:|
| smb302-signing-required | 168.3 → 5.7 ms（-96.6%） | 129.1 → 6.6 ms（-94.9%） | 21.6 → 262.0 MiB/s（+1112%） | 165.2 → 241.7 MiB/s（+46.3%） |
| smb311-signing-required | 166.1 → 2.7 ms（-98.4%） | 132.7 → 4.9 ms（-96.3%） | 22.7 → 790.7 MiB/s（+3387%） | 134.1 → 197.6 MiB/s（+47.4%） |
| smb311-encrypted-required | 168.0 → 5.2 ms（-96.9%） | 127.6 → 5.8 ms（-95.4%） | 22.2 → 497.0 MiB/s（+2136%） | 240.7 → 442.6 MiB/s（+83.9%） |
| smb302-encrypted-required（CCM） | 263.0 → 119.3 ms（-54.6%） | 224.4 → 118.6 ms（-47.2%） | 7.03 → 8.55 MiB/s（+21.6%） | **9.48 → 8.31 MiB/s（-12.4%）** |

全行「差あり」。常設の `samba-network-performance`（CCM、1 MiB × 100）も CI（`bin/ci/verify-agent-push 3f5f0d7`、rc=0）で p50 が
read 約 241 → 41.2 ms、write 約 200 → 42.1 ms になった。

**CCM の 64 MiB write だけ悪化した（-12.4%）**。client の **user** CPU が同じ仕事で約 17% 増えている（6,267 → 7,334 ms。system は変化なし）。
user 空間のコードは修正前後で同じ（違いは TCP_NODELAY だけ）で、097 の TCP_NODELAY A/B（run 36682119995、EPYC 7763）では同じ行が
+2.9%（within noise）、user CPU も 4,356 → 4,349 ms で変わらなかった。今回の job の runner は EPYC 9V45。**仮説（未検証）**: 待ちが消えて
client と Samba（こちらも CCM）が同時に CPU を使うようになり、4 vCPU の runner で物理 core（SMT / cache）を取り合って、同じ仕事の CPU 時間が
増えた。確かめるなら client と server を別の core に pin して（docker の `--cpuset-cpus`）A/B を取り直す。CCM が CPU 律速であること自体は 075 の対象で、
075 の本体（CCM の高速化）が入ればこの行の律速も変わる。

## 要件照合（[7]、2026-09-30）

| 要件 | 判定 | 根拠 |
|---|---|---|
| R1 往復待ちを生まない | 充足（TCP_NODELAY が立つ接続） | fix-ab の 1 MiB wall が 4 profile とも -47〜-98%。設定に失敗した接続（fail-soft）では待ちが残りうる |
| R2 payload の連結 copy を増やさない | 充足 | 送信経路・`DirectTCPFraming` は無変更（diff） |
| R3 sendBlocking の契約 | 充足 | 送信経路は無変更。既存の transport テスト（部分書き込み・EINTR・cancel・poison・非 interleave）green |
| R4 Linux / macOS | 充足（POSIX）/ 範囲外（NW） | Linux（swift:6.2）build green、macOS unit green。`NWConnectionTransport` は分割送信が無い（segment を連結して 1 回で送る）が、`.tcp` の noDelay 既定値は未確認 |
| R5 test 専用の状態を足さない | 充足 | 既存の `setSocketOption` seam を fake で観測。昇格点との順序は pin していない（pin には test 専用 seam が要るため） |
| A1〜A5 | 充足 | 上のチェックリスト。A4 は基準の行（1 MiB wall・64 MiB read）がすべて改善。基準外の CCM 64 MiB write は悪化（上） |

## 決着（2026-09-30）

TCP_NODELAY を立てる修正で、SMB の往復ごとの待ちが消えた（4 profile の 1 MiB で -47〜-98%）。残したもの:
- CCM の 64 MiB write の -12.4%（上の仮説。検証の手順つきで 075 に書き足した）
- `NWConnectionTransport` の noDelay 既定値（macOS app の経路。この issue の範囲外）
- vectored `sendmsg` は採らなかった（後で測るなら、小さな要求が大量に続く workload と 3 segment の暗号化 frame で比べる）
