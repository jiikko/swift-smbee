# 099 perf: direct TCP の frame header を別の send() で送るため、往復ごとに Nagle と遅延 ACK で約 40 ms 待つ

起票日: 2026-09-30
親: [097](done/097-perf-samba-real-transfer-measurement.md)（実 Samba 転送の分解測定。この issue は 097 の「client 側の単一候補が
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

- [ ] 1 frame が 1 回の syscall で書かれる（または `TCP_NODELAY` が立つ）ことを unit で固定し、今の実装に戻す変異で red を確認
- [ ] `network-performance-study.yml` の profiles（1・64 MiB × 10 invocation）で、4 profile の 1 MiB wall と 64 MiB read が
  097 の表から「差あり」で改善していることを run URL つきで記録
- [ ] `make smoke` と CI（`bin/ci/verify-agent-push`）が green。Performance の regression gate を通る

## 進捗

- 2026-09-30: issue 097 の study で検出して起票。codex の反証レビューで、write の往復数（FLUSH の数え漏れ）・
  3 profile と CCM の値の混同・「Linux だけ」「各往復に 40 ms」の言い過ぎ・NODELAY 単独の効果についての根拠の無い推論を
  指摘され、実測（JSONL の command 数・`send_calls`）に合わせて直した。
