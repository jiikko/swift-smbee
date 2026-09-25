# 097 perf: 実 Samba 転送で、synthetic の署名改善がどれだけ効いているかと律速箇所を測る

起票日: 2026-09-25
親: [done/061](done/061-perf-create-measurement-driven-follow-up-issues.md) (測定駆動の個別 issue を起こすメタ issue)
関連: [done/060](done/060-perf-profile-and-reduce-aes-cmac-write-cost.md) (AES-CMAC 改善) /
[075](075-perf-linux-aes-ccm-pure-swift-throughput.md) (Linux AES-CCM fallback) /
`Tests/SMBeeTests/SMBeeNetworkPerformanceE2ETests.swift` / `.github/workflows/performance.yml` の `samba-network-performance` job /
`docs/performance-resource-baseline.md`

## 概要

issue 060 は AES-CMAC 署名を速くし、in-memory synthetic の write を大きく改善した
(Linux 同一 runner 10-run で signing-only 653.962 → 9.095 ms、full synthetic 669.927 → 23.797 ms)。
しかし**その改善が実 Samba 転送に効いているかは、今もどこでも測れていない**。現状の 2 つの計測は別の経路を見ている:

| 計測 | 経路 | 最新値 (commit b143e72, run [36089942046](https://github.com/jiikko/swift-smbee/actions/runs/36089942046)) |
|---|---|---|
| resource performance (`SMBeePerformanceRegressionTests`) | in-memory transport、**署名 (AES-CMAC)**、Linux release | read_stream 518.550 MiB/s / write_stream 311.223 MiB/s (median) |
| `samba-network-performance` job | 実 Samba (同一 host の docker)、**SMB 3.0.2 暗号化必須 = AES-CCM**、Linux release、1 MiB × 100 | read 4.116 MiB/s (p50 242.959 ms) / write 4.950 MiB/s (p50 201.930 ms) |

2 つの間に約 100 倍の差があるが、暗号 (CCM と CMAC)・transport・server が同時に違うので、差の内訳は言えない。
Linux の CCM は pure-Swift fallback (issue 075) だが、075 の Linux **release** 実測は 34.5 / 34.1 MiB/s で、1 MiB あたり約 30 ms にしかならない。
ネットワーク側の 1 MiB 約 200〜240 ms のうち、暗号で説明できるのは 1 割強で、**残りは内訳不明**。

さらに、**060 の対象である AES-CMAC を実 Samba で確実に通す profile が無い**。`test/e2e/smb/` に在るのは
SMB 3.0.2 の暗号化必須 (CCM) と SMB 3.1.1 の署名必須 / 暗号化必須だけである。SMB 3.1.1 の署名は、client が
AES-GMAC だけを提示する (`SMBNegotiate.swift` の `encodeSigningData`) ので必ず GMAC になり、CMAC は通らない。

### 起票時の予備測定 (2026-09-25、手元の macOS)

内訳不明の部分について、TCP の Nagle / delayed ACK を疑った (CI の write は p50 201.930 / p99 203.945 ms と、200 ms 付近に張り付いている。
Sources に `TCP_NODELAY` の設定は 1 件も無い)。手元の Apple container (macOS / Apple silicon、同じ `smb302-encrypted-required`、
`SMBeeNetworkPerformanceE2ETests` の debug ビルド、1 MiB × 100) で、connect 直後に `setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)` を
足した版 (B) と、そのままの版 (A) を A, B, B, A の順に 1 invocation ずつ測った:

| run | read MiB/s (p50 ms) | write MiB/s (p50 ms) |
|---|---:|---:|
| A1 | 57.703 (17.218) | 51.028 (19.411) |
| B1 | 69.383 (14.319) | 60.196 (16.760) |
| B2 | 63.588 (16.444) | 54.663 (18.585) |
| A2 | 64.031 (15.626) | 54.926 (17.985) |

- 手元では 200 ms への張り付きは再現しない (1 MiB あたり 15〜19 ms)。**CI の Linux だけ約 10 倍遅い**。
- `TCP_NODELAY` の差は A2 と B2 がほぼ同じで、**手元ではノイズの範囲**。仮説は支持されないが、Linux の delayed ACK は macOS と
  挙動が違うので棄却もできない。**Linux での A/B を下の分解測定に入れる**。
- invocation が各 2 回しかなく、比較の条件 (debug・macOS) も CI と違うので、これは判定ではなく着手時の手がかりとして扱う。

## 目的

1. 060 の CMAC 改善が、実 Samba 転送の throughput / client CPU にどれだけ反映されたかを、同一条件の A/B で数字にする。
2. 実転送の律速が client の暗号 (CMAC / GMAC / CCM / GCM)・client のその他 (copy / socket 待ち)・server のどれかを、分解測定で判定する。
3. 全体の 10% 以上を占める client 側の候補があれば、それだけを次の実装 issue にする。無ければ実装変更なしで閉じる。

## 測定開始 protocol

### 固定するもの (metadata として全 sample に付ける)

- **commit**: after = 着手時の HEAD (記録する)。060 の A/B は **before = `e91809a^` / after = `e91809a`**
  (commit「perf: accelerate AES-CMAC signing」)。
- **環境**: `ubuntu-latest` の GitHub-hosted runner (runner image version・CPU model・core 数を `/proc/cpuinfo` と `nproc` で記録)。
  Swift は `swift:${SWIFT_VERSION}` の tag で起動される (`test/e2e/run-swift-in-container.sh`。digest pin は resource performance 側にしか無い)。
  各 invocation で `docker image inspect --format '{{index .RepoDigests 0}}' swift:6.2` を実行して digest を記録し、A/B 間で違えば比較不能とする。Samba は `ubuntu:24.04` の distro Samba
  (`smbd --version` を記録)。container runtime は docker (version を記録)。
- **SMB**: dialect、署名アルゴリズム、暗号アルゴリズムを `smbcli probe` の出力から記録する
  (`SMBEE_DEBUG=1 swift run smbcli probe smb://127.0.0.1:445`)。**期待と違う値が出たら、その sample 群は比較不能**。
- **network**: client は `--network host` の container、server は host の 445 に bind した container (同一 host)。
  帯域・RTT の固定 (traffic shaping) は GitHub-hosted runner で `tc` が使えるかを最初に 1 回確かめる。
  使えなければ shaping 条件は測らず、その理由 (権限 / kernel module) を結果に書く。
- **cache**: 各 invocation の前に server の file を作り直す (read 用 fixture は upload してから warmup を回す。page cache は温まった状態を前提にし、その旨を記録する)。
- **payload**: 決定的な内容 (seed 固定の疑似乱数) で 1 MiB / 64 MiB / 1 GiB。1 GiB は 1 invocation あたり 1 sample でよい (時間の上限は下記)。

### 手順

1. **profile を 1 つ新設する**: `test/e2e/smb/smb302-signing-required.conf`
   (`server min protocol = SMB3_00` / `server max protocol = SMB3_02` / `server signing = mandatory` / `smb encrypt = off`)。
   SMB 3.0.x の署名は AES-CMAC 固定 (MS-SMB2 3.1.4.1) なので、060 の経路を確実に通す。既存の `smb311-signing-required` (GMAC) /
   `smb302-encrypted-required` (CCM) / `smb311-encrypted-required` (GCM) と合わせて **4 profile** を測る。
2. **harness を拡張する**: `SMBeeNetworkPerformanceE2ETests` に size を env (`SMBEE_NETWORK_PERF_SIZES_MIB`) で渡せるようにし、
   sample ごとに次を 1 行 (`PERF_NETWORK_SAMPLE`) で出す:
   operation / size / iteration / wall ms / throughput / client の user・system CPU (`getrusage(RUSAGE_SELF)` の差分) /
   client の max RSS / 送受信 byte 数 / READ・WRITE command 数。
   byte 数と command 数の計数は**今は無い**ので新設する: harness 側で `SMBTransportTestOverride.factory` に
   `POSIXSocketTransport` を包む計数 transport を差し込み、`send` の byte 数と `receive` の byte 数を数える
   (command 数は送った frame の SMB2 header の Command field を数える)。production は変えない。
   server 側は sample の前後で `docker stats --no-stream` の CPU・RSS を採る (粒度が粗いので参考値。invocation 単位で集計する)。
3. **correctness**: 各 sample で size の一致を assert する。invocation の最初と最後の 1 回は SHA-256 も照合する
   (毎回の hash は client CPU を汚すので避ける)。upload 後に server 側から読み戻した hash、download 後の client 側の hash の両方。
4. **回数と順序**: warmup 5 回 → 各 size 最低 5 sample。同一 commit で **10 invocation**。
   060 の A/B は同一 runner の 1 job 内で before / after を **ABBA 順** (A, B, B, A, …) に交互に実行する
   (runner の揺れを片側に押し付けない)。
5. **A/B の組み方**: `e91809a^` と `e91809a` をそれぞれ worktree に取り出し、**HEAD の harness ファイルをコピーして**同じ harness で測る。
   harness は public API (`SMBee.connect` / `session.read` / `session.upload`) と上の計数 transport だけを使う形に保つ。
   それでも古い commit でコンパイルできなければ、この A/B は「比較不能」として理由を記録し、以降の手順 (4 profile の現状測定と分解) だけを行う。
   (署名 backend の切り替えは `AESCMAC.swift` のコンパイル時分岐で、実転送の経路から切り替える口は無い。代替 A/B にはしない。)
6. **分解測定** (律速の判定): 最低 1 つは次の形で取る。
   - client の Linux `perf record -g` (runner で使えるか最初に確かめる。使えなければ
     `swift test` を `valgrind --tool=callgrind` ではなく、`SMBeePerformanceRegressionTests` の stage 別 profile
     (`PERF_WRITE_PROFILE`: codec_only / signing_only / session_no_outbound_retention / full_synthetic) を同じ size・同じ暗号で取り、
     実転送の wall time との差を「transport + server」とみなす)。
   - 暗号だけの時間 (同じ payload を同じ backend で署名 / 暗号化する時間) ÷ 実転送の wall time を、比率として出す。
   - **`TCP_NODELAY` の A/B** (Linux・4 profile のうち最低 `smb302-encrypted-required` と `smb302-signing-required`):
     `POSIXSocketTransport.connectInstalledCandidate` の `try connectSocket(...)` の直後に次の 2 行を足した worktree と、足さない worktree を
     手順 4 と同じ ABBA・10 invocation で比べる。
     `var noDelay: Int32 = 1` / `_ = setsockopt(descriptor, Int32(IPPROTO_TCP), TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))`
     (Linux では `IPPROTO_TCP` の型が違うので、コンパイルが通らなければ `Int32(IPPROTO_TCP)` の変換を合わせる)。
     差が「比較の方法」の閾値を超えれば、それ自体を実装候補として 10% 基準で判定する。
7. **artifact**: raw sample と metadata を JSONL (`.build/network-performance.jsonl`、1 行 1 sample) で保存し、GHA の artifact と
   job summary (median / p10 / p90 / MAD / min / max の表) に出す。local で回した場合も同じ JSONL を残す。
8. **時間の上限**: 1 job 30 分に収まらない組み合わせは、先に 64 MiB で throughput を測り、1 GiB に掛かる時間を見積もってから入れる
   (目安: 今の実転送は 1 MiB で約 4〜5 MiB/s なので、そのままなら 1 GiB は 1 方向で 3〜4 分)。入らないものは測らず、見積もりを結果に書く。

## before / after の比較方法

- 比較してよいのは、上の「固定するもの」がすべて一致した sample だけ。dialect / 署名 / 暗号アルゴリズム・runner の CPU model・
  Swift image digest・Samba version のどれかが違えば比較不能として別表に分ける。
- 集計: invocation ごとに median を取り、その 10 個に対して median / p10 / p90 / MAD / min / max を出す (sample を直接混ぜない)。
- noise の判定: 同一 commit の invocation 間の MAD を noise とし、**before / after の差が 3×MAD かつ 5% を両方超えたとき**だけ「差がある」とする。
- 差の分解: throughput の差と client CPU (user + system) の差を並べ、「CPU が減ったのに throughput が変わらない」なら
  client 以外 (network / server) が律速と判定する。

結果は次の表で書く:

| Profile | Size | Metric | Before median / MAD | After median / MAD | Change | Decision |
|---|---|---|---:|---:|---:|---|

## 完了条件

- [ ] 4 profile × 3 size (入らないものは見積もりを記録) について、10 invocation の raw sample と metadata が JSONL と run URL で残っている。
- [ ] 060 の A/B (または手順 5 の代替 A/B) の表があり、「synthetic の改善のうち実転送の throughput / client CPU に反映された割合」を数字で書いている。
- [ ] 分解測定が最低 1 つあり、各 profile で「律速は client の暗号 / client のその他 / network・server」のどれかを判定している。
- [ ] 全 sample で size が一致し、SHA-256 の照合が通っている。署名・暗号の交渉結果が期待どおりである。
- [ ] `swift test` (unit 全体)、`make smoke` (container Samba E2E) が green。harness の変更で CI の `samba-network-performance` job が
  壊れていない (job の summary に新しい表が出る)。
- [ ] 結果を `docs/performance-resource-baseline.md` に「Issue 097: real Samba transfer」節として書き戻した。
- [ ] **次の実装 issue は、client 側の単一の候補が全体の wall time の 10% 以上を占めるときだけ起票する**。
  CCM が支配的と出た場合は新しい issue を作らず、075 に数字を書き足す (075 がその候補の受け皿)。
- [ ] **10% 以上の候補が無ければ、「現条件では network / server 律速」と結果を書き、実装変更なしで done にしてよい**。
  shaping が使えなかった・1 GiB が時間に入らなかった・古い commit で harness がコンパイルできなかった、はいずれも理由を書けば完了を妨げない。

## スコープ外

- 性能の実装変更 (この issue は測定と判定だけ)。
- macOS 上の実 Samba 計測 (Apple container は CI で回らず、同一条件の反復が取れない)。必要になったら別 issue にする。
- 既存の guardrail (`bin/ci/run-performance-regression` の閾値) の変更。
