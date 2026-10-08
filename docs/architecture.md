# SMBee — 内部アーキテクチャ

## transport 抽象（決定 2026-06-29）

SMB のプロトコル/framing/session コードは **transport に依存しない**。バイト列を運ぶ層を
**protocol で抽象化**し、プラットフォームで実装を差し替える。

```
SMBSession / NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / READ / WRITE ...
        │  (依存するのは下の protocol だけ)
        ▼
protocol SMBTransport            // TCP 445 上の双方向バイトストリーム
  - connect(host:port:) async throws
  - send(_ bytes:) async throws
  - receive(maxLength:) async throws -> [UInt8]   // or AsyncStream
  - close()
        ▲                         ▲
        │                         │
 NWConnectionTransport      POSIXSocketTransport
 (opt-in / 明示 injection)   (既定。macOS 本番 / Linux CI / E2E 共通)
```

### なぜ抽象化するか

- **既定の transport は全プラットフォームで `POSIXSocketTransport`**
  （`SMBClient.resolvedTransportFactory` が OS 分岐なしで返す）。macOS の本番 consumer
  （obaket）も `makeTransport` を渡さないため POSIX を使っている（2026-07-29 の issue 072
  調査で確定した実態。かつて本ドキュメントは「macOS 本番は NWConnection」と書いていたが、
  それは実装されなかった構想であり実態と乖離していたため訂正した）。
- **CI の E2E** は **Linux runner + Docker の Samba** で回す（無料・再現可能）。Linux では
  `Network.framework` が無いため POSIX 一択。
- 両者を `SMBTransport` protocol の差し替えで吸収する。SMB の本体ロジックは
  一切プラットフォーム分岐を持たない。`NWConnection` へ切り替えたい場合は
  `makeTransport` で明示的に注入する（省電力・接続管理を優先したい場合の opt-in）。

### 実装方針

- `SMBTransport` は SMB に固有の概念を持たない（純粋に「接続して send/receive」だけ）。
  direct-TCP の **4 byte length framing** は `DirectTCPFraming` としてtransportの外側に実装済み。
  protocol 契約として「同時 send 可・各 send の byte 列は非交錯・同時 send 間の順序は未規定」を
  明文化してある（issue 072）。
- `NWConnectionTransport`: `#if canImport(Network)` でガード。既定では使われない（明示 injection）。
- `POSIXSocketTransport`: Linux + macOS 両対応の**既定実装**。SwiftNIO依存は採用していない。
  送信は serial executor で frame 単位に直列化し（issue 072）、fd の physical close は
  descriptor lease が drain した後に一度だけ行う（issue 073）。`close()` は「terminal 化と
  blocking I/O interrupt の開始」であり、同一 instance の再接続は不可（one-shot）。
- テスト（unit）は transport を **in-memory fake / loopback** に差し替えて framing を検証できる。
  POSIX の writer / reader / lifecycle hook は internal injection seam を持ち、送信交錯・
  lease・poison の決定論的テストに使う。

### session の reader（issue 010 M3）

- `SMBSession` は一つの transport lifetime に一つの generation と reader handle を所有する。
  同一 session の再接続はしない。再接続は `SMBClient` が新しい session / transport を作る。
- reader は需要駆動で動く。request の `transport.send` が全量成功し、orphan replay を終えた後に
  `.sent` の応答待ちが残っていれば起動する。`.sent` の応答待ちが 0 件になったら、最後の dispatch と
  同じ actor turn で dormant に戻り、次の送信完了まで `transport.receive` に入らない（master の
  `receiveLoop` と同じ idle の挙動）。cancel 後の final を待つ tombstone は `.sent` のまま残るので、
  その final は reader が読む。dormant 中に届いた frame は次に reader が起きるまで transport に残る。
- reader の受信ループは session actor に隔離され、reader Task は session を強参照する。framing、
  復号、credit grant、generation 確認、demux は frame ごとの actor 間の受け渡し無しに同じ actor で
  行う。`[weak self]` の Task は actor の外で始まり、Linux で frame ごとに余分な起床を生んだ
  （issue 010 の probe 3）。応答待ちのまま session を手放すと reader が session を保持し続けるので、
  中断には明示の close が要る（master の `receiveLoop` と同じ制約）。
- reader は自分が現在の reader (generation と handle) か確かめてから受信する。dormant にした後で
  古い Task が戻りきる前に次の reader が起きても、close はすべての reader Task を join する。
- close は generation を terminal にしてから transport を閉じ、reader、通常 send、CANCEL send、
  connect と credit waiter の終了を待つ。graceful disconnect は TREE_DISCONNECT / LOGOFF の
  response を受け取ってから close する。reader が受信中に起きた fault / EOF は pending 件数に関係なく
  wire を terminal にし、transport を閉じる。dormant 中は受信しないので、idle 中の EOF は次の request の
  送信または受信で見つかる。
- `SMBTransport.close()` は未完了 connect / send / receive を相手側の応答待ちなしで終了させ、
  以後の I/O を拒否する契約を持つ。外部 conformer がこの要件を守らない場合、session teardown
  の join はその conformer の operation 完了に依存する。
- 応答が full-send 完了通知より先に届いた場合は MessageId ごとの順序付き FIFO に退避し、`.sent`
  後に replay する。orphan は unknown 応答を優先して退避し、総 frame 数を 64 に制限する。
  required 応答を保持できない場合は session を閉じて黙った応答欠落を避ける。
- 可変長の READ / WRITE は残高 snapshot から長さと charge を決めず、credit window が実際に予約した
  charge を受け取ってから payload 長と MessageId 範囲を確定する。credit が0なら待ち、1〜N 個あれば
  その範囲に request を縮めて送るため、並行要求の stale な multi-credit 見積もりで waiter が止まらない。
  固定長コマンドは従来どおり要求 charge 全量を予約する。
- 通常 request の cancel tombstone は遅着応答との相関に残すが、件数は64を上限とする。上限を超えたら
  共有 wire を terminal にして全 pending / credit waiter を解放する。close は通常 send と SMB CANCEL send
  の双方を cancel して join し、close 後に遅れて戻る connect が transport candidate を公開しても再 close する。

### 転送ごとの READ window（M2）

- 各 `withReadStream` 転送は、呼び出し側の Task が drive する独立した window を持つ。session actor は
  window の slot、MessageId 採番、pending 登録、response 完了、停止理由、drain 状態を記録し、共有 reader は
  これまでどおり応答を相関する。
- window は最大4 slot を持ち、各 READ は最大1 MiB。request offset は commit 時に進み、completion の順序に
  関係なく `onChunk` は offset 順に一度だけ呼ぶ。callback と progress 通知は session actor の外で実行する。
- credit は各 request の実予約 charge から payload 長を決める。転送に committed slot があれば予約を待たずに
  試し、取れない場合はその転送の slot 変化を待つ。committed slot がない場合は credit 予約を待てるため、
  1 credit の接続では従来と同じ逐次 READ になる。
- short READ / EOF は新規 commit を止める。short data を手前まで配送し、送信済み request の final と send owner
  の完了を drain してから、受信長分だけ進んだ offset で次の epoch を始める。EOF と空成功は rebase せず失敗する。
- cancel、callback error、operation deadline、通常の READ error は新規 commit を止め、送信済み request の final
  を待つ。転送 owner が window の drain deadline までに drain できないときは session を閉じて reader / send を join
  する。READ pipelining は SMB CANCEL や transfer 専用 tombstone を作らない。

### プラットフォーム条件

- `SMBSession` / protocol / crypto / auth は **Linux でもビルド可能**に保つ（swift-crypto は
  Linux 対応）。`Network.framework` 依存は `NWConnectionTransport` の中だけに閉じ込め、
  `#if canImport(Network)` で囲う。これを破ると CI(Linux) の E2E が動かなくなる。

## レイヤリング（repo 内）

| 層 | 役割 |
|----|----|
| `SMBTransport`（protocol）+ 実装 | TCP バイトストリーム。platform 差はここだけ |
| `Protocol/` | SMB2 header / command codec / framing |
| `Auth/` | NTLMv2 / SPNEGO |
| `Crypto/` | preauth / KDF / signing / encryption。3.1.1 は GMAC/GCM をswift-cryptoで扱う。3.0.2 CMACはCommonCrypto（Apple）/ CryptoExtras（Linux）、CCMはCommonCrypto（Apple）/ pure Swift（Linux）で扱う |
| `Session/` | `SMBSession`（actor）: 接続シーケンス・直列化・再接続・cancellation |
| `API/` | 公開 API（list/stat/read/write/mkdir/rename/delete）。型は path/offset/length/attrs |
| `smbcli` | CLI（probe/ls/stat/cat/put/...） |

GUI / `ObjectStorageProtocol` 適合などの consumer 側は **本 repo に置かない**（consumer 側で
SMBee を薄くラップする）。

## dialect / crypto scope（実測 2026-06-29）

- macOS SMBX は macOS 26.5.1（最新）でも negotiated dialect が **0x0302 (SMB 3.0.2)** で上限。
  3.1.1 は喋らない。
- Samba 等の 3.1.1 対応サーバでは **0x0311 (SMB 3.1.1)** も対象。
- 3.1.1はAES-GMAC / AES-GCMをswift-cryptoで扱う。3.0.2のAES-CMACはCommonCrypto（Apple）と
  swift-crypto CryptoExtras（Linux）を使い、同一RFC 4493 vectorで結果を照合する。pure-Swift CMACは
  differential test用に残す。AES-128-CCMはCommonCrypto（Apple）/ in-repo pure Swift（Linux）で扱う。
