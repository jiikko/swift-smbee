# 033 API: timeoutとkeepalive intervalの値域検証がない

- 種別: API contract / crash safety / resource usage
- 重要度: medium
- 状態: open
- 関連: `Sources/smbcli/SMBCLI.swift` (`TransportOptions`), `Sources/SMBee/POSIXSocketTransport.swift`, `Sources/SMBee/SMBClient.swift` (`startKeepAlive`)

## 問題

CLIのtimeout optionは任意の`Double`を受け、finite/正数の確認なしに`Int64`へ変換する。
NaN、infinity、Int64範囲外はruntime trapになり得る。負値と0も受理される。

POSIX transportは負のDurationを0へclampするが、socket timeoutのtimeval 0は一般にtimeout無効を意味し、
connectのpoll 0は即時timeoutになるため、同じ値でもoperationごとに意味が異なる。

public `startKeepAlive(interval:)`も0/負値を拒否せず、sleepが即時完了する場合はECHOのtight loopになる。

## 影響

- CLI引数だけでprocess crash、即時timeout、または意図しない無期限I/Oが起きる。
- keepalive設定ミスでserverとnetworkへ高頻度ECHOを送る。
- platform/operation間でtimeout semanticsが一致しない。

## 対応方針

1. CLI parse時にfiniteかつ0より大きく、実装上限以下であることをvalidateする。
2. libraryのDuration引数も共通validatorで拒否し、0の意味を明文化する。
3. POSIX timevalへの丸めで正のsub-microsecond値が0にならないよう最小値を定める。
4. keepalive intervalに安全な最小値を設定するか、少なくとも正値を必須にする。

## リグレッションテスト

- `nan`、`inf`、巨大値、負値、0のCLI timeoutがcrashせずValidationErrorになる。
- 正の小数timeoutがconnect/send/receiveで一貫した有限timeoutになる。
- 0/負のkeepalive intervalを拒否し、ECHOが送られない。
- 通常timeoutとkeepalive設定の既存挙動を維持する。

