# 074: [wire] 診断イベントに session 識別子がない

状態: **open（P3）**

`[wire]` 診断イベントに SMBClientSession の識別子がないため、複数 session を並行利用する
ケース（obaket のマルチタブなど）では、`first_fault` の因果を別 session と混同しうる。

## 対応案

SMBSession ごとに非機密な短縮 ID を生成し、全 `[wire]` イベントへ付与する。credit 待ちの
診断を出す `SMB2CreditWindow` にも、その ID を渡す必要がある。

P3。実機診断でこの混線が実際に調査を妨げた時点で着手する。
