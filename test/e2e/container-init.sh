# This is the container init body passed to `bash -lc`; it runs inside the
# container and must not reference host-side variables or environment.
# It is passed as a single argv, so keep it small (ARG_MAX). If it needs to
# grow, switch to a bind mount.
# Keep fixture sentinel offsets/bytes and truncate size as literals in this
# one place. The Swift-side expectations in Tests/SMBeeTests/SMBeeE2ETests.swift
# are intentionally handwritten and independent so the test retains an
# independent oracle; if either side changes, update the other by hand.

    set -euxo pipefail
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba
    # smb.conf を /etc/samba にbind-mountすると samba-common の postinst が
    # read-only ファイルに書けず失敗するため、install 後に書き込み可能な場所へ cp する。
    cp /tmp/smbee-smb.conf /etc/samba/smb.conf
    mkdir -p /srv/smbee/public /srv/smbee/dfsroot
    useradd -M -s /usr/sbin/nologin smbee
    printf "smbee\nsmbee\n" | smbpasswd -a -s smbee
    printf "hello from SMBee E2E\n" > /srv/smbee/public/known.txt
    # Samba msdfs links are symlinks whose target uses the msdfs: prefix.
    ln -s "msdfs:127.0.0.1\\public" /srv/smbee/dfsroot/public-link
    ln -s "msdfs:127.0.0.1\\dfsroot\\public-link" /srv/smbee/dfsroot/chain-link
    ln -s "msdfs:127.0.0.1\\dfsroot\\loop-b" /srv/smbee/dfsroot/loop-a
    ln -s "msdfs:127.0.0.1\\dfsroot\\loop-a" /srv/smbee/dfsroot/loop-b
    # Sparse size = (UInt32.max - 64KiB) + 2MiB + 1 byte of end headroom.
    truncate -s 4296998912 /srv/smbee/public/large-4gib-plus.bin
    # Non-zero sentinel after 4GiB detects READ offset wrap to UInt32.
    dd if=/dev/zero bs=4096 count=1 iflag=fullblock status=none | LC_ALL=C tr "\\0" "\\245" | dd of=/srv/smbee/public/large-4gib-plus.bin bs=4096 seek=1048588 count=1 conv=notrunc iflag=fullblock status=none
    # 2 個目以降の READ offset の wrap 検出用（第 1 sentinel は最初の chunk 内に収まるため）。
    dd if=/dev/zero bs=4096 count=1 iflag=fullblock status=none | LC_ALL=C tr "\\0" "\\132" | dd of=/srv/smbee/public/large-4gib-plus.bin bs=4096 seek=1048817 count=1 conv=notrunc iflag=fullblock status=none
    chown -R smbee:smbee /srv/smbee
    smbd --version
    testparm -s
    exec smbd --foreground --no-process-group --debug-stdout --debuglevel=3
