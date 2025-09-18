#!/usr/bin/env bash
set -euo pipefail
export RUN_ON_DEVICE=1 
export DISABLE_USB_FLOW=1
OUT=out
DEV_PUSH_PATH="/data/local/tmp/usb_crypto"
DEV_LICENSE="$DEV_PUSH_PATH/license.dat"

mkdir -p "$OUT"

echo "[1/4] 采集音箱字段(ADB)..."
SERIAL=$(adb shell getprop ro.serialno | tr -d '\r')
BOOTSN=$(adb shell getprop ro.boot.serialno | tr -d '\r')
BOARD=$(adb shell getprop ro.product.board | tr -d '\r')
DTBSN=$(adb shell 'cat /proc/device-tree/serial-number 2>/dev/null' | tr -d '\r')
EMMC=$(adb shell 'cat /sys/block/mmcblk0/device/cid 2>/dev/null || cat /sys/block/mmcblk1/device/cid 2>/dev/null' | tr -d '\r')
MAC=$(adb shell 'cat /sys/class/net/wlan0/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null' | tr -d '\r' | tr '[:upper:]' '[:lower:]' | tr -d ':')

# 规范化并生成 HWID(hex)
echo "[2/4] 规范化并计算 HWID..."
PYOUT=$(python3 - <<'PY'
import json,hashlib,sys,os
import re
def norm_mac(s): 
    s=(s or "").strip().lower()
    return re.sub(r'[:-]','',s)
payload={
  "ver":1,
  "serial": os.environ.get("SERIAL","").strip() or os.environ.get("BOOTSN","").strip() or os.environ.get("DTBSN","").strip(),
  "board":  os.environ.get("BOARD","").strip(),
  "emmc_cid": os.environ.get("EMMC","").strip(),
  "mac": norm_mac(os.environ.get("MAC","")),
  "extras":{"vendor":"Lenovo","device":"speaker"}
}
canon=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
hwid=hashlib.sha256(canon).hexdigest()
open("out/hwid.json","w",encoding="utf-8").write(json.dumps({**payload,"hash_hex":hwid},ensure_ascii=False,indent=2))
open("out/hwid.hex","w").write(hwid+"\n")
print(hwid)
PY
)
echo "$PYOUT" > "$OUT/hwid.hex"
echo "HWID(hex)=$PYOUT"
export TARGET_HWID_HEX="$PYOUT"

echo "[3/4] 用加密狗生成 license（消耗一条 key）..."
# 注意：此处就是你的编译好的程序（会去找卷标为 qdreamer 的U盘、读取 valid_keys.dat 并写 license.dat）
# 建议 sudo 运行以便读写U盘和 /etc/usb_crypto
sudo env "TARGET_HWID_HEX=$PYOUT" ./usb_crypto

# 从U盘取出 license.dat（你的程序写在U盘根目录）
MNT=$(lsblk -o MOUNTPOINT,LABEL | awk '$2=="qdreamer"{print $1;exit}')
if [ -z "$MNT" ]; then echo "找不到加密狗(U盘 qdreamer)的挂载点"; exit 2; fi
cp "$MNT/license.dat" "$OUT/license.dat"
echo "license 已复制到 $OUT/license.dat"

echo "[4/4] 推送到音箱并创建持久目录..."
adb shell "mkdir -p '$DEV_PUSH_PATH'"
adb push "$OUT/license.dat" "$DEV_LICENSE" >/dev/null
echo "已推送到设备: $DEV_LICENSE"

echo "完成。现在在设备上运行你的应用/守护进程进行验证即可。"

