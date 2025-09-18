#!/usr/bin/env bash
set -euo pipefail

# ====== 可按需修改的变量 ======
DONGLE_VOL_NAME="${USB_VOLUME_NAME:-qdreamer}"        # 加密狗U盘卷标，可用环境变量覆盖
DEVICE_DIR="/data/local/tmp/usb_crypto"               # 设备上 license.dat 存放路径
DEVICE_BIN="$DEVICE_DIR/usb_crypto"                   # 设备上你的可执行文件路径
PC_AUTH_BIN="./usb_crypto"                            # PC 上你的授权程序（可写绝对路径）
OUT_DIR="./out"                                       # PC 本地中转输出目录
ADB_BIN="${ADB_BIN:-adb}"                             # 可用环境变量覆盖 adb 路径

# ====== 帮助函数 ======
err() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
ok() { echo -e "\e[32m[OK]\e[0m $*"; }
info() { echo -e "\e[36m[INFO]\e[0m $*"; }

find_dongle_mount() {
  # Linux: 通过卷标找挂载点（尝试 /media/$USER、/run/media/$USER、/media 等）
  for base in "/run/media/$USER" "/media/$USER" "/media" "/Volumes"; do
    [[ -d "$base/$DONGLE_VOL_NAME" ]] && { echo "$base/$DONGLE_VOL_NAME"; return 0; }
  done
  return 1
}

# ====== 前置检查 ======
command -v "$ADB_BIN" >/dev/null || err "未找到 adb，请先安装 Android Platform-Tools。"
[[ -x "$PC_AUTH_BIN" ]] || err "未找到 PC 授权程序：$PC_AUTH_BIN（或无执行权限）"

# 设备连通性
$ADB_BIN get-state 1>/dev/null 2>&1 || err "未检测到已连接的 ADB 设备。"

# ====== 第1步：在设备上获取 HWID ======
info "在设备上生成并打印 HWID ..."
$ADB_BIN shell "mkdir -p '$DEVICE_DIR'"

# 这里运行你的程序一次，让它打印“当前硬件指纹:xxxx”
# 关键：禁用U盘流程，仅做本地HWID生成/打印，不要求有 license.dat
HW_LOG=$($ADB_BIN shell "RUN_ON_DEVICE=1 DISABLE_USB_FLOW=1 '$DEVICE_BIN' 2>/dev/null" || true)

echo "$HW_LOG" | sed -n '1,120p' >/dev/null  # 限制输出避免刷屏；可注释掉
HWID=$(echo "$HW_LOG" | grep -oE '([0-9a-f]{64})' | head -n1 || true)
[[ -n "${HWID:-}" ]] || err "未能从设备日志中提取 HWID。请检查设备二进制是否存在并会打印 HWID（例如包含“当前硬件指纹:”行）。"

ok "已获取设备 HWID: $HWID"

# ====== 第2步：在PC上消耗密钥并签发（写入U盘license.dat） ======
info "查找加密狗U盘挂载点（卷标=${DONGLE_VOL_NAME}) ..."
MNT=$(find_dongle_mount) || err "未找到卷标为 ${DONGLE_VOL_NAME} 的U盘，请确认已插入并成功挂载。"
ok "加密狗U盘挂载点：$MNT"

# 运行你的 PC 授权程序：它会在 U 盘里消费 key 并把 HWID 加入 license.dat
info "在PC上签发许可证（消耗一条密钥并写入 HWID） ..."
( export TARGET_HWID_HEX="$HWID"; "$PC_AUTH_BIN" )

# 基本校验：U盘上要能看到 license.dat
[[ -f "$MNT/license.dat" ]] || err "签发后未在U盘发现 license.dat：$MNT/license.dat"

# ====== 第3步：下发 license.dat 到设备 ======
mkdir -p "$OUT_DIR"
cp -f "$MNT/license.dat" "$OUT_DIR/license.dat"
ok "已从U盘复制 license.dat → $OUT_DIR/license.dat"

info "推送 license.dat 到设备：$DEVICE_DIR ..."
$ADB_BIN shell "mkdir -p '$DEVICE_DIR'"
$ADB_BIN push "$OUT_DIR/license.dat" "$DEVICE_DIR/license.dat" >/dev/null

# ====== 第4步：设备侧离线自检 ======
info "触发设备侧本地许可证验证 ..."
VERIFY_LOG=$($ADB_BIN shell "RUN_ON_DEVICE=1 DISABLE_USB_FLOW=1 TARGET_LICENSE_DIR='$DEVICE_DIR' '$DEVICE_BIN' 2>/dev/null" || true)

echo "$VERIFY_LOG" | sed -n '1,120p' >/dev/null  # 控制屏幕输出

# 你程序里的成功关键字（可按你日志实际改成更严谨的判断）
echo "$VERIFY_LOG" | grep -qE '设备已注册|验证成功|初始化.*成功' \
  && ok "授权成功：设备已可在无加密狗情况下本地验证运行。" \
  || err "设备侧验证未检测到成功标志，请检查设备日志。"

