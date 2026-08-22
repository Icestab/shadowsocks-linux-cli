#!/usr/bin/env bash
# sscli 远程一键安装脚本
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/Icestab/shadowsocks-linux-cli/master/scripts/install-remote.sh | bash
#
# 环境变量:
#   SS_VERSION   指定版本（默认安装最新 Release，如 v0.1.1）
#   PREFIX       安装前缀（默认 /usr/local）
#   SUDO         覆盖提权命令（如 SUDO="" 且以 root 运行）
#
# 流程: 探测架构 -> 解析最新版本 -> 下载 Release 包 -> SHA256 校验
#       -> 解压 -> 调用包内 install.sh（含 sslocal/规则/配置模板）
set -euo pipefail

REPO="Icestab/shadowsocks-linux-cli"

log() { echo "[sscli-installer] $*"; }
die() { echo "[sscli-installer] 错误: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"; }
need curl; need tar; need sha256sum

case "$(uname -s):$(uname -m)" in
    Linux:x86_64)          PKG_ARCH=x86_64 ;;
    Linux:aarch64|Linux:arm64) PKG_ARCH=aarch64 ;;
    *) die "仅支持 Linux x86_64/aarch64（当前: $(uname -s):$(uname -m)）" ;;
esac

# ---- 解析要安装的版本 ----------------------------------------------------
if [ "${SS_VERSION:-}" != "" ]; then
    TAG="$SS_VERSION"
else
    log "查询最新版本..."
    # releases/latest 会 302 到 /tag/vX.Y.Z，取最终 URL 的末段即为 tag。
    TAG=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" \
        | awk -F'/tag/' '{print $2}')
    [ -n "$TAG" ] || die "无法解析最新版本号（网络不通？可指定 SS_VERSION=重试）"
fi
log "目标版本: $TAG ($PKG_ARCH)"

BASE="https://github.com/${REPO}/releases/download/${TAG}"
TARBALL="sscli-${TAG}-linux-${PKG_ARCH}.tar.xz"

# ---- 下载 + 校验 ----------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
log "下载 ${TARBALL} ..."
curl -fsSL --retry 5 --max-time 600 -o "$TMP/$TARBALL" "${BASE}/${TARBALL}"
curl -fsSL --retry 5 --max-time 120 -o "$TMP/${TARBALL}.sha256" "${BASE}/${TARBALL}.sha256"

EXPECTED_SHA=$(awk 'NR==1{print $1}' "$TMP/${TARBALL}.sha256")
ACTUAL_SHA=$(sha256sum "$TMP/$TARBALL" | awk '{print $1}')
[ -n "$EXPECTED_SHA" ] && [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] \
    || die "SHA256 校验失败（期望 $EXPECTED_SHA，实际 $ACTUAL_SHA）"
log "SHA256 校验通过"

# ---- 解压并执行包内安装 --------------------------------------------------
tar xJf "$TMP/$TARBALL" -C "$TMP"
PKG_DIR="$TMP/sscli-${TAG}-linux-${PKG_ARCH}"
[ -x "$PKG_DIR/install.sh" ] || die "发布包内容异常（缺少 install.sh）"

cd "$PKG_DIR"
export SUDO="${SUDO-sudo}"
[ "${PREFIX:-}" != "" ] && export PREFIX
log "开始安装（如提示输入密码，是 sudo 提权用于写入系统目录与配置 TUN）..."
./install.sh

log "完成！运行 'sudo sscli start' 启动。"
