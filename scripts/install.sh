#!/usr/bin/env bash
# sscli 一键安装脚本
#
# 用法:
#   ./scripts/install.sh            # 安装到 /usr/local，配置放 /etc/sscli
#   PREFIX=~/.local ./scripts/install.sh   # 用户级安装（无需 root，装到 ~/.local）
#
# 完成内容:
#   1. 构建 sscli
#   2. 安装 sslocal（优先复用 .toolchain/ss-rust 缓存，否则从 GitHub 下载）
#   3. 安装二进制到系统路径
#   4. 生成交互式配置模板
#   5. 下载分流规则
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=${PREFIX:-/usr/local}
ETC=/etc/sscli
LIB=/var/lib/sscli
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SS_ARCH="x86_64" ;;
    aarch64) SS_ARCH="aarch64" ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

USE_SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then USE_SUDO=""; fi

step() { echo; echo "==> $1"; }

step "1/6 构建 sscli"
cd "$PROJECT_ROOT"
. scripts/env.sh
go build -trimpath -ldflags "-s -w" -o bin/sscli ./cmd/sscli
echo "    bin/sscli 构建完成"

step "2/6 准备 sslocal"
CACHED="$PROJECT_ROOT/.toolchain/ss-rust/sslocal"
if [ -x "$CACHED" ]; then
    echo "    使用已缓存的预编译 sslocal: $CACHED"
    SSLOCAL_SRC="$CACHED"
else
    # 固定版本号（可用 SS_TAG=xxx 覆盖），避免 latest 指向未知构建。
    SS_TAG=${SS_TAG:-v1.24.0}
    URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_TAG}/shadowsocks-${SS_TAG}.${SS_ARCH}-unknown-linux-musl.tar.xz"
    SHA_URL="${URL}.sha256"
    echo "    从 GitHub 下载: $URL"
    mkdir -p .toolchain/ss-rust
    curl -sL --retry 5 -C - -o .toolchain/ss-rust.tar.xz "$URL"
    curl -sL --retry 5 -o .toolchain/ss-rust.tar.xz.sha256 "$SHA_URL"
    echo "    校验 SHA256 ..."
    # 校验文件里记录的是原始发布文件名，与我们保存的 ss-rust.tar.xz 不同，
    # 所以不能直接 sha256sum -c，改为提取哈希值比对。
    EXPECTED_SHA=$(awk 'NR==1{print $1}' .toolchain/ss-rust.tar.xz.sha256)
    ACTUAL_SHA=$(sha256sum .toolchain/ss-rust.tar.xz | awk '{print $1}')
    if [ -z "$EXPECTED_SHA" ] || [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
        echo "    SHA256 校验失败！下载的 sslocal 可能被篡改或损坏，中止安装。" >&2
        exit 1
    fi
    echo "    SHA256 校验通过 ($ACTUAL_SHA)"
    tar xJf .toolchain/ss-rust.tar.xz -C .toolchain/ss-rust sslocal ssserver
    SSLOCAL_SRC=".toolchain/ss-rust/sslocal"
fi

step "3/6 安装文件到 $PREFIX"
$USE_SUDO install -Dm755 bin/sscli "$PREFIX/bin/sscli"
$USE_SUDO install -Dm755 "$SSLOCAL_SRC" "$PREFIX/bin/sslocal"

step "4/6 生成配置"
CONF_SRC="$HOME/.config/sscli/config.yaml"
if [ "$USE_SUDO" = "sudo" ]; then
    CONF_DST="$ETC/config.yaml"
    $USE_SUDO mkdir -p "$ETC/rules" "$LIB"
    if [ ! -f "$CONF_DST" ]; then
        if [ ! -f "$CONF_SRC" ]; then
            "$PROJECT_ROOT/bin/sscli" config init
        else
            echo "    复用现有 ~/.config/sscli/config.yaml 作为模板"
        fi
        $USE_SUDO cp "$CONF_SRC" "$CONF_DST"
        $USE_SUDO chmod 600 "$CONF_DST"
        # 只删除模板文件本身；目录里可能还有已下载的规则（rules/），不能整目录删。
        rm -f "$CONF_SRC"
        echo "    配置模板: $CONF_DST （权限 600）— 稍后编辑服务器信息"
    else
        echo "    已有配置，保留: $CONF_DST"
    fi
else
    CONF_DST="$HOME/.config/sscli/config.yaml"
    [ -f "$CONF_DST" ] || "$PROJECT_ROOT/bin/sscli" config init
    echo "    配置: $CONF_DST"
fi

step "5/6 下载分流规则"
"$PROJECT_ROOT/bin/sscli" --config "$CONF_DST" update

step "6/6 自检"
"$PROJECT_ROOT/bin/sscli" --config "$CONF_DST" test || true

cat <<EOF

安装完成。接下来：
  1. 编辑服务器信息:   ${USE_SUDO:+sudo }vim $CONF_DST
     (server.address / port / method / password)
  2. 再次自检确认:     $PREFIX/bin/sscli test
  3. 启动:             sudo sscli start
     停止:             sudo sscli stop（任何方式退出都会自动恢复网络）
EOF
