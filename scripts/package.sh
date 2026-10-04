#!/usr/bin/env bash
# 打包发布产物：构建指定架构的静态 sscli，组装成"解压即可安装"的 tar.xz。
#
# 包内容力求离线自足：
#   sscli            静态编译的主程序
#   sslocal          shadowsocks-rust 官方预编译（固定版本 + SHA256 校验）
#   rules/           打包时点的三份路由规则（解决无代理新机的引导问题）
#   install.sh       安装脚本（检测到包内资源即离线安装）
#   README/LICENSE
#
# 用法:
#   ./scripts/package.sh <版本号> [x86_64|aarch64]
# 示例:
#   ./scripts/package.sh v0.2.0            # 当前架构
#   ./scripts/package.sh v0.2.0 aarch64    # 交叉编译 ARM64
#
# 产物: dist/sscli-<版本>-linux-<架构>.tar.xz(.sha256)
set -euo pipefail

VERSION=${1:?用法: package.sh <版本号> [x86_64|aarch64]}
GOARCH_IN=${2:-$(uname -m)}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SS_TAG=${SS_TAG:-v1.25.0}

case "$GOARCH_IN" in
    x86_64|amd64) GOARCH=amd64;  PKG_ARCH=x86_64; SS_ARCH="x86_64" ;;
    aarch64|arm64) GOARCH=arm64; PKG_ARCH=aarch64; SS_ARCH="aarch64" ;;
    *) echo "不支持的架构: $GOARCH_IN"; exit 1 ;;
esac

cd "$PROJECT_ROOT"
. scripts/env.sh

echo "==> 构建 linux/$PKG_ARCH ($VERSION)"
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "dist/sscli-$VERSION-linux-$PKG_ARCH/sscli" ./cmd/sscli

STAGE="dist/sscli-$VERSION-linux-$PKG_ARCH"

echo "==> 准备 sslocal ($SS_TAG/$SS_ARCH)"
mkdir -p "$STAGE/bin"
CACHED=".toolchain/ss-rust/sslocal"
if [ -x "$CACHED" ] && [ "$(uname -m)" = "$GOARCH_IN" ]; then
    cp "$CACHED" "$STAGE/bin/sslocal"
    echo "    复用本地缓存"
else
    URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_TAG}/shadowsocks-${SS_TAG}.${SS_ARCH}-unknown-linux-musl.tar.xz"
    mkdir -p .toolchain/ss-rust
    curl -sL --retry 5 -C - -o .toolchain/ss-rust.tar.xz "$URL"
    curl -sL --retry 5 -o .toolchain/ss-rust.tar.xz.sha256 "${URL}.sha256"
    EXPECTED_SHA=$(awk 'NR==1{print $1}' .toolchain/ss-rust.tar.xz.sha256)
    ACTUAL_SHA=$(sha256sum .toolchain/ss-rust.tar.xz | awk '{print $1}')
    if [ -z "$EXPECTED_SHA" ] || [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
        echo "    SHA256 校验失败，中止。" >&2
        exit 1
    fi
    tar xJf .toolchain/ss-rust.tar.xz -C .toolchain/ss-rust sslocal
    cp .toolchain/ss-rust/sslocal "$STAGE/bin/sslocal"
    echo "    已下载并校验: $ACTUAL_SHA"
fi
chmod +x "$STAGE/bin/sslocal"

echo "==> 抓取打包时点的路由规则"
mkdir -p "$STAGE/rules" .toolchain/rules
RULE_URLS="
gfw.list|https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
china-domains.list|https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
china-ipv4.list|https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt
"
FAILED=0
while IFS='|' read -r name url; do
    [ -z "$name" ] && continue
    dest="$STAGE/rules/$name"
    if curl -sL --retry 5 --max-time 180 -C - -o "$dest" "$url" \
       && [ "$(wc -c <"$dest")" -ge 1024 ]; then
        cp "$dest" ".toolchain/rules/$name"   # 成功的版本留作本地缓存
        echo "    $name  在线抓取 OK ($(wc -c <"$dest") bytes)"
    elif [ -s ".toolchain/rules/$name" ]; then
        # 网络不通时退回上次成功抓取的缓存基线。
        cp ".toolchain/rules/$name" "$dest"
        echo "    $name  在线失败，使用本地缓存基线 ($(wc -c <"$dest") bytes)"
    else
        echo "    $name  在线失败且无缓存，中止。" >&2
        FAILED=1
    fi
done <<< "$RULE_URLS"
[ "$FAILED" -eq 0 ] || exit 1
ls -la "$STAGE/rules/"

echo "==> 组装发布目录"
cp scripts/install.sh "$STAGE/"
cp README.md LICENSE "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/sscli"

echo "==> 打包"
TARBALL="dist/sscli-$VERSION-linux-$PKG_ARCH.tar.xz"
tar -cJf "$TARBALL" -C dist "sscli-$VERSION-linux-$PKG_ARCH"
( cd dist && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo "完成:"
ls -la "$TARBALL" "$TARBALL.sha256"
