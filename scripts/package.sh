#!/usr/bin/env bash
# 打包发布产物：构建指定架构的静态 sscli，组装成"解压即可安装"的 tar.xz。
#
# 用法:
#   ./scripts/package.sh <版本号> [x86_64|aarch64]
# 示例:
#   ./scripts/package.sh v0.1.0            # 当前架构
#   ./scripts/package.sh v0.1.0 aarch64    # 交叉编译 ARM64
#
# 产物: dist/sscli-<版本>-linux-<架构>.tar.xz(.sha256)
set -euo pipefail

VERSION=${1:?用法: package.sh <版本号> [x86_64|aarch64]}
GOARCH_IN=${2:-$(uname -m)}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$GOARCH_IN" in
    x86_64|amd64) GOARCH=amd64;  PKG_ARCH=x86_64 ;;
    aarch64|arm64) GOARCH=arm64; PKG_ARCH=aarch64 ;;
    *) echo "不支持的架构: $GOARCH_IN"; exit 1 ;;
esac

cd "$PROJECT_ROOT"
. scripts/env.sh

echo "==> 构建 linux/$PKG_ARCH ($VERSION)"
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "dist/sscli-$VERSION-linux-$PKG_ARCH/sscli" ./cmd/sscli

echo "==> 组装发布目录"
STAGE="dist/sscli-$VERSION-linux-$PKG_ARCH"
cp scripts/install.sh "$STAGE/"
cp README.md LICENSE "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/sscli"

echo "==> 打包"
TARBALL="dist/sscli-$VERSION-linux-$PKG_ARCH.tar.xz"
tar -cJf "$TARBALL" -C dist "sscli-$VERSION-linux-$PKG_ARCH"
( cd dist && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo "完成:"
ls -la "$TARBALL" "$TARBALL.sha256"
