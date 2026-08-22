#!/bin/sh
# Source this file for all sscli build/test commands.
# Keeps the entire Go toolchain state inside the project so builds work
# without touching $HOME.
# Works both when executed and when sourced.
_self="${BASH_SOURCE[0]:-$0}"
PROJECT_ROOT="$(cd "$(dirname "$_self")/.." && pwd)"
export GOBIN="$PROJECT_ROOT/bin"
export GOPATH="$PROJECT_ROOT/.toolchain/gopath"
export GOCACHE="$PROJECT_ROOT/.toolchain/gocache"
export GOMODCACHE="$GOPATH/pkg/mod"
export PATH="$GOBIN:$PATH"
