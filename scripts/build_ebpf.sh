#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
mkdir -p "$BUILD_DIR"

if [[ ! -f "$BUILD_DIR/vmlinux.h" ]]; then
  if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "Missing /sys/kernel/btf/vmlinux. Install kernel BTF data or provide build/vmlinux.h" >&2
    exit 1
  fi
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$BUILD_DIR/vmlinux.h"
fi

clang -O2 -g -Wall -target bpf \
  -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
  -I"$BUILD_DIR" \
  -c "$ROOT_DIR/ebpf/xdp_ddos_kern.c" \
  -o "$BUILD_DIR/xdp_ddos_kern.o"

echo "Built $BUILD_DIR/xdp_ddos_kern.o"
