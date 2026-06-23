#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: $0 <iface>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ="$ROOT_DIR/build/xdp_ddos_kern.o"
PIN_ROOT="/sys/fs/bpf/xdp_ddos"

if [[ ! -f "$OBJ" ]]; then
  echo "Missing $OBJ. Run: make ebpf" >&2
  exit 1
fi

mkdir -p "$PIN_ROOT"

# Load and pin maps/program. If a previous pinned program exists, remove it first.
rm -f "$PIN_ROOT/xdp_ddos_guard"

bpftool prog load "$OBJ" "$PIN_ROOT/xdp_ddos_guard" type xdp pinmaps "$PIN_ROOT"
ip link set dev "$IFACE" xdpgeneric pinned "$PIN_ROOT/xdp_ddos_guard"

echo "Attached xdp_ddos_guard to $IFACE in xdpgeneric mode"
echo "Pinned maps under $PIN_ROOT"
