#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: $0 <iface>" >&2
  exit 1
fi

ip link set dev "$IFACE" xdpgeneric off || true
rm -f /sys/fs/bpf/xdp_ddos/xdp_ddos_guard || true

echo "Detached XDP program from $IFACE"
