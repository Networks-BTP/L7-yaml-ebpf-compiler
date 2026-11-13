#!/usr/bin/env bash
set -euo pipefail

IFACE="${XDP_IFACE:-eth0}"
OBJ="${1:-generated/tracer.bpf.o}"

if [[ ! -f "$OBJ" ]]; then
  echo "BPF object not found: $OBJ" >&2
  exit 1
fi

sudo ip link set dev "$IFACE" xdp off || true
sudo ip link set dev "$IFACE" xdpgeneric obj "$OBJ" sec xdp

echo "XDP program loaded on $IFACE using $OBJ"
