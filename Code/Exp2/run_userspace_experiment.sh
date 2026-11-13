#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-9999}"
RATE="${RATE:-1000}"
DURATION="${DURATION:-10}"
HOST="${HOST:-127.0.0.1}"
OUT_DIR="${OUT_DIR:-logs}"

mkdir -p "$OUT_DIR"

python3 udp_receiver_userspace.py --host 0.0.0.0 --port "$PORT" --duration "$DURATION" --out-dir "$OUT_DIR" > "$OUT_DIR/receiver.log" 2>&1 &
RECV_PID=$!

sleep 0.5
python3 udp_sender.py --host "$HOST" --port "$PORT" --rate "$RATE" --duration "$DURATION" --out-dir "$OUT_DIR" > "$OUT_DIR/sender.log" 2>&1

wait "$RECV_PID"
python3 summarize_latency.py --csv "$OUT_DIR/userspace_metrics.csv"

echo "logs are in $OUT_DIR"
