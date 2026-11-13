#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-9999}"
RATE="${RATE:-1000}"
DURATION="${DURATION:-10}"
MIN_LEN="${MIN_LEN:-8}"
MAX_LEN="${MAX_LEN:-64}"
MATCH_PROB="${MATCH_PROB:-0.5}"
OUT_DIR="${OUT_DIR:-logs}"

mkdir -p "$OUT_DIR"

python3 udp_sender.py \
  --host "$HOST" \
  --port "$PORT" \
  --rate "$RATE" \
  --duration "$DURATION" \
  --min-len "$MIN_LEN" \
  --max-len "$MAX_LEN" \
  --match-prob "$MATCH_PROB" \
  --out-dir "$OUT_DIR"
