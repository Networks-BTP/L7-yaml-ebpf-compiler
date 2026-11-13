#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-9999}"
DURATION="${DURATION:-10}"
COUNT="${COUNT:-0}"
SENT_COUNT="${SENT_COUNT:-0}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
OUT_DIR="${OUT_DIR:-logs}"
MODE="${MODE:-userspace}"
XDP_IFACE="${XDP_IFACE:-eno3}"

mkdir -p "$OUT_DIR"
export MODE

case "$MODE" in
  userspace)
    python3 udp_receiver_userspace.py \
      --host "$HOST" \
      --port "$PORT" \
      --duration "$DURATION" \
      --count "$COUNT" \
      --sent-count "$SENT_COUNT" \
      --sample-interval "$SAMPLE_INTERVAL" \
      --out-dir "$OUT_DIR"
    ;;
  xdp)
    if [[ ! -x "generated/loader" ]]; then
      echo "Telemetry loader not found at generated/loader." >&2
      echo "On Linux, generate telemetry output with:" >&2
      echo "  ./build/dslc --telemetry sampleprotocol.yaml Exp2/generated" >&2
      echo "  make -C Exp2/generated" >&2
      exit 1
    fi
    STATS_LOG="$OUT_DIR/xdp_stats.log"
    LOADER_PID=""
    stop_loader() {
      if [[ -n "$LOADER_PID" ]]; then
        sudo kill -INT "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" || true
        LOADER_PID=""
      fi
    }
    trap stop_loader EXIT INT TERM

    echo "Attaching telemetry XDP program to $XDP_IFACE"
    sudo ./generated/loader -q -s 1 "$XDP_IFACE" >"$STATS_LOG" 2>&1 &
    LOADER_PID=$!
    for _ in {1..100}; do
      if grep -q "attached to $XDP_IFACE" "$STATS_LOG"; then
        break
      fi
      if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        cat "$STATS_LOG" >&2
        exit 1
      fi
      sleep 0.1
    done
    if ! grep -q "attached to $XDP_IFACE" "$STATS_LOG"; then
      echo "Timed out waiting for the XDP loader to attach." >&2
      cat "$STATS_LOG" >&2
      exit 1
    fi

    python3 udp_receiver_userspace.py \
      --host "$HOST" \
      --port "$PORT" \
      --duration "$DURATION" \
      --count "$COUNT" \
      --sent-count "$SENT_COUNT" \
      --sample-interval "$SAMPLE_INTERVAL" \
      --out-dir "$OUT_DIR"
    stop_loader
    echo "[receiver] XDP counters (matched/parsed/rejected/filtered): $STATS_LOG"
    tail -n 2 "$STATS_LOG"
    ;;
  *)
    echo "Unknown MODE: $MODE (expected userspace or xdp)" >&2
    exit 2
    ;;
 esac
