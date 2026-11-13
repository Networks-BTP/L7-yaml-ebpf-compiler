#!/usr/bin/env python3
import argparse
import csv
import os
import random
import socket
import struct
import sys
import time
from pathlib import Path


def build_packet(send_ts_ns: int, flag: int, body_len: int) -> bytes:
    """Build a toyproto UDP payload.

    Wire format:
      u16 length (big-endian)
      u8 flag
      body[body_len]

    The first 8 bytes of the body carry the sender timestamp, so the receiver can
    compute one-way latency without requiring a separate control channel.
    """
    if body_len < 8:
        body_len = 8
    body = struct.pack(">Q", send_ts_ns) + os.urandom(body_len - 8)
    return struct.pack(">H", body_len) + bytes([flag]) + body[:body_len]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Send random toyproto UDP packets")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--rate", type=float, default=1000.0, help="Packets per second")
    p.add_argument("--duration", type=float, default=10.0, help="Seconds to run")
    p.add_argument("--min-len", type=int, default=8)
    p.add_argument("--max-len", type=int, default=64)
    p.add_argument("--match-prob", type=float, default=0.5, help="Probability that flag == 1")
    p.add_argument("--out-dir", type=str, default="logs")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "sender_metrics.csv"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    interval = 1.0 / max(1e-6, args.rate)
    deadline = time.monotonic() + args.duration
    packet_id = 0
    start_ns = time.monotonic_ns()

    with csv_path.open("w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["packet_id", "send_ts_ns", "len", "flag", "payload_len", "rate_hz"])

        while True:
            now = time.monotonic()
            if args.duration > 0 and now >= deadline:
                break

            # Cross-host one-way latency requires wall clocks synchronized by NTP/PTP.
            send_ts_ns = time.time_ns()
            if random.random() < args.match_prob:
                flag = 1
            else:
                flag = random.randint(0, 255)
                if flag == 1:
                    flag = 2

            body_len = random.randint(args.min_len, args.max_len)
            packet = build_packet(send_ts_ns, flag, body_len)
            sock.sendto(packet, (args.host, args.port))

            writer.writerow([packet_id, send_ts_ns, body_len, flag, len(packet), args.rate])
            packet_id += 1

            # Keep a fixed packet rate.
            target_next = interval
            elapsed = time.monotonic() - now
            if elapsed < target_next:
                time.sleep(target_next - elapsed)

    print(f"[sender] sent {packet_id} packets to {args.host}:{args.port}")
    print(f"[sender] metrics written to {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
