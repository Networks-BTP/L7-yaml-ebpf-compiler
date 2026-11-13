#!/usr/bin/env python3
import argparse
import csv
import os
import resource
import socket
import sys
import time
from pathlib import Path


def parse_packet(data: bytes):
    if len(data) < 3:
        return None, None, None, False, "truncated"

    body_len = int.from_bytes(data[:2], byteorder="big", signed=False)
    flag = data[2]
    body = data[3:3 + body_len]

    if len(body) != body_len:
        return None, flag, None, False, "payload-short"
    if len(body) < 8:
        return body_len, flag, None, False, "timestamp-short"

    send_ts_ns = int.from_bytes(body[:8], byteorder="big", signed=False)
    return body_len, flag, send_ts_ns, (flag == 1), "ok"


def percentile(values, p):
    if not values:
        return 0.0
    xs = sorted(values)
    idx = max(0, min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1)))))
    return xs[idx]


def read_host_cpu_times():
    with open("/proc/stat", "r", encoding="utf-8") as cpu_file:
        fields = cpu_file.readline().split()
    if not fields or fields[0] != "cpu":
        raise RuntimeError("Could not read aggregate CPU counters from /proc/stat")
    values = [int(value) for value in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def host_cpu_percent(previous, current):
    total_delta = current[0] - previous[0]
    idle_delta = current[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    return 100.0 * (1.0 - idle_delta / total_delta)


def process_cpu_seconds():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive toyproto UDP packets and collect performance metrics")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--duration", type=float, default=10.0, help="Run duration in seconds; <= 0 runs until count or Ctrl-C")
    parser.add_argument("--count", type=int, default=0, help="Stop after this many received packets; 0 disables count limit")
    parser.add_argument("--sample-interval", type=float, default=1.0, help="CPU/throughput sampling interval in seconds")
    parser.add_argument("--sent-count", type=int, default=0, help="Sender's total sent packet count for estimated end-to-end loss")
    parser.add_argument("--out-dir", type=str, default="logs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.sample_interval <= 0:
        raise ValueError("--sample-interval must be greater than zero")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    packet_csv = out_dir / "receiver_packets.csv"
    interval_csv = out_dir / "receiver_intervals.csv"
    summary_csv = out_dir / "receiver_summary.csv"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(min(args.sample_interval, 0.5))
    sock.bind((args.host, args.port))

    start_mono = time.monotonic()
    start_wall_ns = time.time_ns()
    deadline = start_mono + args.duration if args.duration > 0 else None
    interval_start = start_mono
    next_sample = start_mono + args.sample_interval
    previous_host_cpu = read_host_cpu_times()
    previous_process_cpu = process_cpu_seconds()

    packet_id = 0
    received_bytes = 0
    accepted = 0
    filtered_out = 0
    invalid = 0
    latencies_ns = []
    host_cpu_samples = []
    process_cpu_samples = []
    interval_packets = 0
    interval_bytes = 0
    interval_accepted = 0
    interval_filtered = 0
    interval_invalid = 0

    def write_interval(writer, now):
        nonlocal interval_start, next_sample
        nonlocal interval_packets, interval_bytes, interval_accepted, interval_filtered, interval_invalid
        nonlocal previous_host_cpu, previous_process_cpu

        elapsed = now - interval_start
        if elapsed <= 0:
            return
        current_host_cpu = read_host_cpu_times()
        current_process_cpu = process_cpu_seconds()
        host_percent = host_cpu_percent(previous_host_cpu, current_host_cpu)
        process_percent = 100.0 * (current_process_cpu - previous_process_cpu) / elapsed
        host_cpu_samples.append(host_percent)
        process_cpu_samples.append(process_percent)
        writer.writerow([
            time.time_ns(), f"{elapsed:.6f}", interval_packets, interval_bytes,
            f"{interval_packets / elapsed:.3f}",
            f"{(interval_bytes * 8 / elapsed) / 1_000_000:.3f}",
            interval_accepted, interval_filtered, interval_invalid,
            f"{host_percent:.3f}", f"{process_percent:.3f}",
        ])
        previous_host_cpu = current_host_cpu
        previous_process_cpu = current_process_cpu
        interval_start = now
        next_sample = now + args.sample_interval
        interval_packets = interval_bytes = 0
        interval_accepted = interval_filtered = interval_invalid = 0

    try:
        with packet_csv.open("w", newline="") as packet_file, interval_csv.open("w", newline="") as interval_file:
            packet_writer = csv.writer(packet_file)
            interval_writer = csv.writer(interval_file)
            packet_writer.writerow([
                "packet_id", "recv_ts_unix_ns", "send_ts_unix_ns", "one_way_latency_ns",
                "udp_payload_bytes", "body_len", "flag", "accepted", "filtered", "invalid",
            ])
            interval_writer.writerow([
                "interval_end_unix_ns", "interval_seconds", "received_packets", "received_bytes",
                "packets_per_second", "mbps", "accepted", "filtered", "invalid",
                "host_cpu_percent", "receiver_process_cpu_percent",
            ])

            while True:
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    break
                if args.count > 0 and packet_id >= args.count:
                    break

                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    now = time.monotonic()
                    if now >= next_sample:
                        write_interval(interval_writer, now)
                    continue

                recv_ts_ns = time.time_ns()
                body_len, flag, send_ts_ns, matched, status = parse_packet(data)
                received_bytes += len(data)
                interval_packets += 1
                interval_bytes += len(data)

                if status != "ok":
                    invalid += 1
                    interval_invalid += 1
                    packet_writer.writerow([
                        packet_id, recv_ts_ns, "", "", len(data),
                        "" if body_len is None else body_len,
                        "" if flag is None else flag, 0, 0, 1,
                    ])
                else:
                    latency_ns = recv_ts_ns - send_ts_ns
                    latencies_ns.append(latency_ns)
                    if matched:
                        accepted += 1
                        interval_accepted += 1
                    else:
                        filtered_out += 1
                        interval_filtered += 1
                    packet_writer.writerow([
                        packet_id, recv_ts_ns, send_ts_ns, latency_ns, len(data),
                        body_len, flag, int(matched), int(not matched), 0,
                    ])

                packet_id += 1
                now = time.monotonic()
                if now >= next_sample:
                    write_interval(interval_writer, now)
    except KeyboardInterrupt:
        print("[receiver] interrupted; writing final metrics")
    finally:
        sock.close()

    end_mono = time.monotonic()
    if end_mono > interval_start:
        with interval_csv.open("a", newline="") as interval_file:
            write_interval(csv.writer(interval_file), end_mono)

    elapsed = max(end_mono - start_mono, 1e-9)
    valid_count = len(latencies_ns)
    summary = {
        "mode": os.environ.get("MODE", "userspace"),
        "start_unix_ns": start_wall_ns,
        "duration_seconds": f"{elapsed:.6f}",
        "received_packets": packet_id,
        "received_bytes": received_bytes,
        "sender_reported_packets": args.sent_count if args.sent_count > 0 else "",
        "sent_minus_socket_received_packets": max(args.sent_count - packet_id, 0) if args.sent_count > 0 else "",
        "sent_minus_socket_received_percent": (
            f"{100.0 * max(args.sent_count - packet_id, 0) / args.sent_count:.3f}"
            if args.sent_count > 0 else ""
        ),
        "packets_per_second": f"{packet_id / elapsed:.3f}",
        "mbps": f"{(received_bytes * 8 / elapsed) / 1_000_000:.3f}",
        "host_cpu_avg_percent": f"{sum(host_cpu_samples) / len(host_cpu_samples):.3f}" if host_cpu_samples else "",
        "receiver_process_cpu_avg_percent": f"{sum(process_cpu_samples) / len(process_cpu_samples):.3f}" if process_cpu_samples else "",
        "accepted": accepted,
        "filtered": filtered_out,
        "invalid": invalid,
        "latency_samples": valid_count,
        "latency_mean_ns": f"{sum(latencies_ns) / valid_count:.3f}" if valid_count else "",
        "latency_p50_ns": f"{percentile(latencies_ns, 50):.3f}" if valid_count else "",
        "latency_p95_ns": f"{percentile(latencies_ns, 95):.3f}" if valid_count else "",
        "latency_p99_ns": f"{percentile(latencies_ns, 99):.3f}" if valid_count else "",
    }
    with summary_csv.open("w", newline="") as summary_file:
        writer = csv.DictWriter(summary_file, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)

    print(f"[receiver] received={packet_id}, bytes={received_bytes}, duration={elapsed:.2f}s")
    print(f"[receiver] throughput={packet_id / elapsed:.2f} packets/s, {(received_bytes * 8 / elapsed) / 1_000_000:.3f} Mbps")
    print(f"[receiver] accepted={accepted}, filtered={filtered_out}, invalid={invalid}")
    if args.sent_count > 0:
        not_received = max(args.sent_count - packet_id, 0)
        print(
            f"[receiver] sender-minus-socket-received={not_received}/{args.sent_count} "
            f"({100.0 * not_received / args.sent_count:.2f}%)"
        )
        if os.environ.get("MODE", "userspace") == "xdp":
            print("[receiver] in XDP mode this includes intentional kernel drops; use xdp_stats.log to separate them")
    if host_cpu_samples:
        print(f"[receiver] average host CPU={sum(host_cpu_samples) / len(host_cpu_samples):.2f}%")
        print(f"[receiver] average receiver-process CPU={sum(process_cpu_samples) / len(process_cpu_samples):.2f}% of one core")
    if latencies_ns:
        print(
            "[receiver] one-way latency ns "
            f"mean={sum(latencies_ns) / valid_count:.2f}, "
            f"p50={percentile(latencies_ns, 50):.2f}, "
            f"p95={percentile(latencies_ns, 95):.2f}, "
            f"p99={percentile(latencies_ns, 99):.2f}"
        )
    print("[receiver] CPU averages and interval throughput are in receiver_intervals.csv")
    print(f"[receiver] packet details: {packet_csv}")
    print(f"[receiver] run summary: {summary_csv}")
    print("[receiver] one-way latency requires synchronized system clocks (e.g. chrony/PTP)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
