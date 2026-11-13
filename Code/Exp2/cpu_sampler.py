#!/usr/bin/env python3
import argparse
import csv
import os
import time
from pathlib import Path


def read_system_cpu_times():
    with open('/proc/stat', 'r', encoding='utf-8') as fh:
        line = fh.readline().strip()
    fields = [int(v) for v in line.split()[1:]]
    return fields


def cpu_usage_percent(curr, prev):
    curr_total = sum(curr)
    prev_total = sum(prev)
    curr_idle = curr[3]
    prev_idle = prev[3]
    total_delta = curr_total - prev_total
    idle_delta = curr_idle - prev_idle
    if total_delta <= 0:
        return 0.0
    return 100.0 * (1.0 - (idle_delta / total_delta))


def main():
    p = argparse.ArgumentParser(description='Sample overall system CPU usage in Linux')
    p.add_argument('--duration', type=float, default=10.0)
    p.add_argument('--interval', type=float, default=0.1)
    p.add_argument('--out', type=str, default='logs/cpu_usage.csv')
    args = p.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    prev = read_system_cpu_times()
    start = time.monotonic_ns()
    deadline = start + int(args.duration * 1e9)

    with out_path.open('w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['ts_ns', 'cpu_percent'])
        while time.monotonic_ns() < deadline:
            time.sleep(args.interval)
            curr = read_system_cpu_times()
            ts = time.monotonic_ns()
            value = cpu_usage_percent(curr, prev)
            writer.writerow([ts, f'{value:.2f}'])
            prev = curr

    print(f'[cpu] wrote samples to {out_path}')


if __name__ == '__main__':
    main()
