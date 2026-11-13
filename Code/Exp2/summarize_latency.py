#!/usr/bin/env python3
import argparse
import csv
import statistics
from pathlib import Path


def percentile(values, pct):
    if not values:
        return 0.0
    xs = sorted(values)
    idx = max(0, min(len(xs) - 1, int(round((pct / 100.0) * (len(xs) - 1)))))
    return xs[idx]


def main():
    p = argparse.ArgumentParser(description='Summarize user-space latency CSV output')
    p.add_argument('--csv', type=str, required=True)
    args = p.parse_args()

    values = []
    total = 0
    accepted = 0
    filtered = 0
    invalid = 0

    with open(args.csv, newline='') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            total += 1
            if row['invalid'] == '1':
                invalid += 1
            else:
                lat = int(row['latency_ns'])
                values.append(lat)
                if int(row['accepted']) == 1:
                    accepted += 1
                if int(row['filtered']) == 1:
                    filtered += 1

    if values:
        mean = statistics.fmean(values)
        p50 = percentile(values, 50)
        p95 = percentile(values, 95)
        p99 = percentile(values, 99)
        print(f'total_packets={total}')
        print(f'accepted={accepted}, filtered={filtered}, invalid={invalid}')
        print(f'mean_latency_ns={mean:.2f}')
        print(f'p50={p50}, p95={p95}, p99={p99}')
    else:
        print('no valid latency samples found')


if __name__ == '__main__':
    main()
