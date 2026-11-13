#!/usr/bin/env python3
"""Plot generated C LOC and XDP verifier/attach outcomes from results.csv."""

import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_csv", type=Path, help="CSV emitted by run_scalability.py")
    parser.add_argument(
        "--output",
        type=Path,
        help="PNG path (default: scalability.png beside the CSV).",
    )
    args = parser.parse_args()
    if not args.results_csv.is_file():
        parser.error(f"results CSV not found: {args.results_csv}")

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        parser.error("matplotlib is required for plotting; install it with: python3 -m pip install matplotlib")

    with args.results_csv.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))
    if not rows:
        parser.error("results CSV contains no experiment rows")

    fields = [int(row["fields_total"]) for row in rows]
    loc_rows = [
        (int(row["fields_total"]), int(row["c_loc"]))
        for row in rows
        if row["c_loc"].strip()
    ]
    if not loc_rows:
        parser.error("results CSV contains no generated C LOC values")

    statuses = ("yes", "no", "unknown", "not_tested")
    labels = {
        "yes": "Verifier accepted (attach succeeded)",
        "no": "Verifier rejected",
        "unknown": "Attach failed; verifier result unknown",
        "not_tested": "Not tested",
    }
    colors = {"yes": "#2ca02c", "no": "#d62728", "unknown": "#ff7f0e", "not_tested": "#7f7f7f"}
    y = {status: index for index, status in enumerate(statuses)}

    figure, (loc_axis, verifier_axis) = plt.subplots(
        2, 1, figsize=(11, 8), sharex=True, constrained_layout=True
    )
    loc_axis.plot(
        [item[0] for item in loc_rows],
        [item[1] for item in loc_rows],
        marker=".",
        linewidth=1.5,
    )
    loc_axis.set_ylabel("Generated tracer.bpf.c LOC")
    loc_axis.set_title("Compiler scalability: generated code size and XDP verifier outcome")
    loc_axis.grid(True, alpha=0.3)

    plotted = set()
    for row in rows:
        status = row["verifier_safe"]
        if status not in y:
            continue
        label = labels[status] if status not in plotted else None
        verifier_axis.scatter(
            int(row["fields_total"]),
            y[status],
            color=colors[status],
            label=label,
            s=28,
        )
        plotted.add(status)
    verifier_axis.set_yticks([y[status] for status in statuses])
    verifier_axis.set_yticklabels([labels[status] for status in statuses])
    verifier_axis.set_xlabel("Fields in the protocol layout")
    verifier_axis.set_xlim(min(fields) - 1, max(fields) + 1)
    verifier_axis.grid(True, axis="x", alpha=0.3)
    verifier_axis.legend(loc="best", fontsize="small")

    output = args.output or args.results_csv.with_name("scalability.png")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=160)
    print(f"Plot written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
