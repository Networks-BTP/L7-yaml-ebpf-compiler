#!/usr/bin/env python3
"""Generate, compile, and optionally try to attach protocols with 1..100 fields."""

import argparse
import csv
import datetime as dt
import os
import platform
import random
import shutil
import subprocess
import sys
from pathlib import Path


FIELD_KINDS = ("fixed", "length_prefixed", "delimiter")
VARIABLE_FIELD_LIMIT = 10
VERIFIER_FAILURE_HINTS = (
    "verifier",
    "invalid mem access",
    "invalid bpf",
    "unbounded",
    "program is too large",
    "too many instructions",
    "stack limit",
    "r0 !read_ok",
)


def make_protocol(field_count, rng):
    protocol = f"scale_{field_count:03d}"
    fields = [
        "      length: { type: fixed, data_type: int, size: 2 }",
    ]
    counts = {kind: 0 for kind in FIELD_KINDS}
    counts["fixed"] += 1

    for index in range(1, field_count):
        kind = rng.choice(FIELD_KINDS)
        name = f"field_{index:03d}"
        counts[kind] += 1
        if kind == "fixed":
            size = rng.choice((1, 2, 4))
            fields.append(
                f"      {name}: {{ type: fixed, data_type: int, size: {size} }}"
            )
        elif kind == "length_prefixed":
            fields.append(
                f"      {name}: {{ type: length_prefixed, length_field: length, "
                f"max_bytes: {VARIABLE_FIELD_LIMIT} }}"
            )
        else:
            fields.append(
                f'      {name}: {{ type: delimiter, marker: "|", '
                f"max_bytes: {VARIABLE_FIELD_LIMIT} }}"
            )

    yaml = "\n".join(
        [
            f"protocol: {protocol}",
            "transport: udp",
            "port: 9999",
            "",
            "types:",
            "  Payload:",
            "    fields:",
            *fields,
            "",
            "layout:",
            "  - name: payload",
            "    type: Payload",
            "",
        ]
    )
    return yaml, counts


def run_command(command, *, timeout=120):
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return subprocess.CompletedProcess(
            command, 124, stdout, f"Command timed out after {timeout} seconds.\n{stderr}"
        )


def write_process_log(path, command, result):
    with path.open("w", encoding="utf-8") as log:
        log.write("$ " + subprocess.list2cmdline([str(arg) for arg in command]) + "\n")
        log.write(f"exit_code: {result.returncode}\n\n")
        if result.stdout:
            log.write("stdout:\n" + result.stdout)
        if result.stderr:
            log.write("\nstderr:\n" + result.stderr)


def compiler_arch():
    machine = platform.machine().lower()
    architectures = {
        "x86_64": "x86",
        "amd64": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "riscv64": "riscv",
        "ppc64le": "powerpc",
        "s390x": "s390",
    }
    if machine not in architectures:
        raise RuntimeError(f"Unsupported BPF target architecture: {machine}")
    return architectures[machine]


def verifier_result(attach_succeeded, attach_output):
    if attach_succeeded:
        return "yes"
    lowered = attach_output.lower()
    if any(hint in lowered for hint in VERIFIER_FAILURE_HINTS):
        return "no"
    return "unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Generate protocol sizes 1..100, compile them, and test XDP attach."
    )
    parser.add_argument(
        "--interface",
        help="Linux network interface for generic XDP attach tests (required unless --no-attach).",
    )
    parser.add_argument(
        "--no-attach",
        action="store_true",
        help="Generate and compile only; do not attempt XDP attachment.",
    )
    parser.add_argument(
        "--min-fields", type=int, default=1, help="First field count to run (default: 1)."
    )
    parser.add_argument(
        "--max-fields", type=int, default=100, help="Last field count to run (default: 100)."
    )
    parser.add_argument(
        "--seed", type=int, default=1, help="Deterministic random seed (default: 1)."
    )
    parser.add_argument(
        "--compiler",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "build" / "dslc",
        help="Path to the built DSL compiler.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Experiment output directory (default: Exp1/results/run_<timestamp>).",
    )
    args = parser.parse_args()

    if not 1 <= args.min_fields <= args.max_fields <= 100:
        parser.error("field range must satisfy 1 <= --min-fields <= --max-fields <= 100")
    if args.no_attach and args.interface:
        parser.error("--interface cannot be combined with --no-attach")
    if not args.no_attach and not args.interface:
        parser.error("--interface is required unless --no-attach is specified")
    if not args.no_attach and os.geteuid() != 0:
        parser.error("XDP attach requires root; run with sudo, or use --no-attach")
    if not args.compiler.is_file():
        parser.error(
            f"Compiler not found at {args.compiler}. Build it first with "
            "'cmake -S Code -B Code/build && cmake --build Code/build -j'."
        )

    if not args.no_attach and shutil.which("ip") is None:
        parser.error("'ip' command not found; install iproute2 before running attach tests")

    try:
        arch = compiler_arch()
    except RuntimeError as exc:
        parser.error(str(exc))

    if args.output_dir:
        output_dir = args.output_dir.resolve()
    else:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(__file__).resolve().parent / "results" / f"run_{stamp}"
        suffix = 1
        base = output_dir
        while output_dir.exists():
            output_dir = base.with_name(f"{base.name}_{suffix:02d}")
            suffix += 1

    cases_dir = output_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=False)

    rng = random.Random(args.seed)
    attach_stop_reason = None
    results_path = output_dir / "results.csv"
    columns = [
        "fields_total",
        "fixed_fields",
        "length_prefixed_fields",
        "delimiter_fields",
        "c_loc",
        "generation_status",
        "compile_status",
        "xdp_attach_status",
        "verifier_safe",
        "detach_status",
        "error",
    ]

    print(f"Experiment output: {output_dir}")
    print(f"Random seed: {args.seed}")
    if not args.no_attach:
        print(
            f"Generic XDP tests on {args.interface}; no existing program will be "
            "detached before a test."
        )

    with results_path.open("w", newline="", encoding="utf-8") as results_file:
        writer = csv.DictWriter(results_file, fieldnames=columns)
        writer.writeheader()
        for field_count in range(args.min_fields, args.max_fields + 1):
            case_dir = cases_dir / f"fields_{field_count:03d}"
            case_dir.mkdir()
            yaml, counts = make_protocol(field_count, rng)
            yaml_path = case_dir / "protocol.yaml"
            yaml_path.write_text(yaml, encoding="utf-8")
            generated_dir = case_dir / "generated"
            generated_dir.mkdir()

            errors = []
            row = {
                "fields_total": field_count,
                "fixed_fields": counts["fixed"],
                "length_prefixed_fields": counts["length_prefixed"],
                "delimiter_fields": counts["delimiter"],
                "c_loc": "",
                "generation_status": "failed",
                "compile_status": "not_tested",
                "xdp_attach_status": "not_tested",
                "verifier_safe": "not_tested",
                "detach_status": "not_tested",
                "error": "",
            }

            generate_cmd = [str(args.compiler), str(yaml_path), str(generated_dir)]
            generated = run_command(generate_cmd)
            write_process_log(case_dir / "generate.log", generate_cmd, generated)
            if generated.returncode == 0:
                row["generation_status"] = "success"
            else:
                errors.append(f"generation: {(generated.stderr or generated.stdout).strip()}")

            c_source = generated_dir / "tracer.bpf.c"
            object_file = generated_dir / "tracer.bpf.o"
            if c_source.is_file():
                row["c_loc"] = len(c_source.read_text(encoding="utf-8").splitlines())

            if row["generation_status"] == "success":
                include_dirs = []
                multiarch = run_command(["gcc", "-print-multiarch"], timeout=10)
                if multiarch.returncode == 0 and multiarch.stdout.strip():
                    include_dir = Path("/usr/include") / multiarch.stdout.strip()
                    if include_dir.is_dir():
                        include_dirs.extend(["-I", str(include_dir)])
                compile_cmd = [
                    "clang",
                    "-O2",
                    "-g",
                    "-target",
                    "bpf",
                    f"-D__TARGET_ARCH_{arch}",
                    *include_dirs,
                    "-c",
                    str(c_source),
                    "-o",
                    str(object_file),
                ]
                compiled = run_command(compile_cmd)
                write_process_log(case_dir / "compile.log", compile_cmd, compiled)
                row["compile_status"] = (
                    "success" if compiled.returncode == 0 else "failed"
                )
                if compiled.returncode != 0:
                    errors.append(
                        f"compile: {(compiled.stderr or compiled.stdout).strip()}"
                    )

                if row["compile_status"] == "success" and not args.no_attach:
                    if attach_stop_reason:
                        errors.append(attach_stop_reason)
                    else:
                        attach_cmd = [
                            "ip",
                            "link",
                            "set",
                            "dev",
                            args.interface,
                            "xdpgeneric",
                            "obj",
                            str(object_file),
                            "sec",
                            "xdp",
                        ]
                        attached = run_command(attach_cmd, timeout=30)
                        attach_output = attached.stdout + attached.stderr
                        write_process_log(case_dir / "attach.log", attach_cmd, attached)
                        row["xdp_attach_status"] = (
                            "attached" if attached.returncode == 0 else "failed"
                        )
                        row["verifier_safe"] = verifier_result(
                            attached.returncode == 0, attach_output
                        )
                        if attached.returncode != 0:
                            errors.append(f"attach: {attach_output.strip()}")
                        else:
                            detach_cmd = [
                                "ip",
                                "link",
                                "set",
                                "dev",
                                args.interface,
                                "xdpgeneric",
                                "off",
                            ]
                            detached = run_command(detach_cmd, timeout=30)
                            write_process_log(case_dir / "detach.log", detach_cmd, detached)
                            row["detach_status"] = (
                                "success" if detached.returncode == 0 else "failed"
                            )
                            if detached.returncode != 0:
                                detach_error = (detached.stderr or detached.stdout).strip()
                                errors.append(f"detach: {detach_error}")
                                attach_stop_reason = (
                                    "attach tests stopped because the previous program "
                                    f"could not be detached: {detach_error}"
                                )

            row["error"] = " | ".join(errors)
            writer.writerow(row)
            results_file.flush()
            summary = (
                f"{field_count:3d} fields: {row['generation_status']}, "
                f"compile={row['compile_status']}, "
                f"attach={row['xdp_attach_status']}, "
                f"verifier_safe={row['verifier_safe']}"
            )
            print(summary)
            if row["error"]:
                print(f"  error: {row['error'].splitlines()[0][:240]}", file=sys.stderr)

    print(f"Results CSV: {results_path}")
    print(f"Per-case sources and logs: {cases_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
