# Exp1: compiler scalability and XDP verifier limits

`run_scalability.py` generates one protocol for every layout size from 1 to 100
fields. Each layout contains a fixed 2-byte length field followed by randomly
selected fixed, length-prefixed, and delimiter fields. Variable-length fields
are capped at 10 bytes. Delimiters use a one-byte marker because this compiler
supports markers up to 8 bytes.

## Linux prerequisites

- Build the compiler from the `Code` directory:

  ```sh
  cmake -S . -B build
  cmake --build build -j"$(nproc)"
  ```

- Install `clang`, `gcc`, Linux UAPI headers, `iproute2`, and the BPF headers
  (typically provided by `libbpf-dev`).
- For attach tests, use a dedicated test interface and run as root. Generic XDP
  is used for compatibility. The script does not detach an existing program
  before attempting an attach; attach errors are recorded rather than forcing a
  replacement. Each successful test attach is detached immediately afterward.

## Run

From `Code/Exp1`:

```sh
sudo python3 run_scalability.py --interface eth0
```

By default, the script tests all field counts from 1 through 100 using seed 1.
Each run gets a new directory under `results/`, including generated YAML and C,
compiled BPF objects, per-stage logs, and `results.csv`. Change the network
interface and seed as needed:

```sh
sudo python3 run_scalability.py --interface eth0 --seed 42
```

Generate and compile without attaching (for example, on a machine without XDP
privileges):

```sh
python3 run_scalability.py --no-attach --min-fields 1 --max-fields 10
```

The range options are useful for short reruns; the default experiment remains
1..100. The compiler executable defaults to `../build/dslc`; use `--compiler`
to select another build.

## Results and plots

`results.csv` contains one row per field count, with field-kind counts, physical
lines in generated `tracer.bpf.c`, generation/compile/attach status,
`verifier_safe`, and an error summary. Detailed stdout/stderr is retained in
the case directory.

`verifier_safe` is `yes` when the kernel accepted the program and the attach
command succeeded. It is `no` only when the attach diagnostic contains a
recognizable verifier rejection; other attach failures (for example, an
interface or permission problem) are `unknown`, not treated as verifier
failures. Results without an attach attempt are `not_tested`. If detaching a
successfully attached test program fails, the script stops attempting later
attaches and marks them `not_tested`.

If `detach_status` is `failed`, check the interface and remove the test
program manually when safe to do so:

```sh
sudo ip link set dev eth0 xdpgeneric off
```

Install matplotlib on the plotting machine, then run:

```sh
python3 -m pip install matplotlib
python3 plot_results.py results/run_<timestamp>/results.csv
```

The plot shows generated C LOC and verifier/attach outcomes against field
count. Review `error` and the matching `attach.log` before interpreting an
unknown result as a compiler limit.
