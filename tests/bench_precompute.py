#!/usr/bin/env python3
#
# Rainbow Crackalack: tests/bench_precompute.py
#
# Tune the precomputation global work size without waiting on a real run.
#
# Precomputation is the most expensive phase of a lookup -- roughly
# chain_len^2 / 2 hash operations per hash -- so measuring it against a
# production chain length costs tens of minutes per data point.  The cost is
# quadratic in chain_len and the dispatch shape is identical, so a small chain
# length is a faithful and much cheaper proxy: at chain_len 40,000 a data point
# takes seconds instead of half an hour, while still exercising the same kernel
# with the same occupancy.
#
# It works by planting a throwaway table of random chains and looking up a hash
# that is not in it.  The lookup finds nothing, but it has to precompute first,
# which is the part being measured.  The precompute cache is cleared between
# runs so every data point actually does the work.
#
# Usage:
#   tests/bench_precompute.py                        # sweep the default sizes
#   tests/bench_precompute.py --chain-len 80000
#   tests/bench_precompute.py --gws 0 12288 98304    # 0 means "the built-in default"
#

import argparse
import glob
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.environ.get(
    "CRACKALACK_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOOKUP_PROG = os.path.join(REPO_ROOT, "crackalack_lookup")

KERNEL_DIRS = ("CL", "CUDA", "Metal")

# Not in the planted table, so the lookup precomputes and then finds nothing.
DEFAULT_HASH = "59b8beffd0c2aec5"

_PRECOMP_RE = re.compile(r"Precomputation:\s+(.*)")
_GWS_RE = re.compile(r"precompute GWS:\s+(\d+)")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_human_time(s):
    """The lookup reports e.g. '7.2 secs' or '1 mins, 3 secs'."""
    total = 0.0
    for value, unit in re.findall(r"([\d.]+)\s*(secs?|mins?|hours?|days?)", s):
        v = float(value)
        if unit.startswith("sec"):
            total += v
        elif unit.startswith("min"):
            total += v * 60
        elif unit.startswith("hour"):
            total += v * 3600
        elif unit.startswith("day"):
            total += v * 86400
    return total


def make_workdir():
    tmp = tempfile.mkdtemp(prefix="bench_precompute")
    for name in KERNEL_DIRS:
        src = os.path.join(REPO_ROOT, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(tmp, name))
            shutil.copy(os.path.join(REPO_ROOT, "shared.h"), os.path.join(tmp, name))
    return tmp


def plant_table(rt_dir, chain_len, num_chains):
    rng = random.Random(0xBE4C11)
    chains = sorted((rng.getrandbits(56), rng.getrandbits(56)) for _ in range(num_chains))
    path = os.path.join(rt_dir, "netntlmv1_byte#7-7_0_%ux%u_0.rt" % (chain_len, num_chains))
    with open(path, "wb") as f:
        for start, end in sorted(chains, key=lambda c: c[1]):
            f.write(struct.pack("<QQ", start, end))


def clear_precompute_cache(workdir):
    for path in glob.glob(os.path.join(workdir, "rcracki.precalc.*")):
        os.unlink(path)


def run_one(workdir, rt_dir, hashes_file, gws):
    clear_precompute_cache(workdir)

    cmd = [LOOKUP_PROG, rt_dir, hashes_file, os.path.join(rt_dir, "out.pot")]
    if gws:
        cmd += ["-precompute-gws", str(gws)]

    wall_start = time.monotonic()
    proc = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=7200)
    wall = time.monotonic() - wall_start
    output = _ANSI.sub("", proc.stdout.decode("utf-8", "replace"))

    if proc.returncode != 0:
        print(output)
        raise SystemExit("crackalack_lookup exited %d" % proc.returncode)

    m = _PRECOMP_RE.search(output)
    precomp = parse_human_time(m.group(1)) if m else float("nan")

    actual = _GWS_RE.findall(output)
    actual_gws = int(actual[0]) if actual else 0

    return precomp, wall, actual_gws


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chain-len", type=int, default=40000,
                    help="chain length to measure at (cost is quadratic; default 40000)")
    ap.add_argument("--num-chains", type=int, default=1024,
                    help="chains in the throwaway table (default 1024)")
    ap.add_argument("--hash", default=DEFAULT_HASH,
                    help="Net-NTLMv1 ciphertext to precompute for")
    ap.add_argument("--gws", type=int, nargs="+",
                    default=[0, 12288, 24576, 49152, 98304, 196608],
                    help="GWS values to sweep; 0 means the built-in default")
    ap.add_argument("--repeat", type=int, default=1,
                    help="runs per data point, best time kept (default 1)")
    args = ap.parse_args()

    if not os.path.isfile(LOOKUP_PROG):
        raise SystemExit("%s not found; build it first." % LOOKUP_PROG)

    workdir = make_workdir()
    rt_dir = os.path.join(workdir, "tables")
    os.makedirs(rt_dir)
    plant_table(rt_dir, args.chain_len, args.num_chains)

    hashes_file = os.path.join(rt_dir, "hashes.txt")
    with open(hashes_file, "w") as f:
        f.write(args.hash + "\n")

    print("Precompute benchmark: chain_len=%u, hash=%s" % (args.chain_len, args.hash))
    print("Real runs use chain_len 881689; cost scales as chain_len^2, so multiply")
    print("these by roughly %.0fx to project a production run.\n"
          % ((881689.0 / args.chain_len) ** 2))
    print("%12s  %10s  %10s  %10s" % ("requested", "actual GWS", "precomp s", "wall s"))
    print("%12s  %10s  %10s  %10s" % ("-" * 12, "-" * 10, "-" * 10, "-" * 10))

    baseline = None
    try:
        for gws in args.gws:
            best = None
            actual_gws = 0
            for _ in range(args.repeat):
                precomp, wall, actual_gws = run_one(workdir, rt_dir, hashes_file, gws)
                if best is None or precomp < best[0]:
                    best = (precomp, wall)
            label = "default" if gws == 0 else str(gws)
            if baseline is None:
                baseline = best[0]
                speedup = ""
            else:
                speedup = "   %.2fx" % (baseline / best[0]) if best[0] > 0 else ""
            print("%12s  %10u  %10.2f  %10.2f%s"
                  % (label, actual_gws, best[0], best[1], speedup))
            sys.stdout.flush()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
