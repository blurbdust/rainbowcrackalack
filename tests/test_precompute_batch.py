#!/usr/bin/env python3
#
# Rainbow Crackalack: tests/test_precompute_batch.py
#
# Batched pre-computation must be a pure speedup: the cache files it produces
# have to be byte-for-byte identical to the ones the one-hash-at-a-time path
# produces, because everything downstream (binary search, false alarm checks)
# reads them.
#
# This runs the same set of hashes twice against a throwaway table -- once with
# -precompute-batch 1 (one dispatch per hash, the historical behaviour) and once
# with batching on -- and compares the resulting rcracki.precalc.N payloads by
# their cache key.  It also reports the wall time of each, since the whole point
# is that N hashes should cost about what one costs.
#
# A small chain length is used deliberately: pre-computation is O(chain_len^2),
# so this finishes in seconds while exercising exactly the same kernel and
# dispatch shape as a production run.
#
# Usage: tests/test_precompute_batch.py [--chain-len N] [--hashes H1 H2 ...]
#

import argparse
import glob
import hashlib
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

GREEN, RED, CLR = "\033[0;32m", "\033[0;31m", "\033[0m"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Arbitrary Net-NTLMv1 ciphertexts; none of them will be in the planted table,
# so every one is a cache miss and actually gets pre-computed.
DEFAULT_HASHES = ["59b8beffd0c2aec5", "a9d83c6ca210be62",
                  "cec31640e20cbfca", "1122334455667788"]


def fail(msg):
    print("%sFAILED%s: %s" % (RED, CLR, msg))
    return False


def make_workdir():
    tmp = tempfile.mkdtemp(prefix="precompute_batch")
    for name in KERNEL_DIRS:
        src = os.path.join(REPO_ROOT, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(tmp, name))
            shutil.copy(os.path.join(REPO_ROOT, "shared.h"), os.path.join(tmp, name))
    return tmp


def plant_table(rt_dir, chain_len, num_chains=1024):
    rng = random.Random(0xBE4C11)
    chains = [(rng.getrandbits(56), rng.getrandbits(56)) for _ in range(num_chains)]
    path = os.path.join(rt_dir, "netntlmv1_byte#7-7_0_%ux%u_0.rt" % (chain_len, num_chains))
    with open(path, "wb") as f:
        for start, end in sorted(chains, key=lambda c: c[1]):
            f.write(struct.pack("<QQ", start, end))


def collect_cache(workdir):
    """Map each precompute cache key -> sha256 of its payload."""
    out = {}
    for index_path in glob.glob(os.path.join(workdir, "rcracki.precalc.*.index")):
        with open(index_path, "r") as f:
            key = f.read().strip()
        data_path = index_path[:-len(".index")]
        with open(data_path, "rb") as f:
            payload = f.read()
        out[key] = (hashlib.sha256(payload).hexdigest(), len(payload))
    return out


def clear_cache(workdir):
    for path in glob.glob(os.path.join(workdir, "rcracki.precalc.*")):
        os.unlink(path)


def run(workdir, rt_dir, hashes_file, extra):
    clear_cache(workdir)
    cmd = [LOOKUP_PROG, rt_dir, hashes_file, os.path.join(rt_dir, "out.pot")] + extra
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=7200)
    elapsed = time.monotonic() - start
    output = _ANSI.sub("", proc.stdout.decode("utf-8", "replace"))
    if proc.returncode != 0:
        print(output)
        raise SystemExit("crackalack_lookup exited %d" % proc.returncode)
    return collect_cache(workdir), elapsed, output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain-len", type=int, default=20000)
    ap.add_argument("--hashes", nargs="+", default=DEFAULT_HASHES)
    args = ap.parse_args()

    if not os.path.isfile(LOOKUP_PROG):
        raise SystemExit("%s not found; build it first." % LOOKUP_PROG)

    workdir = make_workdir()
    rt_dir = os.path.join(workdir, "tables")
    os.makedirs(rt_dir)
    plant_table(rt_dir, args.chain_len)

    hashes_file = os.path.join(rt_dir, "hashes.txt")
    with open(hashes_file, "w") as f:
        f.write("\n".join(args.hashes) + "\n")

    passed = True
    try:
        print("Pre-compute batching: %u hashes, chain_len=%u"
              % (len(args.hashes), args.chain_len))

        print("  one dispatch per hash... ", end="", flush=True)
        serial_cache, serial_time, _ = run(workdir, rt_dir, hashes_file,
                                           ["-precompute-batch", "1"])
        print("%.1fs" % serial_time)

        print("  batched...               ", end="", flush=True)
        batch_cache, batch_time, batch_out = run(workdir, rt_dir, hashes_file, [])
        print("%.1fs" % batch_time)

        # Correctness is the point: identical cache payloads, keyed by hash.
        if set(serial_cache) != set(batch_cache):
            missing = set(serial_cache) ^ set(batch_cache)
            passed = fail("different set of cache entries; symmetric difference: %s"
                          % sorted(missing))
        else:
            mismatched = [k for k in serial_cache if serial_cache[k] != batch_cache[k]]
            if mismatched:
                for k in mismatched:
                    print("    %s\n      serial: %s\n      batch:  %s"
                          % (k, serial_cache[k], batch_cache[k]))
                passed = fail("%u of %u pre-computations differ between batched and "
                              "unbatched" % (len(mismatched), len(serial_cache)))
            elif not serial_cache:
                passed = fail("no precompute cache files were produced; the test "
                              "did not exercise anything")
            else:
                print("%spassed%s: all %u pre-computations byte-identical."
                      % (GREEN, CLR, len(serial_cache)))

        # Not a hard assertion -- a tiny chain length on a busy GPU can be noise --
        # but the whole reason batching exists is that it should be faster.
        if batch_time > 0:
            print("  speedup: %.2fx (%u hashes)" % (serial_time / batch_time, len(args.hashes)))
            if batch_time >= serial_time:
                print("  %sNOTE%s: batching was not faster here. On a very short chain "
                      "length the fixed per-run costs dominate; re-check with "
                      "--chain-len 100000 before concluding anything."
                      % (RED, CLR))
        if "in one batch" not in batch_out:
            passed = fail("batched run never reported a batch; the batch path did "
                          "not actually run")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n\t%s%s%s\n" % (GREEN if passed else RED,
                            "PRE-COMPUTE BATCHING TESTS PASS!" if passed
                            else "PRE-COMPUTE BATCHING TESTS FAILED!", CLR))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
