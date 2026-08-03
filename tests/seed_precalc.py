#!/usr/bin/env python3
#
# Rainbow Crackalack: tests/seed_precalc.py
#
# Produce reusable precomputation files for a set of Net-NTLMv1 ciphertexts.
#
# crackalack_lookup caches its precomputation in rcracki.precalc.N (raw
# little-endian u64 candidate end indices) plus rcracki.precalc.N.index, a one
# line key of the form:
#
#     <hash name>_<charset>#<min>-<max>_<table index>_<chain len>:<hash>
#
# That key does not include the table's part index or chain count, so a
# precomputation done against any table with matching parameters is valid for
# every other part of the same table set.  See search_precompute_cache() in
# crackalack_lookup.c.
#
# Precomputation is the expensive phase (roughly chain_len^2 / 2 hash operations
# per ciphertext), so run this once on a GPU and reuse the output.  Everything
# after it (table I/O, binary search, false alarm checks) is cheap enough to run
# on a CPU OpenCL device, which is what makes real table lookups viable in CI.
#
# This deliberately runs against a tiny throwaway table so nothing large has to
# be downloaded: the lookup finds nothing, and the precomputation files are left
# behind for us to collect.
#
# Example:
#   tests/seed_precalc.py --chain-len 881689 --out precalc.tar.gz \
#       59b8beffd0c2aec5 a9d83c6ca210be62
#

import argparse
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

REPO_ROOT = os.environ.get(
    "CRACKALACK_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Chains in the throwaway table.  Small enough to be free, large enough that the
# lookup exercises its normal search path.
DUMMY_CHAINS = 1024


def main():
    ap = argparse.ArgumentParser(
        description="Generate reusable crackalack_lookup precomputation files.")
    ap.add_argument("hashes", nargs="+",
                    help="Net-NTLMv1 ciphertexts, 16 hex chars each")
    ap.add_argument("--chain-len", type=int, required=True,
                    help="chain length of the table set you will search")
    ap.add_argument("--table-index", type=int, default=0,
                    help="table index of that set (default: 0)")
    ap.add_argument("--charset", default="byte", help="default: byte")
    ap.add_argument("--plaintext-len", type=int, default=7, help="default: 7")
    ap.add_argument("--hash-name", default="netntlmv1", help="default: netntlmv1")
    ap.add_argument("--out", default="precalc.tar.gz",
                    help="output tarball (default: precalc.tar.gz)")
    args = ap.parse_args()

    hashes = [h.strip().lower() for h in args.hashes]
    for h in hashes:
        if len(h) != 16 or not re.fullmatch(r"[0-9a-f]{16}", h):
            print("Error: %r is not a 16 hex character Net-NTLMv1 ciphertext" % h)
            return 2

    lookup_prog = os.path.join(REPO_ROOT, "crackalack_lookup")
    if not os.path.isfile(lookup_prog):
        print("Error: %s not found.  Build it first." % lookup_prog)
        return 2

    out_path = os.path.abspath(args.out)
    workdir = tempfile.mkdtemp(prefix="seed_precalc")
    try:
        shutil.copytree(os.path.join(REPO_ROOT, "CL"), os.path.join(workdir, "CL"))
        shutil.copy(os.path.join(REPO_ROOT, "shared.h"), os.path.join(workdir, "CL"))
        rt_dir = os.path.join(workdir, "tables")
        os.mkdir(rt_dir)

        # A throwaway table with the parameters we want precomputed.  Its part
        # index and chain count are irrelevant to the cache key; only the
        # charset, plaintext lengths, table index and chain length matter.
        table_name = "%s_%s#%u-%u_%u_%ux%u_0.rt" % (
            args.hash_name, args.charset, args.plaintext_len, args.plaintext_len,
            args.table_index, args.chain_len, DUMMY_CHAINS)
        rng = random.Random(0x5EED)
        chains = sorted(((rng.getrandbits(56), rng.getrandbits(56))
                         for _ in range(DUMMY_CHAINS)), key=lambda c: c[1])
        with open(os.path.join(rt_dir, table_name), "wb") as f:
            for start, end in chains:
                f.write(struct.pack("<QQ", start, end))

        hashes_file = os.path.join(workdir, "hashes.txt")
        with open(hashes_file, "w") as f:
            f.write("\n".join(hashes) + "\n")

        print("Precomputing %u ciphertext(s) at chain_len=%u, table_index=%u."
              % (len(hashes), args.chain_len, args.table_index))
        print("This is the expensive phase (about chain_len^2 / 2 hash operations")
        print("per ciphertext).  Run it on a GPU.\n")

        started = time.time()
        proc = subprocess.run(
            [lookup_prog, rt_dir, hashes_file, os.path.join(workdir, "seed.pot")],
            cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ANSI.sub("", proc.stdout.decode("utf-8", "replace"))
        if proc.returncode != 0:
            print("Error: crackalack_lookup exited %d:\n%s" % (proc.returncode, output))
            return 1
        print("Precomputation finished in %u seconds." % int(time.time() - started))

        # Collect the precomputation files and check their keys look right.
        produced = sorted(f for f in os.listdir(workdir)
                          if f.startswith("rcracki.precalc."))
        index_files = [f for f in produced if f.endswith(".index")]
        if len(index_files) != len(hashes):
            print("Error: expected %u index files, found %u: %r\n%s"
                  % (len(hashes), len(index_files), produced, output))
            return 1

        expected_prefix = "%s_%s#%u-%u_%u_%u:" % (
            args.hash_name, args.charset, args.plaintext_len, args.plaintext_len,
            args.table_index, args.chain_len)
        seen = set()
        for name in index_files:
            with open(os.path.join(workdir, name)) as f:
                key = f.read().strip()
            if not key.startswith(expected_prefix):
                print("Error: %s has unexpected key %r (expected prefix %r)"
                      % (name, key, expected_prefix))
                return 1
            seen.add(key.rsplit(":", 1)[1])
            data_size = os.path.getsize(os.path.join(workdir, name[:-len(".index")]))
            if data_size != (args.chain_len - 1) * 8:
                print("Error: %s holds %u bytes, expected %u"
                      % (name[:-len(".index")], data_size, (args.chain_len - 1) * 8))
                return 1
            print("  %s -> %s (%u indices)" % (name, key, data_size // 8))

        if seen != set(hashes):
            print("Error: precomputed %r but asked for %r" % (sorted(seen), sorted(hashes)))
            return 1

        with tarfile.open(out_path, "w:gz") as tar:
            for name in produced:
                tar.add(os.path.join(workdir, name), arcname=name)

        print("\nWrote %s (%u bytes, %u files)."
              % (out_path, os.path.getsize(out_path), len(produced)))
        print("Unpack it into crackalack_lookup's working directory to skip "
              "precomputation for these ciphertexts against any table part\n"
              "of this set.")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
